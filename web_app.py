from __future__ import annotations

import importlib.util
import json
import os
import secrets
import shutil
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Dict

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
    Response,
)

import run_all as phase2_runner


BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
AGGREGATE_FILE = REPORTS_DIR / "aggregate" / "latest_aggregate_internal.json"
PHASE3_DIR = REPORTS_DIR / "phase3"
PHASE3_FILE = PHASE3_DIR / "latest_phase3_analysis.json"
ACTION_PLAN_FILE = PHASE3_DIR / "latest_action_plan.json"
WEB_PENDING_FILE = PHASE3_DIR / "web_pending_phase3.json"
PHASE4_DIR = REPORTS_DIR / "phase4"
PHASE4_STATE_FILE = PHASE4_DIR / "latest_phase4_state.json"
PHASE4_SHAREABLE_FILE = PHASE4_DIR / "latest_phase4_shareable.json"
VERIFICATION_DIR = REPORTS_DIR / "verification"
VERIFICATION_PENDING_FILE = VERIFICATION_DIR / "pending_rescan.json"
VERIFICATION_LATEST_FILE = VERIFICATION_DIR / "latest_verification.json"
VISUAL_CACHE_DIR = REPORTS_DIR / "visual_cache"

ALLOWED_REFERENCE_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
MAX_REFERENCE_IMAGE_BYTES = 8 * 1024 * 1024

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_REFERENCE_IMAGE_BYTES
app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)


@app.errorhandler(413)
def reference_image_too_large(_error):
    flash("Reference image is larger than 8 MB.", "error")
    return redirect(url_for("phase1"))


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------

def read_json(path: Path) -> Dict[str, Any] | None:
    try:
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------

def mask_email(value: str) -> str:
    value = (value or "").strip()
    if "@" not in value:
        return ""
    local, domain = value.split("@", 1)
    if not local:
        return f"***@{domain}"
    return f"{local[:1]}{'*' * max(3, len(local) - 1)}@{domain}"


def mask_phone(value: str) -> str:
    digits = "".join(ch for ch in (value or "") if ch.isdigit())
    if not digits:
        return ""
    return "*" * max(0, len(digits) - 4) + digits[-4:]


def public_profile(aggregate: Dict[str, Any] | None) -> Dict[str, Any]:
    profile = (aggregate or {}).get("input_profile", {})
    return {
        "full_name": profile.get("full_name", ""),
        "email_masked": mask_email(str(profile.get("email") or "")),
        "username": profile.get("username", ""),
        "phone_masked": mask_phone(str(profile.get("phone") or "")),
        "context_terms": profile.get("context_terms", []),
    }


def phase2_summary(aggregate: Dict[str, Any] | None) -> Dict[str, Any]:
    if not aggregate:
        return {}

    summary = dict(aggregate.get("cross_layer_summary", {}))
    layers = aggregate.get("layers", {})

    p2a = layers.get("phase_2A_public", {})
    p2b = layers.get("phase_2B_breach_and_broker", {})
    p2c = layers.get("phase_2C_local_passive", {})

    summary["phase2a_status"] = p2a.get("status", "unknown")
    summary["phase2b_status"] = p2b.get("status", "unknown")
    summary["phase2c_status"] = p2c.get("status", "unknown")
    summary["breach_lookup_status"] = p2b.get("breach_lookup_status", "not_run")
    summary["local_audit_authorized"] = bool(
        p2c.get("consent", {}).get("local_browser_audit", False)
    )

    visual = p2a.get("visual_identity_summary", {})
    summary["visual_search_status"] = (
        visual.get("status")
        or summary.get("visual_search_status")
        or "not_used"
    )
    summary["visual_matches"] = int(
        visual.get("visual_match_count", summary.get("visual_matches", 0)) or 0
    )
    summary["visual_images_checked"] = int(
        visual.get(
            "candidate_images_checked",
            summary.get("visual_images_checked", 0),
        ) or 0
    )
    summary["visual_faces_checked"] = int(
        visual.get(
            "candidate_faces_checked",
            summary.get("visual_faces_checked", 0),
        ) or 0
    )
    summary["visual_independent_queries"] = int(
        visual.get(
            "independent_query_count",
            summary.get("visual_independent_queries", 0),
        ) or 0
    )
    summary["visual_independent_images_discovered"] = int(
        visual.get(
            "independent_images_discovered",
            summary.get("visual_independent_images_discovered", 0),
        ) or 0
    )
    summary["visual_independent_images_checked"] = int(
        visual.get(
            "independent_images_checked",
            summary.get("visual_independent_images_checked", 0),
        ) or 0
    )
    summary["visual_independent_faces_checked"] = int(
        visual.get(
            "independent_faces_checked",
            summary.get("visual_independent_faces_checked", 0),
        ) or 0
    )
    summary["visual_independent_matches"] = int(
        visual.get(
            "independent_match_count",
            summary.get("visual_independent_matches", 0),
        ) or 0
    )
    summary["visual_reason"] = visual.get("reason", "")
    review_items = p2a.get("visual_review_items", []) or []
    summary["visual_reviewable_images"] = len(
        [item for item in review_items if item.get("cache_file")]
    )
    summary["visual_manual_confirmed_images"] = sum(
        item.get("manual_verification") == "confirmed"
        for item in review_items
    )

    return summary


def phase2_public_preview(aggregate: Dict[str, Any] | None) -> list[Dict[str, Any]]:
    if not aggregate:
        return []

    results = (
        aggregate
        .get("layers", {})
        .get("phase_2A_public", {})
        .get("results", [])
    )

    preview = []

    for item in results:
        url = (
            item.get("canonical_url")
            or item.get("resolved_url")
            or item.get("url")
            or ""
        )
        identity_status = item.get("identity_status") or "Unknown"
        preview.append({
            "title": item.get("title") or "Untitled result",
            "url": url,
            "source_category": item.get("source_category") or "Public result",
            "identity_status": identity_status,
            "identity_score": item.get("identity_score"),
            "match_reasons": list(item.get("match_reasons") or [])[:3],
            "needs_identity_confirmation": (identity_status in {"Strong", "Possible"}),
            "risk_score": item.get("risk_score"),
            "risk_level": item.get("risk_level") or "Unknown",
            "public_value": item.get("public_value") or "",
            "domain": item.get("domain") or "",
            "visual_match_found": bool(
                (item.get("visual_identity") or {}).get("face_match_found")
            ),
            "visual_match_strength": (
                (item.get("visual_identity") or {}).get("match_strength") or ""
            ),
            "visual_face_distance": (
                (item.get("visual_identity") or {}).get("best_face_distance")
            ),
            "visual_images_checked": int(
                (item.get("visual_identity") or {}).get(
                    "candidate_images_checked", 0
                ) or 0
            ),
            "visual_manual_verification": (
                (item.get("visual_identity") or {}).get(
                    "manual_verification_status", "unreviewed"
                )
            ),
            "visual_manual_confirmed_count": int(
                (item.get("visual_identity") or {}).get(
                    "manual_confirmed_image_count", 0
                ) or 0
            ),
        })

    return preview


def phase2_visual_review_items(aggregate: Dict[str, Any] | None) -> list[Dict[str, Any]]:
    if not aggregate:
        return []
    items = (
        aggregate
        .get("layers", {})
        .get("phase_2A_public", {})
        .get("visual_review_items", [])
    )
    return [dict(item) for item in items if item.get("cache_file")]


def persist_current_aggregate(aggregate: Dict[str, Any]) -> None:
    """Persist manual visual-review changes to the current aggregate files."""
    write_json(AGGREGATE_FILE, aggregate)

    saved = aggregate.get("saved_files", {}) or {}
    internal_report = saved.get("internal_report")
    if internal_report:
        write_json(BASE_DIR / Path(internal_report), aggregate)

    shareable = phase2_runner.make_shareable(aggregate)
    latest_shareable = saved.get("latest_shareable")
    if latest_shareable:
        write_json(BASE_DIR / Path(latest_shareable), shareable)
    shareable_report = saved.get("shareable_report")
    if shareable_report:
        write_json(BASE_DIR / Path(shareable_report), shareable)


def apply_visual_review_decisions(
    aggregate: Dict[str, Any],
    decisions: Dict[str, str],
) -> Dict[str, int]:
    layer_a = (
        aggregate
        .setdefault("layers", {})
        .setdefault("phase_2A_public", {})
    )
    review_items = layer_a.get("visual_review_items", []) or []

    allowed = {"confirmed", "rejected", "unsure", "unreviewed"}
    updated = 0

    for item in review_items:
        review_id = str(item.get("review_id") or "")
        decision = decisions.get(review_id)
        if decision not in allowed:
            continue
        if item.get("manual_verification") != decision:
            item["manual_verification"] = decision
            updated += 1

    # Roll image-level decisions up to the parent public result.
    by_page: Dict[str, list[Dict[str, Any]]] = {}
    for item in review_items:
        page_url = str(item.get("page_url") or "")
        if page_url:
            by_page.setdefault(page_url, []).append(item)

    for result in layer_a.get("results", []) or []:
        page_url = str(
            result.get("canonical_url")
            or result.get("resolved_url")
            or result.get("url")
            or ""
        )
        page_items = by_page.get(page_url, [])
        if not page_items:
            continue

        statuses = [
            str(item.get("manual_verification") or "unreviewed")
            for item in page_items
        ]
        confirmed_count = statuses.count("confirmed")
        if confirmed_count:
            page_status = "confirmed"
        elif "unsure" in statuses:
            page_status = "unsure"
        elif statuses and all(value == "rejected" for value in statuses):
            page_status = "rejected"
        else:
            page_status = "unreviewed"

        visual_meta = result.setdefault("visual_identity", {})
        visual_meta["manual_verification_status"] = page_status
        visual_meta["manual_confirmed_image_count"] = confirmed_count

        signals = result.setdefault("identity_signals", {})
        signals["visual_manual_verification"] = page_status
        signals["visual_manual_confirmed"] = page_status == "confirmed"

    # The same user-confirmed visual evidence can resolve a broker's identity
    # gate when that broker record points to the same public page.
    broker_layer = (
        aggregate
        .get("layers", {})
        .get("phase_2B_breach_and_broker", {})
    )
    for broker in broker_layer.get("data_broker_exposures", []) or []:
        page_items = by_page.get(str(broker.get("record_url") or ""), [])
        if not any(
            item.get("manual_verification") == "confirmed"
            for item in page_items
        ):
            continue
        broker["visual_manual_verification"] = "confirmed"
        broker["requires_identity_confirmation"] = False
        broker["recommended_action"] = (
            "The fetched public image was confirmed by the user. Review the "
            "broker record and approve any later opt-out/removal action."
        )

    confirmed_images = sum(
        item.get("manual_verification") == "confirmed"
        for item in review_items
    )
    confirmed_pages = len({
        str(item.get("page_url") or "")
        for item in review_items
        if item.get("manual_verification") == "confirmed"
        and item.get("page_url")
    })

    layer_summary = layer_a.setdefault("summary", {})
    layer_summary["visual_manual_confirmed_images"] = confirmed_images
    layer_summary["visual_manual_confirmed_pages"] = confirmed_pages

    aggregate.setdefault("cross_layer_summary", {})[
        "visual_manual_confirmed_images"
    ] = confirmed_images
    aggregate["cross_layer_summary"][
        "visual_manual_confirmed_pages"
    ] = confirmed_pages

    return {
        "updated": updated,
        "confirmed_images": confirmed_images,
        "confirmed_pages": confirmed_pages,
    }


def risk_class(level: str) -> str:
    value = (level or "").strip().lower()

    if value == "critical":
        return "critical"

    if value == "high":
        return "high"

    if value in {"medium", "moderate"}:
        return "medium"

    return "low"


app.jinja_env.globals["risk_class"] = risk_class


def get_common_context():
    aggregate = read_json(AGGREGATE_FILE)
    phase3 = read_json(PHASE3_FILE)
    action_plan = read_json(ACTION_PLAN_FILE)
    phase4 = read_json(PHASE4_STATE_FILE)

    # Never surface stale remediation state after Phase 3 has been regenerated.
    if phase4 and action_plan:
        if (
            phase4.get("source_run_id") != action_plan.get("source_run_id")
            or phase4.get("source_phase3_run_time") != action_plan.get("run_time")
        ):
            phase4 = None

    return {
        "aggregate": aggregate,
        "profile": public_profile(aggregate),
        "p2": phase2_summary(aggregate),
        "public_results": phase2_public_preview(aggregate),
        "visual_review_items": phase2_visual_review_items(aggregate),
        "phase3": phase3,
        "action_plan": action_plan,
        "phase4": phase4,
    }


# ---------------------------------------------------------------------------
# Load Phase 3 V2
# ---------------------------------------------------------------------------

def load_phase3_module():
    phase3_path = BASE_DIR / "run_phase3.py"

    if not phase3_path.exists():
        raise FileNotFoundError(
            "run_phase3.py was not found in the project folder."
        )

    spec = importlib.util.spec_from_file_location(
        "phase3_runtime_v2",
        phase3_path,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load run_phase3.py")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module




# ---------------------------------------------------------------------------
# Load Phase 4 remediation engine
# ---------------------------------------------------------------------------

def load_phase4_module():
    phase4_path = BASE_DIR / "phase4_remediation.py"

    if not phase4_path.exists():
        raise FileNotFoundError(
            "phase4_remediation.py was not found in the project folder."
        )

    spec = importlib.util.spec_from_file_location(
        "phase4_runtime_v1",
        phase4_path,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load phase4_remediation.py")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_phase4_mail_module():
    path = BASE_DIR / "phase4_mail.py"
    if not path.exists():
        raise FileNotFoundError("phase4_mail.py was not found in the project folder.")
    spec = importlib.util.spec_from_file_location("phase4_mail_runtime_v1", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load phase4_mail.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def phase4_mail_context() -> Dict[str, Any]:
    """Return safe provider-aware mailbox context for the Phase 4 UI."""
    aggregate = read_json(AGGREGATE_FILE) or {}
    identity_email = str((aggregate.get("input_profile") or {}).get("email") or "").strip()
    try:
        mail = load_phase4_mail_module()
        capability = mail.mail_capability_for_address(identity_email)
        status = mail.connection_status()
    except Exception:
        capability = {
            "domain": identity_email.rsplit("@", 1)[-1].casefold() if "@" in identity_email else "",
            "provider": "mail provider",
            "automatic_oauth_supported": False,
            "manual_fallback": True,
        }
        status = {"provider": "Gmail", "configured": False, "connected": False}

    capability = dict(capability)
    capability["email_masked"] = mask_email(identity_email)
    status = dict(status)
    status["address_masked"] = mask_email(str(status.get("address") or ""))
    status["matches_identity"] = bool(
        identity_email
        and status.get("address")
        and identity_email.casefold() == str(status.get("address") or "").casefold()
    )
    return {
        "mail_identity": capability,
        "mail_status": status,
    }


def load_phase4_verification_module():
    path = BASE_DIR / "phase4_verification.py"
    if not path.exists():
        raise FileNotFoundError("phase4_verification.py was not found in the project folder.")
    spec = importlib.util.spec_from_file_location("phase4_verification_runtime_v1", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load phase4_verification.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def finalize_pending_rescan_verification() -> Dict[str, Any] | None:
    """Finalize a before/after comparison only after Phase 3 is current."""
    if not VERIFICATION_PENDING_FILE.exists():
        return None
    aggregate = read_json(AGGREGATE_FILE)
    phase3 = read_json(PHASE3_FILE)
    if not aggregate or not phase3:
        return None
    verifier = load_phase4_verification_module()
    return verifier.finalize_pending_if_possible(aggregate, phase3)


def invalidate_phase4_latest() -> None:
    # Historical Phase 4 snapshots and backups are intentionally preserved.
    # Only the latest pointers are invalidated when underlying evidence changes.
    for path in (PHASE4_STATE_FILE, PHASE4_SHAREABLE_FILE):
        try:
            path.unlink()
        except FileNotFoundError:
            pass

def verification_summary(analyses: list[Dict[str, Any]]) -> Dict[str, int]:
    counter = Counter()

    for item in analyses:
        counter[item.get("user_verification", "not_required")] += 1

    return dict(counter)


def snapshot_pre_verification(analysis: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "risk_score": analysis.get("risk_score"),
        "risk_level": analysis.get("risk_level"),
        "risk_explanation": analysis.get("risk_explanation"),
        "recommended_action": analysis.get("recommended_action"),
        "action_reason": analysis.get("action_reason"),
        "confidence": analysis.get("confidence"),
    }


def apply_web_verification(
    analyses: list[Dict[str, Any]],
    decisions: Dict[str, str],
) -> list[str]:

    confirmed_ids: list[str] = []

    for analysis in analyses:
        finding_id = analysis.get("finding_id", "")

        if not analysis.get("needs_user_verification"):
            analysis["user_verification"] = "not_required"
            analysis["verification_reassessment_performed"] = False
            continue

        decision = decisions.get(finding_id)

        if decision not in {"confirmed", "rejected", "unsure"}:
            raise ValueError(
                f"Verification answer missing for {finding_id}."
            )

        original_question = (
            analysis.get("verification_question")
            or "Do you confirm that this finding belongs to you?"
        )

        analysis["pre_verification_assessment"] = snapshot_pre_verification(
            analysis
        )

        analysis["user_verification"] = decision

        analysis["verification_audit"] = {
            "question": original_question,
            "response": decision,
        }

        analysis["verification_reassessment_performed"] = False

        if decision == "confirmed":
            confirmed_ids.append(finding_id)

            analysis["needs_user_verification"] = False
            analysis["verification_question"] = ""
            analysis["recommended_action"] = "review"
            analysis["action_reason"] = (
                "Ownership was confirmed by the user. "
                "Post-verification privacy reassessment is pending."
            )

        elif decision == "rejected":
            analysis["risk_score"] = 0
            analysis["risk_level"] = "Low"
            analysis["risk_explanation"] = (
                "The user stated that this finding does not belong to them. "
                "It is excluded from the subject's privacy-risk assessment."
            )
            analysis["recommended_action"] = "ignore"
            analysis["needs_user_verification"] = False
            analysis["verification_question"] = ""
            analysis["action_reason"] = (
                "No privacy action should be taken because the user "
                "rejected ownership of this finding."
            )

        else:
            analysis["risk_score"] = 0
            analysis["risk_level"] = "Low"
            analysis["risk_explanation"] = (
                "Ownership remains unresolved. This finding is not counted "
                "as a confirmed privacy exposure until identity is established."
            )
            analysis["recommended_action"] = "verify_identity"
            analysis["needs_user_verification"] = True
            analysis["verification_question"] = original_question
            analysis["action_reason"] = (
                "Ownership remains unresolved. No modification, removal, "
                "or opt-out action should be attempted until identity is confirmed."
            )

    return confirmed_ids


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    return render_template(
        "index.html",
        **get_common_context(),
    )


@app.get("/phase1")
def phase1():
    return render_template(
        "phase1.html",
        **get_common_context(),
    )


@app.get("/phase2")
def phase2():
    return render_template(
        "phase2.html",
        **get_common_context(),
    )


@app.get("/phase2/visual-review")
def phase2_visual_review():
    aggregate = read_json(AGGREGATE_FILE)
    if not aggregate:
        flash("Run Phase 2 first. No visual evidence is available.", "error")
        return redirect(url_for("phase2"))

    items = phase2_visual_review_items(aggregate)
    if not items:
        flash("No fetched candidate images are available for manual review.", "warning")
        return redirect(url_for("phase2"))

    return render_template(
        "visual_review.html",
        **get_common_context(),
    )


@app.get("/visual-cache/<path:cache_file>")
def visual_cache_file(cache_file: str):
    # send_from_directory safely constrains the request to VISUAL_CACHE_DIR.
    return send_from_directory(VISUAL_CACHE_DIR, cache_file)


@app.post("/phase2/visual-review")
def phase2_visual_review_submit():
    aggregate = read_json(AGGREGATE_FILE)
    if not aggregate:
        flash("Current Phase 2 aggregate was not found.", "error")
        return redirect(url_for("phase2"))

    decisions: Dict[str, str] = {}
    for item in phase2_visual_review_items(aggregate):
        review_id = str(item.get("review_id") or "")
        if not review_id:
            continue
        value = request.form.get(f"visual_{review_id}")
        if value:
            decisions[review_id] = value

    stats = apply_visual_review_decisions(aggregate, decisions)
    persist_current_aggregate(aggregate)

    # Any old Phase 3 result is stale after evidence-level manual review.
    for path in (
        PHASE3_FILE,
        ACTION_PLAN_FILE,
        WEB_PENDING_FILE,
        PHASE4_STATE_FILE,
        PHASE4_SHAREABLE_FILE,
    ):
        if path.exists():
            path.unlink()

    flash(
        f"Visual review saved. {stats['confirmed_images']} image(s) are "
        f"confirmed across {stats['confirmed_pages']} page(s).",
        "success",
    )
    return redirect(url_for("phase2"))


@app.get("/phase3")
def phase3():
    return render_template(
        "phase3.html",
        **get_common_context(),
    )


@app.get("/phase4")
def phase4():
    context = get_common_context()
    context.update(phase4_mail_context())
    try:
        verifier = load_phase4_verification_module()
        context["verification_pending"] = verifier.pending_status()
        context["latest_verification"] = verifier.latest_verification()
    except Exception:
        context["verification_pending"] = None
        context["latest_verification"] = None

    if not PHASE3_FILE.exists() or not ACTION_PLAN_FILE.exists():
        return render_template("phase4.html", **context)

    try:
        p4 = load_phase4_module()
        state = p4.load_or_initialize_state()
        aggregate = read_json(AGGREGATE_FILE) or {}
        profile = aggregate.get("input_profile", {}) or {}
        previews: Dict[str, Dict[str, Any]] = {}
        for task in state.get("tasks", []) or []:
            if (
                task.get("recommended_action") == "broker_opt_out"
                and (task.get("approval") or {}).get("decision") == "approved"
                and (task.get("target") or {}).get("contact_email")
            ):
                try:
                    previews[str(task.get("task_id"))] = p4.build_broker_email_preview(
                        state, str(task.get("task_id")), profile
                    )
                except Exception:
                    pass

        context = get_common_context()
        context["broker_email_previews"] = previews
        context.update(phase4_mail_context())
        try:
            verifier = load_phase4_verification_module()
            context["verification_pending"] = verifier.pending_status()
            context["latest_verification"] = verifier.latest_verification()
        except Exception:
            context["verification_pending"] = None
            context["latest_verification"] = None
        return render_template("phase4.html", **context)
    except Exception as exc:
        flash(
            f"Phase 4 could not be initialized: {type(exc).__name__}: {exc}",
            "error",
        )
        return render_template("phase4.html", **context)


# ---------------------------------------------------------------------------
# Phase 1 + Phase 2 execution
# ---------------------------------------------------------------------------

@app.post("/scan")
def run_scan():
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip()
    username = request.form.get("username", "").strip()
    phone = request.form.get("phone", "").strip()

    context_terms = [
        item.strip()
        for item in request.form.get("context_terms", "").split(",")
        if item.strip()
    ]

    if not full_name:
        flash("Full name is required to start the scan.", "error")
        return redirect(url_for("phase1"))

    profile = {
        "full_name": full_name,
        "email": email,
        "username": username,
        "phone": phone,
        "context_terms": context_terms,
    }

    breach_consent = request.form.get("consent_breach") == "on"
    local_consent = request.form.get("consent_local") == "on"
    visual_consent = request.form.get("consent_visual") == "on"
    cache_only = request.form.get("cache_only") == "on"
    reference_image = request.files.get("reference_image")

    if breach_consent and not email:
        flash(
            "Breach lookup was authorised, but no email was supplied; the breach layer will be skipped.",
            "warning",
        )

    if cache_only and breach_consent:
        flash(
            "Cache-only mode disables the live email-breach lookup.",
            "warning",
        )

    image_supplied = bool(reference_image and reference_image.filename)
    if image_supplied and not visual_consent:
        flash(
            "A reference image was selected but visual matching was not authorised, so the image will not be processed.",
            "warning",
        )

    if visual_consent and not image_supplied:
        flash(
            "Visual matching was authorised but no reference image was supplied; the scan will continue without visual matching.",
            "warning",
        )

    if visual_consent and cache_only:
        flash(
            "Visual web matching requires network access and will not run in cache-only mode.",
            "warning",
        )

    reference_suffix = ""
    if image_supplied:
        reference_suffix = Path(reference_image.filename or "").suffix.casefold()
        if reference_suffix not in ALLOWED_REFERENCE_IMAGE_EXTENSIONS:
            flash(
                "Reference image must be JPG, JPEG, PNG, or WEBP.",
                "error",
            )
            return redirect(url_for("phase1"))

    try:
        # A new Phase 2 scan supersedes the previous visual-review cache.
        if VISUAL_CACHE_DIR.exists():
            shutil.rmtree(VISUAL_CACHE_DIR, ignore_errors=True)

        if visual_consent and image_supplied and not cache_only:
            # The raw upload exists only for this synchronous scan. It is
            # deleted automatically as soon as the request finishes.
            with tempfile.TemporaryDirectory(prefix="footprint_visual_") as temp_dir:
                reference_path = Path(temp_dir) / f"reference{reference_suffix}"
                reference_image.save(reference_path)

                report = phase2_runner.run_all(
                    profile,
                    allow_network=True,
                    consent_breach_lookup=breach_consent,
                    consent_local_audit=local_consent,
                    consent_visual_search=True,
                    reference_image_path=str(reference_path),
                )
        else:
            report = phase2_runner.run_all(
                profile,
                allow_network=not cache_only,
                consent_breach_lookup=breach_consent,
                consent_local_audit=local_consent,
                consent_visual_search=visual_consent,
                reference_image_path=None,
            )

        phase2_runner.save_aggregate(report)

        for stale_file in (
            PHASE3_FILE,
            ACTION_PLAN_FILE,
            WEB_PENDING_FILE,
            PHASE4_STATE_FILE,
            PHASE4_SHAREABLE_FILE,
        ):
            if stale_file.exists():
                stale_file.unlink()

        flash(
            "Phase 2 scan completed. Review the evidence below.",
            "success",
        )

        return redirect(url_for("phase2"))

    except Exception as exc:
        flash(
            f"Phase 2 scan failed: {type(exc).__name__}: {exc}",
            "error",
        )

        return redirect(url_for("phase1"))


# ---------------------------------------------------------------------------
# Phase 3 - initial AI pass
# ---------------------------------------------------------------------------

@app.post("/phase3/start")
def phase3_start():
    if not AGGREGATE_FILE.exists():
        flash(
            "Run Phase 2 first. No aggregate report is available.",
            "error",
        )
        return redirect(url_for("phase3"))

    # A new AI pass supersedes any previously approved remediation plan.
    invalidate_phase4_latest()

    try:
        p3 = load_phase3_module()

        report = p3.load_aggregate_report()
        compact_input = p3.build_compact_ai_input(report)

        original_findings = compact_input.get("findings", [])

        if not original_findings:
            flash(
                "Phase 3 cannot start because Phase 2 produced no findings.",
                "error",
            )
            return redirect(url_for("phase3"))

        safe_findings = p3.sanitized_findings(
            report,
            compact_input,
        )

        client = p3.get_client()

        analyses = p3.analyze_all_findings(
            client,
            safe_findings,
        )

        pending_payload = {
            "source_run_id": report.get("run_id"),
            "analyses": analyses,
            "safe_findings": safe_findings,
            "original_findings": original_findings,
        }

        write_json(
            WEB_PENDING_FILE,
            pending_payload,
        )

        pending = [
            item
            for item in analyses
            if item.get("needs_user_verification")
        ]

        if pending:
            flash(
                f"Initial AI analysis completed. "
                f"{len(pending)} findings need your confirmation.",
                "success",
            )
            return redirect(url_for("phase3_verify"))

        reassessed_count = 0
        summary = verification_summary(analyses)

        cross_layer = p3.analyze_cross_layer(
            client,
            report.get("cross_layer_summary", {}),
            analyses,
        )

        p3.save_phase3_outputs(
            report,
            analyses,
            summary,
            reassessed_count,
            cross_layer,
        )
        invalidate_phase4_latest()
        try:
            verification_report = finalize_pending_rescan_verification()
            if verification_report and verification_report.get("status") == "completed":
                flash(
                    f"Re-scan verification completed: {verification_report.get('summary', {}).get('verified', 0)} remediation result(s) verified.",
                    "success",
                )
        except Exception as verification_exc:
            flash(
                f"Phase 3 completed, but remediation re-scan comparison needs attention: {verification_exc}",
                "warning",
            )

        if WEB_PENDING_FILE.exists():
            WEB_PENDING_FILE.unlink()

        flash(
            "Phase 3 completed. No identity confirmations were required.",
            "success",
        )

        return redirect(url_for("phase3"))

    except Exception as exc:
        flash(
            f"Phase 3 failed: {type(exc).__name__}: {exc}",
            "error",
        )

        return redirect(url_for("phase3"))


# ---------------------------------------------------------------------------
# Phase 3 - web verification
# ---------------------------------------------------------------------------

@app.get("/phase3/verify")
def phase3_verify():
    pending = read_json(WEB_PENDING_FILE)

    if not pending:
        flash(
            "There is no Phase 3 verification session waiting for input.",
            "error",
        )
        return redirect(url_for("phase3"))

    analyses = pending.get("analyses", [])

    original = {
        item.get("finding_id"): item
        for item in pending.get("original_findings", [])
    }

    verification_items = []

    for item in analyses:
        if not item.get("needs_user_verification"):
            continue

        finding = original.get(
            item.get("finding_id"),
            {},
        )

        verification_items.append({
            "analysis": item,
            "finding": finding,
            "label": (
                finding.get("title")
                or finding.get("service")
                or finding.get("provider")
                or finding.get("browser")
                or finding.get("domain")
                or item.get("finding_id")
            ),
        })

    return render_template(
        "verify.html",
        items=verification_items,
        total=len(verification_items),
    )


@app.post("/phase3/verify")
def phase3_submit_verification():
    pending = read_json(WEB_PENDING_FILE)

    if not pending:
        flash(
            "The Phase 3 verification session has expired.",
            "error",
        )
        return redirect(url_for("phase3"))

    analyses = pending.get("analyses", [])
    safe_findings = pending.get("safe_findings", [])

    decisions: Dict[str, str] = {}

    for analysis in analyses:
        if not analysis.get("needs_user_verification"):
            continue

        finding_id = analysis.get("finding_id", "")

        value = request.form.get(
            f"verification_{finding_id}",
            "",
        )

        if value not in {"confirmed", "rejected", "unsure"}:
            flash(
                "Please answer Yes, No, or Unsure for every verification card.",
                "error",
            )
            return redirect(url_for("phase3_verify"))

        decisions[finding_id] = value

    try:
        p3 = load_phase3_module()
        report = p3.load_aggregate_report()

        if pending.get("source_run_id") != report.get("run_id"):
            raise RuntimeError(
                "The underlying Phase 2 report changed. "
                "Please restart Phase 3."
            )

        confirmed_ids = apply_web_verification(
            analyses,
            decisions,
        )

        client = p3.get_client()

        reassessed_count = p3.reassess_confirmed_findings(
            client,
            analyses,
            confirmed_ids,
            safe_findings,
        )

        summary = verification_summary(analyses)

        cross_layer = p3.analyze_cross_layer(
            client,
            report.get("cross_layer_summary", {}),
            analyses,
        )

        p3.save_phase3_outputs(
            report,
            analyses,
            summary,
            reassessed_count,
            cross_layer,
        )
        invalidate_phase4_latest()
        try:
            verification_report = finalize_pending_rescan_verification()
            if verification_report and verification_report.get("status") == "completed":
                flash(
                    f"Re-scan verification completed: {verification_report.get('summary', {}).get('verified', 0)} remediation result(s) verified.",
                    "success",
                )
        except Exception as verification_exc:
            flash(
                f"Phase 3 completed, but remediation re-scan comparison needs attention: {verification_exc}",
                "warning",
            )

        if WEB_PENDING_FILE.exists():
            WEB_PENDING_FILE.unlink()

        flash(
            f"Phase 3 finalized. "
            f"{reassessed_count} confirmed findings were reassessed.",
            "success",
        )

        return redirect(url_for("phase3"))

    except Exception as exc:
        flash(
            f"Phase 3 verification failed: {type(exc).__name__}: {exc}",
            "error",
        )

        return redirect(url_for("phase3_verify"))


# ---------------------------------------------------------------------------
# Phase 4 - explicit approval, action tracking, and local remediation
# ---------------------------------------------------------------------------

@app.post("/phase4/decisions")
def phase4_save_decisions():
    """Save the compact Phase 4 decision table in one submission."""
    try:
        p4 = load_phase4_module()
        state = p4.load_or_initialize_state()

        decisions: Dict[str, str] = {}
        for task in state.get("tasks", []) or []:
            task_id = str(task.get("task_id") or "")
            if not task_id:
                continue

            approval = task.get("approval", {}) or {}
            is_pending = (
                approval.get("required") and approval.get("decision") == "pending"
            ) or (
                not approval.get("required")
                and task.get("status") == "not_started"
                and not task.get("outcome")
            )
            if not is_pending:
                continue

            value = request.form.get(f"decision_{task_id}", "").strip().casefold()
            if value:
                decisions[task_id] = value

        counts = p4.apply_bulk_decisions(state, decisions)
        flash(
            "Decisions saved: "
            f"{counts.get('approved', 0)} approved, "
            f"{counts.get('retained', 0)} retained, "
            f"{counts.get('skipped', 0)} skipped. "
            "Approved actions are ready below; approval itself did not execute them.",
            "success",
        )
    except Exception as exc:
        flash(
            f"Phase 4 decisions were not saved: {type(exc).__name__}: {exc}",
            "error",
        )

    return redirect(url_for("phase4") + "#remediation-summary")


@app.post("/phase4/task/<task_id>/<command>")
def phase4_task_action(task_id: str, command: str):
    allowed_commands = {
        "approve",
        "reject",
        "start",
        "submitted",
        "pending",
        "complete",
        "fail",
        "skip",
    }
    if command not in allowed_commands:
        flash("Unknown Phase 4 action.", "error")
        return redirect(url_for("phase4"))

    try:
        p4 = load_phase4_module()
        state = p4.load_or_initialize_state()

        if command == "approve":
            task = p4.approve_task(state, task_id)
            flash(
                f"{task.get('finding_id')} approved. No external change has been made yet.",
                "success",
            )

        elif command == "reject":
            task = p4.reject_task(state, task_id)
            flash(
                f"{task.get('finding_id')} was skipped. No remediation was executed.",
                "success",
            )

        else:
            transition_map = {
                "start": "in_progress",
                "submitted": "submitted",
                "pending": "pending_external_confirmation",
                "complete": "completed",
                "fail": "failed",
                "skip": "skipped",
            }
            task = p4.transition_task(
                state,
                task_id,
                transition_map[command],
            )
            flash(
                f"{task.get('finding_id')} is now {task.get('status', '').replace('_', ' ')}.",
                "success",
            )

    except Exception as exc:
        flash(
            f"Phase 4 action blocked: {type(exc).__name__}: {exc}",
            "error",
        )

    return redirect(url_for("phase4"))


@app.post("/phase4/local/<task_id>/preview")
def phase4_local_preview(task_id: str):
    selected_domains = [
        value.strip()
        for value in request.form.getlist("tracker_domain")
        if value.strip()
    ]

    if not selected_domains:
        flash("Select at least one tracker domain group to preview.", "error")
        return redirect(url_for("phase4"))

    try:
        p4 = load_phase4_module()
        state = p4.load_or_initialize_state()
        preview = p4.preview_local_tracker_cleanup(
            state,
            task_id,
            domain_groups=selected_domains,
        )
        flash(
            f"Preview ready: {preview.get('tracker_rows_matched', 0)} tracker-like cookie row(s) "
            "match the selected scope. Nothing was deleted.",
            "success",
        )
    except Exception as exc:
        flash(
            f"Local cleanup preview failed: {type(exc).__name__}: {exc}",
            "error",
        )

    return redirect(url_for("phase4"))


@app.post("/phase4/local/<task_id>/execute")
def phase4_local_execute(task_id: str):
    confirmed = request.form.get("confirm_cleanup") == "on"
    selected_domains = [
        value.strip()
        for value in request.form.getlist("tracker_domain")
        if value.strip()
    ]

    if not confirmed:
        flash(
            "Local cleanup was not executed. Confirm that you reviewed the preview and closed the browser.",
            "error",
        )
        return redirect(url_for("phase4"))

    try:
        p4 = load_phase4_module()
        state = p4.load_or_initialize_state()
        result = p4.execute_local_tracker_cleanup(
            state,
            task_id,
            domain_groups=selected_domains,
            confirmed=True,
        )
        flash(
            f"Local cleanup completed: {result.get('rows_deleted', 0)} tracker-like cookie row(s) removed; "
            f"{result.get('tracker_rows_after', 0)} remain in the selected scope.",
            "success",
        )
    except Exception as exc:
        flash(
            f"Local cleanup was blocked or failed: {type(exc).__name__}: {exc}",
            "error",
        )

    return redirect(url_for("phase4"))


@app.post("/phase4/local/<task_id>/verify")
def phase4_local_verify(task_id: str):
    try:
        p4 = load_phase4_module()
        state = p4.load_or_initialize_state()
        verification = p4.verify_local_tracker_cleanup(state, task_id)
        if verification.get("status") == "verified":
            flash("Local cleanup remains verified by a fresh Phase 2C re-audit.", "success")
        else:
            remaining = (verification.get("evidence") or {}).get("tracker_rows_remaining", 0)
            flash(
                f"Re-audit found {remaining} tracker-like row(s) again in the selected scope.",
                "warning",
            )
    except Exception as exc:
        flash(
            f"Local cleanup verification failed: {type(exc).__name__}: {exc}",
            "error",
        )

    return redirect(url_for("phase4"))



# ---------------------------------------------------------------------------
# Phase 4 - broker email, provider proof, manual fallback
# ---------------------------------------------------------------------------

@app.get("/phase4/mail/connect")
def phase4_mail_connect():
    try:
        aggregate = read_json(AGGREGATE_FILE) or {}
        identity_email = str((aggregate.get("input_profile") or {}).get("email") or "").strip()
        mail = load_phase4_mail_module()
        capability = mail.mail_capability_for_address(identity_email)
        if not capability.get("automatic_oauth_supported"):
            flash(
                "Automatic Gmail OAuth sending is not available for the email used in this scan. "
                "Use the manual assisted-send option instead; the project will not ask for the mailbox password.",
                "warning",
            )
            return redirect(url_for("phase4") + "#open-actions")

        verifier, challenge = mail.create_pkce_pair()
        oauth_state = secrets.token_urlsafe(32)
        session["google_oauth_state"] = oauth_state
        session["google_pkce_verifier"] = verifier
        return redirect(mail.build_authorization_url(state=oauth_state, code_challenge=challenge))
    except Exception as exc:
        flash(f"Gmail connection could not start: {type(exc).__name__}: {exc}", "error")
        return redirect(url_for("phase4"))


@app.get("/phase4/mail/callback")
def phase4_mail_callback():
    if request.args.get("error"):
        flash(
            f"Gmail authorization was cancelled or failed: {request.args.get('error_description') or request.args.get('error')}",
            "error",
        )
        return redirect(url_for("phase4"))

    expected_state = session.pop("google_oauth_state", None)
    verifier = session.pop("google_pkce_verifier", None)
    returned_state = request.args.get("state")
    code = request.args.get("code")
    if not expected_state or returned_state != expected_state or not verifier or not code:
        flash("Google OAuth callback could not be validated. Please connect again.", "error")
        return redirect(url_for("phase4"))

    try:
        mail = load_phase4_mail_module()
        token = mail.exchange_authorization_code(code=code, code_verifier=verifier)
        account = token.get("account") or {}
        address = str(account.get("email") or "").strip()
        aggregate = read_json(AGGREGATE_FILE) or {}
        identity_email = str((aggregate.get("input_profile") or {}).get("email") or "").strip()
        if identity_email and address.casefold() != identity_email.casefold():
            mail.disconnect()
            raise ValueError(
                "You connected a different Gmail account from the email supplied in Phase 1. "
                "Connect the same Gmail account used for this scan."
            )
        flash(
            f"Gmail connected: {mask_email(address)}. Only OAuth tokens are stored locally; no mailbox password is stored.",
            "success",
        )
    except Exception as exc:
        flash(f"Gmail connection failed: {type(exc).__name__}: {exc}", "error")
    return redirect(url_for("phase4") + "#open-actions")


@app.post("/phase4/mail/disconnect")
def phase4_mail_disconnect():
    try:
        mail = load_phase4_mail_module()
        mail.disconnect()
        flash("Gmail disconnected from this local project.", "success")
    except Exception as exc:
        flash(f"Mailbox disconnect failed: {type(exc).__name__}: {exc}", "error")
    return redirect(url_for("phase4") + "#open-actions")


@app.post("/phase4/broker/<task_id>/send")
def phase4_broker_send(task_id: str):
    if request.form.get("confirm_email") != "on":
        flash("Review the recipient and exact message, then confirm before sending.", "error")
        return redirect(url_for("phase4") + "#open-actions")
    try:
        p4 = load_phase4_module()
        mail = load_phase4_mail_module()
        state = p4.load_or_initialize_state()
        aggregate = read_json(AGGREGATE_FILE) or {}
        profile = aggregate.get("input_profile", {}) or {}
        identity_email = str(profile.get("email") or "").strip()
        capability = mail.mail_capability_for_address(identity_email)
        if not capability.get("automatic_oauth_supported"):
            raise ValueError(
                "This Phase 1 mailbox does not use the configured Gmail OAuth path. "
                "Use the manual assisted-send option instead."
            )
        preview = p4.build_broker_email_preview(state, task_id, profile)
        evidence = mail.send_and_verify(
            recipient=preview["recipient"],
            subject=preview["subject"],
            body=preview["body"],
            reference=preview["reference"],
            expected_sender=identity_email,
        )
        task = p4.record_broker_email_submission(state, task_id, evidence)
        if evidence.get("verified"):
            flash(
                f"Privacy request sent through Gmail. Gmail returned the message with its SENT label; "
                f"{task.get('finding_id')} is now awaiting the broker's response/removal.",
                "success",
            )
        else:
            flash(
                "Gmail accepted the email, but the API response did not include SENT-label proof. "
                "Open Gmail Sent and verify the unique request reference before relying on it as provider proof.",
                "warning",
            )
    except Exception as exc:
        flash(f"Broker email was not sent: {type(exc).__name__}: {exc}", "error")
    return redirect(url_for("phase4") + "#open-actions")


@app.post("/phase4/broker/<task_id>/confirm-sent-visible")
def phase4_broker_confirm_sent_visible(task_id: str):
    if request.form.get("confirm_sent_visible") != "on":
        flash("Confirm only after you can see the exact request in Gmail Sent.", "error")
        return redirect(url_for("phase4") + "#open-actions")
    try:
        p4 = load_phase4_module()
        state = p4.load_or_initialize_state()
        p4.record_broker_sent_visibility_confirmation(
            state,
            task_id,
            note="User visually confirmed the exact request is visible in Gmail Sent.",
        )
        flash(
            "Gmail Sent visibility recorded as user-confirmed evidence. The broker request is now awaiting external confirmation.",
            "success",
        )
    except Exception as exc:
        flash(f"Sent visibility could not be recorded: {type(exc).__name__}: {exc}", "error")
    return redirect(url_for("phase4") + "#open-actions")


@app.post("/phase4/broker/<task_id>/manual-sent")
def phase4_broker_manual_sent(task_id: str):
    if request.form.get("confirm_manual_sent") != "on":
        flash("Confirm only after you have actually sent the displayed request from your mailbox.", "error")
        return redirect(url_for("phase4") + "#open-actions")
    try:
        p4 = load_phase4_module()
        state = p4.load_or_initialize_state()
        aggregate = read_json(AGGREGATE_FILE) or {}
        profile = aggregate.get("input_profile", {}) or {}
        preview = p4.build_broker_email_preview(state, task_id, profile)
        p4.record_broker_manual_submission(
            state,
            task_id,
            sender=str(profile.get("email") or "").strip(),
            recipient=preview["recipient"],
            subject=preview["subject"],
            reference=preview["reference"],
            note="User confirmed sending the exact displayed request through their own mail provider.",
        )
        flash(
            "Manual submission recorded. This is user-confirmed evidence, not provider-verified Sent-folder proof; "
            "re-scan or the broker's reply should confirm the final outcome.",
            "success",
        )
    except Exception as exc:
        flash(f"Manual broker submission could not be recorded: {type(exc).__name__}: {exc}", "error")
    return redirect(url_for("phase4") + "#open-actions")


@app.post("/phase4/rescan")
def phase4_rescan():
    try:
        p4 = load_phase4_module()
        verifier = load_phase4_verification_module()
        state = p4.load_or_initialize_state()
        aggregate = read_json(AGGREGATE_FILE)
        phase3 = read_json(PHASE3_FILE)
        if not aggregate or not phase3:
            raise RuntimeError("Current Phase 2/3 evidence is unavailable.")
        baseline = verifier.create_pending_baseline(state, aggregate, phase3)
        flash(
            f"Verification baseline saved ({baseline.get('baseline_id', '')[:8]}). Run the same subject through Phase 1 -> Phase 3; the system will compare before vs after automatically.",
            "success",
        )
        return redirect(url_for("phase1", verify="1"))
    except Exception as exc:
        flash(f"Could not start a remediation re-scan: {type(exc).__name__}: {exc}", "error")
        return redirect(url_for("phase4"))


@app.get("/phase4/report")
def phase4_report():
    try:
        p4 = load_phase4_module()
        state = p4.load_or_initialize_state()
        verifier = load_phase4_verification_module()
        report = p4.build_final_remediation_report(
            state,
            latest_verification=verifier.latest_verification(),
        )
        return render_template("phase4_report.html", report=report)
    except Exception as exc:
        flash(f"Remediation report could not be built: {type(exc).__name__}: {exc}", "error")
        return redirect(url_for("phase4"))


@app.get("/phase4/report.json")
def phase4_report_json():
    try:
        p4 = load_phase4_module()
        state = p4.load_or_initialize_state()
        verifier = load_phase4_verification_module()
        report = p4.build_final_remediation_report(
            state,
            latest_verification=verifier.latest_verification(),
        )
        payload = json.dumps(report, indent=2, ensure_ascii=False)
        return Response(
            payload,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=phase4_remediation_report.json"},
        )
    except Exception as exc:
        flash(f"Remediation report could not be exported: {type(exc).__name__}: {exc}", "error")
        return redirect(url_for("phase4"))


# ---------------------------------------------------------------------------
# Local development server
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
    )
