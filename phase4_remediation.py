"""Phase 4 — User-authorised remediation and action tracking.

Privacy and safety boundaries
-----------------------------
Phase 4 consumes Phase 3's latest action plan. It NEVER treats an AI
recommendation as permission to make a privacy-changing modification.

Sensitive account actions (password changes, MFA, content/account removal and
redaction) remain user-driven/manual. Broker opt-out can additionally use an
approved Gmail OAuth workflow when the Phase 1 identity email is Gmail and a
verified broker contact email is known. The user sees the exact recipient and
message before sending. Gmail's provider response is retained as proof, including
the returned message id and SENT system label. Unsupported mail providers use a
manual assisted-send fallback instead of asking for mailbox passwords. Phase 4
never stores mailbox passwords, account passwords, MFA secrets or recovery codes.

The only directly executable remediation implemented here is selective local
Chromium tracker-cookie cleanup. Even that requires:
  1) an explicit persisted Phase 4 approval,
  2) an immediate second confirmation,
  3) explicit selection of tracker-domain groups,
  4) a local database backup before modification, and
  5) a post-action Phase 2C re-audit.

Cookie values are never read. Exact row metadata is used to avoid broad
"delete every cookie for this domain" behaviour.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit
from uuid import uuid4


BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
PHASE4_DIR = REPORTS_DIR / "phase4"

PHASE3_ACTION_PLAN_FILE = REPORTS_DIR / "phase3" / "latest_action_plan.json"
PHASE3_ANALYSIS_FILE = REPORTS_DIR / "phase3" / "latest_phase3_analysis.json"
AGGREGATE_FILE = REPORTS_DIR / "aggregate" / "latest_aggregate_internal.json"

LATEST_STATE_FILE = PHASE4_DIR / "latest_phase4_state.json"
LATEST_SHAREABLE_STATE_FILE = PHASE4_DIR / "latest_phase4_shareable.json"
HISTORY_FILE = PHASE4_DIR / "phase4_history.jsonl"
BACKUP_DIR = PHASE4_DIR / "backups"

PHASE4_VERSION = 3

VALID_STATUSES = {
    "not_started",
    "awaiting_approval",
    "in_progress",
    "submitted",
    "pending_external_confirmation",
    "completed",
    "failed",
    "skipped",
}

EXECUTION_ACTIONS = {
    "update_or_redact",
    "broker_opt_out",
    "delete_account_or_content",
    "change_password",
    "enable_mfa",
    "revoke_permission",
    "clear_selected_local_data",
}

ALLOWED_TRANSITIONS = {
    "not_started": {"in_progress", "completed", "failed", "skipped"},
    "awaiting_approval": {"not_started", "skipped", "failed"},
    "in_progress": {
        "submitted",
        "pending_external_confirmation",
        "completed",
        "failed",
        "skipped",
    },
    "submitted": {"pending_external_confirmation", "completed", "failed"},
    "pending_external_confirmation": {"in_progress", "completed", "failed", "skipped"},
    "failed": {"in_progress", "skipped"},
    "completed": set(),
    "skipped": set(),
}

ACTION_CONFIG: Dict[str, Dict[str, Any]] = {
    "retain": {
        "label": "Retain this footprint",
        "mode": "decision_only",
        "destructive": False,
        "verification_required": False,
        "steps": [
            "Confirm that the public/local presence is intentional.",
            "Leave it unchanged unless a later review identifies unnecessary exposure.",
        ],
    },
    "review": {
        "label": "Review this exposure",
        "mode": "guided_review",
        "destructive": False,
        "verification_required": False,
        "steps": [
            "Review the evidence and the Phase 3 explanation.",
            "Decide whether the finding should be retained, updated, removed, opted out, or ignored.",
            "Do not perform an external destructive action from this review alone.",
        ],
    },
    "verify_identity": {
        "label": "Resolve identity before action",
        "mode": "identity_verification",
        "destructive": False,
        "verification_required": True,
        "steps": [
            "Confirm whether the finding belongs to the scan subject.",
            "Do not modify or remove the external content while ownership remains unresolved.",
        ],
    },
    "update_or_redact": {
        "label": "Update or redact public information",
        "mode": "manual_external",
        "destructive": False,
        "verification_required": True,
        "steps": [
            "Review exactly which public fields/content should be changed.",
            "Use the service's official account, edit, support or contact workflow.",
            "Record submission/completion here; do not enter credentials into this project.",
        ],
    },
    "broker_opt_out": {
        "label": "Submit data-broker opt-out",
        "mode": "manual_external",
        "destructive": False,
        "verification_required": True,
        "steps": [
            "Confirm that the broker record is the subject's record.",
            "Use the provider's verified email/form/privacy channel only after approval.",
            "When email submission is supported, preview the exact request and send it through the user's OAuth-connected mailbox.",
            "Verify the same message in Sent Items, then re-scan or confirm the broker response later.",
        ],
    },
    "delete_account_or_content": {
        "label": "Delete account or content",
        "mode": "manual_external",
        "destructive": True,
        "verification_required": True,
        "steps": [
            "Confirm the exact account/content target and expected consequences.",
            "Use the provider's official deletion workflow only after explicit approval.",
            "Record the request here and verify the result later.",
        ],
    },
    "change_password": {
        "label": "Change affected password",
        "mode": "manual_external_security",
        "destructive": False,
        "verification_required": True,
        "steps": [
            "Go directly to the affected service or its official security page.",
            "Set a new unique password and check whether the old password was reused elsewhere.",
            "Do not enter or store the old/new password in this project.",
            "Enable MFA as a separate action when the service supports it.",
        ],
    },
    "enable_mfa": {
        "label": "Enable multi-factor authentication",
        "mode": "manual_external_security",
        "destructive": False,
        "verification_required": True,
        "steps": [
            "Open the service's official security settings.",
            "Enable an available MFA method.",
            "Do not store MFA secrets, QR contents or recovery codes in this project.",
        ],
    },
    "revoke_permission": {
        "label": "Revoke unnecessary browser permission",
        "mode": "local_guided",
        "destructive": False,
        "verification_required": True,
        "steps": [
            "Review the exact origin and permission.",
            "Revoke only permissions no longer needed through browser settings.",
            "Re-run the local audit afterwards.",
        ],
    },
    "clear_selected_local_data": {
        "label": "Clear selected tracker-like cookies",
        "mode": "local_tracker_cookie_cleanup",
        "destructive": True,
        "verification_required": True,
        "steps": [
            "Preview tracker-like cookie metadata and choose domain groups.",
            "Close the affected browser profile before execution.",
            "Create a local Cookies-database backup.",
            "Delete only exact rows re-detected as tracker-like.",
            "Re-audit and record the before/after result.",
        ],
    },
    "ignore": {
        "label": "No remediation required",
        "mode": "decision_only",
        "destructive": False,
        "verification_required": False,
        "steps": ["Record that no remediation is currently required."],
    },
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")


def read_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Required file not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def write_json_atomic(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    temp.replace(path)


def append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def stable_task_id(source_run_id: str, finding_id: str, action: str) -> str:
    material = f"{source_run_id}|{finding_id}|{action}".encode("utf-8")
    return "P4-" + hashlib.sha256(material).hexdigest()[:10].upper()


def domain_from_url(url: str) -> str:
    try:
        return urlsplit(url or "").netloc.casefold()
    except ValueError:
        return ""


def load_phase4_sources() -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    action_plan = read_json(PHASE3_ACTION_PLAN_FILE)
    analysis = read_json(PHASE3_ANALYSIS_FILE)
    aggregate = read_json(AGGREGATE_FILE)

    if action_plan.get("artifact_type") != "phase3_action_plan":
        raise ValueError("latest_action_plan.json is not a Phase 3 action plan.")
    if analysis.get("artifact_type") != "phase3_ai_analysis":
        raise ValueError("latest_phase3_analysis.json is not a Phase 3 analysis.")
    if aggregate.get("artifact_type") != "aggregated_footprint_report":
        raise ValueError("latest_aggregate_internal.json is not a Phase 2 aggregate report.")

    source_run_id = action_plan.get("source_run_id")
    if source_run_id and aggregate.get("run_id") and source_run_id != aggregate.get("run_id"):
        raise ValueError(
            "Phase 3 and Phase 2 source run IDs do not match. "
            "Re-run Phase 3 on the current Phase 2 evidence before Phase 4."
        )

    if analysis.get("source_run_id") and source_run_id != analysis.get("source_run_id"):
        raise ValueError("Phase 3 analysis and action-plan source IDs do not match.")

    return action_plan, analysis, aggregate


def _visual_only_source_findings(layer: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Recreate Phase 3's P2A-VISUAL IDs for user-confirmed visual-only pages."""
    results = layer.get("results", []) or []
    retained_urls = {
        str(item.get("canonical_url") or item.get("resolved_url") or item.get("url") or "")
        for item in results
    }

    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for review in layer.get("visual_review_items", []) or []:
        if review.get("manual_verification") != "confirmed":
            continue
        page_url = str(review.get("page_url") or "")
        if not page_url or page_url in retained_urls:
            continue
        grouped.setdefault(page_url, []).append(review)

    output = []
    for index, (page_url, reviews) in enumerate(grouped.items(), start=1):
        first = reviews[0]
        output.append({
            "finding_id": f"P2A-VISUAL-{index:03d}",
            "layer": "2A",
            "finding_type": "visual_public_footprint",
            "label": first.get("page_title") or "User-confirmed public image",
            "domain": first.get("domain") or domain_from_url(page_url),
            "url": page_url,
            "source_category": first.get("source_category", "Visual public footprint"),
            "identity_status": "User-confirmed visual association",
            "confirmed_image_count": len(reviews),
            "control_type": "external_public_content",
        })
    return output


def build_source_finding_index(aggregate: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Recreate Phase 3 finding IDs while keeping private local paths internal."""
    index: Dict[str, Dict[str, Any]] = {}
    layers = aggregate.get("layers", {}) or {}

    p2a = layers.get("phase_2A_public", {}) or {}
    for number, item in enumerate(p2a.get("results", []) or [], start=1):
        finding_id = f"P2A-{number:03d}"
        url = str(item.get("canonical_url") or item.get("resolved_url") or item.get("url") or "")
        index[finding_id] = {
            "finding_id": finding_id,
            "layer": "2A",
            "finding_type": "public_footprint",
            "label": item.get("title") or item.get("source_category") or finding_id,
            "domain": item.get("domain") or domain_from_url(url),
            "url": url,
            "source_category": item.get("source_category", ""),
            "result_subtype": item.get("result_subtype", ""),
            "identity_status": item.get("identity_status", ""),
            "identity_score": item.get("identity_score"),
            "control_type": item.get("control_type", ""),
            "public_value": item.get("public_value", ""),
            "privacy_exposure_status": item.get("privacy_exposure_status", ""),
        }

    for item in _visual_only_source_findings(p2a):
        index[item["finding_id"]] = item

    p2b = layers.get("phase_2B_breach_and_broker", {}) or {}
    for number, item in enumerate(p2b.get("breach_exposures", []) or [], start=1):
        finding_id = f"P2B-BREACH-{number:03d}"
        index[finding_id] = {
            "finding_id": finding_id,
            "layer": "2B",
            "finding_type": "breach_exposure",
            "label": item.get("service") or item.get("breach_name") or finding_id,
            "service": item.get("service") or item.get("breach_name") or "",
            "domain": item.get("domain", ""),
            "breach_date": item.get("breach_date", ""),
            "verified": item.get("verified"),
            "exposed_data": list(item.get("exposed_data") or []),
            "password_risk": item.get("password_risk", ""),
            "provider_sources": list(item.get("provider_sources") or []),
        }

    for number, item in enumerate(p2b.get("data_broker_exposures", []) or [], start=1):
        finding_id = f"P2B-BROKER-{number:03d}"
        record_url = str(item.get("record_url") or "")
        broker_domain = item.get("domain", "") or domain_from_url(record_url)
        registry: Dict[str, Any] = {}
        try:
            import phase2B_exposure as phase2b_module
            registry = dict(getattr(phase2b_module, "BROKER_REGISTRY", {}).get(str(broker_domain).casefold(), {}) or {})
        except Exception:
            registry = {}
        index[finding_id] = {
            "finding_id": finding_id,
            "layer": "2B",
            "finding_type": "data_broker_exposure",
            "label": item.get("provider") or item.get("domain") or finding_id,
            "provider": item.get("provider", ""),
            "domain": broker_domain,
            "url": record_url,
            "privacy_or_opt_out_url": item.get("privacy_or_opt_out_url", "") or registry.get("privacy_url", ""),
            "broker_execution_mode": item.get("execution_mode", "manual_research_required") or registry.get("execution_mode", "manual_research_required"),
            "contact_email": item.get("contact_email", "") or registry.get("contact_email", ""),
            "contact_source_url": item.get("contact_source_url", "") or registry.get("contact_source_url", ""),
            "removal_scope_note": item.get("removal_scope_note", "") or registry.get("removal_scope_note", ""),
            "identity_status": item.get("identity_status", ""),
            "identity_score": item.get("identity_score"),
            "visible_email_count": int(item.get("visible_email_count", 0) or 0),
            "visible_phone_count": int(item.get("visible_phone_count", 0) or 0),
            "requires_identity_confirmation": bool(item.get("requires_identity_confirmation")),
        }

    p2c = layers.get("phase_2C_local_passive", {}) or {}
    for number, item in enumerate(p2c.get("browser_profiles", []) or [], start=1):
        finding_id = f"P2C-{number:03d}"
        summary = item.get("summary", {}) or {}
        tracker_domains = [
            str(value.get("domain") or "")
            for value in (item.get("potential_tracker_domains") or [])
            if value.get("domain")
        ]
        index[finding_id] = {
            "finding_id": finding_id,
            "layer": "2C",
            "finding_type": "local_browser_metadata",
            "label": f"{item.get('browser', 'Browser')} {item.get('profile_name', '')}".strip(),
            "browser": item.get("browser", ""),
            "profile_name": item.get("profile_name", ""),
            "summary": {
                "cookie_count": int(summary.get("cookie_count", 0) or 0),
                "persistent_cookie_count": int(summary.get("persistent_cookie_count", 0) or 0),
                "potential_tracker_cookie_count": int(summary.get("potential_tracker_cookie_count", 0) or 0),
                "risky_allowed_permission_count": int(summary.get("risky_allowed_permission_count", 0) or 0),
            },
            "suggested_tracker_domains": tracker_domains,
            "risky_permissions": list(item.get("risky_permissions") or []),
            "private_target": {"profile_path": item.get("profile_path", "")},
        }

    return index


def _analysis_index(analysis: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        str(item.get("finding_id")): item
        for item in (analysis.get("analyses") or [])
        if item.get("finding_id")
    }


def build_task(
    source_run_id: str,
    source_phase3_run_time: str,
    action_item: Dict[str, Any],
    source_finding: Dict[str, Any],
    analysis_item: Dict[str, Any],
) -> Dict[str, Any]:
    action = str(action_item.get("recommended_action") or "review")
    config = ACTION_CONFIG.get(action, ACTION_CONFIG["review"])
    requires_approval = bool(action_item.get("requires_user_approval") or action in EXECUTION_ACTIONS)
    finding_id = str(action_item.get("finding_id") or "")

    return {
        "task_id": stable_task_id(source_run_id, finding_id, action),
        "finding_id": finding_id,
        "source_phase3_run_time": source_phase3_run_time,
        "created_at": utc_now_iso(),
        "updated_at": utc_now_iso(),
        "status": "awaiting_approval" if requires_approval else "not_started",
        "outcome": None,
        "priority_score": int(action_item.get("priority_score", 0) or 0),
        "risk_score": int(action_item.get("risk_score", 0) or 0),
        "risk_level": action_item.get("risk_level", "Low"),
        "ai_classification": action_item.get("ai_classification", "other"),
        "recommended_action": action,
        "phase3_recommended_action": action,
        "user_action_override": None,
        "action_label": config["label"],
        "action_reason": action_item.get("action_reason", ""),
        "execution": {
            "mode": (
                "broker_email"
                if action == "broker_opt_out" and source_finding.get("contact_email")
                else config["mode"]
            ),
            "destructive": bool(config["destructive"]),
            "automatic_execution_supported": action == "clear_selected_local_data",
            "email_submission_supported": bool(
                action == "broker_opt_out" and source_finding.get("contact_email")
            ),
            "steps": list(config["steps"]),
            "selected_scope": {},
            "last_result": None,
        },
        "approval": {
            "required": requires_approval,
            "decision": "pending" if requires_approval else "not_required",
            "decided_at": None,
        },
        "verification": {
            "required": bool(config["verification_required"]),
            "status": "not_started",
            "checked_at": None,
            "method": None,
            "evidence": {},
        },
        "target": {k: v for k, v in source_finding.items() if k != "private_target"},
        "private_target": dict(source_finding.get("private_target") or {}),
        "private_email_request": {},
        "phase3_context": {
            "user_verification": analysis_item.get("user_verification"),
            "verification_reassessment_performed": bool(
                analysis_item.get("verification_reassessment_performed", False)
            ),
            "risk_explanation": analysis_item.get("risk_explanation", ""),
        },
        "events": [],
    }


def refresh_summary(state: Dict[str, Any]) -> None:
    tasks = state.get("tasks", []) or []
    status_counts = Counter(str(item.get("status") or "unknown") for item in tasks)
    action_counts = Counter(str(item.get("recommended_action") or "unknown") for item in tasks)

    decision_pending = 0
    decisions_recorded = 0
    approved = 0
    retained = 0
    ready = 0
    completed_actions = 0
    initiated_actions = 0

    for task in tasks:
        approval = task.get("approval", {}) or {}
        status = str(task.get("status") or "not_started")
        outcome = str(task.get("outcome") or "")
        requires_approval = bool(approval.get("required"))

        if requires_approval:
            if approval.get("decision") == "pending":
                decision_pending += 1
            else:
                decisions_recorded += 1
            if approval.get("decision") == "approved":
                approved += 1
                if status == "not_started":
                    ready += 1
        else:
            # Non-execution recommendations remain undecided until the user
            # explicitly retains or skips them in the compact Phase 4 table.
            if status == "not_started" and not outcome:
                decision_pending += 1
            else:
                decisions_recorded += 1

        if outcome == "retained":
            retained += 1

        if status == "completed" and outcome != "retained":
            completed_actions += 1

        if (
            task.get("recommended_action") in EXECUTION_ACTIONS
            and status in {
                "in_progress",
                "submitted",
                "pending_external_confirmation",
                "completed",
                "failed",
            }
        ):
            initiated_actions += 1

    active = (
        status_counts.get("in_progress", 0)
        + status_counts.get("submitted", 0)
        + status_counts.get("pending_external_confirmation", 0)
    )
    skipped = status_counts.get("skipped", 0)
    failed = status_counts.get("failed", 0)
    open_actions = ready + active + failed

    state["summary"] = {
        "total_tasks": len(tasks),
        "status_counts": dict(status_counts),
        "action_counts": dict(action_counts),
        "decision_pending": decision_pending,
        "decisions_recorded": decisions_recorded,
        "approved": approved,
        "ready": ready,
        "active": active,
        "completed": status_counts.get("completed", 0),
        "completed_actions": completed_actions,
        "initiated_actions": initiated_actions,
        "retained": retained,
        "failed": failed,
        "skipped": skipped,
        "open_actions": open_actions,
        "plan_resolved": decision_pending == 0 and open_actions == 0,
    }
    state["updated_at"] = utc_now_iso()


def _shareable_copy(state: Dict[str, Any]) -> Dict[str, Any]:
    copied = json.loads(json.dumps(state))
    for task in copied.get("tasks", []):
        task.pop("private_target", None)
        task.pop("private_email_request", None)
        result = (task.get("execution") or {}).get("last_result")
        if isinstance(result, dict):
            result.pop("backup_directory", None)
            result.pop("cookie_database_path", None)
        evidence = (task.get("verification") or {}).get("evidence")
        if isinstance(evidence, dict):
            evidence.pop("backup_directory", None)
            evidence.pop("cookie_database_path", None)
    return copied


def save_state(
    state: Dict[str, Any],
    *,
    event_type: Optional[str] = None,
    event_payload: Optional[Dict[str, Any]] = None,
) -> None:
    refresh_summary(state)
    PHASE4_DIR.mkdir(parents=True, exist_ok=True)

    write_json_atomic(LATEST_STATE_FILE, state)
    shareable = _shareable_copy(state)
    write_json_atomic(LATEST_SHAREABLE_STATE_FILE, shareable)

    # Keep point-in-time snapshots for the audit trail.
    stamp = _stamp()
    write_json_atomic(PHASE4_DIR / f"phase4_state_{stamp}.json", state)
    write_json_atomic(PHASE4_DIR / f"phase4_shareable_{stamp}.json", shareable)

    if event_type:
        append_jsonl(HISTORY_FILE, {
            "event_id": uuid4().hex,
            "timestamp": utc_now_iso(),
            "source_run_id": state.get("source_run_id"),
            "source_phase3_run_time": state.get("source_phase3_run_time"),
            "event_type": event_type,
            "payload": event_payload or {},
        })


def initialize_state(*, force: bool = False) -> Dict[str, Any]:
    action_plan, analysis, aggregate = load_phase4_sources()
    source_run_id = str(action_plan.get("source_run_id") or aggregate.get("run_id") or "unknown")
    phase3_run_time = str(action_plan.get("run_time") or "")

    # Only preserve runtime state when the exact Phase 3 action-plan generation
    # is unchanged. A fresh AI/verification run invalidates prior approvals.
    old_state: Optional[Dict[str, Any]] = None
    if LATEST_STATE_FILE.exists() and not force:
        try:
            candidate = read_json(LATEST_STATE_FILE)
            if (
                candidate.get("source_run_id") == source_run_id
                and candidate.get("source_phase3_run_time") == phase3_run_time
            ):
                old_state = candidate
        except Exception:
            old_state = None

    source_index = build_source_finding_index(aggregate)
    analyses = _analysis_index(analysis)
    old_tasks = {
        str(item.get("task_id")): item
        for item in (old_state or {}).get("tasks", [])
        if item.get("task_id")
    }

    tasks: List[Dict[str, Any]] = []
    for action_item in action_plan.get("actions", []) or []:
        finding_id = str(action_item.get("finding_id") or "")
        source_finding = source_index.get(finding_id, {
            "finding_id": finding_id,
            "label": finding_id or "Finding",
            "finding_type": "unknown",
        })
        task = build_task(
            source_run_id,
            phase3_run_time,
            action_item,
            source_finding,
            analyses.get(finding_id, {}),
        )
        previous = old_tasks.get(task["task_id"])
        if previous:
            for key in ("status", "outcome", "approval", "verification", "events", "updated_at", "private_email_request", "recommended_action", "phase3_recommended_action", "user_action_override", "action_label"):
                if key in previous:
                    task[key] = previous[key]
            old_execution = previous.get("execution", {}) or {}
            for key in ("selected_scope", "last_result"):
                if key in old_execution:
                    task["execution"][key] = old_execution[key]
        tasks.append(task)

    state = {
        "artifact_type": "phase4_remediation_state",
        "phase": 4,
        "version": PHASE4_VERSION,
        "generated_at": utc_now_iso(),
        "updated_at": utc_now_iso(),
        "source_run_id": source_run_id,
        "source_phase3_run_time": phase3_run_time,
        "overall_risk": action_plan.get("overall_risk", {}),
        "execution_policy": {
            "external_destructive_actions_automatic": False,
            "account_credentials_collected": False,
            "passwords_or_mfa_secrets_logged": False,
            "cookie_values_read": False,
            "explicit_user_approval_required": True,
            "local_tracker_cleanup_requires_second_confirmation": True,
            "local_browser_database_backup_before_write": True,
            "broker_email_requires_preview_and_user_confirmation": True,
            "mailbox_password_collected": False,
            "mail_tokens_local_only": True,
            "provider_sent_folder_evidence_required_for_automatic_email_proof": True,
            "unsupported_mail_providers_use_manual_fallback": True,
        },
        "tasks": tasks,
        "summary": {},
    }
    save_state(state, event_type="state_initialized", event_payload={"task_count": len(tasks)})
    return state


def _migrate_legacy_outcomes(state: Dict[str, Any]) -> bool:
    """Infer compact-UI outcomes for Phase 4 states created before v1.1."""
    changed = False
    for task in state.get("tasks", []) or []:
        if task.get("outcome"):
            continue

        status = str(task.get("status") or "not_started")
        action = str(task.get("recommended_action") or "")
        approval = task.get("approval", {}) or {}
        inferred = None

        if status == "skipped":
            inferred = "skipped"
        elif status == "completed":
            inferred = "retained" if action in {"retain", "review"} else "remediated"
        elif status in {"in_progress", "submitted", "pending_external_confirmation"}:
            inferred = "in_progress"
        elif status == "failed":
            inferred = "failed"
        elif approval.get("decision") == "approved":
            inferred = "approved"

        if inferred:
            task["outcome"] = inferred
            changed = True

    return changed


def load_or_initialize_state() -> Dict[str, Any]:
    action_plan, _, _ = load_phase4_sources()
    if not LATEST_STATE_FILE.exists():
        return initialize_state(force=True)

    try:
        state = read_json(LATEST_STATE_FILE)
    except Exception:
        return initialize_state(force=True)

    if (
        state.get("source_run_id") != action_plan.get("source_run_id")
        or state.get("source_phase3_run_time") != action_plan.get("run_time")
    ):
        return initialize_state(force=True)

    # Rebuild task metadata when the Phase 4 schema changes while preserving
    # the user's approvals, outcomes, events and execution evidence for the
    # exact same Phase 3 plan.
    if int(state.get("version", 0) or 0) != PHASE4_VERSION:
        return initialize_state(force=False)

    previous_summary = json.dumps(state.get("summary", {}), sort_keys=True)
    migrated = _migrate_legacy_outcomes(state)
    refresh_summary(state)
    summary_changed = previous_summary != json.dumps(state.get("summary", {}), sort_keys=True)

    # Keep the latest pointers current without creating a historical snapshot
    # on every page view. This also upgrades states made by the earlier UI.
    if migrated or summary_changed:
        write_json_atomic(LATEST_STATE_FILE, state)
        write_json_atomic(LATEST_SHAREABLE_STATE_FILE, _shareable_copy(state))

    return state


def invalidate_latest_state() -> None:
    """Invalidate only current pointers; preserve historical snapshots/backups."""
    for path in (LATEST_STATE_FILE, LATEST_SHAREABLE_STATE_FILE):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def get_task(state: Dict[str, Any], task_id: str) -> Dict[str, Any]:
    for task in state.get("tasks", []) or []:
        if task.get("task_id") == task_id:
            return task
    raise KeyError(f"Unknown Phase 4 task: {task_id}")


def _record_task_event(
    task: Dict[str, Any],
    event_type: str,
    *,
    from_status: Optional[str] = None,
    to_status: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    task.setdefault("events", []).append({
        "event_id": uuid4().hex,
        "timestamp": utc_now_iso(),
        "event_type": event_type,
        "from_status": from_status,
        "to_status": to_status,
        "metadata": metadata or {},
    })
    task["updated_at"] = utc_now_iso()


def approve_task(state: Dict[str, Any], task_id: str) -> Dict[str, Any]:
    task = get_task(state, task_id)
    approval = task.get("approval", {}) or {}
    if not approval.get("required"):
        return task
    if task.get("status") in {"completed", "skipped"}:
        raise ValueError("A completed or skipped task cannot be newly approved.")

    old_status = task.get("status")
    approval["decision"] = "approved"
    approval["decided_at"] = utc_now_iso()
    task["approval"] = approval
    task["outcome"] = "approved"
    if task.get("status") == "awaiting_approval":
        task["status"] = "not_started"

    _record_task_event(task, "approval_granted", from_status=old_status, to_status=task.get("status"))
    save_state(state, event_type="task_approved", event_payload={"task_id": task_id})
    return task


def reject_task(state: Dict[str, Any], task_id: str) -> Dict[str, Any]:
    task = get_task(state, task_id)
    if task.get("status") in {"completed", "skipped"}:
        raise ValueError("A completed or skipped task cannot be rejected.")

    old_status = task.get("status")
    approval = task.get("approval", {}) or {}
    if approval.get("required"):
        approval["decision"] = "rejected"
        approval["decided_at"] = utc_now_iso()
        task["approval"] = approval
    task["status"] = "skipped"
    task["outcome"] = "skipped"
    _record_task_event(task, "task_skipped_by_user", from_status=old_status, to_status="skipped")
    save_state(state, event_type="task_rejected", event_payload={"task_id": task_id})
    return task


def resolve_nonexecution_task(
    state: Dict[str, Any],
    task_id: str,
    decision: str,
) -> Dict[str, Any]:
    """Resolve a review/retain-style task from the compact decision table.

    ``retain`` records an intentional no-change outcome. ``skip`` records that
    the recommendation was considered but not acted on. Neither performs any
    external modification.
    """

    if decision not in {"retain", "skip"}:
        raise ValueError("Non-execution decision must be retain or skip.")

    task = get_task(state, task_id)
    approval = task.get("approval", {}) or {}
    if approval.get("required"):
        raise ValueError("This task requires Approve or Skip, not Retain.")
    if task.get("status") in {"completed", "skipped"}:
        return task

    old_status = str(task.get("status") or "not_started")
    if decision == "retain":
        task["status"] = "completed"
        task["outcome"] = "retained"
        event_type = "footprint_retained_by_user"
    else:
        task["status"] = "skipped"
        task["outcome"] = "skipped"
        event_type = "task_skipped_by_user"

    _record_task_event(
        task,
        event_type,
        from_status=old_status,
        to_status=task["status"],
    )
    save_state(
        state,
        event_type=event_type,
        event_payload={"task_id": task_id, "decision": decision},
    )
    return task


def apply_bulk_decisions(
    state: Dict[str, Any],
    decisions: Dict[str, str],
) -> Dict[str, int]:
    """Apply the compact decision-table choices in one auditable save.

    Execution-changing tasks accept ``approve`` or ``skip``. Review/retain
    tasks accept ``retain`` or ``skip``; a user-confirmed broker review may also
    be upgraded to ``request_removal`` by the user. Every currently pending task must be
    represented so the user gets one clear decision stage instead of a long
    series of per-card submissions.
    """

    pending_tasks: List[Dict[str, Any]] = []
    for task in state.get("tasks", []) or []:
        approval = task.get("approval", {}) or {}
        if approval.get("required"):
            if approval.get("decision") == "pending":
                pending_tasks.append(task)
        elif task.get("status") == "not_started" and not task.get("outcome"):
            pending_tasks.append(task)

    missing = [
        str(task.get("task_id"))
        for task in pending_tasks
        if str(task.get("task_id")) not in decisions
    ]
    if missing:
        raise ValueError(
            f"Choose a decision for every pending row ({len(missing)} missing)."
        )

    counts = {"approved": 0, "retained": 0, "skipped": 0}

    for task in pending_tasks:
        task_id = str(task.get("task_id"))
        choice = str(decisions.get(task_id) or "").strip().casefold()
        approval = task.get("approval", {}) or {}
        old_status = str(task.get("status") or "not_started")

        if approval.get("required"):
            if choice == "approve":
                approval["decision"] = "approved"
                approval["decided_at"] = utc_now_iso()
                task["approval"] = approval
                task["status"] = "not_started"
                task["outcome"] = "approved"
                _record_task_event(
                    task,
                    "approval_granted",
                    from_status=old_status,
                    to_status="not_started",
                )
                counts["approved"] += 1
            elif choice == "skip":
                approval["decision"] = "rejected"
                approval["decided_at"] = utc_now_iso()
                task["approval"] = approval
                task["status"] = "skipped"
                task["outcome"] = "skipped"
                _record_task_event(
                    task,
                    "task_skipped_by_user",
                    from_status=old_status,
                    to_status="skipped",
                )
                counts["skipped"] += 1
            else:
                raise ValueError(
                    f"{task.get('finding_id')}: choose Approve or Skip."
                )
        else:
            target = task.get("target", {}) or {}
            is_confirmed_broker = (
                target.get("finding_type") == "data_broker_exposure"
                and (task.get("phase3_context") or {}).get("user_verification") == "confirmed"
            )
            if choice == "request_removal" and is_confirmed_broker:
                # The AI recommended review, but the user is allowed to choose a
                # stronger broker-remediation action after confirmed ownership.
                # Preserve the original AI recommendation for the audit trail.
                task["phase3_recommended_action"] = task.get("phase3_recommended_action") or task.get("recommended_action")
                task["user_action_override"] = "broker_opt_out"
                task["recommended_action"] = "broker_opt_out"
                task["action_label"] = ACTION_CONFIG["broker_opt_out"]["label"]
                task["approval"] = {
                    "required": True,
                    "decision": "approved",
                    "decided_at": utc_now_iso(),
                }
                task["status"] = "not_started"
                task["outcome"] = "approved"
                task.setdefault("execution", {}).update({
                    "mode": "broker_email" if target.get("contact_email") else "manual_external",
                    "destructive": False,
                    "automatic_execution_supported": False,
                    "email_submission_supported": bool(target.get("contact_email")),
                    "steps": list(ACTION_CONFIG["broker_opt_out"]["steps"]),
                })
                _record_task_event(
                    task,
                    "broker_removal_requested_by_user",
                    from_status=old_status,
                    to_status="not_started",
                    metadata={"phase3_recommended_action": task.get("phase3_recommended_action")},
                )
                counts["approved"] += 1
            elif choice == "retain":
                task["status"] = "completed"
                task["outcome"] = "retained"
                _record_task_event(
                    task,
                    "footprint_retained_by_user",
                    from_status=old_status,
                    to_status="completed",
                )
                counts["retained"] += 1
            elif choice == "skip":
                task["status"] = "skipped"
                task["outcome"] = "skipped"
                _record_task_event(
                    task,
                    "task_skipped_by_user",
                    from_status=old_status,
                    to_status="skipped",
                )
                counts["skipped"] += 1
            else:
                allowed = "Request removal/review, Retain, or Skip" if is_confirmed_broker else "Retain or Skip"
                raise ValueError(
                    f"{task.get('finding_id')}: choose {allowed}."
                )

    save_state(
        state,
        event_type="bulk_decisions_recorded",
        event_payload=counts,
    )
    return counts


def transition_task(state: Dict[str, Any], task_id: str, new_status: str) -> Dict[str, Any]:
    if new_status not in VALID_STATUSES:
        raise ValueError(f"Invalid Phase 4 status: {new_status}")

    task = get_task(state, task_id)
    old_status = str(task.get("status") or "not_started")
    if new_status == old_status:
        return task

    approval = task.get("approval", {}) or {}
    if (
        approval.get("required")
        and approval.get("decision") != "approved"
        and new_status in {
            "in_progress",
            "submitted",
            "pending_external_confirmation",
            "completed",
        }
    ):
        raise PermissionError(
            "This task requires explicit user approval before remediation can proceed."
        )

    if new_status not in ALLOWED_TRANSITIONS.get(old_status, set()):
        raise ValueError(f"Invalid status transition: {old_status} -> {new_status}")

    # The browser cleanup path has its own execution function and must not be
    # falsely marked complete without running/verification.
    if (
        task.get("recommended_action") == "clear_selected_local_data"
        and new_status == "completed"
        and not (task.get("verification") or {}).get("status") == "verified"
    ):
        raise ValueError("Local cleanup must be executed and verified before it is completed.")

    task["status"] = new_status
    if new_status in {"in_progress", "submitted", "pending_external_confirmation"}:
        task["outcome"] = "in_progress"
    elif new_status == "completed":
        task["outcome"] = "remediated"
    elif new_status == "skipped":
        task["outcome"] = "skipped"
    elif new_status == "failed":
        task["outcome"] = "failed"
    _record_task_event(task, "status_changed", from_status=old_status, to_status=new_status)
    save_state(
        state,
        event_type="task_status_changed",
        event_payload={"task_id": task_id, "from_status": old_status, "to_status": new_status},
    )
    return task


def phase2c_module():
    import phase2C_passive as phase2c
    return phase2c


def cookie_database_path(profile_path: Path) -> Path:
    network = profile_path / "Network" / "Cookies"
    if network.exists():
        return network
    return profile_path / "Cookies"


def _selected_domain_groups(values: Iterable[str]) -> List[str]:
    return sorted({str(value).strip().casefold() for value in values if str(value).strip()})


def _suggested_domain_groups(task: Dict[str, Any]) -> List[str]:
    return _selected_domain_groups((task.get("target") or {}).get("suggested_tracker_domains", []))


def _scan_cookie_targets(cookie_db: Path, selected_groups: Sequence[str]) -> Dict[str, Any]:
    """Read only cookie metadata from a temporary copy and return exact row targets."""
    if not cookie_db.exists():
        raise FileNotFoundError(f"Cookie database not found: {cookie_db}")

    phase2c = phase2c_module()
    selected = set(_selected_domain_groups(selected_groups))
    if not selected:
        raise ValueError("At least one tracker domain group must be selected.")

    with tempfile.TemporaryDirectory(prefix="phase4_cookie_preview_") as temp_dir:
        try:
            copied = phase2c.copy_sqlite_database(cookie_db, Path(temp_dir))
        except OSError as exc:
            raise RuntimeError(
                "Could not safely copy the browser Cookies database. "
                "Close the browser and retry."
            ) from exc

        con = sqlite3.connect(f"file:{copied}?mode=ro", uri=True)
        try:
            columns = {str(row[1]) for row in con.execute("PRAGMA table_info(cookies)")}
            required = {"host_key", "name", "path"}
            if not required.issubset(columns):
                raise RuntimeError("Unsupported Chromium cookie schema.")
            rows = con.execute(
                "SELECT rowid, host_key, name, path FROM cookies"
            ).fetchall()
        finally:
            con.close()

    targets = []
    counts: Counter[str] = Counter()
    for rowid, host_key, name, cookie_path in rows:
        domain = str(host_key or "")
        cookie_name = str(name or "")
        is_tracker, reasons = phase2c.is_tracker_cookie(domain, cookie_name)
        if not is_tracker:
            continue
        group = phase2c.registrable_hint(domain).casefold()
        if group not in selected:
            continue
        targets.append({
            "rowid": int(rowid),
            "domain": domain,
            "name": cookie_name,
            "path": str(cookie_path or "/"),
            "domain_group": group,
            "tracker_reasons": list(reasons),
        })
        counts[group] += 1

    return {
        "targets": targets,
        "selected_domain_groups": sorted(selected),
        "matched_by_domain_group": dict(counts),
    }


def preview_local_tracker_cleanup(
    state: Dict[str, Any],
    task_id: str,
    *,
    domain_groups: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    task = get_task(state, task_id)
    if task.get("recommended_action") != "clear_selected_local_data":
        raise ValueError("This task is not a selected-local-data cleanup task.")

    profile_path_value = str((task.get("private_target") or {}).get("profile_path") or "")
    if not profile_path_value:
        raise RuntimeError("The internal Phase 2C browser profile path is unavailable.")

    selected = _selected_domain_groups(domain_groups or _suggested_domain_groups(task))
    scan = _scan_cookie_targets(cookie_database_path(Path(profile_path_value)), selected)

    preview = {
        "task_id": task_id,
        "browser": (task.get("target") or {}).get("browser"),
        "profile_name": (task.get("target") or {}).get("profile_name"),
        "selected_domain_groups": scan["selected_domain_groups"],
        "tracker_rows_matched": len(scan["targets"]),
        "matched_by_domain_group": scan["matched_by_domain_group"],
        "safety": {
            "cookie_values_read": False,
            "all_domain_cookies_deleted": False,
            "only_reidentified_tracker_rows_targeted": True,
            "exact_database_row_identity_used": True,
        },
    }

    task["execution"]["selected_scope"] = {
        "domain_groups": scan["selected_domain_groups"],
        "preview_tracker_rows": len(scan["targets"]),
        "matched_by_domain_group": scan["matched_by_domain_group"],
        "previewed_at": utc_now_iso(),
    }
    _record_task_event(
        task,
        "local_cleanup_previewed",
        metadata={
            "selected_domain_groups": scan["selected_domain_groups"],
            "tracker_rows_matched": len(scan["targets"]),
        },
    )
    save_state(
        state,
        event_type="local_cleanup_previewed",
        event_payload={
            "task_id": task_id,
            "selected_domain_groups": scan["selected_domain_groups"],
            "tracker_rows_matched": len(scan["targets"]),
        },
    )
    return preview


def _backup_cookie_database(cookie_db: Path, task_id: str) -> Path:
    phase2c = phase2c_module()
    destination = BACKUP_DIR / task_id / _stamp()
    destination.mkdir(parents=True, exist_ok=True)
    copied = phase2c.copy_sqlite_database(cookie_db, destination)
    write_json_atomic(destination / "backup_manifest.json", {
        "created_at": utc_now_iso(),
        "task_id": task_id,
        "source_database": str(cookie_db),
        "backup_database": copied.name,
        "purpose": "Backup before explicitly approved selective tracker-cookie cleanup.",
    })
    return destination


def execute_local_tracker_cleanup(
    state: Dict[str, Any],
    task_id: str,
    *,
    domain_groups: Sequence[str],
    confirmed: bool,
) -> Dict[str, Any]:
    task = get_task(state, task_id)
    if task.get("recommended_action") != "clear_selected_local_data":
        raise ValueError("This task does not support automated local cleanup.")
    if (task.get("approval") or {}).get("decision") != "approved":
        raise PermissionError("Approve this Phase 4 task before local cleanup.")
    if not confirmed:
        raise PermissionError("The immediate second confirmation is required before local cleanup.")

    selected = _selected_domain_groups(domain_groups)
    if not selected:
        raise ValueError("Select at least one tracker domain group.")

    profile_path_value = str((task.get("private_target") or {}).get("profile_path") or "")
    if not profile_path_value:
        raise RuntimeError("The internal browser profile path is unavailable.")
    cookie_db = cookie_database_path(Path(profile_path_value))

    # Re-scan immediately before the write. This prevents an old preview from
    # becoming the actual write target.
    scan = _scan_cookie_targets(cookie_db, selected)
    targets = scan["targets"]

    old_status = str(task.get("status") or "not_started")
    if old_status not in {"not_started", "failed", "in_progress"}:
        raise ValueError(f"Local cleanup cannot run from status {old_status}.")
    if old_status != "in_progress":
        task["status"] = "in_progress"
        task["outcome"] = "in_progress"
        _record_task_event(task, "local_cleanup_started", from_status=old_status, to_status="in_progress")

    try:
        backup_path = _backup_cookie_database(cookie_db, task_id)
    except OSError as exc:
        task["status"] = "failed"
        task["outcome"] = "failed"
        save_state(state, event_type="local_cleanup_backup_failed", event_payload={"task_id": task_id})
        raise RuntimeError("Could not back up the browser Cookies database. Close the browser and retry.") from exc

    deleted = 0
    connection: Optional[sqlite3.Connection] = None
    try:
        connection = sqlite3.connect(str(cookie_db), timeout=1.0)
        connection.execute("PRAGMA busy_timeout = 1000")
        connection.execute("BEGIN IMMEDIATE")

        for target in targets:
            cursor = connection.execute(
                """
                DELETE FROM cookies
                WHERE rowid = ?
                  AND host_key = ?
                  AND name = ?
                  AND path = ?
                """,
                (
                    target["rowid"],
                    target["domain"],
                    target["name"],
                    target["path"],
                ),
            )
            if cursor.rowcount and cursor.rowcount > 0:
                deleted += int(cursor.rowcount)

        connection.commit()
    except Exception as exc:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass
        task["status"] = "failed"
        task["outcome"] = "failed"
        task["execution"]["last_result"] = {
            "status": "failed",
            "selected_domain_groups": selected,
            "tracker_rows_before": len(targets),
            "rows_deleted": deleted,
            "backup_directory": str(backup_path),
            "cookie_database_path": str(cookie_db),
            "message": "The database write failed. The backup was retained; close the browser and retry.",
        }
        _record_task_event(task, "local_cleanup_failed", from_status="in_progress", to_status="failed")
        save_state(state, event_type="local_cleanup_failed", event_payload={"task_id": task_id})
        raise RuntimeError(
            "Tracker-cookie cleanup could not write to the browser database. "
            "Close the browser completely and retry."
        ) from exc
    finally:
        if connection is not None:
            connection.close()

    phase2c = phase2c_module()
    audit = phase2c.audit_cookie_db(cookie_db)
    if audit.get("status") != "success":
        task["status"] = "failed"
        task["outcome"] = "failed"
        task["execution"]["last_result"] = {
            "status": "failed",
            "selected_domain_groups": selected,
            "tracker_rows_before": len(targets),
            "rows_deleted": deleted,
            "backup_directory": str(backup_path),
            "cookie_database_path": str(cookie_db),
            "message": "The write completed but post-action verification could not read the cookie database.",
        }
        save_state(state, event_type="local_cleanup_verification_failed", event_payload={"task_id": task_id})
        raise RuntimeError("Cleanup ran, but the post-action Phase 2C re-audit failed.")

    selected_set = set(selected)
    remaining = 0
    remaining_counts: Counter[str] = Counter()
    for item in audit.get("cookies", []) or []:
        if not item.get("potential_tracker"):
            continue
        group = str(item.get("domain_group") or phase2c.registrable_hint(str(item.get("domain") or ""))).casefold()
        if group in selected_set:
            remaining += 1
            remaining_counts[group] += 1

    verified = remaining == 0
    final_status = "completed" if verified else "failed"
    task["status"] = final_status
    task["outcome"] = "remediated" if verified else "failed"
    task["execution"]["selected_scope"] = {
        "domain_groups": selected,
        "preview_tracker_rows": len(targets),
        "matched_by_domain_group": scan["matched_by_domain_group"],
        "executed_at": utc_now_iso(),
    }
    task["execution"]["last_result"] = {
        "status": final_status,
        "selected_domain_groups": selected,
        "tracker_rows_before": len(targets),
        "rows_deleted": deleted,
        "tracker_rows_after": remaining,
        "remaining_by_domain_group": dict(remaining_counts),
        "backup_directory": str(backup_path),
        "cookie_database_path": str(cookie_db),
    }
    task["verification"] = {
        "required": True,
        "status": "verified" if verified else "attention_required",
        "checked_at": utc_now_iso(),
        "method": "local_phase2c_reaudit",
        "evidence": {
            "selected_domain_groups": selected,
            "tracker_rows_before": len(targets),
            "rows_deleted": deleted,
            "tracker_rows_after": remaining,
            "remaining_by_domain_group": dict(remaining_counts),
            "backup_directory": str(backup_path),
            "cookie_database_path": str(cookie_db),
        },
    }
    _record_task_event(
        task,
        "local_cleanup_verified" if verified else "local_cleanup_attention_required",
        from_status="in_progress",
        to_status=final_status,
        metadata={"rows_deleted": deleted, "tracker_rows_after": remaining},
    )
    save_state(
        state,
        event_type="local_cleanup_completed" if verified else "local_cleanup_attention_required",
        event_payload={
            "task_id": task_id,
            "rows_deleted": deleted,
            "tracker_rows_after": remaining,
        },
    )
    return task["execution"]["last_result"]


def verify_local_tracker_cleanup(state: Dict[str, Any], task_id: str) -> Dict[str, Any]:
    task = get_task(state, task_id)
    if task.get("recommended_action") != "clear_selected_local_data":
        raise ValueError("This recheck applies only to local tracker cleanup.")

    selected = _selected_domain_groups(
        ((task.get("execution") or {}).get("selected_scope") or {}).get("domain_groups", [])
    )
    if not selected:
        raise ValueError("No executed tracker-domain scope exists for this task.")

    profile_path_value = str((task.get("private_target") or {}).get("profile_path") or "")
    phase2c = phase2c_module()
    audit = phase2c.audit_cookie_db(cookie_database_path(Path(profile_path_value)))
    if audit.get("status") != "success":
        raise RuntimeError(audit.get("warning") or "Browser cookie data could not be re-audited.")

    selected_set = set(selected)
    remaining = 0
    counts: Counter[str] = Counter()
    for item in audit.get("cookies", []) or []:
        if not item.get("potential_tracker"):
            continue
        group = str(item.get("domain_group") or phase2c.registrable_hint(str(item.get("domain") or ""))).casefold()
        if group in selected_set:
            remaining += 1
            counts[group] += 1

    verified = remaining == 0
    task["verification"] = {
        "required": True,
        "status": "verified" if verified else "attention_required",
        "checked_at": utc_now_iso(),
        "method": "local_phase2c_reaudit",
        "evidence": {
            "selected_domain_groups": selected,
            "tracker_rows_remaining": remaining,
            "remaining_by_domain_group": dict(counts),
        },
    }
    _record_task_event(task, "local_cleanup_rechecked", metadata={"verified": verified, "tracker_rows_remaining": remaining})
    save_state(
        state,
        event_type="local_cleanup_rechecked",
        event_payload={"task_id": task_id, "verified": verified, "tracker_rows_remaining": remaining},
    )
    return task["verification"]




def build_broker_email_preview(
    state: Dict[str, Any],
    task_id: str,
    subject_profile: Dict[str, Any],
) -> Dict[str, Any]:
    """Create the exact minimum-data broker request shown before sending.

    The request reference is deterministic for the Phase 4 task so the exact
    approved request can be tied to Gmail provider evidence or to a manual
    assisted-send confirmation for unsupported providers.
    """
    task = get_task(state, task_id)
    if task.get("recommended_action") != "broker_opt_out":
        raise ValueError("Email submission is available only for broker opt-out tasks.")
    if (task.get("approval") or {}).get("decision") != "approved":
        raise PermissionError("Approve the broker-removal task before preparing an email.")

    target = task.get("target", {}) or {}
    recipient = str(target.get("contact_email") or "").strip()
    if not recipient:
        raise ValueError("No verified broker/privacy contact email is configured for this provider.")

    provider = str(target.get("provider") or target.get("label") or "Data provider")
    full_name = str(subject_profile.get("full_name") or "").strip()
    subject_email = str(subject_profile.get("email") or "").strip()
    record_url = str(target.get("url") or "").strip()
    reference = "DFR-" + str(task.get("task_id") or "")[-8:]
    subject = f"Personal Data Removal / Privacy Review Request - {full_name or 'Data Subject'} [{reference}]"

    lines = [
        f"Hello {provider} Privacy Team,",
        "",
        "I am requesting a privacy review and removal of personal data associated with the record below where removal is permitted.",
        "",
    ]
    if record_url:
        lines.extend([f"Record: {record_url}", ""])
    if full_name:
        lines.append(f"Data subject name: {full_name}")
    if subject_email:
        lines.append(f"Contact email for this request: {subject_email}")
    lines.extend([
        "",
        "Please remove the personal data where your policy and applicable rules allow it. If the information is sourced from an official/public register and cannot be removed, please explain that limitation and advise how incorrect or unnecessary data can be corrected or reduced.",
        "",
        "Please confirm receipt and the outcome of this request, or any identity-verification step that is strictly necessary.",
        "",
        f"Reference: {reference}",
        "",
        "Thank you.",
    ])
    body = "\n".join(lines)
    preview = {
        "recipient": recipient,
        "subject": subject,
        "body": body,
        "reference": reference,
        "provider": provider,
        "record_url": record_url,
        "contact_source_url": target.get("contact_source_url", ""),
        "removal_scope_note": target.get("removal_scope_note", ""),
    }
    task["private_email_request"] = dict(preview)
    return preview


def record_broker_email_submission(
    state: Dict[str, Any],
    task_id: str,
    evidence: Dict[str, Any],
) -> Dict[str, Any]:
    """Record automatic provider acceptance and sent-folder evidence.

    For Gmail OAuth, the send response itself is the provider-side proof: the
    returned Message resource contains a Gmail message id and, normally, the
    ``SENT`` system label. No mailbox-wide read permission is required.
    """
    task = get_task(state, task_id)
    if task.get("recommended_action") != "broker_opt_out":
        raise ValueError("This task is not a broker email remediation task.")
    if (task.get("approval") or {}).get("decision") != "approved":
        raise PermissionError("The broker-removal task is not approved.")

    old_status = str(task.get("status") or "not_started")
    verified = bool(evidence.get("verified"))
    method = str(evidence.get("method") or "gmail_api_email")
    task["status"] = "pending_external_confirmation" if verified else "submitted"
    task["outcome"] = "in_progress"
    task.setdefault("execution", {})["last_result"] = {
        "status": task["status"],
        "method": method,
        "provider": evidence.get("provider"),
        "provider_accepted": bool(evidence.get("provider_accepted")),
        "sent_items_verified": verified,
        "sender": evidence.get("sender"),
        "recipient": evidence.get("recipient"),
        "subject": evidence.get("subject"),
        "reference": evidence.get("reference"),
        "sent_at": evidence.get("sent_at"),
        "provider_message_id": evidence.get("provider_message_id"),
        "provider_thread_id": evidence.get("provider_thread_id"),
        "sent_item_id": evidence.get("sent_item_id"),
        "gmail_label_ids": list(evidence.get("gmail_label_ids") or []),
        "message_sha256": evidence.get("message_sha256"),
        "rfc_message_id": evidence.get("rfc_message_id"),
        "web_link": evidence.get("web_link"),
        "proof_note": evidence.get("proof_note"),
    }
    task["verification"] = {
        "required": True,
        "status": "provider_sent_verified" if verified else "provider_send_accepted",
        "checked_at": utc_now_iso(),
        "method": "gmail_send_response" if method == "gmail_api_email" else method,
        "evidence": {
            "provider": evidence.get("provider"),
            "sender": evidence.get("sender"),
            "recipient": evidence.get("recipient"),
            "subject": evidence.get("subject"),
            "reference": evidence.get("reference"),
            "sent_at": evidence.get("sent_at"),
            "sent_items_verified": verified,
            "provider_message_id": evidence.get("provider_message_id"),
            "gmail_label_ids": list(evidence.get("gmail_label_ids") or []),
            "message_sha256": evidence.get("message_sha256"),
            "proof_note": evidence.get("proof_note"),
        },
    }
    _record_task_event(
        task,
        "broker_email_provider_verified" if verified else "broker_email_provider_accepted",
        from_status=old_status,
        to_status=task["status"],
        metadata={
            "sent_items_verified": verified,
            "reference": evidence.get("reference"),
            "provider": evidence.get("provider"),
        },
    )
    save_state(
        state,
        event_type="broker_email_submission_recorded",
        event_payload={
            "task_id": task_id,
            "sent_items_verified": verified,
            "status": task["status"],
            "provider": evidence.get("provider"),
        },
    )
    return task


def record_broker_sent_visibility_confirmation(
    state: Dict[str, Any],
    task_id: str,
    *,
    note: str = "",
) -> Dict[str, Any]:
    """Record a user's visual confirmation when Gmail accepted a message but
    the send response did not expose the SENT label. Provider acceptance is
    preserved, while the Sent-folder visibility proof is explicitly labelled
    user-confirmed rather than provider-verified.
    """
    task = get_task(state, task_id)
    result = (task.get("execution") or {}).get("last_result") or {}
    if result.get("method") != "gmail_api_email" or not result.get("provider_accepted"):
        raise ValueError("No Gmail provider-accepted submission is awaiting visibility confirmation.")

    old_status = str(task.get("status") or "submitted")
    result["user_confirmed_sent"] = True
    result["sent_visibility_user_confirmed"] = True
    result["note"] = note
    task["execution"]["last_result"] = result
    task["status"] = "pending_external_confirmation"
    task["outcome"] = "in_progress"
    task["verification"] = {
        "required": True,
        "status": "sent_visible_user_confirmed",
        "checked_at": utc_now_iso(),
        "method": "gmail_user_visual_confirmation",
        "evidence": {
            "provider": result.get("provider"),
            "recipient": result.get("recipient"),
            "subject": result.get("subject"),
            "reference": result.get("reference"),
            "provider_message_id": result.get("provider_message_id"),
            "sent_items_verified": False,
            "user_confirmed_sent": True,
        },
    }
    _record_task_event(
        task,
        "gmail_sent_visibility_user_confirmed",
        from_status=old_status,
        to_status=task["status"],
        metadata={"reference": result.get("reference")},
    )
    save_state(
        state,
        event_type="gmail_sent_visibility_user_confirmed",
        event_payload={"task_id": task_id, "status": task["status"]},
    )
    return task


def record_broker_manual_submission(
    state: Dict[str, Any],
    task_id: str,
    *,
    sender: str,
    recipient: str,
    subject: str,
    reference: str,
    note: str = "",
) -> Dict[str, Any]:
    """Record a user-confirmed manual send for a provider without OAuth support.

    This is intentionally labelled as user-confirmed rather than provider-verified.
    It allows Rediffmail/other providers to participate without ever collecting
    a mailbox password.
    """
    task = get_task(state, task_id)
    if task.get("recommended_action") != "broker_opt_out":
        raise ValueError("This task is not a broker-removal task.")
    if (task.get("approval") or {}).get("decision") != "approved":
        raise PermissionError("The broker-removal task is not approved.")

    old_status = str(task.get("status") or "not_started")
    task["status"] = "pending_external_confirmation"
    task["outcome"] = "in_progress"
    task.setdefault("execution", {})["last_result"] = {
        "status": task["status"],
        "method": "manual_user_sent",
        "provider": "User mailbox",
        "provider_accepted": None,
        "sent_items_verified": False,
        "user_confirmed_sent": True,
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "reference": reference,
        "sent_at": utc_now_iso(),
        "note": note,
    }
    task["verification"] = {
        "required": True,
        "status": "manual_send_user_confirmed",
        "checked_at": utc_now_iso(),
        "method": "manual_user_confirmation",
        "evidence": {
            "sender": sender,
            "recipient": recipient,
            "subject": subject,
            "reference": reference,
            "sent_items_verified": False,
            "user_confirmed_sent": True,
        },
    }
    _record_task_event(
        task,
        "broker_email_manual_send_confirmed",
        from_status=old_status,
        to_status=task["status"],
        metadata={"reference": reference},
    )
    save_state(
        state,
        event_type="broker_manual_submission_recorded",
        event_payload={"task_id": task_id, "status": task["status"]},
    )
    return task


def record_broker_sent_item_verification(
    state: Dict[str, Any],
    task_id: str,
    evidence: Dict[str, Any],
) -> Dict[str, Any]:
    """Backward-compatible helper for older saved Phase 4 states.

    Gmail v3 normally records sent proof directly from the messages.send
    response, so a second mailbox-read operation is intentionally unnecessary.
    """
    task = get_task(state, task_id)
    result = (task.get("execution") or {}).get("last_result") or {}
    if not result:
        raise ValueError("No broker email submission is recorded for this task.")
    verified = bool(evidence.get("verified"))
    result.update({
        "sent_items_verified": verified,
        "sent_at": evidence.get("sent_at") or result.get("sent_at"),
        "provider_message_id": evidence.get("provider_message_id") or result.get("provider_message_id"),
        "sent_item_id": evidence.get("sent_item_id") or result.get("sent_item_id"),
        "web_link": evidence.get("web_link") or result.get("web_link"),
    })
    task["execution"]["last_result"] = result
    if verified:
        task["status"] = "pending_external_confirmation"
    task["verification"] = {
        "required": True,
        "status": "provider_sent_verified" if verified else "provider_send_accepted",
        "checked_at": utc_now_iso(),
        "method": str(evidence.get("method") or "provider_send_evidence"),
        "evidence": {
            "recipient": evidence.get("recipient") or result.get("recipient"),
            "subject": evidence.get("subject") or result.get("subject"),
            "reference": evidence.get("reference") or result.get("reference"),
            "sent_at": evidence.get("sent_at") or result.get("sent_at"),
            "sent_items_verified": verified,
            "provider_message_id": evidence.get("provider_message_id") or result.get("provider_message_id"),
        },
    }
    _record_task_event(task, "broker_sent_evidence_updated", to_status=task.get("status"), metadata={"verified": verified})
    save_state(state, event_type="broker_sent_evidence_updated", event_payload={"task_id": task_id, "verified": verified})
    return task


def build_final_remediation_report(
    state: Dict[str, Any],
    *,
    latest_verification: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    safe = _shareable_copy(state)
    task_summaries = []
    for task in safe.get("tasks", []) or []:
        execution = task.get("execution", {}) or {}
        last_result = execution.get("last_result") or {}
        verification = task.get("verification", {}) or {}
        evidence = verification.get("evidence") or {}
        task_summaries.append({
            "task_id": task.get("task_id"),
            "finding_id": task.get("finding_id"),
            "target": (task.get("target") or {}).get("label"),
            "finding_type": (task.get("target") or {}).get("finding_type"),
            "risk_score": task.get("risk_score"),
            "risk_level": task.get("risk_level"),
            "recommended_action": task.get("recommended_action"),
            "decision": (task.get("approval") or {}).get("decision"),
            "status": task.get("status"),
            "outcome": task.get("outcome"),
            "verification_status": verification.get("status"),
            "email_submission": (
                {
                    "method": last_result.get("method"),
                    "provider": last_result.get("provider"),
                    "sender": last_result.get("sender"),
                    "recipient": last_result.get("recipient"),
                    "subject": last_result.get("subject"),
                    "reference": last_result.get("reference"),
                    "sent_at": last_result.get("sent_at"),
                    "sent_items_verified": last_result.get("sent_items_verified"),
                    "user_confirmed_sent": last_result.get("user_confirmed_sent"),
                    "provider_message_id": last_result.get("provider_message_id"),
                    "message_sha256": last_result.get("message_sha256"),
                }
                if last_result.get("method") in {"gmail_api_email", "manual_user_sent", "microsoft_graph_email"}
                else None
            ),
            "local_cleanup": (
                {
                    "rows_deleted": last_result.get("rows_deleted"),
                    "tracker_rows_after": last_result.get("tracker_rows_after"),
                    "selected_domain_groups": last_result.get("selected_domain_groups"),
                }
                if task.get("recommended_action") == "clear_selected_local_data"
                else None
            ),
            "verification_evidence": {
                key: value
                for key, value in evidence.items()
                if key not in {"backup_directory", "cookie_database_path", "web_link"}
            },
        })
    return {
        "artifact_type": "phase4_final_remediation_report",
        "version": 1,
        "generated_at": utc_now_iso(),
        "source_run_id": state.get("source_run_id"),
        "source_phase3_run_time": state.get("source_phase3_run_time"),
        "source_risk": state.get("overall_risk", {}),
        "summary": state.get("summary", {}),
        "tasks": task_summaries,
        "rescan_verification": latest_verification,
        "privacy_note": (
            "This report excludes browser profile paths, cookie values, mailbox tokens, "
            "mailbox passwords, and password/MFA secrets."
        ),
    }

def task_rows(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for task in sorted(state.get("tasks", []) or [], key=lambda item: item.get("priority_score", 0), reverse=True):
        rows.append({
            "task_id": task.get("task_id"),
            "finding_id": task.get("finding_id"),
            "status": task.get("status"),
            "priority": task.get("priority_score"),
            "risk": f"{task.get('risk_level')} ({task.get('risk_score')})",
            "action": task.get("recommended_action"),
            "approval": (task.get("approval") or {}).get("decision"),
            "target": (task.get("target") or {}).get("label"),
            "mode": (task.get("execution") or {}).get("mode"),
        })
    return rows
