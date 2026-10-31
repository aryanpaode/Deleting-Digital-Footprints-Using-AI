"""Before/after re-scan verification for Phase 4 remediation.

The verification loop is intentionally conservative. Historical breach records
are not expected to disappear when a password is changed, so password/MFA
remediation is recorded as self-confirmed rather than falsely 'verified removed'.
Public/broker footprints can be re-discovered and compared after a new scan.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
VERIFICATION_DIR = REPORTS_DIR / "verification"
PENDING_FILE = VERIFICATION_DIR / "pending_rescan.json"
LATEST_FILE = VERIFICATION_DIR / "latest_verification.json"
HISTORY_FILE = VERIFICATION_DIR / "verification_history.jsonl"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    temp.replace(path)


def read_json(path: Path) -> Dict[str, Any] | None:
    try:
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def subject_fingerprint(profile: Dict[str, Any]) -> str:
    raw = "|".join([
        str(profile.get("full_name") or "").strip().casefold(),
        str(profile.get("email") or "").strip().casefold(),
        str(profile.get("username") or "").strip().casefold(),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def subject_identity(profile: Dict[str, Any]) -> Dict[str, str]:
    email = str(profile.get("email") or "").strip().casefold()
    return {
        "full_name": str(profile.get("full_name") or "").strip().casefold(),
        "username": str(profile.get("username") or "").strip().casefold(),
        "email_hash": hashlib.sha256(email.encode("utf-8")).hexdigest() if email else "",
    }


def same_subject(baseline_identity: Dict[str, Any], current_profile: Dict[str, Any]) -> bool:
    current = subject_identity(current_profile)
    if not baseline_identity.get("full_name") or baseline_identity.get("full_name") != current.get("full_name"):
        return False
    # Optional identity signals are compared only when both scans supplied them.
    if baseline_identity.get("username") and current.get("username") and baseline_identity.get("username") != current.get("username"):
        return False
    if baseline_identity.get("email_hash") and current.get("email_hash") and baseline_identity.get("email_hash") != current.get("email_hash"):
        return False
    return True


def normalize_url(value: str) -> str:
    try:
        parts = urlsplit(value or "")
        path = re.sub(r"/+", "/", parts.path or "/").rstrip("/")
        return urlunsplit((parts.scheme.casefold(), parts.netloc.casefold(), path, "", ""))
    except Exception:
        return str(value or "").strip().casefold()


def task_fingerprint(target: Dict[str, Any]) -> str:
    finding_type = str(target.get("finding_type") or "unknown")
    if finding_type in {"public_footprint", "visual_public_footprint", "data_broker_exposure"}:
        url = normalize_url(str(target.get("url") or ""))
        if url:
            return f"{finding_type}|url|{url}"
        return f"{finding_type}|domain|{str(target.get('domain') or '').casefold()}|{str(target.get('label') or '').casefold()}"
    if finding_type == "breach_exposure":
        return "|".join([
            finding_type,
            str(target.get("service") or target.get("label") or "").casefold(),
            str(target.get("domain") or "").casefold(),
            str(target.get("breach_date") or ""),
        ])
    if finding_type == "local_browser_metadata":
        return "|".join([
            finding_type,
            str(target.get("browser") or "").casefold(),
            str(target.get("profile_name") or "").casefold(),
        ])
    return f"{finding_type}|{str(target.get('label') or '').casefold()}"


def _phase3_overall(phase3: Dict[str, Any] | None) -> Dict[str, Any]:
    phase3 = phase3 or {}
    cross = phase3.get("cross_layer_assessment", {}) or {}
    return {
        "score": int(cross.get("overall_risk_score", 0) or 0),
        "level": cross.get("overall_risk_level", "Unknown"),
    }


def create_pending_baseline(
    phase4_state: Dict[str, Any],
    aggregate: Dict[str, Any],
    phase3: Dict[str, Any],
) -> Dict[str, Any]:
    VERIFICATION_DIR.mkdir(parents=True, exist_ok=True)
    baseline_id = uuid4().hex
    tasks = []
    for task in phase4_state.get("tasks", []) or []:
        target = task.get("target", {}) or {}
        tasks.append({
            "task_id": task.get("task_id"),
            "finding_id": task.get("finding_id"),
            "recommended_action": task.get("recommended_action"),
            "status": task.get("status"),
            "outcome": task.get("outcome"),
            "target": target,
            "fingerprint": task_fingerprint(target),
            "selected_scope": ((task.get("execution") or {}).get("selected_scope") or {}),
            "verification": task.get("verification", {}),
        })

    payload = {
        "artifact_type": "phase4_rescan_baseline",
        "version": 1,
        "baseline_id": baseline_id,
        "created_at": utc_now_iso(),
        "source_run_id": phase4_state.get("source_run_id"),
        "source_phase3_run_time": phase4_state.get("source_phase3_run_time"),
        "subject_fingerprint": subject_fingerprint(aggregate.get("input_profile", {}) or {}),
        "subject_identity": subject_identity(aggregate.get("input_profile", {}) or {}),
        "baseline_risk": phase4_state.get("overall_risk") or _phase3_overall(phase3),
        "phase4_summary": phase4_state.get("summary", {}),
        "tasks": tasks,
    }
    write_json(PENDING_FILE, payload)
    write_json(VERIFICATION_DIR / f"baseline_{baseline_id}.json", payload)
    append_jsonl(HISTORY_FILE, {
        "timestamp": utc_now_iso(),
        "event_type": "rescan_baseline_created",
        "baseline_id": baseline_id,
        "source_run_id": payload.get("source_run_id"),
    })
    return payload


def pending_status() -> Dict[str, Any] | None:
    return read_json(PENDING_FILE)


def latest_verification() -> Dict[str, Any] | None:
    return read_json(LATEST_FILE)


def _current_index(aggregate: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    import phase4_remediation as p4
    by_fingerprint: Dict[str, Dict[str, Any]] = {}
    for item in p4.build_source_finding_index(aggregate).values():
        by_fingerprint[task_fingerprint(item)] = item
    return by_fingerprint


def _local_selected_groups(task: Dict[str, Any]) -> set[str]:
    selected = (task.get("selected_scope") or {}).get("domain_groups", []) or []
    return {str(value).casefold() for value in selected if value}


def _compare_one(task: Dict[str, Any], current: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    action = str(task.get("recommended_action") or "")
    status = str(task.get("status") or "")
    outcome = str(task.get("outcome") or "")
    target = task.get("target", {}) or {}
    fingerprint = str(task.get("fingerprint") or task_fingerprint(target))
    matched = current.get(fingerprint)

    result = {
        "task_id": task.get("task_id"),
        "finding_id": task.get("finding_id"),
        "label": target.get("label") or task.get("finding_id"),
        "finding_type": target.get("finding_type"),
        "recommended_action": action,
        "previous_status": status,
        "previous_outcome": outcome,
        "result": "not_applicable",
        "verified": False,
        "note": "",
    }

    if outcome == "retained":
        result.update(result="retained", note="The user intentionally retained this finding.")
        return result
    if outcome == "skipped":
        result.update(result="skipped", note="The user chose not to remediate this finding.")
        return result

    if action in {"change_password", "enable_mfa"} and status == "completed":
        result.update(
            result="security_action_self_confirmed",
            note=(
                "A historical breach record normally remains discoverable after a password/MFA change. "
                "Completion is therefore user-confirmed rather than inferred from disappearance of the breach record."
            ),
        )
        return result

    if action == "clear_selected_local_data" and status == "completed":
        if not matched:
            result.update(result="could_not_verify", note="The browser profile was not present in the re-scan.")
            return result
        selected = _local_selected_groups(task)
        current_domains = {
            str(value).casefold()
            for value in (matched.get("suggested_tracker_domains") or [])
            if value
        }
        remaining = sorted(selected.intersection(current_domains))
        if selected and not remaining:
            result.update(result="verified_cleared", verified=True, note="Selected tracker-domain groups were not re-detected.")
        else:
            result.update(result="tracker_reappeared", note=f"Still detected: {', '.join(remaining) if remaining else 'selected tracker evidence'}.")
        return result

    if action in {"broker_opt_out", "delete_account_or_content", "update_or_redact"} and status in {
        "completed", "submitted", "pending_external_confirmation"
    }:
        if matched:
            result.update(result="still_present", note="The same public/broker footprint was re-discovered.")
        else:
            result.update(result="verified_removed_or_unavailable", verified=True, note="The prior public/broker footprint was not re-discovered in the new scan.")
        return result

    if action == "revoke_permission" and status == "completed":
        if not matched:
            result.update(result="could_not_verify", note="The browser profile was not present in the re-scan.")
        else:
            risky = (matched.get("summary") or {}).get("risky_allowed_permission_count", 0)
            if int(risky or 0) == 0:
                result.update(result="verified_cleared", verified=True, note="No risky allowed permissions were re-detected.")
            else:
                result.update(result="still_present", note=f"{risky} risky allowed permission(s) remain.")
        return result

    if status in {"completed", "submitted", "pending_external_confirmation"}:
        if matched:
            result.update(result="still_present", note="The finding remains discoverable after the re-scan.")
        else:
            result.update(result="verified_removed_or_unavailable", verified=True, note="The finding was not re-discovered.")
        return result

    if outcome == "approved" or status in {"not_started", "in_progress", "failed"}:
        result.update(result="remediation_incomplete", note="The approved remediation was not fully completed before the verification scan.")
    return result


def finalize_pending_if_possible(
    aggregate: Dict[str, Any],
    phase3: Dict[str, Any],
) -> Dict[str, Any] | None:
    baseline = read_json(PENDING_FILE)
    if not baseline:
        return None

    current_profile = aggregate.get("input_profile", {}) or {}
    baseline_identity = baseline.get("subject_identity") or {}
    same = same_subject(baseline_identity, current_profile) if baseline_identity else (
        subject_fingerprint(current_profile) == baseline.get("subject_fingerprint")
    )
    if not same:
        report = {
            "artifact_type": "phase4_rescan_verification",
            "version": 1,
            "baseline_id": baseline.get("baseline_id"),
            "completed_at": utc_now_iso(),
            "status": "subject_mismatch",
            "source_run_id": baseline.get("source_run_id"),
            "current_run_id": aggregate.get("run_id"),
            "before_risk": baseline.get("baseline_risk", {}),
            "after_risk": _phase3_overall(phase3),
            "summary": {},
            "results": [],
        }
    else:
        current = _current_index(aggregate)
        results = [_compare_one(task, current) for task in (baseline.get("tasks") or [])]
        counts = Counter(str(item.get("result") or "unknown") for item in results)
        report = {
            "artifact_type": "phase4_rescan_verification",
            "version": 1,
            "baseline_id": baseline.get("baseline_id"),
            "completed_at": utc_now_iso(),
            "status": "completed",
            "source_run_id": baseline.get("source_run_id"),
            "current_run_id": aggregate.get("run_id"),
            "before_risk": baseline.get("baseline_risk", {}),
            "after_risk": _phase3_overall(phase3),
            "summary": {
                "total": len(results),
                "verified": sum(bool(item.get("verified")) for item in results),
                "still_present": counts.get("still_present", 0) + counts.get("tracker_reappeared", 0),
                "self_confirmed_security_actions": counts.get("security_action_self_confirmed", 0),
                "retained": counts.get("retained", 0),
                "skipped": counts.get("skipped", 0),
                "incomplete": counts.get("remediation_incomplete", 0),
                "result_counts": dict(counts),
            },
            "results": results,
        }

    write_json(LATEST_FILE, report)
    write_json(VERIFICATION_DIR / f"verification_{baseline.get('baseline_id')}.json", report)
    append_jsonl(HISTORY_FILE, {
        "timestamp": utc_now_iso(),
        "event_type": "rescan_verification_completed",
        "baseline_id": baseline.get("baseline_id"),
        "current_run_id": aggregate.get("run_id"),
        "status": report.get("status"),
    })
    try:
        PENDING_FILE.unlink()
    except FileNotFoundError:
        pass
    return report
