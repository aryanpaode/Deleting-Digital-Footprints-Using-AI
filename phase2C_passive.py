"""Phase 2C: local passive browser-footprint audit.

The audit reads metadata from Chromium-family browser profiles on the user's
own Windows computer. It does not decrypt or export cookie values, passwords,
autofill data, or complete browsing URLs. History is aggregated by domain.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sqlite3
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit
from uuid import uuid4

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

if load_dotenv:
    load_dotenv()

LAYER = "2C_local_passive_footprints"
VERSION = 1
REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "reports").strip() or "reports")
OUTPUT_DIR = REPORTS_DIR / "layer2C"

TRACKER_DOMAIN_SUFFIXES = {
    "doubleclick.net",
    "google-analytics.com",
    "googlesyndication.com",
    "googletagmanager.com",
    "scorecardresearch.com",
    "quantserve.com",
    "criteo.com",
    "criteo.net",
    "adnxs.com",
    "taboola.com",
    "outbrain.com",
    "hotjar.com",
    "clarity.ms",
}

TRACKER_COOKIE_PATTERNS = (
    re.compile(r"^_ga(?:_|$)", re.I),
    re.compile(r"^_gid$", re.I),
    re.compile(r"^_gat", re.I),
    re.compile(r"^_fbp$", re.I),
    re.compile(r"^__gads$", re.I),
    re.compile(r"^__gpi$", re.I),
    re.compile(r"^IDE$", re.I),
    re.compile(r"^MUID$", re.I),
    re.compile(r"^ANONCHK$", re.I),
    re.compile(r"^cto_bundle$", re.I),
)

PERMISSION_TYPES = {
    "geolocation": "Location",
    "notifications": "Notifications",
    "media_stream_mic": "Microphone",
    "media_stream_camera": "Camera",
    "popups": "Pop-ups",
    "automatic_downloads": "Automatic downloads",
    "midi_sysex": "MIDI system access",
    "clipboard": "Clipboard",
}

SETTING_NAMES = {
    0: "default",
    1: "allow",
    2: "block",
    3: "ask",
    4: "session_only",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def mask_email(email: str) -> str:
    value = (email or "").strip()
    if "@" not in value:
        return ""
    local, domain = value.split("@", 1)
    return f"{local[:1] or '*'}{'*' * max(3, len(local) - 1)}@{domain}"


def mask_phone(phone: str) -> str:
    digits = re.sub(r"\D", "", phone or "")
    return "" if not digits else "*" * max(0, len(digits) - 4) + digits[-4:]


def profile_for_report(profile: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "full_name": profile.get("full_name", ""),
        "email_masked": mask_email(str(profile.get("email") or "")),
        "username": profile.get("username", ""),
        "phone_masked": mask_phone(str(profile.get("phone") or "")),
        "context_terms": list(profile.get("context_terms") or []),
    }


def browser_roots() -> List[Tuple[str, Path]]:
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    if not str(local):
        return []
    return [
        ("Google Chrome", local / "Google" / "Chrome" / "User Data"),
        ("Microsoft Edge", local / "Microsoft" / "Edge" / "User Data"),
        ("Brave", local / "BraveSoftware" / "Brave-Browser" / "User Data"),
    ]


def discover_browser_profiles(
    extra_roots: Optional[Sequence[Path]] = None,
) -> List[Dict[str, Any]]:
    roots = browser_roots()
    for root in extra_roots or []:
        roots.append((root.name or "Custom Chromium", root))

    profiles: List[Dict[str, Any]] = []
    for browser, root in roots:
        if not root.exists():
            continue
        for child in root.iterdir():
            if not child.is_dir():
                continue
            if child.name != "Default" and not child.name.startswith("Profile "):
                continue
            if not any((child / name).exists() for name in ("History", "Preferences", "Network")):
                continue
            profiles.append({
                "browser": browser,
                "profile_name": child.name,
                "profile_path": str(child),
            })
    return profiles


def copy_sqlite_database(source: Path, destination_dir: Path) -> Path:
    destination = destination_dir / source.name
    shutil.copy2(source, destination)
    for suffix in ("-wal", "-shm"):
        companion = Path(str(source) + suffix)
        if companion.exists():
            try:
                shutil.copy2(companion, Path(str(destination) + suffix))
            except OSError:
                pass
    return destination


def table_columns(connection: sqlite3.Connection, table: str) -> List[str]:
    return [str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")]


def chrome_time_to_iso(value: Any) -> Optional[str]:
    try:
        numeric = int(value)
    except (TypeError, ValueError):
        return None
    if numeric <= 0:
        return None
    try:
        # Chromium timestamps are microseconds since 1601-01-01 UTC.
        moment = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=numeric)
        return moment.isoformat()
    except (OverflowError, ValueError):
        return None


def registrable_hint(domain: str) -> str:
    value = domain.lstrip(".").casefold()
    parts = [part for part in value.split(".") if part]
    return ".".join(parts[-2:]) if len(parts) >= 2 else value


def is_tracker_cookie(domain: str, name: str) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    clean_domain = domain.lstrip(".").casefold()
    if any(clean_domain == suffix or clean_domain.endswith("." + suffix) for suffix in TRACKER_DOMAIN_SUFFIXES):
        reasons.append("known_tracker_domain_heuristic")
    if any(pattern.search(name or "") for pattern in TRACKER_COOKIE_PATTERNS):
        reasons.append("known_tracker_cookie_name_heuristic")
    return bool(reasons), reasons


def audit_cookie_db(cookie_db: Path) -> Dict[str, Any]:
    if not cookie_db.exists():
        return {"status": "not_found", "cookies": [], "warning": None}

    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            copied = copy_sqlite_database(cookie_db, Path(temp_dir))
        except OSError as exc:
            return {
                "status": "locked_or_unreadable",
                "cookies": [],
                "warning": f"Could not copy cookie database. Close the browser and retry: {exc}",
            }

        try:
            connection = sqlite3.connect(f"file:{copied}?mode=ro", uri=True)
            columns = table_columns(connection, "cookies")
            wanted = [
                name for name in (
                    "host_key", "name", "path", "expires_utc", "is_secure",
                    "is_httponly", "samesite", "is_persistent", "has_expires",
                    "source_scheme", "last_access_utc", "creation_utc",
                ) if name in columns
            ]
            if not wanted:
                connection.close()
                return {"status": "unsupported_schema", "cookies": [], "warning": "No supported cookie metadata columns were found."}
            query = "SELECT " + ", ".join(wanted) + " FROM cookies"
            rows = connection.execute(query).fetchall()
            connection.close()
        except sqlite3.Error as exc:
            return {"status": "failed", "cookies": [], "warning": f"Cookie database error: {exc}"}

    cookies: List[Dict[str, Any]] = []
    for row in rows:
        record = dict(zip(wanted, row))
        domain = str(record.get("host_key") or "")
        name = str(record.get("name") or "")
        tracker, tracker_reasons = is_tracker_cookie(domain, name)
        persistent = bool(record.get("is_persistent"))
        if "is_persistent" not in record:
            persistent = bool(int(record.get("expires_utc") or 0) > 0)
        cookies.append({
            "domain": domain,
            "domain_group": registrable_hint(domain),
            "name": name,
            "path": record.get("path"),
            "persistent": persistent,
            "expires_at": chrome_time_to_iso(record.get("expires_utc")),
            "secure": bool(record.get("is_secure")),
            "http_only": bool(record.get("is_httponly")),
            "same_site": record.get("samesite"),
            "potential_tracker": tracker,
            "tracker_reasons": tracker_reasons,
        })

    return {"status": "success", "cookies": cookies, "warning": None}


def audit_history_db(history_db: Path, limit_domains: int = 100) -> Dict[str, Any]:
    if not history_db.exists():
        return {"status": "not_found", "domains": [], "warning": None}

    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            copied = copy_sqlite_database(history_db, Path(temp_dir))
        except OSError as exc:
            return {
                "status": "locked_or_unreadable",
                "domains": [],
                "warning": f"Could not copy history database. Close the browser and retry: {exc}",
            }
        try:
            connection = sqlite3.connect(f"file:{copied}?mode=ro", uri=True)
            rows = connection.execute(
                "SELECT url, visit_count, last_visit_time FROM urls"
            ).fetchall()
            connection.close()
        except sqlite3.Error as exc:
            return {"status": "failed", "domains": [], "warning": f"History database error: {exc}"}

    counts: Counter[str] = Counter()
    last_seen: Dict[str, int] = {}
    for url, visits, last_visit in rows:
        try:
            domain = urlsplit(str(url)).netloc.casefold()
        except ValueError:
            continue
        if domain.startswith("www."):
            domain = domain[4:]
        if not domain:
            continue
        counts[domain] += max(1, int(visits or 0))
        last_seen[domain] = max(last_seen.get(domain, 0), int(last_visit or 0))

    domains = [
        {
            "domain": domain,
            "visit_count": count,
            "last_visit": chrome_time_to_iso(last_seen.get(domain)),
        }
        for domain, count in counts.most_common(limit_domains)
    ]
    return {"status": "success", "domains": domains, "warning": None}


def normalize_permission_origin(value: str) -> str:
    # Chromium keys can contain primary,secondary patterns separated by comma.
    origin = (value or "").split(",", 1)[0]
    return origin.replace("[*.]", "*." )


def audit_preferences(preferences_path: Path) -> Dict[str, Any]:
    if not preferences_path.exists():
        return {"status": "not_found", "permissions": [], "warning": None}
    try:
        payload = json.loads(preferences_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "failed", "permissions": [], "warning": f"Preferences error: {exc}"}

    exceptions = (
        payload.get("profile", {})
        .get("content_settings", {})
        .get("exceptions", {})
    )
    permissions: List[Dict[str, Any]] = []
    for internal_name, label in PERMISSION_TYPES.items():
        entries = exceptions.get(internal_name, {})
        if not isinstance(entries, dict):
            continue
        for origin, details in entries.items():
            if not isinstance(details, dict):
                continue
            setting = details.get("setting")
            if setting is None and details.get("last_modified"):
                setting = "configured"
            permissions.append({
                "origin": normalize_permission_origin(str(origin)),
                "permission": label,
                "setting": SETTING_NAMES.get(setting, setting),
                "last_modified": details.get("last_modified"),
            })
    return {"status": "success", "permissions": permissions, "warning": None}


def summarize_profile_audit(
    browser: str,
    profile_name: str,
    profile_path: Path,
) -> Dict[str, Any]:
    cookie_path = profile_path / "Network" / "Cookies"
    if not cookie_path.exists():
        cookie_path = profile_path / "Cookies"

    cookie_audit = audit_cookie_db(cookie_path)
    history_audit = audit_history_db(profile_path / "History")
    permission_audit = audit_preferences(profile_path / "Preferences")

    cookies = list(cookie_audit.get("cookies") or [])
    permissions = list(permission_audit.get("permissions") or [])
    risky_permissions = [
        item for item in permissions
        if str(item.get("setting")).casefold() == "allow"
        and item.get("permission") in {"Location", "Microphone", "Camera", "Notifications", "Automatic downloads"}
    ]

    insecure_none = [
        item for item in cookies
        if item.get("same_site") in {0, "0", -1, "-1", None}
        and not item.get("secure")
        and item.get("persistent")
    ]
    tracker_cookies = [item for item in cookies if item.get("potential_tracker")]

    domain_counts = Counter(item.get("domain_group") for item in cookies if item.get("domain_group"))
    tracker_domains = Counter(item.get("domain_group") for item in tracker_cookies if item.get("domain_group"))

    risk_score = min(
        100,
        min(30, len(tracker_cookies))
        + min(20, len(risky_permissions) * 5)
        + min(20, len(insecure_none) * 2)
        + (10 if sum(1 for item in cookies if item.get("persistent")) > 100 else 0),
    )
    risk_level = "High" if risk_score >= 40 else "Moderate" if risk_score >= 15 else "Low"

    warnings = [
        warning for warning in (
            cookie_audit.get("warning"),
            history_audit.get("warning"),
            permission_audit.get("warning"),
        ) if warning
    ]

    return {
        "browser": browser,
        "profile_name": profile_name,
        "profile_path": str(profile_path),
        "collection_status": {
            "cookies": cookie_audit.get("status"),
            "history": history_audit.get("status"),
            "permissions": permission_audit.get("status"),
        },
        "summary": {
            "cookie_count": len(cookies),
            "persistent_cookie_count": sum(bool(item.get("persistent")) for item in cookies),
            "potential_tracker_cookie_count": len(tracker_cookies),
            "cookie_domain_count": len(domain_counts),
            "history_domain_count": len(history_audit.get("domains") or []),
            "configured_permission_count": len(permissions),
            "risky_allowed_permission_count": len(risky_permissions),
            "risk_score": risk_score,
            "risk_level": risk_level,
        },
        "top_cookie_domains": [
            {"domain": domain, "cookie_count": count}
            for domain, count in domain_counts.most_common(25)
        ],
        "potential_tracker_domains": [
            {"domain": domain, "cookie_count": count, "classification": "heuristic"}
            for domain, count in tracker_domains.most_common(25)
        ],
        "top_history_domains": list(history_audit.get("domains") or [])[:50],
        "risky_permissions": risky_permissions,
        "permission_summary": dict(Counter(
            f"{item.get('permission')}:{item.get('setting')}" for item in permissions
        )),
        "recommended_actions": build_actions(cookies, tracker_cookies, risky_permissions),
        "warnings": warnings,
    }


def build_actions(
    cookies: Sequence[Dict[str, Any]],
    tracker_cookies: Sequence[Dict[str, Any]],
    risky_permissions: Sequence[Dict[str, Any]],
) -> List[str]:
    actions: List[str] = []
    if tracker_cookies:
        actions.append("Review and clear selected tracking-cookie domains after user approval.")
    if any(item.get("persistent") for item in cookies):
        actions.append("Review persistent site data, especially for sites no longer used.")
    if risky_permissions:
        actions.append("Revoke unnecessary location, camera, microphone, notification, or download permissions.")
    actions.append("Do not clear login or preference cookies automatically; let the user select sites first.")
    return actions


def run_layer3(
    profile: Dict[str, Any],
    *,
    consent_local_audit: bool = False,
    extra_roots: Optional[Sequence[Path]] = None,
) -> Dict[str, Any]:
    if not consent_local_audit:
        return {
            "artifact_type": "layer_report",
            "layer": LAYER,
            "version": VERSION,
            "run_id": uuid4().hex,
            "run_time": utc_now_iso(),
            "status": "skipped",
            "input_profile": profile_for_report(profile),
            "consent": {"local_browser_audit": False},
            "summary": {},
            "browser_profiles": [],
            "warnings": ["The user did not approve the local browser audit."],
            "errors": [],
        }

    discovered = discover_browser_profiles(extra_roots)
    audits: List[Dict[str, Any]] = []
    warnings: List[str] = []
    for item in discovered:
        audit = summarize_profile_audit(
            str(item["browser"]),
            str(item["profile_name"]),
            Path(str(item["profile_path"])),
        )
        audits.append(audit)
        warnings.extend(audit.get("warnings", []))

    report = {
        "artifact_type": "layer_report",
        "layer": LAYER,
        "version": VERSION,
        "run_id": uuid4().hex,
        "run_time": utc_now_iso(),
        "status": "success" if discovered else "partial_failure",
        "input_profile": profile_for_report(profile),
        "consent": {"local_browser_audit": True},
        "privacy_controls": {
            "cookie_values_read": False,
            "passwords_read": False,
            "autofill_read": False,
            "full_history_urls_exported": False,
            "history_aggregation": "domain_only",
        },
        "summary": {
            "browser_profile_count": len(audits),
            "cookie_count": sum(a.get("summary", {}).get("cookie_count", 0) for a in audits),
            "persistent_cookie_count": sum(a.get("summary", {}).get("persistent_cookie_count", 0) for a in audits),
            "potential_tracker_cookie_count": sum(a.get("summary", {}).get("potential_tracker_cookie_count", 0) for a in audits),
            "risky_allowed_permission_count": sum(a.get("summary", {}).get("risky_allowed_permission_count", 0) for a in audits),
            "highest_profile_risk_score": max([a.get("summary", {}).get("risk_score", 0) for a in audits] or [0]),
        },
        "browser_profiles": audits,
        "warnings": list(dict.fromkeys(
            warnings + ([] if discovered else ["No supported Chromium browser profiles were found."])
        )),
        "errors": [],
    }
    return report


def save_layer3_report(report: Dict[str, Any]) -> str:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.fromisoformat(report["run_time"]).strftime("%Y%m%d_%H%M%S_%f")
    path = OUTPUT_DIR / f"layer2C_{stamp}.json"
    latest = OUTPUT_DIR / "latest_layer2C.json"
    report["saved_files"] = {
        "timestamped_report": str(path),
        "latest_report": str(latest),
    }
    write_json(path, report)
    write_json(latest, report)
    return str(path)


def collect_profile() -> Dict[str, Any]:
    full_name = input("Full name: ").strip()
    email = input("Email: ").strip().casefold()
    username = input("Username: ").strip()
    phone = re.sub(r"\D", "", input("Phone (verification only): ").strip())
    context_raw = input("Context terms, comma-separated: ").strip()
    return {
        "full_name": full_name,
        "email": email,
        "username": username,
        "phone": phone,
        "context_terms": [value.strip() for value in context_raw.split(",") if value.strip()],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 2C local passive browser-footprint audit")
    parser.add_argument("--profile-json", help="JSON file containing the shared identity profile")
    parser.add_argument("--approve-local-audit", action="store_true")
    parser.add_argument("--browser-root", action="append", default=[], help="Additional Chromium user-data root")
    args = parser.parse_args()

    profile = load_json(Path(args.profile_json)) if args.profile_json else collect_profile()
    report = run_layer3(
        profile,
        consent_local_audit=args.approve_local_audit,
        extra_roots=[Path(value) for value in args.browser_root],
    )
    save_layer3_report(report)
    print(json.dumps(report.get("summary", {}), indent=2))
    for warning in report.get("warnings", []):
        print("Warning:", warning)


if __name__ == "__main__":
    main()
