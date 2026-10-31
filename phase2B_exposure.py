"""Phase 2B: authorised breach and data-broker exposure analysis.

Supported breach providers:
- XposedOrNot public API (free, no API key)
- LeakCheck public API (free, no API key; optional corroboration)
- Have I Been Pwned API v3 (optional paid provider)

This module does not download breach databases, retrieve leaked passwords, or
attempt account access. It only uses authorised breach-check APIs for the
supplied email address and enriches broker candidates discovered by Phase 2A.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen
from uuid import uuid4

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional convenience dependency
    load_dotenv = None

if load_dotenv:
    load_dotenv()

LAYER = "2B_breach_and_broker"
VERSION = 2
REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "reports").strip() or "reports")
OUTPUT_DIR = REPORTS_DIR / "layer2B"

HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
XON_BASE_URL = "https://api.xposedornot.com/v1"
LEAKCHECK_PUBLIC_URL = "https://leakcheck.io/api/public"
DEFAULT_USER_AGENT = "DeletingFootprintsAI-StudentProject/1.0"

# Only official removal/privacy pages that have been manually verified should
# be placed here. Unknown providers stay in assisted/manual mode rather than
# receiving a guessed removal URL.
BROKER_REGISTRY: Dict[str, Dict[str, str]] = {
    "apollo.io": {
        "provider": "Apollo",
        "privacy_url": "https://www.apollo.io/company/privacy-center",
        "execution_mode": "assisted_form",
        "contact_email": "",
        "contact_source_url": "https://www.apollo.io/company/privacy-center",
        "removal_scope_note": "Use Apollo's official privacy-center workflow.",
    },
    "zoominfo.com": {
        "provider": "ZoomInfo",
        "privacy_url": "https://privacyrequest.zoominfo.com/remove/verify",
        "execution_mode": "assisted_form",
        "contact_email": "",
        "contact_source_url": "https://privacyrequest.zoominfo.com/remove/verify",
        "removal_scope_note": "Use ZoomInfo's official removal/verification form.",
    },
    "tofler.in": {
        "provider": "Tofler",
        "privacy_url": "https://www.tofler.in/privacy",
        "execution_mode": "assisted_email_review",
        "contact_email": "support@tofler.in",
        "contact_source_url": "https://www.tofler.in/privacy",
        "removal_scope_note": (
            "Tofler accepts privacy/data-deletion contact at support@tofler.in, "
            "but its FAQ says company/director details sourced from public registers "
            "are generally not removed merely on request. The email therefore asks "
            "for removal where permitted, or correction/clarification otherwise."
        ),
    },
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().casefold() in {"1", "true", "yes", "y", "on"}


def domain_of(url: str) -> str:
    try:
        domain = urlsplit(url or "").netloc.casefold()
    except ValueError:
        return ""
    return domain[4:] if domain.startswith("www.") else domain


def mask_email(email: str) -> str:
    value = (email or "").strip()
    if "@" not in value:
        return ""
    local, domain = value.split("@", 1)
    visible = local[:1] if local else "*"
    return f"{visible}{'*' * max(3, len(local) - 1)}@{domain}"


def mask_phone(phone: str) -> str:
    digits = re.sub(r"\D", "", phone or "")
    if not digits:
        return ""
    return "*" * max(0, len(digits) - 4) + digits[-4:]


def profile_for_report(profile: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "full_name": profile.get("full_name", ""),
        "email_masked": mask_email(str(profile.get("email") or "")),
        "username": profile.get("username", ""),
        "phone_masked": mask_phone(str(profile.get("phone") or "")),
        "context_terms": list(profile.get("context_terms") or []),
    }


def _request_json(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
) -> Tuple[Optional[Any], Optional[HTTPError], Optional[Exception]]:
    request_headers = {
        "accept": "application/json",
        "user-agent": os.getenv("BREACH_API_USER_AGENT", DEFAULT_USER_AGENT).strip()
        or DEFAULT_USER_AGENT,
    }
    if headers:
        request_headers.update(headers)

    request = Request(url, headers=request_headers, method="GET")
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
        return json.loads(raw), None, None
    except HTTPError as exc:
        return None, exc, None
    except (URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, None, exc


def breach_exposure_score(data_classes: Iterable[str]) -> int:
    score = 10
    values = {str(value).casefold() for value in data_classes}
    if any("password" in value for value in values):
        score += 35
    if any("phone" in value for value in values):
        score += 15
    if any(
        "address" in value and "email address" not in value
        for value in values
    ):
        score += 15
    if any("date of birth" in value or "dates of birth" in value for value in values):
        score += 15
    if any("security question" in value for value in values):
        score += 20
    if any("credit" in value or "financial" in value for value in values):
        score += 25
    return min(score, 100)


def breach_actions(data_classes: Iterable[str]) -> List[str]:
    values = {str(value).casefold() for value in data_classes}
    actions = ["Review whether the affected account is still active."]
    if any("password" in value for value in values):
        actions.extend([
            "Change the affected password if it is still in use.",
            "Change the password on any account where it was reused.",
            "Enable multi-factor authentication where available.",
        ])
    if any("phone" in value for value in values):
        actions.append("Be alert for targeted calls, OTP theft, and SIM-swap attempts.")
    if any(
        "address" in value and "email address" not in value
        for value in values
    ):
        actions.append("Review account recovery details and identity-verification exposure.")
    actions.append("Delete the old account if it is no longer required.")
    return list(dict.fromkeys(actions))


def _clean_data_classes(raw: Any) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        values = re.split(r"[;,|]", raw)
    elif isinstance(raw, (list, tuple, set)):
        values = [str(item) for item in raw]
    else:
        values = [str(raw)]
    cleaned = []
    for value in values:
        text = re.sub(r"\s+", " ", str(value).replace("_", " ")).strip()
        if text:
            cleaned.append(text)
    return list(dict.fromkeys(cleaned))


def _yes(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().casefold() in {"yes", "true", "1", "verified"}


def _normalised_breach(
    *,
    service: str,
    breach_name: str,
    domain: str = "",
    breach_date: str = "",
    exposed_data: Optional[Iterable[str]] = None,
    verified: Optional[bool] = None,
    source: str,
    provider_name: str,
    description: str = "",
    industry: str = "",
    password_risk: str = "",
    record_count: Optional[int] = None,
) -> Dict[str, Any]:
    data_classes = _clean_data_classes(exposed_data)
    return {
        "type": "breach_exposure",
        "service": service or breach_name or domain or "Unknown breach",
        "breach_name": breach_name or service or domain or "Unknown breach",
        "domain": domain or "",
        "breach_date": breach_date or "",
        "verified": verified,
        "exposed_data": data_classes,
        "exposure_score": breach_exposure_score(data_classes),
        "recommended_security_actions": breach_actions(data_classes),
        "description": description or "",
        "industry": industry or "",
        "password_risk": password_risk or "",
        "record_count": record_count,
        "source": source,
        "provider_sources": [provider_name],
    }


def _parse_xon_analytics(payload: Any) -> List[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return []

    exposed = payload.get("ExposedBreaches")
    if not isinstance(exposed, dict):
        return []

    details = exposed.get("breaches_details")
    if not isinstance(details, list):
        return []

    breaches: List[Dict[str, Any]] = []
    for item in details:
        if not isinstance(item, dict):
            continue
        raw_count = item.get("xposed_records")
        try:
            record_count = int(raw_count) if raw_count not in {None, ""} else None
        except (TypeError, ValueError):
            record_count = None

        breaches.append(_normalised_breach(
            service=str(item.get("breach") or item.get("domain") or "Unknown breach"),
            breach_name=str(item.get("breach") or ""),
            domain=str(item.get("domain") or ""),
            breach_date=str(item.get("xposed_date") or ""),
            exposed_data=_clean_data_classes(item.get("xposed_data")),
            verified=_yes(item.get("verified")),
            source="XposedOrNot breach-analytics API",
            provider_name="XposedOrNot",
            description=str(item.get("details") or ""),
            industry=str(item.get("industry") or ""),
            password_risk=str(item.get("password_risk") or ""),
            record_count=record_count,
        ))
    return breaches


def xposedornot_breach_lookup(email: str, *, timeout: int = 30) -> Dict[str, Any]:
    """Use XposedOrNot's public breach analytics endpoint."""
    if not email:
        return {
            "provider": "XposedOrNot",
            "status": "skipped",
            "breaches": [],
            "warning": "No email was supplied for the XposedOrNot lookup.",
        }

    endpoint = f"{XON_BASE_URL}/breach-analytics?{urlencode({'email': email})}"
    payload, http_error, other_error = _request_json(endpoint, timeout=timeout)

    if http_error:
        if http_error.code == 404:
            return {"provider": "XposedOrNot", "status": "success", "breaches": [], "warning": None}
        if http_error.code == 429:
            return {
                "provider": "XposedOrNot",
                "status": "rate_limited",
                "breaches": [],
                "warning": "XposedOrNot rate limit reached; retry later.",
            }
        return {
            "provider": "XposedOrNot",
            "status": "failed",
            "breaches": [],
            "warning": f"XposedOrNot HTTP error {http_error.code}: {http_error.reason}",
        }
    if other_error:
        return {
            "provider": "XposedOrNot",
            "status": "failed",
            "breaches": [],
            "warning": f"XposedOrNot lookup failed: {other_error}",
        }

    breaches = _parse_xon_analytics(payload)
    return {
        "provider": "XposedOrNot",
        "status": "success",
        "breaches": breaches,
        "warning": None,
    }


def _parse_leakcheck_public(payload: Any) -> List[Dict[str, Any]]:
    if not isinstance(payload, dict) or payload.get("success") is not True:
        return []

    fields = _clean_data_classes(payload.get("fields"))
    sources = payload.get("sources")
    if not isinstance(sources, list):
        return []

    breaches: List[Dict[str, Any]] = []
    for source_item in sources:
        if not isinstance(source_item, dict):
            continue
        name = str(source_item.get("name") or "Unknown breach")
        date = str(source_item.get("date") or "")
        domain = name.casefold() if "." in name and " " not in name else ""
        breaches.append(_normalised_breach(
            service=name,
            breach_name=name,
            domain=domain,
            breach_date=date,
            exposed_data=fields,
            verified=None,
            source="LeakCheck Public API (Powered by LeakCheck)",
            provider_name="LeakCheck",
        ))
    return breaches


def leakcheck_public_lookup(email: str, *, timeout: int = 30) -> Dict[str, Any]:
    """Use LeakCheck's unauthenticated public API for corroboration."""
    if not email:
        return {
            "provider": "LeakCheck",
            "status": "skipped",
            "breaches": [],
            "warning": "No email was supplied for the LeakCheck lookup.",
        }

    endpoint = f"{LEAKCHECK_PUBLIC_URL}?{urlencode({'check': email})}"
    payload, http_error, other_error = _request_json(endpoint, timeout=timeout)

    if http_error:
        if http_error.code == 404:
            return {"provider": "LeakCheck", "status": "success", "breaches": [], "warning": None}
        if http_error.code == 429:
            return {
                "provider": "LeakCheck",
                "status": "rate_limited",
                "breaches": [],
                "warning": "LeakCheck public API rate limit reached; retry later.",
            }
        return {
            "provider": "LeakCheck",
            "status": "failed",
            "breaches": [],
            "warning": f"LeakCheck HTTP error {http_error.code}: {http_error.reason}",
        }
    if other_error:
        return {
            "provider": "LeakCheck",
            "status": "failed",
            "breaches": [],
            "warning": f"LeakCheck lookup failed: {other_error}",
        }

    breaches = _parse_leakcheck_public(payload)
    return {
        "provider": "LeakCheck",
        "status": "success",
        "breaches": breaches,
        "warning": None,
    }


def hibp_breach_lookup(
    email: str,
    *,
    api_key: str,
    user_agent: str,
    timeout: int = 30,
) -> Dict[str, Any]:
    """Query the HIBP breached-account endpoint for an authorised email."""
    if not email:
        return {
            "provider": "Have I Been Pwned",
            "status": "skipped",
            "breaches": [],
            "warning": "No email was supplied for the breach lookup.",
        }
    if not api_key:
        return {
            "provider": "Have I Been Pwned",
            "status": "skipped",
            "breaches": [],
            "warning": "HIBP_API_KEY is not configured in .env.",
        }

    endpoint = (
        f"{HIBP_BASE_URL}/breachedaccount/{quote(email, safe='')}"
        "?truncateResponse=false&includeUnverified=true"
    )
    payload, http_error, other_error = _request_json(
        endpoint,
        headers={
            "hibp-api-key": api_key,
            "user-agent": user_agent,
        },
        timeout=timeout,
    )

    if http_error:
        if http_error.code == 404:
            return {"provider": "Have I Been Pwned", "status": "success", "breaches": [], "warning": None}
        if http_error.code == 429:
            retry_after = http_error.headers.get("retry-after", "unknown")
            return {
                "provider": "Have I Been Pwned",
                "status": "rate_limited",
                "breaches": [],
                "warning": f"HIBP rate limit reached; retry after {retry_after} second(s).",
            }
        if http_error.code in {401, 403}:
            return {
                "provider": "Have I Been Pwned",
                "status": "failed",
                "breaches": [],
                "warning": "HIBP rejected the API credentials or request permissions.",
            }
        return {
            "provider": "Have I Been Pwned",
            "status": "failed",
            "breaches": [],
            "warning": f"HIBP HTTP error {http_error.code}: {http_error.reason}",
        }
    if other_error:
        return {
            "provider": "Have I Been Pwned",
            "status": "failed",
            "breaches": [],
            "warning": f"HIBP lookup failed: {other_error}",
        }

    breaches: List[Dict[str, Any]] = []
    for item in payload if isinstance(payload, list) else []:
        if not isinstance(item, dict):
            continue
        data_classes = list(item.get("DataClasses") or [])
        breach = _normalised_breach(
            service=str(item.get("Title") or item.get("Name") or "Unknown breach"),
            breach_name=str(item.get("Name") or ""),
            domain=str(item.get("Domain") or ""),
            breach_date=str(item.get("BreachDate") or ""),
            exposed_data=data_classes,
            verified=bool(item.get("IsVerified")),
            source="Have I Been Pwned API v3",
            provider_name="Have I Been Pwned",
            description=str(item.get("Description") or ""),
        )
        breach.update({
            "added_date": item.get("AddedDate"),
            "modified_date": item.get("ModifiedDate"),
            "fabricated": bool(item.get("IsFabricated")),
            "sensitive": bool(item.get("IsSensitive")),
            "retired": bool(item.get("IsRetired")),
            "spam_list": bool(item.get("IsSpamList")),
        })
        breaches.append(breach)

    return {
        "provider": "Have I Been Pwned",
        "status": "success",
        "breaches": breaches,
        "warning": None,
    }


def _breach_merge_key(item: Dict[str, Any]) -> str:
    service = re.sub(
        r"[^a-z0-9]",
        "",
        str(item.get("service") or item.get("breach_name") or "").casefold(),
    )
    domain = re.sub(r"[^a-z0-9]", "", str(item.get("domain") or "").casefold())
    year_match = re.search(r"(?:19|20)\d{2}", str(item.get("breach_date") or ""))
    year = year_match.group(0) if year_match else ""
    identity = service or domain
    return f"{identity}:{year}" if identity else ""


def merge_breach_results(provider_results: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for provider_result in provider_results:
        for item in provider_result.get("breaches") or []:
            if not isinstance(item, dict):
                continue
            key = _breach_merge_key(item)
            if not key:
                key = uuid4().hex
            if key not in merged:
                merged[key] = json.loads(json.dumps(item))
                continue

            target = merged[key]
            target["provider_sources"] = list(dict.fromkeys(
                list(target.get("provider_sources") or [])
                + list(item.get("provider_sources") or [])
            ))
            target["exposed_data"] = list(dict.fromkeys(
                list(target.get("exposed_data") or [])
                + list(item.get("exposed_data") or [])
            ))
            target["exposure_score"] = max(
                int(target.get("exposure_score") or 0),
                int(item.get("exposure_score") or 0),
                breach_exposure_score(target["exposed_data"]),
            )
            target["recommended_security_actions"] = breach_actions(target["exposed_data"])
            if not target.get("description") and item.get("description"):
                target["description"] = item.get("description")
            if not target.get("domain") and item.get("domain"):
                target["domain"] = item.get("domain")
            if not target.get("breach_date") and item.get("breach_date"):
                target["breach_date"] = item.get("breach_date")
            if target.get("verified") is None and item.get("verified") is not None:
                target["verified"] = item.get("verified")

    return sorted(
        merged.values(),
        key=lambda item: (
            str(item.get("breach_date") or ""),
            str(item.get("service") or "").casefold(),
        ),
        reverse=True,
    )


def configured_provider_names() -> Tuple[List[str], List[str]]:
    warnings: List[str] = []
    raw = os.getenv("BREACH_PROVIDER", "xposedornot").strip().casefold()
    aliases = {
        "xon": "xposedornot",
        "xposed-or-not": "xposedornot",
        "xposedornot": "xposedornot",
        "hibp": "hibp",
        "haveibeenpwned": "hibp",
        "have_i_been_pwned": "hibp",
    }

    requested: List[str] = []
    tokens = re.split(r"[,;+\s]+", raw)
    if raw in {"both", "all"}:
        tokens = ["xposedornot", "hibp"]

    for token in tokens:
        if not token:
            continue
        mapped = aliases.get(token)
        if mapped and mapped not in requested:
            requested.append(mapped)
        elif not mapped:
            warnings.append(
                f"Unknown BREACH_PROVIDER value '{token}'. XposedOrNot was used instead."
            )

    if not requested:
        requested = ["xposedornot"]
    return requested, warnings


def run_breach_providers(email: str) -> Tuple[List[Dict[str, Any]], List[str], Dict[str, str]]:
    """Query independent breach providers concurrently.

    Provider order in the returned list remains stable even though network I/O
    is parallel, so existing report/merging behaviour is preserved.
    """
    providers, warnings = configured_provider_names()
    jobs: List[Tuple[str, Any]] = []

    for provider in providers:
        if provider == "xposedornot":
            jobs.append((provider, lambda: xposedornot_breach_lookup(email)))
        elif provider == "hibp":
            jobs.append((
                provider,
                lambda: hibp_breach_lookup(
                    email,
                    api_key=os.getenv("HIBP_API_KEY", "").strip(),
                    user_agent=os.getenv("HIBP_USER_AGENT", DEFAULT_USER_AGENT).strip()
                    or DEFAULT_USER_AGENT,
                ),
            ))

    if env_bool("ENABLE_LEAKCHECK", default=False):
        jobs.append(("leakcheck", lambda: leakcheck_public_lookup(email)))

    indexed: Dict[int, Dict[str, Any]] = {}
    if len(jobs) <= 1:
        for index, (_name, job) in enumerate(jobs):
            indexed[index] = job()
    else:
        with ThreadPoolExecutor(
            max_workers=min(3, len(jobs)),
            thread_name_prefix="phase2-breach",
        ) as executor:
            futures = {
                executor.submit(job): index
                for index, (_name, job) in enumerate(jobs)
            }
            for future in as_completed(futures):
                index = futures[future]
                name = jobs[index][0]
                try:
                    indexed[index] = future.result()
                except Exception as exc:
                    indexed[index] = {
                        "provider": name,
                        "status": "failed",
                        "warning": f"{type(exc).__name__}: {exc}",
                        "breaches": [],
                    }

    results = [indexed[index] for index in sorted(indexed)]
    statuses: Dict[str, str] = {}
    for result in results:
        provider_name = str(result.get("provider") or "Unknown provider")
        statuses[provider_name] = str(result.get("status") or "unknown")
        warning = result.get("warning")
        if warning:
            warnings.append(str(warning))

    return results, list(dict.fromkeys(warnings)), statuses


def iter_layer1_results(layer1_report: Optional[Dict[str, Any]]) -> Sequence[Dict[str, Any]]:
    if not layer1_report:
        return []
    if "analysis_report" in layer1_report:
        return list(layer1_report.get("analysis_report", {}).get("results", []))
    return list(layer1_report.get("results", []))


def enrich_broker_results(layer1_report: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    enriched: List[Dict[str, Any]] = []
    for result in iter_layer1_results(layer1_report):
        if result.get("source_category") != "Data broker/contact aggregator":
            continue
        domain = domain_of(str(result.get("url") or ""))
        registry = BROKER_REGISTRY.get(domain, {})
        enriched.append({
            "type": "data_broker_exposure",
            "provider": registry.get("provider") or domain or result.get("title"),
            "domain": domain,
            "record_url": result.get("url"),
            "identity_status": result.get("identity_status"),
            "identity_score": result.get("identity_score"),
            "privacy_exposure_status": result.get("privacy_exposure_status"),
            "visible_email_count": len(result.get("extracted_email_addresses") or []),
            "visible_phone_count": len(result.get("phone_candidates") or []),
            "contact_availability_advertised": "advertised" in str(
                result.get("privacy_exposure_status") or ""
            ).casefold(),
            "privacy_or_opt_out_url": registry.get("privacy_url", ""),
            "execution_mode": registry.get("execution_mode", "manual_research_required"),
            "contact_email": registry.get("contact_email", ""),
            "contact_source_url": registry.get("contact_source_url", ""),
            "removal_scope_note": registry.get("removal_scope_note", ""),
            "requires_identity_confirmation": result.get("identity_status") == "Possible",
            "requires_user_approval": True,
            "action_status": "not_started",
            "recommended_action": (
                "Confirm that the record belongs to the user before any request."
                if result.get("identity_status") == "Possible"
                else "Review and approve an opt-out or deletion request."
            ),
        })
    return enriched


def run_layer2(
    profile: Dict[str, Any],
    *,
    layer1_report: Optional[Dict[str, Any]] = None,
    consent_breach_lookup: bool = False,
    allow_network: bool = True,
    prefetched_breach_bundle: Optional[
        Tuple[List[Dict[str, Any]], List[str], Dict[str, str]]
    ] = None,
) -> Dict[str, Any]:
    warnings: List[str] = []
    errors: List[str] = []
    provider_results: List[Dict[str, Any]] = []
    provider_statuses: Dict[str, str] = {}

    if not consent_breach_lookup:
        breach_lookup_status = "skipped"
        warnings.append("The user did not approve the email-breach lookup.")
    elif not allow_network:
        breach_lookup_status = "skipped"
        warnings.append("Network access is disabled for Layer 2B.")
    else:
        if prefetched_breach_bundle is not None:
            provider_results, provider_warnings, provider_statuses = (
                prefetched_breach_bundle
            )
        else:
            provider_results, provider_warnings, provider_statuses = run_breach_providers(
                str(profile.get("email") or "")
            )
        warnings.extend(provider_warnings)

        statuses = list(provider_statuses.values())
        successful = sum(status == "success" for status in statuses)
        failed = sum(status in {"failed", "rate_limited"} for status in statuses)
        if successful and failed:
            breach_lookup_status = "partial_failure"
        elif successful:
            breach_lookup_status = "success"
        elif failed:
            breach_lookup_status = "failed"
        else:
            breach_lookup_status = "skipped"

    breaches = merge_breach_results(provider_results)
    broker_results = enrich_broker_results(layer1_report)

    status = "success"
    if breach_lookup_status in {"failed", "partial_failure"}:
        status = "partial_failure"

    report = {
        "artifact_type": "layer_report",
        "layer": LAYER,
        "version": VERSION,
        "run_id": uuid4().hex,
        "run_time": utc_now_iso(),
        "status": status,
        "input_profile": profile_for_report(profile),
        "consent": {
            "email_breach_lookup": consent_breach_lookup,
            "data_broker_enrichment": True,
        },
        "provider_configuration": {
            "breach_provider": os.getenv("BREACH_PROVIDER", "xposedornot").strip()
            or "xposedornot",
            "leakcheck_enabled": env_bool("ENABLE_LEAKCHECK", default=False),
            "pwned_password_check_enabled": env_bool(
                "ENABLE_PWNED_PASSWORD_CHECK", default=False
            ),
            "note": (
                "Password checking is intentionally not run by this email-only layer. "
                "It should be a separate local, non-persistent user-authorised action."
            ),
        },
        "summary": {
            "known_breach_count": len(breaches),
            "provider_evidence_count": sum(
                len(result.get("breaches") or []) for result in provider_results
            ),
            "successful_breach_provider_count": sum(
                status_value == "success" for status_value in provider_statuses.values()
            ),
            "broker_record_count": len(broker_results),
            "broker_records_requiring_confirmation": sum(
                bool(item.get("requires_identity_confirmation")) for item in broker_results
            ),
            "highest_breach_exposure_score": max(
                [int(item.get("exposure_score") or 0) for item in breaches] or [0]
            ),
        },
        "breach_lookup_status": breach_lookup_status,
        "breach_provider_statuses": provider_statuses,
        "breach_exposures": breaches,
        "data_broker_exposures": broker_results,
        "warnings": list(dict.fromkeys(warnings)),
        "errors": errors,
    }
    return report


def save_layer2_report(report: Dict[str, Any]) -> str:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.fromisoformat(report["run_time"]).strftime("%Y%m%d_%H%M%S_%f")
    path = OUTPUT_DIR / f"layer2B_{stamp}.json"
    latest = OUTPUT_DIR / "latest_layer2B.json"
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
    parser = argparse.ArgumentParser(description="Phase 2B breach and broker exposure analysis")
    parser.add_argument("--profile-json", help="JSON file containing the shared identity profile")
    parser.add_argument("--layer1-report", help="Phase 2A analysis JSON for broker enrichment")
    parser.add_argument("--approve-breach-check", action="store_true")
    parser.add_argument("--no-network", action="store_true")
    args = parser.parse_args()

    profile = load_json(Path(args.profile_json)) if args.profile_json else collect_profile()
    layer1 = load_json(Path(args.layer1_report)) if args.layer1_report else None
    report = run_layer2(
        profile,
        layer1_report=layer1,
        consent_breach_lookup=args.approve_breach_check,
        allow_network=not args.no_network,
    )
    save_layer2_report(report)
    print(json.dumps(report["summary"], indent=2))
    print("Provider statuses:", json.dumps(report.get("breach_provider_statuses", {}), indent=2))
    for warning in report.get("warnings", []):
        print("Warning:", warning)


if __name__ == "__main__":
    main()
