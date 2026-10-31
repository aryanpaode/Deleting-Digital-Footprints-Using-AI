"""Run Phase 2A, 2B, and 2C with one shared identity profile."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import uuid4

import phase2A_public as layer2a
import phase2B_exposure as layer2b
import phase2C_passive as layer2c

REPORTS_DIR = layer2a.REPORTS_DIR
AGGREGATE_DIR = REPORTS_DIR / "aggregate"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def mask_email(email: str) -> str:
    value = (email or "").strip()
    if "@" not in value:
        return ""
    local, domain = value.split("@", 1)
    return f"{local[:1] or '*'}{'*' * max(3, len(local) - 1)}@{domain}"


def mask_phone(phone: str) -> str:
    digits = re.sub(r"\D", "", phone or "")
    return "" if not digits else "*" * max(0, len(digits) - 4) + digits[-4:]


def shareable_profile(profile: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "full_name": profile.get("full_name", ""),
        "email_masked": mask_email(str(profile.get("email") or "")),
        "username": profile.get("username", ""),
        "phone_masked": mask_phone(str(profile.get("phone") or "")),
        "context_terms": list(profile.get("context_terms") or []),
    }


def ask_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    answer = input(prompt + suffix).strip().casefold()
    if not answer:
        return default
    return answer in {"y", "yes"}


def failed_layer(name: str, exc: Exception) -> Dict[str, Any]:
    return {
        "layer": name,
        "status": "failed",
        "summary": {},
        "warnings": [],
        "errors": [f"{type(exc).__name__}: {exc}"],
    }


def run_all(
    profile: Dict[str, Any],
    *,
    allow_network: bool = True,
    consent_breach_lookup: bool = False,
    consent_local_audit: bool = False,
    consent_visual_search: bool = False,
    reference_image_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Run Phase 2 with overlap between independent I/O-heavy layers.

    Phase 2A remains the dependency for broker enrichment.  However, the local
    passive audit (2C) and the email-only breach provider calls do not depend on
    2A, so they start immediately in background threads.  Phase 2B is assembled
    after 2A completes using the already-fetched breach bundle.
    """
    total_started = time.perf_counter()
    timings: Dict[str, float] = {}

    breach_future = None
    local_future = None

    def run_local_layer() -> Dict[str, Any]:
        started = time.perf_counter()
        try:
            result = layer2c.run_layer3(
                profile,
                consent_local_audit=consent_local_audit,
            )
            layer2c.save_layer3_report(result)
            return result
        except Exception as exc:
            return failed_layer("2C_local_passive_footprints", exc)
        finally:
            timings["phase_2C_seconds"] = round(time.perf_counter() - started, 3)

    def run_breach_bundle():
        started = time.perf_counter()
        try:
            if not consent_breach_lookup or not allow_network:
                return None
            return layer2b.run_breach_providers(str(profile.get("email") or ""))
        finally:
            timings["phase_2B_breach_network_seconds"] = round(
                time.perf_counter() - started, 3
            )

    # 2C and authorised breach API calls begin while 2A performs public/visual
    # discovery. Only two background workers are used; the lower-level
    # connectors have their own conservative worker limits.
    with ThreadPoolExecutor(
        max_workers=2,
        thread_name_prefix="phase2-layer",
    ) as layer_executor:
        local_future = layer_executor.submit(run_local_layer)
        if consent_breach_lookup and allow_network:
            breach_future = layer_executor.submit(run_breach_bundle)

        phase2a_started = time.perf_counter()
        try:
            result_2a = layer2a.run_layer1(
                profile,
                allow_network=allow_network,
                save_outputs=True,
                consent_visual_search=consent_visual_search,
                reference_image_path=reference_image_path,
            )
            compact_2a = layer2a.compact_layer1_for_aggregation(result_2a)
            layer1_report = result_2a.get("analysis_report", {})
        except Exception as exc:
            result_2a = failed_layer("2A_public_footprints", exc)
            compact_2a = result_2a
            layer1_report = None
        finally:
            timings["phase_2A_seconds"] = round(
                time.perf_counter() - phase2a_started, 3
            )

        prefetched_breach_bundle = None
        if breach_future is not None:
            try:
                prefetched_breach_bundle = breach_future.result()
            except Exception:
                # Let run_layer2 execute its normal provider path if the
                # prefetch worker unexpectedly failed.
                prefetched_breach_bundle = None

        phase2b_started = time.perf_counter()
        try:
            result_2b = layer2b.run_layer2(
                profile,
                layer1_report=layer1_report,
                consent_breach_lookup=consent_breach_lookup,
                allow_network=allow_network,
                prefetched_breach_bundle=prefetched_breach_bundle,
            )
            layer2b.save_layer2_report(result_2b)
        except Exception as exc:
            result_2b = failed_layer("2B_breach_and_broker", exc)
        finally:
            timings["phase_2B_assembly_seconds"] = round(
                time.perf_counter() - phase2b_started, 3
            )

        try:
            result_2c = local_future.result()
        except Exception as exc:
            result_2c = failed_layer("2C_local_passive_footprints", exc)

    layer1_summary = compact_2a.get("summary", {})
    layer2_summary = result_2b.get("summary", {})
    layer3_summary = result_2c.get("summary", {})
    timings["phase_2_total_seconds"] = round(time.perf_counter() - total_started, 3)

    return {
        "artifact_type": "aggregated_footprint_report",
        "version": 1,
        "run_id": uuid4().hex,
        "run_time": utc_now_iso(),
        "input_profile": profile,
        "consent": {
            "public_footprint_search": True,
            "email_breach_lookup": consent_breach_lookup,
            "local_browser_audit": consent_local_audit,
            "visual_identity_search": consent_visual_search,
        },
        "collection_status": {
            "phase_2A": compact_2a.get("status", "unknown"),
            "phase_2B": result_2b.get("status", "unknown"),
            "phase_2C": result_2c.get("status", "unknown"),
        },
        "performance_metrics": timings,
        "cross_layer_summary": {
            "public_candidates": layer1_summary.get("candidate_results", 0),
            "public_retained_matches": layer1_summary.get("retained_matches", 0),
            "public_possible_matches": layer1_summary.get("possible_matches", 0),
            "visual_search_status": layer1_summary.get("visual_search_status", "not_used"),
            "visual_matches": layer1_summary.get("visual_match_count", 0),
            "visual_images_checked": layer1_summary.get("visual_candidate_images_checked", 0),
            "visual_faces_checked": layer1_summary.get("visual_candidate_faces_checked", 0),
            "visual_independent_queries": layer1_summary.get("visual_independent_query_count", 0),
            "visual_independent_images_discovered": layer1_summary.get("visual_independent_images_discovered", 0),
            "visual_independent_images_checked": layer1_summary.get("visual_independent_images_checked", 0),
            "visual_independent_faces_checked": layer1_summary.get("visual_independent_faces_checked", 0),
            "visual_independent_matches": layer1_summary.get("visual_independent_matches", 0),
            "known_breaches": layer2_summary.get("known_breach_count", 0),
            "broker_records": layer2_summary.get("broker_record_count", 0),
            "browser_profiles": layer3_summary.get("browser_profile_count", 0),
            "persistent_cookies": layer3_summary.get("persistent_cookie_count", 0),
            "potential_tracker_cookies": layer3_summary.get("potential_tracker_cookie_count", 0),
            "risky_permissions": layer3_summary.get("risky_allowed_permission_count", 0),
        },
        "layers": {
            "phase_2A_public": compact_2a,
            "phase_2B_breach_and_broker": result_2b,
            "phase_2C_local_passive": result_2c,
        },
        "next_stage": {
            "phase": 3,
            "purpose": "AI classification, cross-layer correlation, uncertainty handling, risk assessment, and user-authorised action planning.",
        },
    }


def make_shareable(report: Dict[str, Any]) -> Dict[str, Any]:
    copied = json.loads(json.dumps(report))
    copied["input_profile"] = shareable_profile(report.get("input_profile", {}))

    # Local visual-review cache paths are machine-specific and should never
    # appear in the shareable aggregate. Public source URLs and safe dlib
    # metadata may remain, but the cached local copies stay internal only.
    phase2a = (
        copied
        .get("layers", {})
        .get("phase_2A_public", {})
    )
    for item in phase2a.get("visual_review_items", []) or []:
        item.pop("cache_file", None)
    for result in phase2a.get("results", []) or []:
        visual_meta = result.get("visual_identity") or {}
        for image in visual_meta.get("image_evidence", []) or []:
            image.pop("cache_file", None)

    return copied


def save_aggregate(report: Dict[str, Any]) -> Dict[str, str]:
    AGGREGATE_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.fromisoformat(report["run_time"]).strftime("%Y%m%d_%H%M%S_%f")
    internal_path = AGGREGATE_DIR / f"aggregate_internal_{stamp}.json"
    shareable_path = AGGREGATE_DIR / f"aggregate_shareable_{stamp}.json"
    latest_internal = AGGREGATE_DIR / "latest_aggregate_internal.json"
    latest_shareable = AGGREGATE_DIR / "latest_aggregate_shareable.json"

    files = {
        "internal_report": str(internal_path),
        "shareable_report": str(shareable_path),
        "latest_internal": str(latest_internal),
        "latest_shareable": str(latest_shareable),
    }
    report["saved_files"] = files
    shareable = make_shareable(report)
    shareable["saved_files"] = files

    write_json(internal_path, report)
    write_json(latest_internal, report)
    write_json(shareable_path, shareable)
    write_json(latest_shareable, shareable)
    return files


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Phase 2A, 2B and 2C using one identity profile")
    parser.add_argument("--cache-only", action="store_true", help="Do not make web/API requests")
    parser.add_argument("--approve-breach-check", action="store_true")
    parser.add_argument("--approve-local-audit", action="store_true")
    parser.add_argument("--approve-visual-search", action="store_true")
    parser.add_argument("--reference-image", help="Optional local reference image for visual matching")
    parser.add_argument("--non-interactive", action="store_true")
    args = parser.parse_args()

    print("=== Aggregated Digital-Footprint Collection — Phase 2A/2B/2C ===")
    profile = layer2a.prompt_profile()

    breach_consent = args.approve_breach_check
    browser_consent = args.approve_local_audit
    if not args.non_interactive:
        if not breach_consent:
            breach_consent = ask_yes_no(
                "Authorise a breach lookup for the supplied email?",
                default=False,
            )
        if not browser_consent:
            print("For the best local audit result, close Chrome/Edge before continuing.")
            browser_consent = ask_yes_no(
                "Authorise a local metadata-only browser audit?",
                default=False,
            )

    report = run_all(
        profile,
        allow_network=not args.cache_only,
        consent_breach_lookup=breach_consent,
        consent_local_audit=browser_consent,
        consent_visual_search=args.approve_visual_search,
        reference_image_path=args.reference_image,
    )
    files = save_aggregate(report)

    print("\n=== Cross-Layer Summary ===")
    for key, value in report.get("cross_layer_summary", {}).items():
        print(f"{key.replace('_', ' ').title()}: {value}")
    print("\nSaved files:")
    for label, path in files.items():
        print(f"- {label.replace('_', ' ').title()}: {path}")

    failures = {
        key: value for key, value in report.get("collection_status", {}).items()
        if value in {"failed", "partial_failure"}
    }
    if failures:
        print("\nSome layers were incomplete:", failures)


if __name__ == "__main__":
    main()
