import json
import os
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

load_dotenv()

MODEL = "gpt-5.6-luna"

AGGREGATE_FILE = Path(
    "reports/aggregate/latest_aggregate_internal.json"
)


# ---------------------------------------------------------
# Load Phase 2 aggregate report
# ---------------------------------------------------------

def load_aggregate_report():
    if not AGGREGATE_FILE.exists():
        raise FileNotFoundError(
            f"Aggregate report not found: {AGGREGATE_FILE}"
        )

    with open(AGGREGATE_FILE, "r", encoding="utf-8") as file:
        return json.load(file)

def deterministic_risk_level(score):
    """
    Convert numeric risk score into a deterministic level.
    """

    if score is None:
        return "Low"

    if score >= 75:
        return "Critical"

    if score >= 50:
        return "High"

    if score >= 25:
        return "Medium"

    return "Low"

def validate_ai_analysis(result):
    """
    Apply deterministic safeguards to LLM output.
    """

    allowed_actions = {
        "retain",
        "review",
        "verify_identity",
        "update_or_redact",
        "broker_opt_out",
        "delete_account_or_content",
        "change_password",
        "enable_mfa",
        "revoke_permission",
        "clear_selected_local_data",
        "ignore"
    }

    analyses = result.get("analyses", [])

    for item in analyses:

        score = item.get("risk_score", 0)

        # Force score into valid range
        try:
            score = int(score)
        except (TypeError, ValueError):
            score = 0

        score = max(0, min(100, score))

        item["risk_score"] = score

        # Do not trust LLM risk label blindly
        item["risk_level"] = deterministic_risk_level(
            score
        )

        # Invalid action -> safe fallback
        if item.get("recommended_action") not in allowed_actions:
            item["recommended_action"] = "review"

        # Verification guardrail
        if item.get("needs_user_verification"):

            item["recommended_action"] = "verify_identity"

            if not item.get("verification_question"):
                item["verification_question"] = (
                    "Do you confirm that this finding belongs to you?"
                )

    return result
# ---------------------------------------------------------
# Helper
# ---------------------------------------------------------

def get_domain(url):
    if not url:
        return ""

    try:
        return urlparse(url).netloc
    except Exception:
        return ""


# ---------------------------------------------------------
# Convert Phase 2A results into safe compact findings
# ---------------------------------------------------------

def extract_phase2a_findings(report):
    findings = []

    layer = (
        report
        .get("layers", {})
        .get("phase_2A_public", {})
    )

    results = layer.get("results", [])

    for index, item in enumerate(results, start=1):

        url = (
            item.get("canonical_url")
            or item.get("resolved_url")
            or item.get("url")
            or ""
        )

        finding = {
            "finding_id": f"P2A-{index:03d}",
            "layer": "2A",
            "finding_type": "public_footprint",

            "title": item.get("title", ""),
            "domain": get_domain(url),

            "source_category": item.get(
                "source_category", ""
            ),

            "result_subtype": item.get(
                "result_subtype", ""
            ),

            "control_type": item.get(
                "control_type", ""
            ),

            "public_value": item.get(
                "public_value", ""
            ),

            "evidence_quality": item.get(
                "evidence_quality", ""
            ),

            "identity_status": item.get(
                "identity_status", ""
            ),

            "identity_score": item.get(
                "identity_score"
            ),

            "match_reasons": item.get(
                "match_reasons", []
            )[:4],

            "privacy_exposure_status": item.get(
                "privacy_exposure_status", ""
            ),

            "existing_risk_score": item.get(
                "risk_score"
            ),

            "existing_risk_level": item.get(
                "risk_level", ""
            ),

            "existing_recommendation": item.get(
                "recommendation_action", ""
            ),

            # Optional visual identity evidence is computed locally in Phase 2A.
            # The raw image and biometric embedding are intentionally excluded.
            "visual_identity": {
                "used": bool(
                    (item.get("visual_identity") or {}).get("status")
                    not in {None, "", "not_used", "no_candidate_images"}
                ),
                "face_match_found": bool(
                    (item.get("visual_identity") or {}).get("face_match_found")
                ),
                "match_strength": (
                    (item.get("visual_identity") or {}).get("match_strength") or ""
                ),
                "best_face_distance": (
                    (item.get("visual_identity") or {}).get("best_face_distance")
                ),
                "candidate_images_checked": int(
                    (item.get("visual_identity") or {}).get(
                        "candidate_images_checked", 0
                    ) or 0
                ),
                "candidate_faces_checked": int(
                    (item.get("visual_identity") or {}).get(
                        "candidate_faces_checked", 0
                    ) or 0
                ),
                "distance_metric": (
                    (item.get("visual_identity") or {}).get("distance_metric") or ""
                ),
                "manual_verification_status": (
                    (item.get("visual_identity") or {}).get(
                        "manual_verification_status", "unreviewed"
                    )
                ),
                "manual_confirmed_image_count": int(
                    (item.get("visual_identity") or {}).get(
                        "manual_confirmed_image_count", 0
                    ) or 0
                ),
            },
        }

        if finding["visual_identity"]["manual_verification_status"] == "confirmed":
            finding["association_basis"] = "user_confirmed_public_image"
            finding["requires_identity_confirmation"] = False


        findings.append(finding)

    # A manually confirmed fetched image may reveal the subject even when the
    # page failed the ordinary text-identity filter. Preserve that as a
    # separate visual public-footprint finding rather than discarding it.
    retained_urls = {
        str(
            item.get("canonical_url")
            or item.get("resolved_url")
            or item.get("url")
            or ""
        )
        for item in results
    }

    grouped_manual = {}
    for review in layer.get("visual_review_items", []) or []:
        if review.get("manual_verification") != "confirmed":
            continue
        page_url = str(review.get("page_url") or "")
        if not page_url or page_url in retained_urls:
            continue
        grouped_manual.setdefault(page_url, []).append(review)

    for index, (page_url, reviews) in enumerate(
        grouped_manual.items(), start=1
    ):
        distances = [
            item.get("automated_best_face_distance")
            for item in reviews
            if item.get("automated_best_face_distance") is not None
        ]
        findings.append({
            "finding_id": f"P2A-VISUAL-{index:03d}",
            "layer": "2A",
            "finding_type": "visual_public_footprint",
            "title": reviews[0].get("page_title", "Public image result"),
            "domain": get_domain(page_url),
            "source_category": reviews[0].get(
                "source_category", "Visual public footprint"
            ),
            "identity_status": "User-confirmed visual association",
            "identity_score": None,
            "association_basis": "user_confirmed_public_image",
            "requires_identity_confirmation": False,
            "manual_visual_verification": "confirmed",
            "confirmed_image_count": len(reviews),
            "discovery_method": reviews[0].get(
                "discovery_method", "page_image_extraction"
            ),
            "discovery_queries": list(dict.fromkeys(
                query
                for item in reviews
                for query in (item.get("discovery_queries") or [])
                if query
            ))[:4],
            "image_description": reviews[0].get("image_description", ""),
            "visual_identity": {
                "used": True,
                "face_match_found": any(
                    str(item.get("automated_match_strength") or "").casefold()
                    in {"strong", "possible"}
                    for item in reviews
                ),
                "match_strength": max(
                    (
                        str(item.get("automated_match_strength") or "No match")
                        for item in reviews
                    ),
                    key=lambda value: {
                        "strong": 3, "possible": 2, "no match": 1,
                        "unavailable": 0
                    }.get(value.casefold(), 0),
                    default="No match",
                ),
                "best_face_distance": min(distances) if distances else None,
                "candidate_images_checked": len(reviews),
                "candidate_faces_checked": sum(
                    int(item.get("faces_detected", 0) or 0)
                    for item in reviews
                ),
                "distance_metric": "euclidean_dlib_128d",
                "manual_verification_status": "confirmed",
                "manual_confirmed_image_count": len(reviews),
            },
        })

    return findings


# ---------------------------------------------------------
# Convert Phase 2B results
# ---------------------------------------------------------

def extract_phase2b_findings(report):
    findings = []

    layer = (
        report
        .get("layers", {})
        .get("phase_2B_breach_and_broker", {})
    )

    # -------------------------
    # Breaches
    # -------------------------

    breaches = layer.get("breach_exposures", [])

    for index, item in enumerate(breaches, start=1):

        finding = {
            "finding_id": f"P2B-BREACH-{index:03d}",
            "layer": "2B",
            "finding_type": "breach_exposure",

            "service": (
                item.get("service")
                or item.get("breach_name")
                or ""
            ),

            "domain": item.get("domain", ""),

            "breach_date": item.get(
                "breach_date", ""
            ),

            # Breach records are returned by an explicitly authorised
            # lookup of the supplied email address. They are therefore not
            # name-attribution candidates and must not be sent to the user
            # for Yes/No/Unsure identity ownership confirmation.
            "association_basis": "authorised_exact_email_lookup",
            "requires_identity_confirmation": False,

            # This is provider-level breach verification, NOT user ownership
            # verification. True/False/None are preserved exactly.
            "verified": item.get("verified"),

            "exposed_data": item.get(
                "exposed_data", []
            ),

            "exposure_score": item.get(
                "exposure_score"
            ),

            "password_risk": item.get(
                "password_risk", ""
            ),

            "provider_sources": item.get(
                "provider_sources", []
            )
        }

        findings.append(finding)

    # -------------------------
    # Data brokers
    # -------------------------

    brokers = layer.get(
        "data_broker_exposures", []
    )

    for index, item in enumerate(brokers, start=1):

        finding = {
            "finding_id": f"P2B-BROKER-{index:03d}",
            "layer": "2B",
            "finding_type": "data_broker_exposure",

            "provider": item.get(
                "provider", ""
            ),

            "domain": item.get(
                "domain", ""
            ),

            "identity_status": item.get(
                "identity_status", ""
            ),

            "identity_score": item.get(
                "identity_score"
            ),

            "privacy_exposure_status": item.get(
                "privacy_exposure_status", ""
            ),

            "visible_email_count": item.get(
                "visible_email_count", 0
            ),

            "visible_phone_count": item.get(
                "visible_phone_count", 0
            ),

            "requires_identity_confirmation":
                item.get(
                    "requires_identity_confirmation",
                    False
                )
        }

        findings.append(finding)

    return findings


# ---------------------------------------------------------
# Convert Phase 2C results
# ---------------------------------------------------------

def extract_phase2c_findings(report):
    findings = []

    layer = (
        report
        .get("layers", {})
        .get("phase_2C_local_passive", {})
    )

    browser_profiles = layer.get(
        "browser_profiles", []
    )

    for index, profile in enumerate(
        browser_profiles,
        start=1
    ):

        summary = profile.get("summary", {})

        # IMPORTANT:
        # We intentionally do NOT include:
        # - profile_path
        # - history domains
        # - cookie values
        # - full URLs

        tracker_domains = []

        for tracker in profile.get(
            "potential_tracker_domains", []
        )[:15]:
            tracker_domains.append({
                "domain": tracker.get(
                    "domain", ""
                ),
                "cookie_count": tracker.get(
                    "cookie_count", 0
                ),
                "classification": tracker.get(
                    "classification", ""
                )
            })

        risky_permissions = []

        for permission in profile.get(
            "risky_permissions", []
        ):
            risky_permissions.append({
                "origin": permission.get(
                    "origin", ""
                ),
                "permission": permission.get(
                    "permission", ""
                ),
                "setting": permission.get(
                    "setting", ""
                )
            })

        finding = {
            "finding_id": f"P2C-{index:03d}",
            "layer": "2C",
            "finding_type": "local_browser_metadata",

            "browser": profile.get(
                "browser", ""
            ),

            "profile_name": profile.get(
                "profile_name", ""
            ),

            "collection_status": profile.get(
                "collection_status", {}
            ),

            "cookie_count": summary.get(
                "cookie_count", 0
            ),

            "persistent_cookie_count":
                summary.get(
                    "persistent_cookie_count",
                    0
                ),

            "potential_tracker_cookie_count":
                summary.get(
                    "potential_tracker_cookie_count",
                    0
                ),

            "risky_permission_count":
                summary.get(
                    "risky_allowed_permission_count",
                    0
                ),

            "existing_risk_score":
                summary.get("risk_score"),

            "existing_risk_level":
                summary.get("risk_level", ""),

            "tracker_domains":
                tracker_domains,

            "risky_permissions":
                risky_permissions
        }

        findings.append(finding)

    return findings


# ---------------------------------------------------------
# Build privacy-safe AI input
# ---------------------------------------------------------

def build_compact_ai_input(report):

    findings = []

    findings.extend(
        extract_phase2a_findings(report)
    )

    findings.extend(
        extract_phase2b_findings(report)
    )

    findings.extend(
        extract_phase2c_findings(report)
    )

    profile = report.get(
        "input_profile", {}
    )

    compact_input = {

        # Only identity context needed for interpretation.
        # Raw email and phone are deliberately excluded.

        "subject": {
            "full_name": profile.get(
                "full_name", ""
            ),

            "username": profile.get(
                "username", ""
            ),

            "context_terms": profile.get(
                "context_terms", []
            )
        },

        "cross_layer_summary": report.get(
            "cross_layer_summary", {}
        ),

        "findings": findings
    }

    return compact_input


# ---------------------------------------------------------
# Temporary validation
# ---------------------------------------------------------

def main():

    print(
        "=== Phase 3 AI Analyzer - Input Preparation ==="
    )

    report = load_aggregate_report()

    compact_input = build_compact_ai_input(
        report
    )

    print(
        f"Prepared "
        f"{len(compact_input['findings'])} "
        f"findings for AI analysis."
    )

    print()

    print("Privacy check:")
    print("- Raw email excluded")
    print("- Raw phone excluded")
    print("- Browser profile paths excluded")
    print("- Browsing history excluded")
    print("- Cookie values excluded")

    print()

    print("Phase 3 compact input created successfully.")


if __name__ == "__main__":
    main()
