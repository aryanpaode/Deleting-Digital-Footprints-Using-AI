import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import hashlib
import html
import json
import re
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import unquote, urlsplit
from uuid import uuid4

import phase2_core_v4 as core
import visual_identity as visual


PHASE = "2A"
VERSION = 1

REPORTS_DIR = Path(
    core.os.getenv("REPORTS_DIR", "reports").strip() or "reports"
)
RAW_SCANS_DIR = REPORTS_DIR / "raw_scans"
ANALYSIS_DIR = REPORTS_DIR / "analysis"
EXPORTS_DIR = REPORTS_DIR / "exports"

CACHE_SPECIALIZED_CONNECTORS = (
    core.os.getenv("CACHE_SPECIALIZED_CONNECTORS", "true")
    .strip()
    .lower()
    == "true"
)

PHASE2_CONNECTOR_WORKERS = max(
    1,
    min(int(core.os.getenv("PHASE2_CONNECTOR_WORKERS", "4")), 4),
)

TARGETED_PROFILE_WORKERS = max(
    1,
    min(int(core.os.getenv("TARGETED_PROFILE_WORKERS", "4")), 6),
)

TARGETED_PROFILE_RESULTS_PER_QUERY = max(
    1,
    min(int(core.os.getenv("TARGETED_PROFILE_RESULTS_PER_QUERY", "4")), 6),
)

BROAD_WEB_QUERY_WORKERS = max(
    1,
    min(int(core.os.getenv("BROAD_WEB_QUERY_WORKERS", "2")), 3),
)

DATA_BROKER_DOMAINS = {
    "apollo.io",
    "beenverified.com",
    "contactout.com",
    "crunchbase.com",
    "hunter.io",
    "lusha.com",
    "peoplefinder.com",
    "peoplefinders.com",
    "peekyou.com",
    "pipl.com",
    "rocketreach.co",
    "seamless.ai",
    "signalhire.com",
    "spokeo.com",
    "thatsthem.com",
    "tofler.in",
    "truepeoplesearch.com",
    "whitepages.com",
    "zoominfo.com",
}

ACADEMIC_PROFILE_DOMAINS = {
    "academia.edu",
    "orcid.org",
    "researchgate.net",
    "scholar.google.com",
}

ACADEMIC_PUBLICATION_DOMAINS = {
    "acm.org",
    "arxiv.org",
    "doi.org",
    "ieee.org",
    "ieeexplore.ieee.org",
    "researchgate.net",
    "sciencedirect.com",
    "springer.com",
    "springerlink.com",
}

DEVELOPER_PROFILE_DOMAINS = {
    "github.com",
    "gitlab.com",
    "kaggle.com",
    "stackoverflow.com",
}

PROFESSIONAL_PROFILE_DOMAINS = {
    "linkedin.com",
    "wellfound.com",
    "xing.com",
}

SOCIAL_PROFILE_DOMAINS = {
    "facebook.com",
    "instagram.com",
    "threads.net",
    "tiktok.com",
    "twitter.com",
    "x.com",
}

NEWS_OR_INDUSTRY_DOMAINS = {
    "business-standard.com",
    "constructionworld.in",
    "economictimes.com",
    "financialexpress.com",
    "forbes.com",
    "indiatimes.com",
    "livemint.com",
    "moneycontrol.com",
    "nbmcw.com",
    "thehindu.com",
    "timesofindia.com",
}

DIRECTORY_PATH_MARKERS = (
    "/pub/dir/",
    "/directory/",
    "/people/",
    "/search/",
)

GENERIC_ORG_TERMS = {
    "bank",
    "company",
    "corporation",
    "finance",
    "financial services",
    "india",
    "institute",
    "limited",
    "ltd",
    "school",
    "university",
}

JOB_TITLE_PATTERNS = {
    "chief executive officer": r"\bchief executive officer\b|\bceo\b",
    "vice president": r"\b(?:senior|sr\.?)?\s*vice[- ]president\b|\bvp\b",
    "business head": r"\bbusiness head\b",
    "national sales head": r"\bnational sales head\b",
    "student": r"\bstudent\b",
    "researcher": r"\bresearcher\b",
    "founder": r"\bfounder\b",
    "director": r"\bdirector\b",
    "manager": r"\bmanager\b",
    "engineer": r"\bengineer\b",
}

ORG_SUFFIX_PATTERN = (
    r"(?:"
    r"bank|college|company|corporation|fincorp|finance|financial services|"
    r"group|institute|laborator(?:y|ies)|labs?|limited|ltd\.?|"
    r"school|systems|technologies|technology|university"
    r")"
)

ORG_PATTERN = re.compile(
    rf"\b(?:[A-Z][A-Za-z0-9&'.\-]*\s+){{0,6}}"
    rf"{ORG_SUFFIX_PATTERN}"
    rf"(?:\s+[A-Z][A-Za-z0-9&'.\-]*){{0,3}}\b",
    re.IGNORECASE,
)

ORG_FALSE_POSITIVE_PATTERN = re.compile(
    r"\b(?:bachelor(?:'s)?|master(?:'s)?|b\.?\s*tech|m\.?\s*tech|btech|mtech|"
    r"b\.e\.?|m\.e\.?|b\.sc\.?|m\.sc\.?|mba|ph\.?d\.?|undergraduate|"
    r"postgraduate|degree|programme?|program|course)\b",
    re.IGNORECASE,
)

ORG_CANONICAL_ALIASES = (
    (re.compile(r"\b(?:svkm['’]s\s+)?narsee\s+monjee\s+institute\s+of\s+management\s+studies\b|\bnmims\b", re.I), "NMIMS"),
    (re.compile(r"\bmukesh\s+patel\s+school\s+of\s+technology\s+management\s*(?:&|and)\s*engineering\b|\bmpstme\b", re.I), "MPSTME"),
)

OBFUSCATED_EMAIL_PATTERN = re.compile(
    r"\b([a-zA-Z0-9._%+\-]+)\s*"
    r"(?:\[at\]|\(at\)|\sat\s)\s*"
    r"([a-zA-Z0-9.\-]+)\s*"
    r"(?:\[dot\]|\(dot\)|\sdot\s)\s*"
    r"([a-zA-Z]{2,})\b",
    re.IGNORECASE,
)

FREE_EMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
    "live.com", "yahoo.com", "icloud.com", "proton.me",
    "protonmail.com", "rediffmail.com", "aol.com",
}

WEAK_CONTEXT_TERMS = {
    "computer", "engineer", "engineering", "student", "professor",
    "researcher", "university", "college", "school", "technology",
    "india", "mumbai", "director", "manager", "finance",
}

IDENTIFIER_LABEL_PATTERN = re.compile(
    r"\b(?:doi|isbn|issn|din|pan|cin|llpin|document|article|"
    r"vidwan\s*id|researcher\s*id)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def domain_of(url: str) -> str:
    try:
        domain = urlsplit(url or "").netloc.casefold()
    except ValueError:
        return ""

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def path_of(url: str) -> str:
    try:
        return unquote(urlsplit(url or "").path).casefold()
    except ValueError:
        return ""


def domain_matches(domain: str, candidates: Iterable[str]) -> bool:
    return any(
        domain == candidate or domain.endswith("." + candidate)
        for candidate in candidates
    )


def normalized_alnum(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (value or "").casefold())


def identity_tokens(value: Any) -> List[str]:
    """Return decoded lowercase alphanumeric identity tokens."""
    text = html.unescape(str(value or ""))
    text = unquote(text)
    text = unicodedata.normalize("NFKC", text).casefold()
    return re.findall(r"[a-z0-9]+", text)


def identity_windows(value: Any, max_parts: int = 6) -> Set[str]:
    """Build exact canonical tokens and adjacent-token combinations.

    This treats ``rohan malhotra``, ``rohan-malhotra``,
    ``rohan.malhotra``, ``rohan_malhotra`` and ``rohanmalhotra`` as the
    same identity while refusing fuzzy spellings and suffixed usernames
    such as ``rohanmalhotra123``.
    """
    tokens = identity_tokens(value)
    windows: Set[str] = set(tokens)

    upper = min(max_parts, len(tokens))
    for size in range(2, upper + 1):
        for start in range(0, len(tokens) - size + 1):
            windows.add("".join(tokens[start:start + size]))

    return windows


def contains_separator_normalized_identity(
    value: Any,
    target: str,
) -> bool:
    """Return True for an exact identity after separator normalisation."""
    canonical_target = normalized_alnum(target)
    if not canonical_target:
        return False
    return canonical_target in identity_windows(value)


def contains_middle_name_variant(
    value: Any,
    target: str,
    max_extra_middle_tokens: int = 2,
) -> bool:
    """Detect an expanded legal-name variant without fuzzy matching.

    Example:
        target: ``Rohan Malhotra``
        candidate: ``Rohan Dev Malhotra``

    The first and last name must match exactly and the candidate may contain
    only one or two additional tokens between them. Exact-name matches are
    handled by the normal identity logic, so this helper returns False for an
    unchanged two-token name.
    """
    target_tokens = identity_tokens(target)
    if len(target_tokens) < 2:
        return False

    first_name = target_tokens[0]
    last_name = target_tokens[-1]
    candidate_tokens = identity_tokens(value)

    for start, token in enumerate(candidate_tokens):
        if token != first_name:
            continue

        for extra_count in range(1, max_extra_middle_tokens + 1):
            last_index = start + 1 + extra_count
            if last_index >= len(candidate_tokens):
                break
            if candidate_tokens[last_index] != last_name:
                continue

            middle_tokens = candidate_tokens[start + 1:last_index]
            if all(
                middle.isalnum() and 1 <= len(middle) <= 40
                for middle in middle_tokens
            ):
                return True

    return False


def contains_explicit_username(
    text: str,
    url: str,
    username: str,
) -> bool:
    """Match a username only in handle-like evidence.

    Ordinary prose such as ``Kiran Shah`` must not independently
    count as the username ``kiranshah``. Accepted evidence includes
    URL path/query segments, @handles, and compact handle-like tokens.
    Email addresses are removed before token matching so their local part
    does not become a second independent identity signal.
    """
    target = normalized_alnum(username)
    if not target:
        return False

    decoded_url = unquote(url or "")
    for segment in re.split(r"[/?#&=]+", decoded_url):
        if normalized_alnum(segment) == target:
            return True

    clean_text = html.unescape(text or "")
    clean_text = re.sub(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        " ",
        clean_text,
    )

    for handle in re.findall(r"(?<![A-Za-z0-9])@[A-Za-z0-9._\-]+", clean_text):
        if normalized_alnum(handle[1:]) == target:
            return True

    for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9._\-]*", clean_text):
        if normalized_alnum(token) != target:
            continue
        # A compact token or separator-bearing token is handle-like.
        if token.casefold() == target or any(ch in token for ch in "._-"):
            return True

    return False


def split_context_hits(
    text: str,
    context_terms: Sequence[str],
) -> Tuple[List[str], List[str]]:
    strong: List[str] = []
    weak: List[str] = []
    for term in context_terms:
        if not core.contains_exact_phrase(text, term):
            continue
        normalized = normalized_entity(term)
        if normalized in WEAK_CONTEXT_TERMS or (
            len(normalized.split()) == 1 and len(normalized) < 6
        ):
            weak.append(term)
        else:
            strong.append(term)
    return strong, weak


def email_domain(email: str) -> str:
    value = (email or "").strip().casefold()
    return value.rsplit("@", 1)[1] if "@" in value else ""


def is_institutional_email(email: str) -> bool:
    domain = email_domain(email)
    return bool(domain and domain not in FREE_EMAIL_DOMAINS)


def is_official_email_domain(url: str, email: str) -> bool:
    domain = domain_of(url)
    mail_domain = email_domain(email)
    return bool(
        domain and mail_domain and
        (domain == mail_domain or domain.endswith("." + mail_domain))
    )


def is_likely_non_phone_identifier(value: str, excerpt: str) -> bool:
    digits = re.sub(r"\D", "", value or "")
    text = html.unescape(excerpt or "")
    if not digits:
        return False
    if IDENTIFIER_LABEL_PATTERN.search(text):
        return True
    if re.search(rf"10\.\d{{4,9}}/[^\s]*{re.escape(digits)}", text, re.I):
        return True
    if re.search(rf"[A-Za-z]{{1,6}}\d*{re.escape(digits)}[A-Za-z0-9]*", text):
        return True
    return False


def youtube_owned_text(result: Dict[str, Any]) -> str:
    """Return evidence belonging to the YouTube result itself.

    ``channel_title`` is deliberately excluded. A generic video must not
    become an identity match merely because its channel has the same name
    as the searched person.
    """
    return " ".join(
        str(result.get(field) or "")
        for field in ("title", "snippet", "url", "extracted_content")
    )


def is_youtube_result(result: Dict[str, Any]) -> bool:
    source = str(result.get("source") or "").casefold()
    url = str(result.get("url") or "").casefold()
    return (
        source == "youtube"
        or "youtube.com/" in url
        or "youtu.be/" in url
    )


def youtube_channel_key(result: Dict[str, Any]) -> str:
    """Return a stable channel key, falling back to display name."""
    channel_id = normalized_alnum(str(result.get("channel_id") or ""))
    if channel_id:
        return "id:" + channel_id

    source_type = str(result.get("source_type") or "").casefold()
    channel_title = str(result.get("channel_title") or "")
    if not channel_title and source_type == "channel":
        channel_title = str(result.get("title") or "")

    title_key = normalized_alnum(channel_title)
    return "title:" + title_key if title_key else ""


def normalized_entity(value: str) -> str:
    value = core.normalize_spaces(value).casefold()
    value = re.sub(r"\b(?:pvt|private)\b", "", value)
    value = re.sub(r"\b(?:ltd|limited)\b\.?", "", value)
    value = re.sub(r"[^a-z0-9&]+", " ", value)
    return core.normalize_spaces(value)


def title_contains_profile_directory(title: str) -> bool:
    return bool(
        re.search(
            r"\b\d+\+?\s+[\"“]?[a-z0-9 .'\-]+[\"”]?\s+profiles?\b",
            title or "",
            re.IGNORECASE,
        )
    )


def is_directory_page(result: Dict[str, Any]) -> bool:
    path = path_of(str(result.get("url") or ""))
    title = str(result.get("title") or "")

    return (
        any(marker in path for marker in DIRECTORY_PATH_MARKERS)
        or title_contains_profile_directory(title)
    )


def name_slug_match(url: str, full_name: str) -> bool:
    target = normalized_alnum(full_name)
    if not target:
        return False

    path = path_of(url)
    segments = [segment for segment in path.split("/") if segment]

    for segment in segments:
        compact = normalized_alnum(segment)
        if target and target in compact:
            return True

    return False


def result_text(result: Dict[str, Any]) -> str:
    return core.combine_result_text(result)


def safe_filename_component(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9_-]+", "_", value or "").strip("_")
    return value[:60] or "scan"


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, ensure_ascii=False) + "\n")


def strip_old_analysis_fields(result: Dict[str, Any]) -> Dict[str, Any]:
    analysis_fields = {
        "analysis_basis",
        "candidate_exposures",
        "canonical_url",
        "category",
        "contact_evidence",
        "control_type",
        "corroborating_entities",
        "detected_exposures",
        "evidence_quality",
        "extracted_email_addresses",
        "identity_score",
        "identity_signals",
        "identity_status",
        "known_email_found_near_identity",
        "known_phone_found_near_identity",
        "likely_identity_phone_candidates",
        "match_reasons",
        "phone_candidates",
        "privacy_exposure_status",
        "public_value",
        "recommendation_action",
        "recommendation_reason",
        "removal_suggestion",
        "result_subtype",
        "risk_level",
        "risk_reasons",
        "risk_score",
        "source_category",
        "match_type",
        "relationship_type",
        "related_result_urls",
        "personal_account",
        "rejection_reason",
        "youtube_identity",
    }

    return {
        key: value
        for key, value in result.items()
        if key not in analysis_fields
    }


# ---------------------------------------------------------------------------
# Detailed source classification
# ---------------------------------------------------------------------------

def classify_source_detailed(result: Dict[str, Any]) -> Dict[str, str]:
    url = str(result.get("url") or "")
    title = str(result.get("title") or "")
    text = result_text(result)
    domain = domain_of(url)
    path = path_of(url)

    if is_directory_page(result):
        return {
            "source_category": "Directory page",
            "result_subtype": "Multi-person directory",
            "control_type": "Third-party",
            "public_value": "Low identity value",
        }

    if domain_matches(domain, DATA_BROKER_DOMAINS):
        return {
            "source_category": "Data broker/contact aggregator",
            "result_subtype": "People-search or contact listing",
            "control_type": "Third-party",
            "public_value": "Privacy-sensitive",
        }

    if domain_matches(domain, ACADEMIC_PROFILE_DOMAINS):
        if "/publication/" in path or "publication" in title.casefold():
            return {
                "source_category": "Academic publication",
                "result_subtype": "Research publication page",
                "control_type": "Mixed",
                "public_value": "Professional/academic",
            }

        return {
            "source_category": "Academic profile",
            "result_subtype": "Researcher profile",
            "control_type": "Usually user-controlled",
            "public_value": "Professional/academic",
        }

    if (
        domain_matches(domain, ACADEMIC_PUBLICATION_DOMAINS)
        or path.endswith(".pdf")
        or result.get("extracted_type") == "pdf"
    ):
        if re.search(r"\b(resume|curriculum vitae|\bcv\b)\b", text, re.I):
            return {
                "source_category": "Public document",
                "result_subtype": "Resume/CV",
                "control_type": "Mixed",
                "public_value": "Potentially privacy-sensitive",
            }

        return {
            "source_category": "Academic/public document",
            "result_subtype": "Publication or PDF",
            "control_type": "Third-party or publisher",
            "public_value": "Professional/academic",
        }

    if domain_matches(domain, DEVELOPER_PROFILE_DOMAINS):
        return {
            "source_category": "Developer/portfolio profile",
            "result_subtype": "Technical profile",
            "control_type": "Usually user-controlled",
            "public_value": "Professional",
        }

    if domain_matches(domain, PROFESSIONAL_PROFILE_DOMAINS):
        return {
            "source_category": "Professional profile",
            "result_subtype": "Individual professional profile",
            "control_type": "Usually user-controlled",
            "public_value": "Professional",
        }

    if domain_matches(domain, SOCIAL_PROFILE_DOMAINS):
        return {
            "source_category": "Social profile",
            "result_subtype": "Personal social account",
            "control_type": "Usually user-controlled",
            "public_value": "Personal/social",
        }

    if result.get("source") == "YouTube":
        return {
            "source_category": "Public media/content",
            "result_subtype": str(result.get("source_type") or "YouTube result"),
            "control_type": "Mixed",
            "public_value": "Mixed",
        }

    if domain_matches(domain, NEWS_OR_INDUSTRY_DOMAINS):
        return {
            "source_category": "News/industry article",
            "result_subtype": "Third-party editorial coverage",
            "control_type": "Third-party publisher",
            "public_value": "Professional/public-interest",
        }

    if any(
        marker in domain
        for marker in ("medium.com", "blogspot.", "wordpress.com", "substack.com")
    ):
        return {
            "source_category": "Blog/article",
            "result_subtype": "Editorial or personal article",
            "control_type": "Mixed",
            "public_value": "Mixed",
        }

    return {
        "source_category": "General web result",
        "result_subtype": "Unclassified public page",
        "control_type": "Unknown",
        "public_value": "Unknown",
    }


def evidence_quality(result: Dict[str, Any]) -> Dict[str, str]:
    basis = core.determine_analysis_basis(result)

    if basis in {"Fetched PDF text", "Fetched webpage text"}:
        return {
            "analysis_basis": basis,
            "evidence_quality": "High",
        }

    if basis == "API metadata":
        return {
            "analysis_basis": basis,
            "evidence_quality": "Medium-High",
        }

    if result.get("fetch_status") in {"skipped", "failed"}:
        return {
            "analysis_basis": "Search-result title/snippet only",
            "evidence_quality": "Medium-Low",
        }

    return {
        "analysis_basis": basis,
        "evidence_quality": "Medium",
    }


# ---------------------------------------------------------------------------
# Entity extraction and cross-source corroboration
# ---------------------------------------------------------------------------

def clean_entity_phrase(value: str) -> str:
    value = core.normalize_spaces(value)
    value = re.sub(r"^[\W_]+|[\W_]+$", "", value)
    return value


def extract_organizations(text: str) -> List[str]:
    organizations: List[str] = []
    seen: Set[str] = set()
    source_text = text or ""

    # Preserve well-known institution aliases when the public source uses
    # either the long name or acronym.
    for pattern, canonical in ORG_CANONICAL_ALIASES:
        if pattern.search(source_text):
            key = normalized_entity(canonical)
            if key not in seen:
                seen.add(key)
                organizations.append(canonical)

    for match in ORG_PATTERN.finditer(source_text):
        candidate = clean_entity_phrase(match.group(0))
        normalized = normalized_entity(candidate)

        # A degree/program is not an organization. The old broad regex could
        # incorrectly turn "Bachelor of Technology" into an organization.
        if ORG_FALSE_POSITIVE_PATTERN.search(candidate):
            continue

        canonical = candidate
        for pattern, alias in ORG_CANONICAL_ALIASES:
            if pattern.search(candidate):
                canonical = alias
                normalized = normalized_entity(alias)
                break

        if (
            len(normalized) < 3
            or normalized in GENERIC_ORG_TERMS
        ):
            continue

        # For non-acronyms, require at least two words so ordinary suffix words
        # such as "technology" do not become organizations by themselves.
        is_acronym = bool(re.fullmatch(r"[A-Z][A-Z0-9&.-]{1,14}", canonical))
        if not is_acronym and len(normalized.split()) < 2:
            continue

        if normalized not in seen:
            seen.add(normalized)
            organizations.append(canonical)

    return organizations[:20]


def extract_job_titles(text: str) -> List[str]:
    found: List[str] = []

    for canonical, pattern in JOB_TITLE_PATTERNS.items():
        if re.search(pattern, text or "", re.IGNORECASE):
            found.append(canonical)

    return found


def extract_locations(text: str) -> List[str]:
    candidates: List[str] = []

    patterns = [
        r"\bbased in\s+([A-Z][A-Za-z .'\-]{2,40}(?:,\s*[A-Z]{2}|,\s*India)?)",
        r"\b([A-Z][A-Za-z .'\-]{2,30},\s*[A-Z][A-Za-z .'\-]{2,30},\s*India)\b",
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, text or ""):
            value = clean_entity_phrase(match.group(1))
            if value and value not in candidates:
                candidates.append(value)

    return candidates[:10]


def extract_result_entities(
    result: Dict[str, Any],
    context_terms: Sequence[str],
) -> Dict[str, List[str]]:
    text = result_text(result)

    context_hits, weak_context_hits = split_context_hits(
        text, context_terms
    )

    return {
        "organizations": extract_organizations(text),
        "job_titles": extract_job_titles(text),
        "locations": extract_locations(text),
        "context_hits": context_hits,
        "weak_context_hits": weak_context_hits,
    }


def corroboration_tokens(
    entities: Dict[str, List[str]],
) -> Set[str]:
    tokens: Set[str] = set()

    for organization in entities.get("organizations", []):
        normalized = normalized_entity(organization)
        if len(normalized.split()) >= 2 and normalized not in GENERIC_ORG_TERMS:
            tokens.add("org:" + normalized)

    for context in entities.get("context_hits", []):
        normalized = normalized_entity(context)
        if normalized:
            tokens.add("context:" + normalized)

    # A job title is too generic by itself, but it becomes useful with an org.
    organizations = [
        normalized_entity(value)
        for value in entities.get("organizations", [])
        if normalized_entity(value)
    ]

    for job_title in entities.get("job_titles", []):
        for organization in organizations[:5]:
            tokens.add(f"role_org:{job_title}|{organization}")

    return tokens


def build_corroboration_index(
    prepared_results: Sequence[Dict[str, Any]],
    full_name: str,
) -> Dict[str, Set[str]]:
    index: Dict[str, Set[str]] = defaultdict(set)

    for result in prepared_results:
        if result.get("directory_page"):
            continue

        text = result_text(result)
        if not contains_separator_normalized_identity(text, full_name):
            continue

        youtube_identity = result.get("youtube_identity", {})
        if (
            youtube_identity.get("is_youtube")
            and not youtube_identity.get("direct_identity")
        ):
            continue

        domain = domain_of(str(result.get("url") or "")) or str(
            result.get("source") or "unknown"
        ).casefold()

        for token in result.get("corroboration_tokens", []):
            index[token].add(domain)

    return index


def corroborating_entities_for_result(
    result: Dict[str, Any],
    index: Dict[str, Set[str]],
) -> List[Dict[str, Any]]:
    corroborated: List[Dict[str, Any]] = []

    for token in result.get("corroboration_tokens", []):
        domains = sorted(index.get(token, set()))
        if len(domains) >= 2:
            token_type, _, value = token.partition(":")
            corroborated.append({
                "type": token_type,
                "value": value,
                "independent_domains": domains,
                "domain_count": len(domains),
            })

    return corroborated


# ---------------------------------------------------------------------------
# Contact extraction and privacy exposure evidence
# ---------------------------------------------------------------------------

def deobfuscate_emails(text: str) -> List[str]:
    values: List[str] = []

    for match in OBFUSCATED_EMAIL_PATTERN.finditer(text or ""):
        candidate = (
            f"{match.group(1)}@{match.group(2)}.{match.group(3)}"
        ).casefold()
        if candidate not in values:
            values.append(candidate)

    return values


def add_contact_evidence(
    evidence: List[Dict[str, Any]],
    *,
    evidence_type: str,
    value: str,
    confidence: str,
    source_field: str,
    anchor_type: str,
    anchor_value: str,
    excerpt: str,
    visibility: str = "visible_value",
) -> None:
    key = (
        evidence_type,
        value.casefold(),
        source_field,
        visibility,
    )

    existing_keys = {
        (
            item.get("type"),
            str(item.get("value") or "").casefold(),
            item.get("source_field"),
            item.get("visibility"),
        )
        for item in evidence
    }

    if key in existing_keys:
        return

    evidence.append({
        "type": evidence_type,
        "value": value,
        "confidence": confidence,
        "source_field": source_field,
        "identity_anchor": {
            "type": anchor_type,
            "value": anchor_value,
        },
        "evidence_excerpt": core.normalize_spaces(excerpt),
        "visibility": visibility,
    })


def extract_contact_evidence(
    result: Dict[str, Any],
    full_name: str,
    email: str,
    username: str,
    phone: str,
) -> Dict[str, Any]:
    # Start with v4's proximity-safe extraction.
    base = core.extract_identity_contact_evidence(
        result,
        full_name=full_name,
        email=email,
        username=username,
        phone=phone,
    )

    evidence = list(base.get("contact_evidence", []))
    known_email = (email or "").strip().casefold()
    known_phone = core.normalize_phone(phone)
    combined_text = result_text(result)

    exact_name_present = (
        core.contains_exact_phrase(combined_text, full_name)
        or contains_separator_normalized_identity(
            combined_text,
            full_name,
        )
    )
    exact_username_present = contains_explicit_username(
        combined_text, str(result.get("url") or ""), username
    )

    # Exact supplied email anywhere on the candidate page is high-confidence.
    if known_email and core.contains_exact_email(combined_text, known_email):
        add_contact_evidence(
            evidence,
            evidence_type="email",
            value=known_email,
            confidence="High — exact supplied email",
            source_field="combined_result_text",
            anchor_type="known_email",
            anchor_value=known_email,
            excerpt=known_email,
        )

    # Exact supplied phone is only used after a name/username candidate exists.
    if known_phone and (exact_name_present or exact_username_present):
        for field_name, field_text in core.result_text_fields(result):
            for raw in core.extract_phone_candidates(field_text):
                if raw == known_phone:
                    index = field_text.find(raw)
                    excerpt = (
                        field_text[max(0, index - 140):index + len(raw) + 140]
                        if index >= 0
                        else raw
                    )
                    add_contact_evidence(
                        evidence,
                        evidence_type="phone",
                        value=known_phone,
                        confidence="High — exact supplied phone",
                        source_field=field_name,
                        anchor_type=(
                            "full_name"
                            if exact_name_present
                            else "username"
                        ),
                        anchor_value=(
                            full_name
                            if exact_name_present
                            else username
                        ),
                        excerpt=excerpt,
                    )

    # Obfuscated email candidates are accepted only when close to an identity anchor.
    for field_name, field_text in core.result_text_fields(result):
        spans = core.phrase_spans(field_text, full_name)
        spans += core.username_spans(field_text, username)

        for start, end in spans:
            window_start = max(
                0,
                start - core.IDENTITY_CONTACT_WINDOW_CHARS,
            )
            window_end = min(
                len(field_text),
                end + core.IDENTITY_CONTACT_WINDOW_CHARS,
            )
            window_text = field_text[window_start:window_end]

            for candidate in deobfuscate_emails(window_text):
                if core.is_generic_site_email(candidate, known_email):
                    continue

                add_contact_evidence(
                    evidence,
                    evidence_type="email",
                    value=candidate,
                    confidence=(
                        "High — supplied email in obfuscated form"
                        if known_email and candidate == known_email
                        else "Candidate — obfuscated email near identity"
                    ),
                    source_field=field_name,
                    anchor_type="identity_nearby",
                    anchor_value=full_name or username,
                    excerpt=window_text,
                )

    title_and_snippet = " ".join(
        str(result.get(field) or "")
        for field in ("title", "snippet")
    )

    advertised_contact = bool(
        re.search(
            r"\b(?:email\s*(?:&|and)\s*phone(?:\s*number)?|"
            r"phone\s*(?:&|and)\s*email|"
            r"contact\s+(?:details|information)|"
            r"email\s+address\s+and\s+phone)\b",
            title_and_snippet,
            re.IGNORECASE,
        )
    )

    if advertised_contact:
        add_contact_evidence(
            evidence,
            evidence_type="contact_advertised",
            value="Email/phone availability advertised; values not visible",
            confidence="Medium — provider title/snippet signal",
            source_field="title_or_snippet",
            anchor_type="full_name",
            anchor_value=full_name,
            excerpt=title_and_snippet,
            visibility="advertised_only",
        )

    filtered_evidence: List[Dict[str, Any]] = []
    for item in evidence:
        if item.get("type") == "phone" and is_likely_non_phone_identifier(
            str(item.get("value") or ""),
            str(item.get("evidence_excerpt") or ""),
        ):
            continue
        filtered_evidence.append(item)
    evidence = filtered_evidence

    emails = list(dict.fromkeys(
        item["value"]
        for item in evidence
        if item.get("type") == "email"
        and item.get("visibility") == "visible_value"
    ))

    phones = list(dict.fromkeys(
        item["value"]
        for item in evidence
        if item.get("type") == "phone"
        and item.get("visibility") == "visible_value"
    ))

    return {
        "email_addresses": emails,
        "phone_candidates": phones,
        "known_email_found": bool(
            known_email and known_email in {value.casefold() for value in emails}
        ),
        "known_phone_found": bool(
            known_phone and known_phone in phones
        ),
        "contact_advertised": advertised_contact,
        "contact_evidence": evidence,
    }


def detect_non_contact_exposures(
    result: Dict[str, Any],
) -> List[str]:
    text = result_text(result)
    labels: List[str] = []

    if re.search(
        r"\b(resume|curriculum vitae|\bcv\b)\b",
        text,
        re.IGNORECASE,
    ):
        labels.append("Resume/CV context")

    if re.search(
        r"\b(?:roll\s*(?:no|number)|sap\s*id|"
        r"student\s*id|employee\s*id)\b",
        text,
        re.IGNORECASE,
    ):
        labels.append("Student/employee identifier context")

    if re.search(
        r"\b(?:home address|residential address|"
        r"permanent address)\b",
        text,
        re.IGNORECASE,
    ):
        labels.append("Address context")

    return labels


# ---------------------------------------------------------------------------
# Identity scoring
# ---------------------------------------------------------------------------

def prepare_result(
    raw_result: Dict[str, Any],
    profile: Dict[str, Any],
) -> Dict[str, Any]:
    result = strip_old_analysis_fields(raw_result)
    result["canonical_url"] = core.normalize_url(
        str(result.get("url") or "")
    )

    classification = classify_source_detailed(result)
    result.update(classification)
    result.update(evidence_quality(result))

    full_name = str(profile.get("full_name") or "")
    email = str(profile.get("email") or "")
    username = str(profile.get("username") or "")
    context_terms = list(profile.get("context_terms") or [])

    text = result_text(result)
    url = str(result.get("url") or "")

    exact_full_name = (
        core.contains_exact_phrase(text, full_name)
        or contains_separator_normalized_identity(text, full_name)
    )
    middle_name_variant = (
        not exact_full_name
        and contains_middle_name_variant(
            f"{text} {url}",
            full_name,
        )
    )
    exact_username = contains_explicit_username(text, url, username)
    strong_context_hits, weak_context_hits = split_context_hits(
        text, context_terms
    )

    result["directory_page"] = is_directory_page(result)
    result["identity_signals"] = {
        "exact_email": core.contains_exact_email(text, email),
        "exact_full_name": exact_full_name,
        "middle_name_variant": middle_name_variant,
        "exact_username": exact_username,
        "separator_normalized_full_name": (
            contains_separator_normalized_identity(text, full_name)
        ),
        "separator_normalized_username": exact_username,
        "name_in_url_slug": name_slug_match(url, full_name),
        "context_hits": strong_context_hits,
        "weak_context_hits": weak_context_hits,
        "visual_match": bool(
            (result.get("visual_identity") or {}).get("face_match_found")
        ),
        "visual_match_strength": str(
            (result.get("visual_identity") or {}).get("match_strength") or ""
        ),
        "visual_face_distance": (
            (result.get("visual_identity") or {}).get("best_face_distance")
        ),
        "visual_manual_verification": str(
            (result.get("visual_identity") or {}).get(
                "manual_verification_status", "unreviewed"
            )
        ),
        "visual_manual_confirmed": (
            (result.get("visual_identity") or {}).get(
                "manual_verification_status"
            ) == "confirmed"
        ),
    }
    result["supplied_email_is_institutional"] = is_institutional_email(email)
    result["official_domain_match"] = is_official_email_domain(url, email)

    if (
        exact_full_name
        and is_official_email_domain(url, email)
        and result.get("source_category") == "General web result"
    ):
        result.update({
            "source_category": "Organization/academic profile",
            "result_subtype": "Official institutional profile or directory",
            "control_type": "Institution-controlled",
            "public_value": "Professional/academic",
        })

    youtube = is_youtube_result(result)
    youtube_own = youtube_owned_text(result) if youtube else ""
    source_type = str(result.get("source_type") or "").casefold()
    own_context_hits, own_weak_context_hits = split_context_hits(
        youtube_own, context_terms
    )
    own_exact_name = (
        contains_separator_normalized_identity(youtube_own, full_name)
        if youtube else False
    )
    own_exact_username = (
        contains_explicit_username(
            youtube_own, str(result.get("url") or ""), username
        )
        if youtube else False
    )
    own_exact_email = (
        core.contains_exact_email(youtube_own, email)
        if youtube and email else False
    )
    channel_name_match = (
        contains_separator_normalized_identity(
            str(result.get("channel_title") or ""),
            full_name,
        )
        or contains_separator_normalized_identity(
            str(result.get("channel_title") or ""),
            username,
        )
    ) if youtube else False

    result["youtube_identity"] = {
        "is_youtube": youtube,
        "source_type": source_type,
        "own_exact_name": own_exact_name,
        "own_exact_username": own_exact_username,
        "own_exact_email": own_exact_email,
        "own_context_hits": own_context_hits,
        "own_weak_context_hits": own_weak_context_hits,
        "channel_name_match": channel_name_match,
        "direct_identity": bool(
            own_exact_name or own_exact_username or own_exact_email
        ),
        "related_source": False,
        "channel_key": youtube_channel_key(result) if youtube else "",
        "related_result_urls": [],
    }

    result["entities"] = extract_result_entities(
        result,
        context_terms=context_terms,
    )
    result["corroboration_tokens"] = sorted(
        corroboration_tokens(result["entities"])
    )

    result["contact_analysis"] = extract_contact_evidence(
        result,
        full_name=full_name,
        email=email,
        username=username,
        phone=str(profile.get("phone") or ""),
    )
    result["non_contact_exposures"] = detect_non_contact_exposures(result)

    return result


def finalize_identity(
    result: Dict[str, Any],
    corroboration_index: Dict[str, Set[str]],
) -> Tuple[str, int, List[str], List[Dict[str, Any]]]:
    signals = result["identity_signals"]
    corroborated = corroborating_entities_for_result(
        result,
        corroboration_index,
    )
    reasons: List[str] = []

    visual_evidence = result.get("visual_identity") or {}
    visual_strength = str(
        visual_evidence.get("match_strength") or ""
    ).casefold()
    visual_strong = visual_strength == "strong"
    visual_possible = visual_strength == "possible"
    visual_distance = visual_evidence.get("best_face_distance")

    youtube_identity = result.get("youtube_identity", {})
    if youtube_identity.get("is_youtube"):
        source_type = youtube_identity.get("source_type")

        if source_type == "video":
            if youtube_identity.get("direct_identity"):
                if youtube_identity.get("own_exact_email"):
                    reasons.append(
                        "Exact supplied email found in the video's own metadata"
                    )
                    result["match_type"] = "Direct identity mention"
                    result["rejection_reason"] = ""
                    return "Confirmed", 100, reasons, corroborated

                if youtube_identity.get("own_exact_name"):
                    reasons.append(
                        "Exact separator-normalized full name found in the "
                        "video's own metadata"
                    )
                if youtube_identity.get("own_exact_username"):
                    reasons.append(
                        "Exact separator-normalized username found in the "
                        "video's own metadata"
                    )
                if youtube_identity.get("own_context_hits"):
                    reasons.append(
                        "Supporting context: "
                        + ", ".join(
                            youtube_identity["own_context_hits"]
                        )
                    )

                score = 84
                if youtube_identity.get("own_exact_name") and (
                    youtube_identity.get("own_exact_username")
                    or youtube_identity.get("own_context_hits")
                ):
                    score = 90

                result["match_type"] = "Direct identity mention"
                result["personal_account"] = (
                    True
                    if youtube_identity.get("channel_name_match")
                    else False
                )
                result["rejection_reason"] = ""
                return "Strong", score, reasons, corroborated

            result["personal_account"] = False
            if youtube_identity.get("channel_name_match"):
                result["match_type"] = "Unsupported same-name channel"
                result["rejection_reason"] = (
                    "same_name_channel_without_identity_corroboration"
                )
                return "Rejected", 0, [
                    "The target name appears only as the channel display "
                    "name; the video's own title, description, URL, and "
                    "content contain no exact identity anchor"
                ], corroborated

            result["match_type"] = "No exact identity mention"
            result["rejection_reason"] = (
                "no_exact_full_identity_match"
            )
            return "Rejected", 0, [
                "The video's own metadata contains no exact full-name, "
                "email, or separator-normalized username anchor"
            ], corroborated

        if source_type == "channel":
            if youtube_identity.get("related_source"):
                reasons.append(
                    "Channel hosts a directly matched YouTube result"
                )
                result["match_type"] = "Relationship match"
                result["relationship_type"] = (
                    "Hosts matched YouTube content"
                )
                result["related_result_urls"] = list(
                    youtube_identity.get("related_result_urls", [])
                )
                result["personal_account"] = False
                result["rejection_reason"] = ""
                return "Strong", 72, reasons, corroborated

            if (
                youtube_identity.get("direct_identity")
                and youtube_identity.get("own_context_hits")
            ):
                reasons.extend([
                    "Exact identity appears in the channel's own metadata",
                    "Supporting context: "
                    + ", ".join(
                        youtube_identity["own_context_hits"]
                    ),
                ])
                result["match_type"] = (
                    "Same-name channel with contextual evidence"
                )
                result["personal_account"] = None
                result["rejection_reason"] = ""
                return "Possible", 55, reasons, corroborated

            result["match_type"] = "No verified channel relationship"
            result["personal_account"] = False
            result["rejection_reason"] = "unverified_youtube_channel"
            return "Rejected", 0, [
                "The channel does not host a directly matched result in "
                "this scan and lacks independent identity context"
            ], corroborated

    if signals["exact_email"]:
        reasons.append(
            "Exact supplied email found; email is an independent positive identity anchor"
        )
        if signals["exact_full_name"]:
            reasons.append("Exact full name found")
        else:
            reasons.append(
                "The page is retained even without an exact name match because the exact supplied email independently corroborates identity"
            )
        result["match_type"] = "Exact email identity match"
        result["association_basis"] = "exact_supplied_email"
        result["rejection_reason"] = ""
        return "Confirmed", 100, reasons, corroborated

    if (
        result["contact_analysis"].get("known_phone_found")
        and signals["exact_full_name"]
    ):
        reasons.extend([
            "Exact full name found",
            "Exact supplied phone found after candidate discovery",
        ])
        return "Confirmed", 98, reasons, corroborated

    if result.get("directory_page"):
        if signals["exact_full_name"]:
            reasons.append(
                "Exact full name appears on a multi-person directory page"
            )
            return "Possible", 32, reasons, corroborated

        if signals.get("middle_name_variant"):
            reasons.extend([
                "First and last name match with an additional middle name",
                "Expanded legal-name variants require user confirmation",
            ])
            result["match_type"] = "Expanded-name variant"
            result["rejection_reason"] = "identity_confirmation_required"
            return "Possible", 35, reasons, corroborated

        return "Rejected", 0, [
            "Directory page lacks an exact individual identity anchor"
        ], corroborated

    if signals.get("middle_name_variant"):
        reasons.append(
            "First and last name match the supplied identity with an "
            "additional middle name"
        )
        if signals.get("context_hits"):
            reasons.append(
                "Supporting distinctive context: "
                + ", ".join(signals["context_hits"])
            )

        if visual_strong:
            reasons.append(
                "Strong local face-descriptor match to the optional "
                "reference image"
                + (
                    f" (distance {visual_distance})"
                    if visual_distance is not None else ""
                )
            )
            result["match_type"] = "Expanded-name + visual corroboration"
            result["rejection_reason"] = ""
            return "Strong", 86, reasons, corroborated

        if visual_possible:
            reasons.append(
                "Possible visual similarity supports review but is not "
                "strong enough to establish identity"
            )

        reasons.append(
            "The expanded legal-name variant requires user confirmation "
            "before it is treated as the same person"
        )
        result["match_type"] = "Expanded-name variant"
        result["rejection_reason"] = "identity_confirmation_required"
        score = 58 if visual_possible else (52 if signals.get("context_hits") else 48)
        return "Possible", score, reasons, corroborated

    if signals["exact_full_name"] and signals["exact_username"]:
        reasons.extend([
            "Exact full name found",
            "Exact distinctive username found",
        ])
        return "Strong", 94, reasons, corroborated

    if signals["exact_full_name"] and signals["name_in_url_slug"]:
        reasons.extend([
            "Exact full name found",
            "Full name also appears in the individual page URL",
        ])

        if visual_strong:
            reasons.append(
                "Strong local face-descriptor match to the optional "
                "reference image"
                + (
                    f" (distance {visual_distance})"
                    if visual_distance is not None else ""
                )
            )
            result["match_type"] = "Text + visual corroboration"
            result["rejection_reason"] = ""
            return "Strong", 92, reasons, corroborated

        if signals["context_hits"]:
            reasons.append(
                "Supporting distinctive context: "
                + ", ".join(signals["context_hits"])
            )
            return "Strong", 90, reasons, corroborated

        reasons.append(
            "No supplied identifier or distinctive context confirms that "
            "this same-name page belongs to the searched person"
        )
        result["match_type"] = "Unverified same-name page"
        result["rejection_reason"] = "identity_confirmation_required"
        return "Possible", 58, reasons, corroborated

    if signals["exact_full_name"] and signals["context_hits"]:
        reasons.extend([
            "Exact full name found",
            "Supporting distinctive context: "
            + ", ".join(signals["context_hits"]),
        ])
        score = min(92, 82 + 3 * len(signals["context_hits"]))
        return "Strong", score, reasons, corroborated

    if signals["exact_full_name"] and corroborated:
        top = sorted(
            corroborated,
            key=lambda item: item["domain_count"],
            reverse=True,
        )
        reasons.append("Exact full name found")
        reasons.append(
            "Cross-source corroboration: "
            + "; ".join(
                f"{item['value']} across "
                f"{item['domain_count']} domains"
                for item in top[:3]
            )
        )
        score = min(
            91,
            80 + max(item["domain_count"] for item in top),
        )
        return "Strong", score, reasons, corroborated

    if (
        str(result.get("source") or "").casefold() == "github"
        and signals["exact_username"]
        and str(result.get("lookup_type") or "") == "exact_username"
    ):
        reasons.append("Exact GitHub username lookup")
        if signals["exact_full_name"]:
            reasons.append("Exact full name found")
        return "Strong", 85, reasons, corroborated

    if signals["exact_full_name"]:
        reasons.append(
            "Exact full name found without independent supporting evidence"
        )
        if visual_strong:
            reasons.append(
                "Strong local face-descriptor match to the optional "
                "reference image"
                + (
                    f" (distance {visual_distance})"
                    if visual_distance is not None else ""
                )
            )
            result["match_type"] = "Text + visual corroboration"
            result["rejection_reason"] = ""
            return "Strong", 88, reasons, corroborated

        if signals.get("weak_context_hits"):
            reasons.append(
                "Only broad context was found: "
                + ", ".join(signals["weak_context_hits"])
            )
        result["match_type"] = "Unverified same-name page"
        result["rejection_reason"] = "identity_confirmation_required"
        return "Possible", 55, reasons, corroborated

    if signals["exact_username"]:
        reasons.append(
            "Exact distinctive username found without supporting context"
        )
        if visual_strong:
            reasons.append(
                "Strong local face-descriptor match to the optional "
                "reference image"
            )
            result["match_type"] = "Username + visual corroboration"
            result["rejection_reason"] = ""
            return "Strong", 86, reasons, corroborated
        return "Possible", 45, reasons, corroborated

    if visual_strong:
        result["match_type"] = "Visual identity candidate"
        result["rejection_reason"] = "identity_confirmation_required"
        return "Possible", 60, [
            "A strong local face-descriptor match was found in a public "
            "candidate image, but text identity evidence is insufficient",
            "User confirmation is required before treating the page as the "
            "same person",
        ], corroborated

    return "Rejected", 0, [
        "No exact name, email, or distinctive username anchor found"
    ], corroborated


# ---------------------------------------------------------------------------
# Risk and recommendation logic
# ---------------------------------------------------------------------------

def privacy_exposure_status(
    result: Dict[str, Any],
    identity_status: str,
) -> str:
    contacts = result["contact_analysis"]
    non_contact = result["non_contact_exposures"]

    if identity_status not in {"Confirmed", "Strong"}:
        if (
            contacts["email_addresses"]
            or contacts["phone_candidates"]
            or contacts["contact_advertised"]
            or non_contact
        ):
            return "Candidate exposure pending identity verification"
        return "No verified exposure"

    if (
        contacts["known_email_found"]
        and result.get("supplied_email_is_institutional")
        and result.get("official_domain_match")
        and not contacts["known_phone_found"]
    ):
        return "Institutional contact published on official domain"

    if (
        contacts["known_email_found"]
        or contacts["known_phone_found"]
    ):
        return "Verified supplied contact exposed"

    if contacts["email_addresses"] or contacts["phone_candidates"]:
        return "Visible contact candidate near verified identity"

    if contacts["contact_advertised"]:
        return "Contact availability advertised; values not visible"

    if non_contact:
        return "Non-contact personal data context detected"

    return "No sensitive exposure detected"


def score_privacy_risk(
    result: Dict[str, Any],
    identity_status: str,
) -> Tuple[Optional[int], str, List[str]]:
    if identity_status == "Rejected":
        return None, "Not applicable", ["Rejected identity match."]

    if identity_status == "Possible":
        return None, "Pending identity verification", [
            "Risk is withheld until the identity match is verified."
        ]

    contacts = result["contact_analysis"]
    non_contact = result["non_contact_exposures"]
    score = 0
    reasons: List[str] = []

    if contacts["known_email_found"]:
        if (
            result.get("supplied_email_is_institutional")
            and result.get("official_domain_match")
        ):
            score += 5
            reasons.append(
                "Institutional email is visible on its official domain: +5"
            )
        elif result.get("supplied_email_is_institutional"):
            score += 12
            reasons.append("Institutional email is visible: +12")
        else:
            score += 30
            reasons.append("Exact supplied personal email is visible: +30")
    elif contacts["email_addresses"]:
        score += 18
        reasons.append("Email candidate near verified identity: +18")

    if contacts["known_phone_found"]:
        score += 35
        reasons.append("Exact supplied phone is visible: +35")
    elif contacts["phone_candidates"]:
        score += 25
        reasons.append("Phone candidate near verified identity: +25")

    if "Address context" in non_contact:
        score += 30
        reasons.append("Address context detected: +30")

    if "Student/employee identifier context" in non_contact:
        score += 25
        reasons.append("Identifier context detected: +25")

    if "Resume/CV context" in non_contact:
        score += 10
        reasons.append("Resume/CV context detected: +10")

    category = result["source_category"]

    if category == "Data broker/contact aggregator":
        score += 20
        reasons.append("Data-broker listing: +20")

        if contacts["contact_advertised"] and not (
            contacts["email_addresses"]
            or contacts["phone_candidates"]
        ):
            score += 10
            reasons.append(
                "Contact availability advertised but hidden: +10"
            )

    elif category == "Social profile":
        score += 5
        reasons.append("Public social profile: +5")

    elif category == "Public document":
        score += 5
        reasons.append("Public document exposure: +5")

    elif category in {
        "Professional profile",
        "Developer/portfolio profile",
        "Academic profile",
        "Organization/academic profile",
    }:
        score += 2
        reasons.append("Public professional profile: +2")

    # News and academic publications do not receive a risk penalty merely
    # because the person's name appears.
    score = min(score, 100)

    if score >= 70:
        level = "Very High"
    elif score >= 40:
        level = "High"
    elif score >= 15:
        level = "Moderate"
    else:
        level = "Low"

    if not reasons:
        reasons.append(
            "No sensitive contact or identifier exposure was detected."
        )

    return score, level, reasons


def recommendation_for_result(
    result: Dict[str, Any],
    identity_status: str,
) -> Tuple[str, str, str]:
    category = result["source_category"]
    contacts = result["contact_analysis"]
    non_contact = result["non_contact_exposures"]
    sensitive_visible = bool(
        contacts["email_addresses"]
        or contacts["phone_candidates"]
        or non_contact
    )

    if identity_status == "Rejected":
        return (
            "Exclude",
            "No reliable identity match.",
            "Exclude this result from the user's footprint report.",
        )

    if identity_status == "Possible":
        return (
            "Manual verification",
            "The identity match is not strong enough for action.",
            "Verify that the page belongs to the person before requesting "
            "editing, removal, redaction, or opt-out.",
        )

    if category == "Related source":
        return (
            "Retain as related source",
            "The channel is relevant because it hosts directly matched "
            "content, but it is not established as the person's account.",
            "Keep the channel as relationship evidence. Do not recommend "
            "deleting or reporting the entire channel based on this link.",
        )

    if category == "Data broker/contact aggregator":
        return (
            "Opt out",
            "A data broker or contact aggregator presents the person as a "
            "searchable contact record.",
            "Open the provider's privacy or opt-out page, submit the required "
            "identity verification, request suppression, and later re-check "
            "the public listing.",
        )

    if category == "Directory page":
        return (
            "Manual verification",
            "The page lists multiple people and is weak evidence for one person.",
            "Open the individual result, if available, before taking action.",
        )

    if category in {
        "News/industry article",
        "Academic publication",
        "Academic/public document",
    }:
        if sensitive_visible:
            return (
                "Request redaction",
                "The content has professional/public value but may expose "
                "unnecessary personal information.",
                "Retain the publication where possible and ask the publisher "
                "to redact only the sensitive contact or identifier fields.",
            )

        return (
            "Retain",
            "The page is a professional, academic, or public-interest footprint "
            "without detected sensitive data.",
            "No removal is recommended. Keep the record unless it is inaccurate "
            "or the person specifically wants it removed.",
        )

    if category in {
        "Professional profile",
        "Developer/portfolio profile",
        "Academic profile",
        "Organization/academic profile",
    }:
        if (
            category == "Organization/academic profile"
            and contacts.get("known_email_found")
            and result.get("supplied_email_is_institutional")
            and result.get("official_domain_match")
        ):
            return (
                "Retain or review",
                "The official institutional profile publishes a professional "
                "contact address for legitimate academic or work use.",
                "Keep the profile unless the information is inaccurate. The "
                "user may ask the institution to update the contact details.",
            )

        if sensitive_visible:
            return (
                "Update or redact",
                "The profile is professionally useful but contains visible "
                "contact or personal-data candidates.",
                "Sign in to the account and remove unnecessary contact fields, "
                "old documents, or identifiers while retaining useful "
                "professional information.",
            )

        return (
            "Retain or review",
            "The profile appears professionally useful and low-risk.",
            "Review the profile for outdated details and privacy settings; "
            "removal is not necessary unless the account is unwanted.",
        )

    if category == "Social profile":
        if sensitive_visible:
            return (
                "Privatize or redact",
                "A personal social profile contains visible personal-data "
                "candidates.",
                "Review audience settings, remove exposed contact fields, and "
                "privatize or delete the profile if it is no longer wanted.",
            )

        return (
            "Review privacy settings",
            "The social profile is public but no sensitive contact was detected.",
            "Review visibility, audience, tagging, and discoverability settings.",
        )

    if result["result_subtype"] == "Resume/CV":
        if sensitive_visible:
            return (
                "Redact or remove",
                "A public resume can expose multiple personal identifiers.",
                "Replace the document with a redacted version or ask the host "
                "to remove it.",
            )

        return (
            "Review",
            "A public resume may become outdated even without obvious contact data.",
            "Check whether the document should remain public and replace it with "
            "a current, minimal version if needed.",
        )

    if sensitive_visible:
        return (
            "Request redaction",
            "A third-party page may expose unnecessary personal information.",
            "Contact the page owner and request targeted redaction, preserving "
            "the URL and evidence excerpt.",
        )

    return (
        "Review",
        "The page is relevant but does not currently show a clear privacy risk.",
        "Review the content for accuracy and decide whether it should remain public.",
    )


def finalize_result(
    prepared: Dict[str, Any],
    corroboration_index: Dict[str, Set[str]],
) -> Dict[str, Any]:
    result = dict(prepared)

    status, score, reasons, corroborated = finalize_identity(
        result,
        corroboration_index,
    )

    result["identity_status"] = status
    result["identity_score"] = score
    result["match_reasons"] = reasons
    result["corroborating_entities"] = corroborated

    if status == "Rejected" and not result.get("rejection_reason"):
        result["rejection_reason"] = "no_exact_identity_anchor"

    contacts = result["contact_analysis"]
    result["extracted_email_addresses"] = contacts["email_addresses"]
    result["phone_candidates"] = contacts["phone_candidates"]
    result["likely_identity_phone_candidates"] = contacts[
        "phone_candidates"
    ]
    result["known_email_found_near_identity"] = contacts[
        "known_email_found"
    ]
    result["known_phone_found_near_identity"] = contacts[
        "known_phone_found"
    ]
    result["contact_evidence"] = contacts["contact_evidence"]

    verified_exposures: List[str] = []
    candidate_exposures: List[str] = []

    target = (
        verified_exposures
        if status in {"Confirmed", "Strong"}
        else candidate_exposures
    )

    if contacts["known_email_found"]:
        target.append(
            "Known institutional email"
            if result.get("supplied_email_is_institutional")
            else "Known personal email"
        )
    elif contacts["email_addresses"]:
        target.append("Email address near identity")

    if contacts["known_phone_found"]:
        target.append("Known personal phone")
    elif contacts["phone_candidates"]:
        target.append("Phone number near identity")

    if contacts["contact_advertised"]:
        target.append(
            "Email/phone availability advertised; values not visible"
        )

    target.extend(result["non_contact_exposures"])

    result["detected_exposures"] = list(dict.fromkeys(
        verified_exposures
    ))
    result["candidate_exposures"] = list(dict.fromkeys(
        candidate_exposures
    ))
    result["privacy_exposure_status"] = privacy_exposure_status(
        result,
        status,
    )

    risk_score, risk_level, risk_reasons = score_privacy_risk(
        result,
        status,
    )
    result["risk_score"] = risk_score
    result["risk_level"] = risk_level
    result["risk_reasons"] = risk_reasons

    action, reason, suggestion = recommendation_for_result(
        result,
        status,
    )
    result["recommendation_action"] = action
    result["recommendation_reason"] = reason
    result["removal_suggestion"] = suggestion

    # Remove internal helper-only fields from final report.
    result.pop("corroboration_tokens", None)
    result.pop("directory_page", None)
    result.pop("contact_analysis", None)
    result.pop("non_contact_exposures", None)

    return result


def analyze_candidates(
    candidates: Sequence[Dict[str, Any]],
    profile: Dict[str, Any],
) -> List[Dict[str, Any]]:
    prepared = [
        prepare_result(candidate, profile)
        for candidate in candidates
    ]

    # Establish YouTube parent/child relationships before final scoring.
    # A channel is retained only when a directly matching video in the same
    # result batch identifies that channel as its host.
    matched_channel_urls: Dict[str, List[str]] = defaultdict(list)
    for result in prepared:
        youtube_identity = result.get("youtube_identity", {})
        if (
            youtube_identity.get("is_youtube")
            and youtube_identity.get("source_type") == "video"
            and youtube_identity.get("direct_identity")
        ):
            key = str(youtube_identity.get("channel_key") or "")
            if key:
                matched_channel_urls[key].append(
                    str(result.get("url") or "")
                )

    for result in prepared:
        youtube_identity = result.get("youtube_identity", {})
        if not (
            youtube_identity.get("is_youtube")
            and youtube_identity.get("source_type") == "channel"
        ):
            continue

        key = str(youtube_identity.get("channel_key") or "")
        related_urls = list(dict.fromkeys(
            matched_channel_urls.get(key, [])
        ))
        if not related_urls:
            continue

        youtube_identity["related_source"] = True
        youtube_identity["related_result_urls"] = related_urls
        result["youtube_identity"] = youtube_identity
        result["source_category"] = "Related source"
        result["result_subtype"] = "YouTube channel hosting matched content"
        result["control_type"] = "Third-party"
        result["public_value"] = "Relationship evidence"

    index = build_corroboration_index(
        prepared,
        full_name=str(profile.get("full_name") or ""),
    )

    finalized = [
        finalize_result(result, index)
        for result in prepared
    ]

    return finalized


# ---------------------------------------------------------------------------
# Cached connectors and fresh raw scan
# ---------------------------------------------------------------------------

def cached_youtube_search(
    query: str,
    max_results: int,
    allow_network: bool,
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    provider = "youtube"
    cache_key = f"{max_results}|{query}"

    if CACHE_SPECIALIZED_CONNECTORS:
        cached = core.get_cached_response(provider, cache_key)
        if cached is not None:
            return list(cached.get("results", [])), {
                "api_requests": 0,
                "cache_hits": 1,
            }

    if not allow_network:
        return [], {"api_requests": 0, "cache_hits": 0}

    results = core.search_youtube(query, max_results=max_results)

    if CACHE_SPECIALIZED_CONNECTORS:
        core.set_cached_response(provider, cache_key, {"results": results})

    return results, {"api_requests": 1, "cache_hits": 0}


def cached_github_lookup(
    username: str,
    allow_network: bool,
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    provider = "github"
    cache_key = username.casefold()

    if CACHE_SPECIALIZED_CONNECTORS:
        cached = core.get_cached_response(provider, cache_key)
        if cached is not None:
            return list(cached.get("results", [])), {
                "api_requests": 0,
                "cache_hits": 1,
            }

    if not allow_network:
        return [], {"api_requests": 0, "cache_hits": 0}

    results = core.lookup_github_user(username)

    if CACHE_SPECIALIZED_CONNECTORS:
        core.set_cached_response(provider, cache_key, {"results": results})

    return results, {"api_requests": 1, "cache_hits": 0}


def cached_broad_web_search(
    query: str,
    provider: Optional[str],
    max_results: int,
    allow_network: bool,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    if not provider:
        return [], {
            "provider": None,
            "api_requests": 0,
            "cache_hits": 0,
            "warning": "No broad-web provider is configured.",
        }

    cache_key = f"{max_results}|{query}"
    cached = core.get_cached_response(provider, cache_key)

    if cached is not None:
        parser = (
            core.parse_brave_results
            if provider == "brave"
            else core.parse_tavily_results
        )
        return parser(cached, query), {
            "provider": provider,
            "api_requests": 0,
            "cache_hits": 1,
            "warning": None,
        }

    if not allow_network:
        return [], {
            "provider": provider,
            "api_requests": 0,
            "cache_hits": 0,
            "warning": (
                "Cache-only mode was enabled and no cached broad-web "
                "response exists for this query."
            ),
        }

    return core.search_broad_web(
        query,
        max_results=max_results,
        provider=provider,
    )


def build_profile(
    full_name: str,
    email: str,
    username: str,
    phone: str,
    context_terms: Sequence[str],
) -> Dict[str, Any]:
    return {
        "full_name": core.normalize_spaces(full_name),
        "email": (email or "").strip().casefold(),
        "username": (username or "").strip(),
        "phone": core.normalize_phone(phone),
        "context_terms": list(dict.fromkeys(
            core.normalize_spaces(term)
            for term in context_terms
            if core.normalize_spaces(term)
        )),
    }


def build_targeted_profile_queries(
    profile: Dict[str, Any],
) -> List[Dict[str, str]]:
    """Build broad category and high-value platform searches.

    These queries supplement, rather than replace, the open-web search.
    They improve recall for profiles that generic ranking may otherwise miss.
    Email and phone are deliberately excluded from these platform queries;
    exact email has its own additive corroboration search in the broad plan.
    Every returned page still passes through the ordinary identity scorer.
    """
    full_name = core.normalize_spaces(str(profile.get("full_name") or ""))
    username = str(profile.get("username") or "").strip()

    anchor = f'"{full_name}"' if full_name else (f'"{username}"' if username else "")
    if not anchor:
        return []

    queries: List[Dict[str, str]] = [
        # Category-level searches keep discovery broad even when an important
        # site is not in the platform list below.
        {"purpose": "category_profile", "query": f"{anchor} profile"},
        {"purpose": "category_professional", "query": f"{anchor} professional"},
        {"purpose": "category_research_publication", "query": f"{anchor} research publication"},
        {"purpose": "category_developer_data", "query": f"{anchor} developer data science"},

        # High-value professional / academic / developer / social surfaces.
        {"purpose": "targeted_linkedin_profile", "query": f"{anchor} site:linkedin.com/in"},
        {"purpose": "targeted_researchgate_profile", "query": f"{anchor} site:researchgate.net/profile"},
        {"purpose": "targeted_ieee_profile_or_publication", "query": f"{anchor} site:ieeexplore.ieee.org"},
        {"purpose": "targeted_orcid_profile", "query": f"{anchor} site:orcid.org"},
        {"purpose": "targeted_google_scholar_profile", "query": f"{anchor} site:scholar.google.com"},
        {"purpose": "targeted_semantic_scholar", "query": f"{anchor} site:semanticscholar.org"},
        {"purpose": "targeted_kaggle_profile", "query": f"{anchor} site:kaggle.com"},
        {"purpose": "targeted_stackoverflow_profile", "query": f"{anchor} site:stackoverflow.com/users"},
        {"purpose": "targeted_github_profile", "query": f"{anchor} site:github.com"},
        {"purpose": "targeted_gitlab_profile", "query": f"{anchor} site:gitlab.com"},
        {"purpose": "targeted_medium_profile", "query": f"{anchor} site:medium.com"},
        {"purpose": "targeted_facebook_profile", "query": f"{anchor} site:facebook.com"},
        {"purpose": "targeted_instagram_profile", "query": f"{anchor} site:instagram.com"},
        {"purpose": "targeted_x_profile", "query": f"{anchor} site:x.com"},
    ]

    # Username-led pages may omit the legal name entirely. Add a small set of
    # high-value username searches without doubling every platform request.
    if username and full_name:
        username_anchor = f'"{username}"'
        queries.extend([
            {"purpose": "targeted_linkedin_username", "query": f"{username_anchor} site:linkedin.com/in"},
            {"purpose": "targeted_github_username", "query": f"{username_anchor} site:github.com"},
            {"purpose": "targeted_kaggle_username", "query": f"{username_anchor} site:kaggle.com"},
            {"purpose": "targeted_stackoverflow_username", "query": f"{username_anchor} site:stackoverflow.com/users"},
        ])

    seen: Set[str] = set()
    output: List[Dict[str, str]] = []
    for item in queries:
        query = item["query"].strip()
        if query.casefold() in seen:
            continue
        seen.add(query.casefold())
        output.append(item)
    return output

def create_raw_scan(
    profile: Dict[str, Any],
    *,
    allow_network: bool = True,
    web_max_results: int = core.DEFAULT_WEB_RESULTS,
    youtube_max_results: int = core.DEFAULT_YOUTUBE_RESULTS,
) -> Dict[str, Any]:
    """Collect Phase 2A connector evidence with safe I/O parallelism.

    Broad-web, YouTube and GitHub requests are independent and therefore run
    concurrently.  The broad-web email/no-email fallback remains sequential
    *inside* its own worker so the existing identity/privacy semantics are
    unchanged.
    """
    scan_id = uuid4().hex
    scan_time = utc_now_iso()
    provider = core.choose_web_provider()

    query_plan = core.generate_web_query_plan(
        full_name=profile["full_name"],
        email=profile["email"],
        username=profile["username"],
    )
    youtube_query = core.generate_youtube_query(
        full_name=profile["full_name"],
        username=profile["username"],
    )
    targeted_profile_queries = build_targeted_profile_queries(profile)

    metrics = {
        "broad_web_provider": provider,
        "broad_web_api_requests": 0,
        "broad_web_cache_hits": 0,
        "targeted_profile_queries": len(targeted_profile_queries),
        "targeted_profile_api_requests": 0,
        "targeted_profile_cache_hits": 0,
        "youtube_api_requests": 0,
        "youtube_cache_hits": 0,
        "github_api_requests": 0,
        "github_cache_hits": 0,
        "connector_workers": PHASE2_CONNECTOR_WORKERS,
        "targeted_profile_workers": TARGETED_PROFILE_WORKERS,
        "broad_web_query_workers": BROAD_WEB_QUERY_WORKERS,
    }

    def broad_web_job() -> Dict[str, Any]:
        job_results: List[Dict[str, Any]] = []
        records: List[Dict[str, Any]] = []
        job_warnings: List[str] = []
        job_metrics = {
            "broad_web_api_requests": 0,
            "broad_web_cache_hits": 0,
        }

        if not query_plan:
            return {
                "results": job_results,
                "records": records,
                "warnings": job_warnings,
                "metrics": job_metrics,
            }

        def run_query(item: Dict[str, Any]):
            record = {
                "connector": "broad_web",
                "provider": provider,
                "purpose": item["purpose"],
                "query": item["query"],
                "includes_email": bool(item.get("includes_email")),
                "status": "planned",
                "api_requests": 0,
                "cache_hits": 0,
            }
            warning = None
            try:
                found, search_metrics = cached_broad_web_search(
                    item["query"],
                    provider=provider,
                    max_results=web_max_results,
                    allow_network=allow_network,
                )
                record["api_requests"] = int(search_metrics.get("api_requests", 0) or 0)
                record["cache_hits"] = int(search_metrics.get("cache_hits", 0) or 0)
                record["status"] = (
                    "cache_hit"
                    if record["cache_hits"]
                    else ("success" if found or record["api_requests"] else "skipped")
                )
                if search_metrics.get("warning"):
                    warning = str(search_metrics["warning"])
                return found, record, warning
            except Exception as exc:
                record["status"] = "failed"
                record["error"] = str(exc)
                warning = f"Broad web search failed for {item['purpose']}: {exc}"
                return [], record, warning

        workers = min(BROAD_WEB_QUERY_WORKERS, len(query_plan))
        if workers <= 1:
            completed = [run_query(item) for item in query_plan]
        else:
            ordered: Dict[int, Any] = {}
            with ThreadPoolExecutor(
                max_workers=workers,
                thread_name_prefix="phase2-broad-query",
            ) as executor:
                futures = {
                    executor.submit(run_query, item): index
                    for index, item in enumerate(query_plan)
                }
                for future in as_completed(futures):
                    index = futures[future]
                    try:
                        ordered[index] = future.result()
                    except Exception as exc:
                        item = query_plan[index]
                        ordered[index] = (
                            [],
                            {
                                "connector": "broad_web",
                                "provider": provider,
                                "purpose": item["purpose"],
                                "query": item["query"],
                                "includes_email": bool(item.get("includes_email")),
                                "status": "failed",
                                "api_requests": 0,
                                "cache_hits": 0,
                                "error": str(exc),
                            },
                            f"Broad-web worker failed: {exc}",
                        )
            completed = [ordered[index] for index in sorted(ordered)]

        for found, record, warning in completed:
            job_results.extend(found)
            records.append(record)
            job_metrics["broad_web_api_requests"] += int(record.get("api_requests", 0) or 0)
            job_metrics["broad_web_cache_hits"] += int(record.get("cache_hits", 0) or 0)
            if warning:
                job_warnings.append(warning)

        return {
            "results": job_results,
            "records": records,
            "warnings": job_warnings,
            "metrics": job_metrics,
        }

    def targeted_profiles_job() -> Dict[str, Any]:
        if not targeted_profile_queries or not provider:
            return {
                "results": [],
                "records": [],
                "warnings": [],
                "metrics": {
                    "targeted_profile_api_requests": 0,
                    "targeted_profile_cache_hits": 0,
                },
            }

        results: List[Dict[str, Any]] = []
        records: List[Dict[str, Any]] = []
        warnings: List[str] = []
        api_requests = 0
        cache_hits = 0

        def run_one(item: Dict[str, str]) -> Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, Any]]:
            record = {
                "connector": "targeted_profile_search",
                "provider": provider,
                "purpose": item["purpose"],
                "query": item["query"],
                "includes_email": False,
                "status": "planned",
                "api_requests": 0,
                "cache_hits": 0,
            }
            try:
                found, search_metrics = cached_broad_web_search(
                    item["query"],
                    provider=provider,
                    max_results=TARGETED_PROFILE_RESULTS_PER_QUERY,
                    allow_network=allow_network,
                )
                record["api_requests"] = int(search_metrics.get("api_requests", 0) or 0)
                record["cache_hits"] = int(search_metrics.get("cache_hits", 0) or 0)
                record["status"] = (
                    "cache_hit"
                    if record["cache_hits"]
                    else ("success" if found or record["api_requests"] else "skipped")
                )
                if search_metrics.get("warning"):
                    record["warning"] = str(search_metrics["warning"])
                return found, record, {}
            except Exception as exc:
                record["status"] = "failed"
                record["error"] = str(exc)
                return [], record, {"warning": f"Targeted profile search failed for {item['purpose']}: {exc}"}

        workers = min(TARGETED_PROFILE_WORKERS, len(targeted_profile_queries))
        if workers <= 1:
            completed = [run_one(item) for item in targeted_profile_queries]
        else:
            completed = []
            with ThreadPoolExecutor(
                max_workers=workers,
                thread_name_prefix="phase2-profile-search",
            ) as executor:
                futures = {
                    executor.submit(run_one, item): index
                    for index, item in enumerate(targeted_profile_queries)
                }
                ordered: Dict[int, Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, Any]]] = {}
                for future in as_completed(futures):
                    index = futures[future]
                    try:
                        ordered[index] = future.result()
                    except Exception as exc:
                        item = targeted_profile_queries[index]
                        ordered[index] = (
                            [],
                            {
                                "connector": "targeted_profile_search",
                                "provider": provider,
                                "purpose": item["purpose"],
                                "query": item["query"],
                                "includes_email": False,
                                "status": "failed",
                                "api_requests": 0,
                                "cache_hits": 0,
                                "error": str(exc),
                            },
                            {"warning": f"Targeted profile worker failed: {exc}"},
                        )
                completed = [ordered[index] for index in sorted(ordered)]

        for found, record, extra in completed:
            results.extend(found)
            records.append(record)
            api_requests += int(record.get("api_requests", 0) or 0)
            cache_hits += int(record.get("cache_hits", 0) or 0)
            if extra.get("warning"):
                warnings.append(str(extra["warning"]))
            if record.get("warning"):
                warnings.append(str(record["warning"]))

        return {
            "results": results,
            "records": records,
            "warnings": warnings,
            "metrics": {
                "targeted_profile_api_requests": api_requests,
                "targeted_profile_cache_hits": cache_hits,
            },
        }

    def youtube_job() -> Dict[str, Any]:
        if not youtube_query:
            return {"results": [], "records": [], "warnings": [], "metrics": {}}
        record = {
            "connector": "youtube",
            "provider": "YouTube Data API",
            "purpose": "name_or_username_media_search",
            "query": youtube_query,
            "includes_email": False,
            "status": "planned",
            "api_requests": 0,
            "cache_hits": 0,
        }
        warnings: List[str] = []
        results: List[Dict[str, Any]] = []
        try:
            youtube_results, youtube_metrics = cached_youtube_search(
                youtube_query,
                max_results=youtube_max_results,
                allow_network=allow_network,
            )
            results.extend(youtube_results)
            record["api_requests"] = youtube_metrics["api_requests"]
            record["cache_hits"] = youtube_metrics["cache_hits"]
            record["status"] = (
                "cache_hit"
                if record["cache_hits"]
                else ("success" if record["api_requests"] else "skipped")
            )
        except Exception as exc:
            record["status"] = "failed"
            record["error"] = str(exc)
            warnings.append(f"YouTube search failed: {exc}")
        return {
            "results": results,
            "records": [record],
            "warnings": warnings,
            "metrics": {
                "youtube_api_requests": int(record["api_requests"] or 0),
                "youtube_cache_hits": int(record["cache_hits"] or 0),
            },
        }

    def github_job() -> Dict[str, Any]:
        username = str(profile.get("username") or "")
        if not username:
            return {"results": [], "records": [], "warnings": [], "metrics": {}}
        record = {
            "connector": "github",
            "provider": "GitHub REST API",
            "purpose": "exact_username_lookup",
            "query": username,
            "includes_email": False,
            "status": "planned",
            "api_requests": 0,
            "cache_hits": 0,
        }
        warnings: List[str] = []
        results: List[Dict[str, Any]] = []
        try:
            github_results, github_metrics = cached_github_lookup(
                username,
                allow_network=allow_network,
            )
            results.extend(github_results)
            record["api_requests"] = github_metrics["api_requests"]
            record["cache_hits"] = github_metrics["cache_hits"]
            record["status"] = (
                "cache_hit"
                if record["cache_hits"]
                else ("success" if record["api_requests"] else "skipped")
            )
        except Exception as exc:
            record["status"] = "failed"
            record["error"] = str(exc)
            warnings.append(f"GitHub lookup failed: {exc}")
        return {
            "results": results,
            "records": [record],
            "warnings": warnings,
            "metrics": {
                "github_api_requests": int(record["api_requests"] or 0),
                "github_cache_hits": int(record["cache_hits"] or 0),
            },
        }

    jobs = [
        ("broad_web", broad_web_job) if query_plan else None,
        ("targeted_profiles", targeted_profiles_job) if targeted_profile_queries else None,
        ("youtube", youtube_job) if youtube_query else None,
        ("github", github_job) if profile.get("username") else None,
    ]
    jobs = [job for job in jobs if job is not None]

    job_outputs: Dict[str, Dict[str, Any]] = {}
    if len(jobs) <= 1 or PHASE2_CONNECTOR_WORKERS <= 1:
        for name, job in jobs:
            job_outputs[name] = job()
    else:
        with ThreadPoolExecutor(
            max_workers=min(PHASE2_CONNECTOR_WORKERS, len(jobs)),
            thread_name_prefix="phase2-connector",
        ) as executor:
            futures = {executor.submit(job): name for name, job in jobs}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    job_outputs[name] = future.result()
                except Exception as exc:
                    job_outputs[name] = {
                        "results": [],
                        "records": [],
                        "warnings": [f"{name} connector worker failed: {exc}"],
                        "metrics": {},
                    }

    results: List[Dict[str, Any]] = []
    executed_queries: List[Dict[str, Any]] = []
    warnings: List[str] = []
    for name in ("broad_web", "targeted_profiles", "youtube", "github"):
        output = job_outputs.get(name)
        if not output:
            continue
        results.extend(output.get("results", []))
        executed_queries.extend(output.get("records", []))
        warnings.extend(output.get("warnings", []))
        for key, value in output.get("metrics", {}).items():
            if key in metrics:
                metrics[key] += int(value or 0)

    unique = core.dedupe_results(results)
    enriched, extraction_metrics = core.enrich_with_content(unique)

    return {
        "artifact_type": "raw_scan",
        "phase": PHASE,
        "version": VERSION,
        "scan_id": scan_id,
        "scan_time": scan_time,
        "input_profile": profile,
        "network_mode": ("network_allowed" if allow_network else "cache_only"),
        "web_search_provider": provider,
        "web_query_plan": query_plan,
        "executed_queries": executed_queries,
        "connector_metrics": metrics,
        "extraction_metrics": extraction_metrics,
        "warnings": list(dict.fromkeys(warnings)),
        "raw_results_count": len(results),
        "unique_results_count": len(unique),
        "candidates": enriched,
    }


# ---------------------------------------------------------------------------
# Analysis report and report-ready metrics
# ---------------------------------------------------------------------------

def count_values(
    results: Sequence[Dict[str, Any]],
    key: str,
) -> Dict[str, int]:
    counter = Counter(
        str(result.get(key) or "Unknown")
        for result in results
    )
    return dict(sorted(counter.items()))


def evaluation_metrics(
    all_results: Sequence[Dict[str, Any]],
    retained: Sequence[Dict[str, Any]],
    raw_scan: Dict[str, Any],
) -> Dict[str, Any]:
    total = len(all_results)
    rejected = sum(
        1 for result in all_results
        if result.get("identity_status") == "Rejected"
    )
    strong_or_confirmed = sum(
        1 for result in retained
        if result.get("identity_status") in {"Strong", "Confirmed"}
    )
    snippet_only = sum(
        1 for result in retained
        if result.get("analysis_basis")
        == "Search-result title/snippet only"
    )
    with_contacts = sum(
        1 for result in retained
        if (
            result.get("extracted_email_addresses")
            or result.get("phone_candidates")
        )
    )

    considered = int(
        raw_scan.get("extraction_metrics", {}).get(
            "pages_considered",
            0,
        )
    )
    fetched = int(
        raw_scan.get("extraction_metrics", {}).get(
            "pages_fetched",
            0,
        )
    )

    return {
        "filter_rejection_rate_percent": round(
            (rejected / total * 100) if total else 0,
            2,
        ),
        "strong_or_confirmed_share_percent": round(
            (
                strong_or_confirmed / len(retained) * 100
                if retained
                else 0
            ),
            2,
        ),
        "snippet_only_share_percent": round(
            (
                snippet_only / len(retained) * 100
                if retained
                else 0
            ),
            2,
        ),
        "contact_candidate_share_percent": round(
            (
                with_contacts / len(retained) * 100
                if retained
                else 0
            ),
            2,
        ),
        "content_fetch_coverage_percent": round(
            (fetched / considered * 100) if considered else 0,
            2,
        ),
        "broad_web_api_requests": raw_scan.get(
            "connector_metrics",
            {},
        ).get("broad_web_api_requests", 0),
        "broad_web_cache_hits": raw_scan.get(
            "connector_metrics",
            {},
        ).get("broad_web_cache_hits", 0),
        "targeted_profile_queries": raw_scan.get(
            "connector_metrics",
            {},
        ).get("targeted_profile_queries", 0),
        "targeted_profile_api_requests": raw_scan.get(
            "connector_metrics",
            {},
        ).get("targeted_profile_api_requests", 0),
        "targeted_profile_cache_hits": raw_scan.get(
            "connector_metrics",
            {},
        ).get("targeted_profile_cache_hits", 0),
        "offline_reanalysis": True,
        "accuracy_note": (
            "These are operational metrics, not precision/recall. "
            "Ground-truth labels are required for accuracy claims."
        ),
    }


def build_key_findings(
    retained: Sequence[Dict[str, Any]],
    raw_scan: Dict[str, Any],
) -> List[str]:
    findings: List[str] = []

    status_counts = Counter(
        result["identity_status"]
        for result in retained
    )
    recommendation_counts = Counter(
        result["recommendation_action"]
        for result in retained
    )
    category_counts = Counter(
        result["source_category"]
        for result in retained
    )

    findings.append(
        f"{len(retained)} reviewable footprints were retained from "
        f"{raw_scan.get('unique_results_count', len(retained))} unique "
        f"candidates."
    )

    findings.append(
        "Identity confidence: "
        + ", ".join(
            f"{status}={count}"
            for status, count in sorted(status_counts.items())
        )
        + "."
    )

    if category_counts:
        findings.append(
            "Most common source categories: "
            + ", ".join(
                f"{category}={count}"
                for category, count in category_counts.most_common(4)
            )
            + "."
        )

    if recommendation_counts:
        findings.append(
            "Recommended actions: "
            + ", ".join(
                f"{action}={count}"
                for action, count in recommendation_counts.most_common()
            )
            + "."
        )

    contact_results = [
        result
        for result in retained
        if (
            result.get("extracted_email_addresses")
            or result.get("phone_candidates")
            or "advertised" in str(
                result.get("privacy_exposure_status") or ""
            ).casefold()
        )
    ]

    if contact_results:
        findings.append(
            f"{len(contact_results)} retained result(s) contained visible "
            f"contact candidates or advertised contact availability."
        )
    else:
        findings.append(
            "No visible email or phone values were associated with a "
            "verified identity in the accessible content."
        )

    return findings


def build_visual_review_items(
    all_results: Sequence[Dict[str, Any]],
    scan_id: str,
) -> List[Dict[str, Any]]:
    """Build local manual-review records for fetched page images.

    Rejected text candidates are hidden when dlib detected zero faces and no
    visual similarity. This removes obvious banners/logos such as unrelated
    college assets while preserving image-only candidates that contain a face.
    """
    items: List[Dict[str, Any]] = []

    for result in all_results:
        visual_meta = result.get("visual_identity") or {}
        page_url = str(result.get("url") or result.get("canonical_url") or "")
        page_title = str(result.get("title") or "Untitled result")
        rejected_text = result.get("identity_status") == "Rejected"

        for image in visual_meta.get("image_evidence", []) or []:
            cache_file = str(image.get("cache_file") or "")
            if not cache_file:
                continue

            faces = int(image.get("faces_detected", 0) or 0)
            strength = str(image.get("automated_match_strength") or "Unavailable")
            if rejected_text and faces == 0 and strength.casefold() not in {
                "strong", "possible"
            }:
                continue

            image_id = str(image.get("image_id") or "")
            review_key = f"{scan_id}|{page_url}|{image_id}"
            review_id = hashlib.sha256(review_key.encode("utf-8")).hexdigest()[:20]

            items.append({
                "review_id": review_id,
                "scan_id": scan_id,
                "page_title": page_title,
                "page_url": page_url,
                "domain": domain_of(page_url),
                "source_category": result.get("source_category", ""),
                "identity_status_before_manual_review": result.get(
                    "identity_status", ""
                ),
                "identity_score_before_manual_review": result.get(
                    "identity_score"
                ),
                "source_image_url": image.get("source_image_url", ""),
                "cache_file": cache_file,
                "width": image.get("width"),
                "height": image.get("height"),
                "faces_detected": faces,
                "automated_best_face_distance": image.get(
                    "automated_best_face_distance"
                ),
                "automated_match_strength": strength,
                "manual_verification": image.get(
                    "manual_verification", "unreviewed"
                ),
                "discovery_method": "page_image_extraction",
                "discovery_queries": [],
                "image_description": "",
            })

    return items


def build_independent_visual_review_items(
    raw_scan: Dict[str, Any],
    scan_id: str,
) -> List[Dict[str, Any]]:
    """Convert identity-guided Tavily image-search evidence into review cards."""
    items: List[Dict[str, Any]] = []
    discovery = raw_scan.get("independent_visual_discovery", {}) or {}

    for image in discovery.get("image_evidence", []) or []:
        cache_file = str(image.get("cache_file") or "")
        if not cache_file:
            continue

        image_url = str(image.get("source_image_url") or "")
        page_url = str(image.get("source_page_url") or image_url)
        page_title = str(
            image.get("source_page_title")
            or image.get("image_description")
            or "Independent visual discovery"
        )
        image_id = str(image.get("image_id") or "")
        review_key = f"{scan_id}|independent|{page_url}|{image_id}"
        review_id = hashlib.sha256(review_key.encode("utf-8")).hexdigest()[:20]

        items.append({
            "review_id": review_id,
            "scan_id": scan_id,
            "page_title": page_title,
            "page_url": page_url,
            "domain": domain_of(page_url or image_url),
            "source_category": "Independent visual discovery",
            "identity_status_before_manual_review": "Visual candidate",
            "identity_score_before_manual_review": None,
            "source_image_url": image_url,
            "cache_file": cache_file,
            "width": image.get("width"),
            "height": image.get("height"),
            "faces_detected": int(image.get("faces_detected", 0) or 0),
            "automated_best_face_distance": image.get(
                "automated_best_face_distance"
            ),
            "automated_match_strength": image.get(
                "automated_match_strength", "Unavailable"
            ),
            "manual_verification": image.get(
                "manual_verification", "unreviewed"
            ),
            "discovery_method": "independent_tavily_image_search",
            "discovery_queries": list(image.get("discovery_queries") or []),
            "discovery_anchor_types": list(
                image.get("discovery_anchor_types") or []
            ),
            "context_terms": list(image.get("context_terms") or []),
            "image_description": str(image.get("image_description") or ""),
            "retrieval_scope": str(image.get("retrieval_scope") or ""),
        })

    return items


def analyze_raw_scan(
    raw_scan: Dict[str, Any],
    profile_override: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    profile = profile_override or raw_scan.get("input_profile") or {}

    candidates = raw_scan.get("candidates")
    if candidates is None:
        # Support older Phase 2 reports that contain only retained results.
        candidates = raw_scan.get("results", [])

    all_results = analyze_candidates(candidates, profile)
    scan_id = str(raw_scan.get("scan_id") or "")
    visual_review_items = build_visual_review_items(
        all_results,
        scan_id,
    )
    visual_review_items.extend(
        build_independent_visual_review_items(raw_scan, scan_id)
    )

    retained = [
        result
        for result in all_results
        if result.get("identity_status")
        in {"Confirmed", "Strong", "Possible"}
    ]
    rejected = [
        result
        for result in all_results
        if result.get("identity_status") == "Rejected"
    ]

    priority = {
        "Confirmed": 3,
        "Strong": 2,
        "Possible": 1,
        "Rejected": 0,
    }

    retained.sort(
        key=lambda result: (
            priority.get(result.get("identity_status"), 0),
            (
                result.get("risk_score")
                if result.get("risk_score") is not None
                else -1
            ),
            result.get("identity_score", 0),
        ),
        reverse=True,
    )

    summary = {
        "candidate_results": len(all_results),
        "retained_matches": len(retained),
        "rejected_results": len(rejected),
        "confirmed_matches": sum(
            result["identity_status"] == "Confirmed"
            for result in retained
        ),
        "strong_matches": sum(
            result["identity_status"] == "Strong"
            for result in retained
        ),
        "possible_matches": sum(
            result["identity_status"] == "Possible"
            for result in retained
        ),
        "results_with_visible_email": sum(
            bool(result.get("extracted_email_addresses"))
            for result in retained
        ),
        "results_with_visible_phone": sum(
            bool(result.get("phone_candidates"))
            for result in retained
        ),
        "data_broker_results": sum(
            result.get("source_category")
            == "Data broker/contact aggregator"
            for result in retained
        ),
        "visual_search_status": (
            raw_scan.get("visual_identity_summary", {}).get("status", "not_used")
        ),
        "visual_match_count": int(
            raw_scan.get("visual_identity_summary", {}).get(
                "visual_match_count", 0
            ) or 0
        ),
        "visual_candidate_faces_checked": int(
            raw_scan.get("visual_identity_summary", {}).get(
                "candidate_faces_checked", 0
            ) or 0
        ),
        "visual_candidate_images_checked": int(
            raw_scan.get("visual_identity_summary", {}).get(
                "candidate_images_checked", 0
            ) or 0
        ),
        "visual_independent_query_count": int(
            raw_scan.get("visual_identity_summary", {}).get(
                "independent_query_count", 0
            ) or 0
        ),
        "visual_independent_images_discovered": int(
            raw_scan.get("visual_identity_summary", {}).get(
                "independent_images_discovered", 0
            ) or 0
        ),
        "visual_independent_images_checked": int(
            raw_scan.get("visual_identity_summary", {}).get(
                "independent_images_checked", 0
            ) or 0
        ),
        "visual_independent_faces_checked": int(
            raw_scan.get("visual_identity_summary", {}).get(
                "independent_faces_checked", 0
            ) or 0
        ),
        "visual_independent_matches": int(
            raw_scan.get("visual_identity_summary", {}).get(
                "independent_match_count", 0
            ) or 0
        ),
        "visual_reviewable_images": len(visual_review_items),
        "visual_manual_confirmed_images": sum(
            item.get("manual_verification") == "confirmed"
            for item in visual_review_items
        ),
    }

    compact_rejected = [
        {
            "title": result.get("title"),
            "url": result.get("url"),
            "source": result.get("source"),
            "match_reasons": result.get("match_reasons"),
            "match_type": result.get("match_type"),
            "rejection_reason": result.get("rejection_reason"),
        }
        for result in rejected
    ]

    report = {
        "artifact_type": "analysis_report",
        "phase": PHASE,
        "version": VERSION,
        "analysis_id": uuid4().hex,
        "analysis_time": utc_now_iso(),
        "source_scan_id": raw_scan.get("scan_id"),
        "source_scan_time": raw_scan.get("scan_time"),
        "source_artifact_type": raw_scan.get(
            "artifact_type",
            "legacy_phase2_report",
        ),
        "visual_identity_summary": raw_scan.get(
            "visual_identity_summary",
            {"status": "not_used", "raw_reference_image_retained": False},
        ),
        "input_profile": profile,
        "executed_queries": raw_scan.get("executed_queries", []),
        "connector_metrics": raw_scan.get("connector_metrics", {}),
        "extraction_metrics": raw_scan.get("extraction_metrics", {}),
        "warnings": raw_scan.get("warnings", []),
        "summary": summary,
        "category_counts": count_values(
            retained,
            "source_category",
        ),
        "identity_status_counts": count_values(
            retained,
            "identity_status",
        ),
        "recommendation_counts": count_values(
            retained,
            "recommendation_action",
        ),
        "risk_level_counts": count_values(
            retained,
            "risk_level",
        ),
        "evidence_basis_counts": count_values(
            retained,
            "analysis_basis",
        ),
        "evaluation_metrics": evaluation_metrics(
            all_results,
            retained,
            raw_scan,
        ),
        "key_findings": build_key_findings(
            retained,
            raw_scan,
        ),
        "limitations": [
            "Blocked, login-only, paywalled, or robots-restricted pages "
            "cannot reveal hidden contact values.",
            "A title such as 'Email & Phone Number' indicates advertised "
            "contact availability but does not prove the actual values.",
            "Cross-source corroboration strengthens identity confidence but "
            "does not replace manual review for consequential removal action.",
            "Search coverage depends on provider indexing and the supplied "
            "identity anchors.",
        ],
        "visual_review_items": visual_review_items,
        "results": retained,
        "rejected_results": compact_rejected,
    }

    return report


# ---------------------------------------------------------------------------
# Persistence and CSV exports
# ---------------------------------------------------------------------------

def timestamp_for_filename(iso_time: str) -> str:
    return datetime.fromisoformat(iso_time).strftime(
        "%Y%m%d_%H%M%S_%f"
    )


def save_raw_scan(raw_scan: Dict[str, Any]) -> Dict[str, str]:
    RAW_SCANS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = timestamp_for_filename(raw_scan["scan_time"])
    person = safe_filename_component(
        raw_scan.get("input_profile", {}).get("full_name", "")
    )

    raw_path = RAW_SCANS_DIR / (
        f"raw_scan_{person}_{timestamp}.json"
    )
    latest_path = RAW_SCANS_DIR / "latest_raw_scan.json"
    history_path = REPORTS_DIR / "scan_history.jsonl"
    query_history_path = REPORTS_DIR / "query_history.jsonl"

    raw_scan["saved_files"] = {
        "timestamped_raw_scan": str(raw_path),
        "latest_raw_scan": str(latest_path),
        "scan_history": str(history_path),
        "query_history": str(query_history_path),
    }

    write_json(raw_path, raw_scan)
    write_json(latest_path, raw_scan)

    append_jsonl(
        history_path,
        {
            "artifact_type": "raw_scan",
            "scan_id": raw_scan.get("scan_id"),
            "scan_time": raw_scan.get("scan_time"),
            "input_profile": raw_scan.get("input_profile"),
            "connector_metrics": raw_scan.get("connector_metrics"),
            "raw_results_count": raw_scan.get("raw_results_count"),
            "unique_results_count": raw_scan.get(
                "unique_results_count"
            ),
            "raw_scan_file": str(raw_path),
        },
    )

    for query in raw_scan.get("executed_queries", []):
        append_jsonl(
            query_history_path,
            {
                "scan_id": raw_scan.get("scan_id"),
                "scan_time": raw_scan.get("scan_time"),
                "full_name": raw_scan.get(
                    "input_profile",
                    {},
                ).get("full_name", ""),
                **query,
            },
        )

    return raw_scan["saved_files"]


def flatten_for_csv(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "identity_status": result.get("identity_status"),
        "identity_score": result.get("identity_score"),
        "risk_level": result.get("risk_level"),
        "risk_score": result.get("risk_score"),
        "source_category": result.get("source_category"),
        "result_subtype": result.get("result_subtype"),
        "title": result.get("title"),
        "url": result.get("url"),
        "source": result.get("source"),
        "analysis_basis": result.get("analysis_basis"),
        "evidence_quality": result.get("evidence_quality"),
        "privacy_exposure_status": result.get(
            "privacy_exposure_status"
        ),
        "emails": "; ".join(
            result.get("extracted_email_addresses", [])
        ),
        "phones": "; ".join(
            result.get("phone_candidates", [])
        ),
        "detected_exposures": "; ".join(
            result.get("detected_exposures", [])
        ),
        "candidate_exposures": "; ".join(
            result.get("candidate_exposures", [])
        ),
        "recommendation_action": result.get(
            "recommendation_action"
        ),
        "recommendation_reason": result.get(
            "recommendation_reason"
        ),
        "match_reasons": "; ".join(
            result.get("match_reasons", [])
        ),
    }


def write_csv(
    path: Path,
    rows: Sequence[Dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    if not rows:
        path.write_text("", encoding="utf-8")
        return

    fieldnames = list(rows[0].keys())

    with path.open(
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(rows)


def save_analysis_report(report: Dict[str, Any]) -> Dict[str, str]:
    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = timestamp_for_filename(report["analysis_time"])
    person = safe_filename_component(
        report.get("input_profile", {}).get("full_name", "")
    )

    report_path = ANALYSIS_DIR / (
        f"analysis_{person}_{timestamp}.json"
    )
    latest_path = ANALYSIS_DIR / "latest_analysis.json"
    results_csv = EXPORTS_DIR / (
        f"results_{person}_{timestamp}.csv"
    )
    queries_csv = EXPORTS_DIR / (
        f"queries_{person}_{timestamp}.csv"
    )
    contacts_csv = EXPORTS_DIR / (
        f"contact_evidence_{person}_{timestamp}.csv"
    )
    analysis_history = REPORTS_DIR / "analysis_history.jsonl"

    result_rows = [
        flatten_for_csv(result)
        for result in report.get("results", [])
    ]

    query_rows = [
        {
            "connector": query.get("connector"),
            "provider": query.get("provider"),
            "purpose": query.get("purpose"),
            "query": query.get("query"),
            "status": query.get("status"),
            "api_requests": query.get("api_requests"),
            "cache_hits": query.get("cache_hits"),
            "includes_email": query.get("includes_email"),
        }
        for query in report.get("executed_queries", [])
    ]

    contact_rows: List[Dict[str, Any]] = []

    for result in report.get("results", []):
        for evidence in result.get("contact_evidence", []):
            contact_rows.append({
                "title": result.get("title"),
                "url": result.get("url"),
                "identity_status": result.get("identity_status"),
                "contact_type": evidence.get("type"),
                "value": evidence.get("value"),
                "confidence": evidence.get("confidence"),
                "visibility": evidence.get("visibility"),
                "source_field": evidence.get("source_field"),
                "identity_anchor_type": evidence.get(
                    "identity_anchor",
                    {},
                ).get("type"),
                "identity_anchor_value": evidence.get(
                    "identity_anchor",
                    {},
                ).get("value"),
                "evidence_excerpt": evidence.get(
                    "evidence_excerpt"
                ),
            })

    report["saved_files"] = {
        "timestamped_analysis": str(report_path),
        "latest_analysis": str(latest_path),
        "results_csv": str(results_csv),
        "queries_csv": str(queries_csv),
        "contact_evidence_csv": str(contacts_csv),
        "analysis_history": str(analysis_history),
    }

    write_json(report_path, report)
    write_json(latest_path, report)
    write_csv(results_csv, result_rows)
    write_csv(queries_csv, query_rows)
    write_csv(contacts_csv, contact_rows)

    append_jsonl(
        analysis_history,
        {
            "artifact_type": "analysis_report",
            "analysis_id": report.get("analysis_id"),
            "analysis_time": report.get("analysis_time"),
            "source_scan_id": report.get("source_scan_id"),
            "input_profile": report.get("input_profile"),
            "summary": report.get("summary"),
            "evaluation_metrics": report.get(
                "evaluation_metrics"
            ),
            "analysis_file": str(report_path),
        },
    )

    return report["saved_files"]


# ---------------------------------------------------------------------------
# Legacy import and interactive profile collection
# ---------------------------------------------------------------------------

def extract_profile_from_legacy(
    artifact: Dict[str, Any],
) -> Dict[str, Any]:
    profile = artifact.get("input_profile")

    if profile:
        context_terms = profile.get("context_terms", [])
        if isinstance(context_terms, str):
            context_terms = core.parse_context_terms(context_terms)

        return build_profile(
            profile.get("full_name", ""),
            profile.get("email", ""),
            profile.get("username", ""),
            profile.get("phone", ""),
            context_terms,
        )

    return build_profile("", "", "", "", [])


def artifact_to_raw_scan(
    artifact: Dict[str, Any],
    profile: Dict[str, Any],
) -> Dict[str, Any]:
    if artifact.get("artifact_type") == "raw_scan":
        copied = dict(artifact)
        copied["input_profile"] = profile
        return copied

    candidates = artifact.get("candidates")
    if candidates is None:
        candidates = artifact.get("results", [])

    return {
        "artifact_type": "raw_scan",
        "phase": PHASE,
        "version": VERSION,
        "scan_id": artifact.get("scan_id") or uuid4().hex,
        "scan_time": artifact.get("scan_time") or utc_now_iso(),
        "input_profile": profile,
        "network_mode": "legacy_import_no_network",
        "web_search_provider": artifact.get(
            "web_search_provider"
        ),
        "web_query_plan": artifact.get("web_query_plan", []),
        "executed_queries": artifact.get(
            "executed_queries",
            [
                {
                    "connector": "broad_web",
                    "provider": artifact.get(
                        "web_search_provider"
                    ),
                    "purpose": "legacy_saved_query",
                    "query": artifact.get(
                        "web_search_query",
                        "",
                    ),
                    "status": "imported",
                    "api_requests": artifact.get(
                        "connector_metrics",
                        {},
                    ).get("broad_web_api_requests", 0),
                    "cache_hits": artifact.get(
                        "connector_metrics",
                        {},
                    ).get("broad_web_cache_hits", 0),
                },
                {
                    "connector": "youtube",
                    "provider": "YouTube Data API",
                    "purpose": "legacy_saved_query",
                    "query": artifact.get(
                        "youtube_search_query",
                        "",
                    ),
                    "status": "imported",
                    "api_requests": artifact.get(
                        "connector_metrics",
                        {},
                    ).get("youtube_api_requests", 0),
                    "cache_hits": 0,
                },
            ],
        ),
        "connector_metrics": artifact.get(
            "connector_metrics",
            {},
        ),
        "extraction_metrics": artifact.get(
            "extraction_metrics",
            {},
        ),
        "warnings": list(artifact.get("warnings", [])) + [
            "This analysis was imported from an older report. "
            "Only the results stored in that file can be reanalysed."
        ],
        "raw_results_count": artifact.get(
            "summary",
            {},
        ).get("raw_results", len(candidates)),
        "unique_results_count": artifact.get(
            "summary",
            {},
        ).get("unique_results", len(candidates)),
        "candidates": [
            strip_old_analysis_fields(result)
            for result in candidates
        ],
    }


def prompt_context_terms(default: Sequence[str]) -> List[str]:
    default_text = ", ".join(default)
    prompt = "Context terms, comma-separated"

    if default_text:
        prompt += f" [{default_text}]"

    value = input(prompt + ": ").strip()

    if not value:
        return list(default)

    return core.parse_context_terms(value)


def prompt_profile(
    default: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    default = default or {}

    def ask(label: str, key: str) -> str:
        current = str(default.get(key) or "")
        suffix = f" [{current}]" if current else ""
        value = input(f"{label}{suffix}: ").strip()
        return value or current

    full_name = ask("Full name", "full_name")
    email = ask("Email", "email")
    username = ask("Username", "username")
    phone = ask(
        "Phone (verification/exposure only)",
        "phone",
    )
    context_terms = prompt_context_terms(
        default.get("context_terms", []),
    )

    return build_profile(
        full_name,
        email,
        username,
        phone,
        context_terms,
    )


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------

def print_report(report: Dict[str, Any]) -> None:
    print("\n=== Phase 2A Public-Footprint Analysis Summary ===")

    for key, value in report.get("summary", {}).items():
        print(f"{key.replace('_', ' ').title()}: {value}")

    print("\n=== Evaluation Metrics ===")
    for key, value in report.get("evaluation_metrics", {}).items():
        print(f"{key.replace('_', ' ').title()}: {value}")

    print("\n=== Key Findings ===")
    for finding in report.get("key_findings", []):
        print(f"- {finding}")

    print("\n=== Retained Matches ===")

    results = report.get("results", [])

    if not results:
        print("No reviewable identity matches were retained.")
        return

    for index, result in enumerate(results, 1):
        risk_score = result.get("risk_score")
        risk_display = (
            f"{risk_score}/100"
            if risk_score is not None
            else result.get("risk_level")
        )

        print(
            f"\n[{index}] {result.get('source_category')} | "
            f"{result.get('identity_status')} "
            f"(Identity {result.get('identity_score')}/100) | "
            f"Risk {risk_display}"
        )
        print("Title :", result.get("title", ""))
        print("URL   :", result.get("url", ""))
        print("Basis :", result.get("analysis_basis", ""))
        print("Why   :", "; ".join(result.get("match_reasons", [])))
        print(
            "Exposure:",
            result.get("privacy_exposure_status", ""),
        )

        if result.get("extracted_email_addresses"):
            print(
                "Emails:",
                ", ".join(
                    result["extracted_email_addresses"]
                ),
            )

        if result.get("phone_candidates"):
            print(
                "Phones:",
                ", ".join(result["phone_candidates"]),
            )

        print(
            "Action:",
            result.get("recommendation_action", ""),
            "—",
            result.get("removal_suggestion", ""),
        )


def print_saved_files(files: Dict[str, str]) -> None:
    print("\nSaved files:")

    for label, path in files.items():
        print(f"- {label.replace('_', ' ').title()}: {path}")


# ---------------------------------------------------------------------------
# Programmatic Layer 2A entry point
# ---------------------------------------------------------------------------

def run_layer1(
    profile: Dict[str, Any],
    *,
    allow_network: bool = True,
    save_outputs: bool = True,
    web_max_results: int = core.DEFAULT_WEB_RESULTS,
    youtube_max_results: int = core.DEFAULT_YOUTUBE_RESULTS,
    consent_visual_search: bool = False,
    reference_image_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Run public-footprint discovery for ``run_all.py``.

    The function preserves the same profile fields used by the standalone
    program and returns both the raw scan and filtered analysis report.
    """
    raw_scan = create_raw_scan(
        profile,
        allow_network=allow_network,
        web_max_results=web_max_results,
        youtube_max_results=youtube_max_results,
    )
    raw_scan["independent_visual_discovery"] = {
        "status": "not_used",
        "reason": "",
        "query_count": 0,
        "images_discovered": 0,
        "candidate_images_checked": 0,
        "candidate_faces_checked": 0,
        "visual_match_count": 0,
        "reviewable_images": 0,
        "image_evidence": [],
        "query_log": [],
        "warnings": [],
    }

    if consent_visual_search and not allow_network:
        visual_summary = {
            "status": "skipped_network_disabled",
            "reason": "Visual web matching requires network access and does not run in cache-only mode.",
            "candidate_results_checked": 0,
            "candidate_images_checked": 0,
            "candidate_faces_checked": 0,
            "visual_match_count": 0,
            "independent_query_count": 0,
            "independent_images_discovered": 0,
            "independent_images_checked": 0,
            "independent_faces_checked": 0,
            "independent_match_count": 0,
            "raw_reference_image_retained": False,
            "embedding_persisted": False,
        }
    elif consent_visual_search and reference_image_path:
        visual_cache_dir = (
            REPORTS_DIR
            / "visual_cache"
            / str(raw_scan.get("scan_id") or "current")
        )

        page_summary = visual.apply_visual_matching_to_candidates(
            raw_scan.get("candidates", []),
            reference_image_path,
            cache_dir=visual_cache_dir,
        )

        if page_summary.get("status") == "completed":
            independent = visual.run_independent_visual_discovery(
                profile,
                reference_image_path,
                cache_dir=visual_cache_dir,
                allow_network=allow_network,
            )
        else:
            independent = {
                "status": "skipped_reference_unavailable",
                "reason": page_summary.get("reason", "Reference face unavailable."),
                "query_count": 0,
                "images_discovered": 0,
                "candidate_images_checked": 0,
                "candidate_faces_checked": 0,
                "visual_match_count": 0,
                "reviewable_images": 0,
                "image_evidence": [],
                "query_log": [],
                "warnings": [],
            }

        raw_scan["independent_visual_discovery"] = independent
        for warning in independent.get("warnings", []) or []:
            raw_scan.setdefault("warnings", []).append(str(warning))

        visual_summary = dict(page_summary)
        visual_summary["candidate_images_checked"] = int(
            page_summary.get("candidate_images_checked", 0) or 0
        ) + int(independent.get("candidate_images_checked", 0) or 0)
        visual_summary["candidate_faces_checked"] = int(
            page_summary.get("candidate_faces_checked", 0) or 0
        ) + int(independent.get("candidate_faces_checked", 0) or 0)
        visual_summary["visual_match_count"] = int(
            page_summary.get("visual_match_count", 0) or 0
        ) + int(independent.get("visual_match_count", 0) or 0)
        visual_summary["reviewable_images"] = int(
            page_summary.get("reviewable_images", 0) or 0
        ) + int(independent.get("reviewable_images", 0) or 0)

        visual_summary.update({
            "independent_status": independent.get("status", "not_used"),
            "independent_query_count": int(independent.get("query_count", 0) or 0),
            "independent_api_requests": int(independent.get("api_requests", 0) or 0),
            "independent_cache_hits": int(independent.get("cache_hits", 0) or 0),
            "independent_raw_image_candidates": int(
                independent.get("raw_image_candidates", 0) or 0
            ),
            "independent_unique_image_candidates": int(
                independent.get("unique_image_candidates", 0) or 0
            ),
            "independent_images_discovered": int(
                independent.get("images_discovered", 0) or 0
            ),
            "independent_images_checked": int(
                independent.get("candidate_images_checked", 0) or 0
            ),
            "independent_faces_checked": int(
                independent.get("candidate_faces_checked", 0) or 0
            ),
            "independent_match_count": int(
                independent.get("visual_match_count", 0) or 0
            ),
        })
    elif consent_visual_search and not reference_image_path:
        visual_summary = {
            "status": "no_reference_image",
            "reason": "Visual matching was authorised but no reference image was supplied.",
            "candidate_results_checked": 0,
            "candidate_images_checked": 0,
            "candidate_faces_checked": 0,
            "visual_match_count": 0,
            "independent_query_count": 0,
            "independent_images_discovered": 0,
            "independent_images_checked": 0,
            "independent_faces_checked": 0,
            "independent_match_count": 0,
            "raw_reference_image_retained": False,
            "embedding_persisted": False,
        }
    else:
        visual_summary = {
            "status": "not_used",
            "reason": "Optional visual identity matching was not authorised for this scan.",
            "candidate_results_checked": 0,
            "candidate_images_checked": 0,
            "candidate_faces_checked": 0,
            "visual_match_count": 0,
            "independent_query_count": 0,
            "independent_images_discovered": 0,
            "independent_images_checked": 0,
            "independent_faces_checked": 0,
            "independent_match_count": 0,
            "raw_reference_image_retained": False,
            "embedding_persisted": False,
        }

    raw_scan["visual_identity_summary"] = visual_summary
    if visual_summary.get("status") not in {"completed", "not_used"}:
        raw_scan.setdefault("warnings", []).append(
            str(visual_summary.get("reason") or "Visual identity matching was incomplete.")
        )

    raw_files: Dict[str, str] = {}
    if save_outputs:
        raw_files = save_raw_scan(raw_scan)

    report = analyze_raw_scan(raw_scan)
    analysis_files: Dict[str, str] = {}
    if save_outputs:
        analysis_files = save_analysis_report(report)

    return {
        "layer": "2A_public_footprints",
        "version": VERSION,
        "status": "success",
        "raw_scan": raw_scan,
        "analysis_report": report,
        "saved_files": {**raw_files, **analysis_files},
        "warnings": list(dict.fromkeys(
            raw_scan.get("warnings", []) + report.get("warnings", [])
        )),
        "errors": [],
    }


def compact_layer1_for_aggregation(
    layer_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Remove bulky fetched page bodies while preserving evidence."""
    report = dict(layer_result.get("analysis_report") or {})
    compact_results: List[Dict[str, Any]] = []
    for item in report.get("results", []):
        copied = dict(item)
        copied.pop("extracted_content", None)
        copied.pop("candidate_image_urls", None)
        if isinstance(copied.get("visual_identity"), dict):
            visual_meta = dict(copied["visual_identity"])
            visual_meta.pop("matched_image_url", None)
            copied["visual_identity"] = visual_meta
        compact_results.append(copied)
    report["results"] = compact_results

    return {
        "layer": layer_result.get("layer"),
        "version": layer_result.get("version"),
        "status": layer_result.get("status"),
        "summary": report.get("summary", {}),
        "visual_identity_summary": report.get(
            "visual_identity_summary", {"status": "not_used"}
        ),
        "visual_review_items": report.get("visual_review_items", []),
        "key_findings": report.get("key_findings", []),
        "results": compact_results,
        "rejected_results": report.get("rejected_results", []),
        "saved_files": layer_result.get("saved_files", {}),
        "warnings": layer_result.get("warnings", []),
        "errors": layer_result.get("errors", []),
    }


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

def command_scan(args: argparse.Namespace) -> None:
    print("=== Phase 2A — Fresh Public-Footprint Scan ===")
    profile = prompt_profile()

    raw_scan = create_raw_scan(
        profile,
        allow_network=not args.cache_only,
    )
    raw_files = save_raw_scan(raw_scan)

    report = analyze_raw_scan(raw_scan)
    analysis_files = save_analysis_report(report)

    print_report(report)
    print_saved_files({**raw_files, **analysis_files})


def command_reanalyse(args: argparse.Namespace) -> None:
    source_path = Path(args.path)

    if not source_path.exists():
        raise FileNotFoundError(
            f"Saved scan/report not found: {source_path}"
        )

    artifact = load_json(source_path)
    saved_profile = extract_profile_from_legacy(artifact)

    print("=== Phase 2A — Offline Reanalysis ===")
    print("No web, YouTube, or GitHub API request will be made.")

    use_saved = False
    if saved_profile.get("full_name"):
        response = input(
            "Use the saved identity profile? [Y/n]: "
        ).strip().casefold()
        use_saved = response in {"", "y", "yes"}

    profile = (
        saved_profile
        if use_saved
        else prompt_profile(saved_profile)
    )

    raw_scan = artifact_to_raw_scan(
        artifact,
        profile=profile,
    )
    report = analyze_raw_scan(raw_scan)
    files = save_analysis_report(report)

    print_report(report)
    print_saved_files(files)


def command_reanalyse_latest(
    args: argparse.Namespace,
) -> None:
    latest_path = RAW_SCANS_DIR / "latest_raw_scan.json"
    args.path = str(latest_path)
    command_reanalyse(args)


def interactive_menu() -> None:
    print("=== Digital Footprint Identification Module — Phase 2A ===")
    print("1. Fresh scan (uses cache first; may call APIs)")
    print("2. Fresh scan in cache-only mode (no API calls)")
    print("3. Reanalyse latest raw scan (no API calls)")
    print("4. Reanalyse a saved raw scan or older report (no API calls)")

    choice = input("Choose 1-4: ").strip()

    if choice == "1":
        command_scan(argparse.Namespace(cache_only=False))
    elif choice == "2":
        command_scan(argparse.Namespace(cache_only=True))
    elif choice == "3":
        command_reanalyse_latest(argparse.Namespace(path=""))
    elif choice == "4":
        path = input("Path to saved JSON file: ").strip()
        command_reanalyse(argparse.Namespace(path=path))
    else:
        raise ValueError("Invalid choice. Select 1, 2, 3, or 4.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Phase 2A public digital-footprint discovery and offline "
            "reanalysis module."
        )
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser(
        "scan",
        help="Run a fresh scan.",
    )
    scan_parser.add_argument(
        "--cache-only",
        action="store_true",
        help="Use saved API cache only and make no API requests.",
    )
    scan_parser.set_defaults(function=command_scan)

    reanalyse_parser = subparsers.add_parser(
        "reanalyse",
        help="Reanalyse a saved raw scan or older report with no API calls.",
    )
    reanalyse_parser.add_argument(
        "path",
        help="Path to a saved JSON raw scan or Phase 2 report.",
    )
    reanalyse_parser.set_defaults(function=command_reanalyse)

    latest_parser = subparsers.add_parser(
        "reanalyse-latest",
        help="Reanalyse reports/raw_scans/latest_raw_scan.json.",
    )
    latest_parser.set_defaults(function=command_reanalyse_latest)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if hasattr(args, "function"):
        args.function(args)
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
