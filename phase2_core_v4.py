import json
import os
import re
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit
from urllib import robotparser

import fitz  # PyMuPDF
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv


load_dotenv()

# -----------------------------
# Configuration
# -----------------------------

WEB_SEARCH_PROVIDER = os.getenv("WEB_SEARCH_PROVIDER", "auto").strip().lower()

BRAVE_SEARCH_API_KEY = os.getenv("BRAVE_SEARCH_API_KEY", "").strip()
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "").strip()
YOUTUBE_API_KEY = os.getenv("YOUTUBE_API_KEY", "").strip()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()

BRAVE_WEB_SEARCH_URL = "https://api.search.brave.com/res/v1/web/search"
TAVILY_SEARCH_URL = "https://api.tavily.com/search"
YOUTUBE_SEARCH_URL = "https://www.googleapis.com/youtube/v3/search"
GITHUB_USER_URL = "https://api.github.com/users/{username}"

SEARCH_CACHE_DB = os.getenv("SEARCH_CACHE_DB", "phase2_search_cache.db").strip()
SEARCH_CACHE_DAYS = int(os.getenv("SEARCH_CACHE_DAYS", "7"))
USE_SEARCH_CACHE = os.getenv("USE_SEARCH_CACHE", "true").strip().lower() == "true"

FETCH_FULL_CONTENT = os.getenv("FETCH_FULL_CONTENT", "true").strip().lower() == "true"
PHASE2_FETCH_WORKERS = max(
    1,
    min(int(os.getenv("PHASE2_FETCH_WORKERS", "6")), 12),
)
RESPECT_ROBOTS_TXT = os.getenv("RESPECT_ROBOTS_TXT", "true").strip().lower() == "true"
MAX_FETCH_BYTES = int(os.getenv("MAX_FETCH_BYTES", str(5 * 1024 * 1024)))
MAX_EXTRACTED_CHARS = int(os.getenv("MAX_EXTRACTED_CHARS", "120000"))
MAX_CANDIDATE_IMAGE_URLS = int(os.getenv("MAX_CANDIDATE_IMAGE_URLS", "12"))

DEFAULT_WEB_RESULTS = int(os.getenv("DEFAULT_WEB_RESULTS", "15"))
DEFAULT_YOUTUBE_RESULTS = int(os.getenv("DEFAULT_YOUTUBE_RESULTS", "10"))

REQUEST_TIMEOUT_SECONDS = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "20"))
USER_AGENT = os.getenv(
    "FOOTPRINT_USER_AGENT",
    "AcademicDigitalFootprintResearch/2.0 (+local student project)"
).strip()


REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "reports").strip())
IDENTITY_CONTACT_WINDOW_CHARS = int(
    os.getenv("IDENTITY_CONTACT_WINDOW_CHARS", "350")
)
TAVILY_RETRY_WITHOUT_EMAIL = (
    os.getenv("TAVILY_RETRY_WITHOUT_EMAIL", "true").strip().lower() == "true"
)

GENERIC_SITE_EMAIL_LOCAL_PARTS = {
    "admin", "advertise", "careers", "contact", "editor", "editorial",
    "help", "hello", "info", "marketing", "newsletter", "privacy",
    "sales", "subscribe", "support", "webmaster",
}

GENERIC_USERNAMES = {
    "admin", "official", "user", "test", "hello", "support", "contact",
}

TRACKING_QUERY_PARAMETERS = {
    "fbclid", "gclid", "mc_cid", "mc_eid",
    "utm_campaign", "utm_content", "utm_medium",
    "utm_source", "utm_term",
}


# -----------------------------
# Generic helpers
# -----------------------------

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def normalize_spaces(value: str) -> str:
    return " ".join((value or "").strip().split())


def normalize_phone(value: str) -> str:
    digits = re.sub(r"\D+", "", value or "")
    if len(digits) == 12 and digits.startswith("91"):
        return digits[2:]
    return digits


def is_distinctive_username(username: str) -> bool:
    username = (username or "").strip().lower()
    return len(username) >= 5 and username not in GENERIC_USERNAMES


def contains_exact_phrase(text: str, phrase: str) -> bool:
    text = normalize_spaces(text).casefold()
    phrase = normalize_spaces(phrase).casefold()
    if not text or not phrase:
        return False
    pattern = rf"(?<!\w){re.escape(phrase)}(?!\w)"
    return bool(re.search(pattern, text))


def contains_exact_email(text: str, email: str) -> bool:
    text = (text or "").casefold()
    email = (email or "").strip().casefold()
    if not text or not email:
        return False
    pattern = rf"(?<![a-z0-9._%+\-]){re.escape(email)}(?![a-z0-9._%+\-])"
    return bool(re.search(pattern, text))


def contains_exact_username(text: str, url: str, username: str) -> bool:
    username = (username or "").strip().casefold()
    if not is_distinctive_username(username):
        return False

    if contains_exact_phrase(text, username):
        return True

    try:
        path_segments = [
            unquote(segment).casefold()
            for segment in urlsplit(url or "").path.split("/")
            if segment
        ]
    except ValueError:
        return False

    return username in path_segments


def parse_context_terms(extra_keywords: str) -> List[str]:
    terms: List[str] = []
    seen = set()

    for term in re.split(r"[,;]", extra_keywords or ""):
        cleaned = normalize_spaces(term)
        lowered = cleaned.casefold()
        if cleaned and lowered not in seen:
            seen.add(lowered)
            terms.append(cleaned)

    return terms


def quote_search_value(value: str) -> str:
    value = normalize_spaces(value).replace('"', r'\"')
    return f'"{value}"'


def normalize_url(url: str) -> str:
    if not url:
        return ""

    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return url.strip()

    scheme = parts.scheme.lower() or "https"
    netloc = parts.netloc.lower()
    path = parts.path or "/"

    if path != "/":
        path = path.rstrip("/")

    filtered_query = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key.lower() not in TRACKING_QUERY_PARAMETERS
    ]

    return urlunsplit(
        (scheme, netloc, path, urlencode(filtered_query, doseq=True), "")
    )


def classify_source(url: str) -> str:
    lowered = (url or "").lower()
    path = urlsplit(lowered).path if lowered else ""

    if path.endswith(".pdf"):
        return "Public document"
    if "github.com" in lowered:
        return "Developer profile"
    if "linkedin.com" in lowered:
        return "Professional profile"
    if "instagram.com" in lowered or "facebook.com" in lowered:
        return "Social profile"
    if "youtube.com" in lowered or "youtu.be" in lowered:
        return "Public media/content"
    if any(domain in lowered for domain in ("medium.com", "blogspot.", "wordpress.com", "substack.com")):
        return "Blog/article"
    return "Web result"


def choose_web_provider() -> Optional[str]:
    if WEB_SEARCH_PROVIDER in {"brave", "tavily"}:
        return WEB_SEARCH_PROVIDER

    if WEB_SEARCH_PROVIDER not in {"", "auto"}:
        raise ValueError(
            "WEB_SEARCH_PROVIDER must be auto, brave, or tavily."
        )

    if BRAVE_SEARCH_API_KEY:
        return "brave"
    if TAVILY_API_KEY:
        return "tavily"
    return None


# -----------------------------
# Search query generation
# -----------------------------

def generate_web_identity_query(
    full_name: str = "",
    email: str = "",
    username: str = "",
    include_email: bool = True,
) -> str:
    """
    Build one exact-anchor OR query.

    Primary query:
        exact name OR exact email OR exact username

    Optional Tavily fallback:
        exact name OR exact username

    Phone and context terms are never used as discovery anchors.
    """
    anchors: List[str] = []

    full_name = normalize_spaces(full_name)
    email = (email or "").strip().lower()
    username = (username or "").strip()

    if full_name:
        anchors.append(quote_search_value(full_name))

    if include_email and email:
        anchors.append(quote_search_value(email))

    if is_distinctive_username(username):
        anchors.append(quote_search_value(username))

    return " OR ".join(dict.fromkeys(anchors))


def generate_web_query_plan(
    full_name: str = "",
    email: str = "",
    username: str = "",
) -> List[Dict[str, Any]]:
    """Build additive public-discovery queries.

    The name/username discovery query always runs independently of email.
    If an email is supplied, an exact-email corroboration query is added rather
    than replacing or narrowing the name-based search. This makes evidence
    monotonic: supplying an email can add candidates or strengthen identity,
    but its absence from a page never removes an otherwise valid name match.

    Phone is deliberately excluded from public web discovery.
    """
    full_name = normalize_spaces(full_name)
    email = (email or "").strip().lower()
    username = (username or "").strip()

    plan: List[Dict[str, Any]] = []

    public_identity = generate_web_identity_query(
        full_name=full_name,
        email="",
        username=username,
        include_email=False,
    )
    if public_identity:
        plan.append({
            "purpose": "public_identity_without_email",
            "query": public_identity,
            "includes_email": False,
        })

    if email:
        plan.append({
            "purpose": "exact_email_corroboration",
            "query": quote_search_value(email),
            "includes_email": True,
        })

    # Preserve order while preventing accidental duplicates.
    seen = set()
    unique_plan: List[Dict[str, Any]] = []
    for item in plan:
        key = str(item.get("query") or "").casefold()
        if not key or key in seen:
            continue
        seen.add(key)
        unique_plan.append(item)

    return unique_plan


def is_probable_tavily_pii_rejection(error: Exception) -> bool:
    """Detect a provider response that specifically objects to personal data."""
    message = str(error).casefold()
    pii_terms = (
        "personally identifiable",
        "personal information",
        "privacy",
        "pii",
        "sensitive data",
        "email address",
    )
    return ("400" in message or "403" in message) and any(
        term in message for term in pii_terms
    )


def generate_youtube_query(full_name: str = "", username: str = "") -> str:
    """
    YouTube supports the pipe character as OR.

    Email is intentionally excluded because YouTube search primarily checks
    resource metadata and email queries usually add little value.
    """
    anchors: List[str] = []

    full_name = normalize_spaces(full_name)
    username = (username or "").strip()

    if full_name:
        anchors.append(quote_search_value(full_name))
    if is_distinctive_username(username):
        anchors.append(username)

    return "|".join(dict.fromkeys(anchors))


# -----------------------------
# SQLite response cache
# -----------------------------

# Search/image connectors now run concurrently. Serialising cache schema/write
# operations avoids transient ``database is locked`` errors while still allowing
# concurrent reads.
_CACHE_INIT_LOCK = threading.Lock()
_CACHE_WRITE_LOCK = threading.Lock()

def init_cache() -> None:
    with _CACHE_INIT_LOCK:
        with sqlite3.connect(SEARCH_CACHE_DB, timeout=15.0) as connection:
            connection.execute("PRAGMA busy_timeout = 15000")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS search_cache (
                    provider TEXT NOT NULL,
                    query TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    fetched_at TEXT NOT NULL,
                    PRIMARY KEY (provider, query)
                )
                """
            )


def get_cached_response(provider: str, query: str) -> Optional[Dict[str, Any]]:
    if not USE_SEARCH_CACHE:
        return None

    init_cache()

    with sqlite3.connect(SEARCH_CACHE_DB, timeout=15.0) as connection:
        connection.execute("PRAGMA busy_timeout = 15000")
        row = connection.execute(
            """
            SELECT response_json, fetched_at
            FROM search_cache
            WHERE provider = ? AND query = ?
            """,
            (provider, query),
        ).fetchone()

    if not row:
        return None

    response_json, fetched_at = row

    try:
        fetched = datetime.fromisoformat(fetched_at)
    except ValueError:
        return None

    if utc_now() - fetched > timedelta(days=SEARCH_CACHE_DAYS):
        return None

    return json.loads(response_json)


def set_cached_response(provider: str, query: str, response: Dict[str, Any]) -> None:
    if not USE_SEARCH_CACHE:
        return

    init_cache()

    # SQLite supports concurrent readers but only one writer at a time.
    # A small process-local write lock keeps the parallel connectors reliable.
    with _CACHE_WRITE_LOCK:
        with sqlite3.connect(SEARCH_CACHE_DB, timeout=15.0) as connection:
            connection.execute("PRAGMA busy_timeout = 15000")
            connection.execute(
                """
                INSERT INTO search_cache(provider, query, response_json, fetched_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(provider, query) DO UPDATE SET
                    response_json = excluded.response_json,
                    fetched_at = excluded.fetched_at
                """,
                (
                    provider,
                    query,
                    json.dumps(response, ensure_ascii=False),
                    utc_now_iso(),
                ),
            )


# -----------------------------
# Broad web search connectors
# -----------------------------

def search_brave(query: str, max_results: int) -> Dict[str, Any]:
    if not BRAVE_SEARCH_API_KEY:
        raise RuntimeError("BRAVE_SEARCH_API_KEY is not configured.")

    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "X-Subscription-Token": BRAVE_SEARCH_API_KEY,
    }

    params = {
        "q": query,
        "count": max(1, min(max_results, 20)),
        "extra_snippets": "true",
        "safesearch": "moderate",
    }

    response = requests.get(
        BRAVE_WEB_SEARCH_URL,
        headers=headers,
        params=params,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()


def parse_brave_results(data: Dict[str, Any], query: str) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for item in data.get("web", {}).get("results", []):
        snippets = [item.get("description", "")]
        snippets.extend(item.get("extra_snippets") or [])

        results.append({
            "source": "Brave Web Search",
            "source_type": "web",
            "title": item.get("title", ""),
            "snippet": "\n".join(s for s in snippets if s),
            "url": item.get("url", ""),
            "query_used": query,
            "provider_rank": item.get("rank"),
            "discovered_at": utc_now_iso(),
        })

    return results


def search_tavily(
    query: str,
    max_results: int,
    *,
    include_images: bool = False,
    include_image_descriptions: bool = False,
) -> Dict[str, Any]:
    if not TAVILY_API_KEY:
        raise RuntimeError("TAVILY_API_KEY is not configured.")

    headers = {
        "Authorization": f"Bearer {TAVILY_API_KEY}",
        "Content-Type": "application/json",
    }

    body = {
        "query": query,
        "search_depth": "basic",
        "max_results": max(1, min(max_results, 20)),
        "include_answer": False,
        "include_raw_content": False,
        "include_images": bool(include_images),
        "include_image_descriptions": bool(
            include_images and include_image_descriptions
        ),
        "include_usage": True,
        # Exact identity validation is performed after retrieval by this module.
        "exact_match": False,
    }

    response = requests.post(
        TAVILY_SEARCH_URL,
        headers=headers,
        json=body,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )

    if not response.ok:
        response_text = (response.text or "").strip()
        if len(response_text) > 500:
            response_text = response_text[:500] + "..."

        raise RuntimeError(
            f"Tavily returned HTTP {response.status_code}. "
            f"Response: {response_text or 'No response body'}"
        )

    return response.json()


def _tavily_image_record(
    raw: Any,
    *,
    query: str,
    source_page_url: str = "",
    source_page_title: str = "",
    retrieval_scope: str = "query_image",
) -> Optional[Dict[str, Any]]:
    if isinstance(raw, dict):
        url = str(raw.get("url") or "").strip()
        description = str(raw.get("description") or "").strip()
    else:
        url = str(raw or "").strip()
        description = ""

    if not url:
        return None

    return {
        "image_url": url,
        "description": description,
        "query_used": query,
        "source_page_url": source_page_url,
        "source_page_title": source_page_title,
        "retrieval_scope": retrieval_scope,
    }


def search_tavily_image_candidates(
    query: str,
    *,
    max_results: int = 5,
    allow_network: bool = True,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Return query-related image candidates from Tavily image search.

    The response is cached separately from ordinary web-search responses so
    enabling image discovery never changes existing Phase 2A web-cache keys.
    Both top-level query images and per-result images are retained when Tavily
    returns them.
    """
    if not TAVILY_API_KEY:
        return [], {
            "provider": "tavily_images",
            "api_requests": 0,
            "cache_hits": 0,
            "warning": "TAVILY_API_KEY is not configured for independent image discovery.",
        }

    provider = "tavily_images"
    cache_key = f"{max_results}|descriptions=1|{query}"
    cached = get_cached_response(provider, cache_key)

    if cached is not None:
        data = cached
        api_requests = 0
        cache_hits = 1
    elif not allow_network:
        return [], {
            "provider": provider,
            "api_requests": 0,
            "cache_hits": 0,
            "warning": "Cache-only mode was enabled and no cached image-search response exists for this query.",
        }
    else:
        data = search_tavily(
            query,
            max_results,
            include_images=True,
            include_image_descriptions=True,
        )
        set_cached_response(provider, cache_key, data)
        api_requests = 1
        cache_hits = 0

    records: List[Dict[str, Any]] = []

    for raw in data.get("images", []) or []:
        record = _tavily_image_record(
            raw,
            query=query,
            retrieval_scope="query_image",
        )
        if record:
            records.append(record)

    for result in data.get("results", []) or []:
        if not isinstance(result, dict):
            continue
        page_url = str(result.get("url") or "")
        page_title = str(result.get("title") or "")
        for raw in result.get("images", []) or []:
            record = _tavily_image_record(
                raw,
                query=query,
                source_page_url=page_url,
                source_page_title=page_title,
                retrieval_scope="result_image",
            )
            if record:
                records.append(record)

    deduped: List[Dict[str, Any]] = []
    seen = set()
    for record in records:
        url = str(record.get("image_url") or "")
        if not url or url in seen:
            continue
        seen.add(url)
        deduped.append(record)

    return deduped, {
        "provider": provider,
        "api_requests": api_requests,
        "cache_hits": cache_hits,
        "warning": None,
        "raw_image_candidates": len(records),
        "unique_image_candidates": len(deduped),
    }


def parse_tavily_results(data: Dict[str, Any], query: str) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for item in data.get("results", []):
        results.append({
            "source": "Tavily Web Search",
            "source_type": "web",
            "title": item.get("title", ""),
            "snippet": item.get("content", ""),
            "url": item.get("url", ""),
            "query_used": query,
            "provider_score": item.get("score"),
            "published_date": (
                item.get("published_date")
                or item.get("publishedDate")
                or ""
            ),
            "discovered_at": utc_now_iso(),
        })

    return results


def search_broad_web(
    query: str,
    max_results: int = DEFAULT_WEB_RESULTS,
    provider: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    provider = provider or choose_web_provider()

    if not provider:
        return [], {
            "provider": None,
            "api_requests": 0,
            "cache_hits": 0,
            "warning": (
                "Broad web search skipped because neither "
                "BRAVE_SEARCH_API_KEY nor TAVILY_API_KEY is configured."
            ),
        }

    cache_key = f"{max_results}|{query}"
    cached = get_cached_response(provider, cache_key)

    if cached is not None:
        if provider == "brave":
            results = parse_brave_results(cached, query)
        else:
            results = parse_tavily_results(cached, query)

        return results, {
            "provider": provider,
            "api_requests": 0,
            "cache_hits": 1,
            "warning": None,
        }

    if provider == "brave":
        raw = search_brave(query, max_results)
        results = parse_brave_results(raw, query)
    else:
        raw = search_tavily(query, max_results)
        results = parse_tavily_results(raw, query)

    set_cached_response(provider, cache_key, raw)

    return results, {
        "provider": provider,
        "api_requests": 1,
        "cache_hits": 0,
        "warning": None,
    }


# -----------------------------
# Specialized connectors
# -----------------------------

def search_youtube(query: str, max_results: int = DEFAULT_YOUTUBE_RESULTS) -> List[Dict[str, Any]]:
    if not YOUTUBE_API_KEY:
        raise RuntimeError("YOUTUBE_API_KEY is not configured.")

    params = {
        "part": "snippet",
        "q": query,
        "maxResults": max(1, min(max_results, 50)),
        "type": "video,channel,playlist",
        "key": YOUTUBE_API_KEY,
    }

    response = requests.get(
        YOUTUBE_SEARCH_URL,
        params=params,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    data = response.json()

    results: List[Dict[str, Any]] = []

    for item in data.get("items", []):
        identifier = item.get("id", {})
        kind = identifier.get("kind", "")
        snippet = item.get("snippet", {})

        if kind.endswith("#video"):
            url = f"https://www.youtube.com/watch?v={identifier.get('videoId', '')}"
            result_type = "video"
        elif kind.endswith("#channel"):
            url = f"https://www.youtube.com/channel/{identifier.get('channelId', '')}"
            result_type = "channel"
        elif kind.endswith("#playlist"):
            url = (
                "https://www.youtube.com/playlist?list="
                f"{identifier.get('playlistId', '')}"
            )
            result_type = "playlist"
        else:
            continue

        thumbnails = snippet.get("thumbnails") or {}
        candidate_image_urls = list(dict.fromkeys(
            str(value.get("url") or "")
            for value in thumbnails.values()
            if isinstance(value, dict) and value.get("url")
        ))

        results.append({
            "source": "YouTube",
            "source_type": result_type,
            "title": snippet.get("title", ""),
            "snippet": snippet.get("description", ""),
            "channel_title": snippet.get("channelTitle", ""),
            "url": url,
            "candidate_image_urls": candidate_image_urls,
            "query_used": query,
            "discovered_at": utc_now_iso(),
        })

    return results


def lookup_github_user(username: str) -> List[Dict[str, Any]]:
    username = (username or "").strip()

    if not is_distinctive_username(username):
        return []

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }

    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    response = requests.get(
        GITHUB_USER_URL.format(username=username),
        headers=headers,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )

    if response.status_code == 404:
        return []

    response.raise_for_status()
    data = response.json()

    return [{
        "source": "GitHub",
        "source_type": "profile",
        "lookup_type": "exact_username",
        "title": f"{data.get('login', '')} on GitHub",
        "snippet": " | ".join(
            value
            for value in [
                data.get("name", ""),
                data.get("bio", ""),
                data.get("company", ""),
                data.get("location", ""),
                data.get("blog", ""),
            ]
            if value
        ),
        "url": data.get("html_url", ""),
        "candidate_image_urls": (
            [str(data.get("avatar_url"))] if data.get("avatar_url") else []
        ),
        "query_used": username,
        "discovered_at": utc_now_iso(),
    }]


# -----------------------------
# Public-page and PDF extraction
# -----------------------------

def robots_allows(url: str) -> bool:
    if not RESPECT_ROBOTS_TXT:
        return True

    try:
        parts = urlsplit(url)
        robots_url = f"{parts.scheme}://{parts.netloc}/robots.txt"

        parser = robotparser.RobotFileParser()
        parser.set_url(robots_url)
        parser.read()

        return parser.can_fetch(USER_AGENT, url)
    except Exception:
        # Conservative default if robots.txt cannot be checked.
        return False


def response_body_limited(response: requests.Response) -> bytes:
    chunks: List[bytes] = []
    total = 0

    for chunk in response.iter_content(chunk_size=65536):
        if not chunk:
            continue

        total += len(chunk)
        if total > MAX_FETCH_BYTES:
            raise ValueError(
                f"Content exceeds MAX_FETCH_BYTES ({MAX_FETCH_BYTES} bytes)."
            )

        chunks.append(chunk)

    return b"".join(chunks)


def extract_candidate_image_urls(
    content: bytes,
    encoding: Optional[str],
    base_url: str,
) -> List[str]:
    """Extract a small, public-image candidate set from an HTML page.

    The list is evidence for the optional visual-identity pass. Raw image
    bytes are never persisted here.
    """
    html = content.decode(encoding or "utf-8", errors="replace")
    soup = BeautifulSoup(html, "html.parser")
    urls: List[str] = []

    def add(value: Any) -> None:
        raw = str(value or "").strip()
        if not raw or raw.startswith(("data:", "blob:", "javascript:")):
            return
        absolute = urljoin(base_url, raw)
        try:
            parts = urlsplit(absolute)
        except ValueError:
            return
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            return
        if absolute not in urls:
            urls.append(absolute)

    for attrs in (
        {"property": "og:image"},
        {"property": "og:image:secure_url"},
        {"name": "twitter:image"},
        {"name": "twitter:image:src"},
    ):
        tag = soup.find("meta", attrs=attrs)
        if tag:
            add(tag.get("content"))

    for image in soup.find_all("img"):
        add(image.get("src"))
        add(image.get("data-src"))
        srcset = str(image.get("srcset") or image.get("data-srcset") or "")
        for part in srcset.split(","):
            add(part.strip().split(" ", 1)[0])
        if len(urls) >= MAX_CANDIDATE_IMAGE_URLS:
            break

    return urls[:MAX_CANDIDATE_IMAGE_URLS]


def extract_html_text(content: bytes, encoding: Optional[str]) -> str:
    html = content.decode(encoding or "utf-8", errors="replace")
    soup = BeautifulSoup(html, "html.parser")

    for tag in soup(["script", "style", "noscript", "svg"]):
        tag.decompose()

    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    body = soup.get_text(" ", strip=True)

    return normalize_spaces(f"{title} {body}")[:MAX_EXTRACTED_CHARS]


def extract_pdf_text(content: bytes) -> str:
    document = fitz.open(stream=content, filetype="pdf")
    text_parts: List[str] = []

    for page in document:
        text_parts.append(page.get_text("text"))
        if sum(len(part) for part in text_parts) >= MAX_EXTRACTED_CHARS:
            break

    document.close()
    return normalize_spaces(" ".join(text_parts))[:MAX_EXTRACTED_CHARS]


def fetch_public_content(url: str) -> Dict[str, Any]:
    if not url:
        return {
            "fetch_status": "skipped",
            "fetch_reason": "Missing URL",
            "extracted_content": "",
        }

    if not robots_allows(url):
        return {
            "fetch_status": "skipped",
            "fetch_reason": "Disallowed or unverifiable by robots.txt policy",
            "extracted_content": "",
        }

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/pdf;q=0.9,*/*;q=0.1",
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=REQUEST_TIMEOUT_SECONDS,
        stream=True,
        allow_redirects=True,
    )
    response.raise_for_status()

    content_type = response.headers.get("Content-Type", "").lower()
    body = response_body_limited(response)

    candidate_image_urls: List[str] = []

    if "application/pdf" in content_type or urlsplit(url).path.lower().endswith(".pdf"):
        text = extract_pdf_text(body)
        extracted_type = "pdf"
    elif "text/html" in content_type or "application/xhtml+xml" in content_type:
        text = extract_html_text(body, response.encoding)
        candidate_image_urls = extract_candidate_image_urls(
            body, response.encoding, response.url
        )
        extracted_type = "html"
    else:
        return {
            "fetch_status": "skipped",
            "fetch_reason": f"Unsupported content type: {content_type or 'unknown'}",
            "extracted_content": "",
        }

    return {
        "fetch_status": "success",
        "fetch_reason": "",
        "extracted_type": extracted_type,
        "resolved_url": response.url,
        "extracted_content": text,
        "extracted_characters": len(text),
        "candidate_image_urls": candidate_image_urls,
    }


def _fetch_result_content(result: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    """Fetch one result for ``enrich_with_content``.

    The function is deliberately side-effect free so network I/O can run in a
    thread pool while metrics remain deterministic in the calling thread.
    """
    item = dict(result)
    try:
        fetched = fetch_public_content(str(item.get("url") or ""))
        item.update(fetched)
        outcome = (
            "fetched" if fetched.get("fetch_status") == "success" else "skipped"
        )
    except Exception as exc:
        item.update({
            "fetch_status": "failed",
            "fetch_reason": str(exc),
            "extracted_content": "",
        })
        outcome = "failed"
    return item, outcome


def enrich_with_content(
    results: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Fetch independent public pages concurrently while preserving order.

    GitHub/YouTube are already API-backed and are not fetched again.  Only the
    network-bound page retrieval is parallelised; downstream identity analysis
    remains deterministic and single-threaded.
    """
    metrics = {
        "pages_considered": 0,
        "pages_fetched": 0,
        "pages_skipped": 0,
        "fetch_failures": 0,
        "fetch_workers": PHASE2_FETCH_WORKERS,
    }

    if not FETCH_FULL_CONTENT or not results:
        return results, metrics

    enriched: List[Optional[Dict[str, Any]]] = [None] * len(results)
    pending: List[Tuple[int, Dict[str, Any]]] = []

    for index, result in enumerate(results):
        item = dict(result)
        if item.get("source") in {"GitHub", "YouTube"}:
            item["fetch_status"] = "not_required"
            item["extracted_content"] = ""
            enriched[index] = item
            continue

        metrics["pages_considered"] += 1
        pending.append((index, result))

    def record(index: int, item: Dict[str, Any], outcome: str) -> None:
        enriched[index] = item
        if outcome == "fetched":
            metrics["pages_fetched"] += 1
        elif outcome == "failed":
            metrics["fetch_failures"] += 1
        else:
            metrics["pages_skipped"] += 1

    worker_count = min(PHASE2_FETCH_WORKERS, len(pending))
    if worker_count <= 1:
        for index, result in pending:
            item, outcome = _fetch_result_content(result)
            record(index, item, outcome)
    else:
        with ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix="phase2-page",
        ) as executor:
            future_map = {
                executor.submit(_fetch_result_content, result): index
                for index, result in pending
            }
            for future in as_completed(future_map):
                index = future_map[future]
                # _fetch_result_content absorbs normal request errors, so this
                # catch only protects against an unexpected worker failure.
                try:
                    item, outcome = future.result()
                except Exception as exc:
                    item = dict(results[index])
                    item.update({
                        "fetch_status": "failed",
                        "fetch_reason": str(exc),
                        "extracted_content": "",
                    })
                    outcome = "failed"
                record(index, item, outcome)

    return [
        item if item is not None else dict(results[index])
        for index, item in enumerate(enriched)
    ], metrics


# -----------------------------
# Strict identity verification
# -----------------------------

def combine_result_text(result: Dict[str, Any]) -> str:
    return " ".join(
        str(result.get(field) or "")
        for field in (
            "title",
            "snippet",
            "channel_title",
            "extracted_content",
        )
    )


def classify_identity_match(
    result: Dict[str, Any],
    full_name: str = "",
    email: str = "",
    username: str = "",
    extra_keywords: str = "",
) -> Tuple[str, int, List[str]]:
    text = combine_result_text(result)
    url = str(result.get("url") or "")
    source = str(result.get("source") or "")

    exact_email = contains_exact_email(text, email)
    exact_name = contains_exact_phrase(text, full_name)
    exact_username = contains_exact_username(text, url, username)

    context_hits = [
        term
        for term in parse_context_terms(extra_keywords)
        if contains_exact_phrase(text, term)
    ]

    reasons: List[str] = []

    if exact_email:
        reasons.append("Exact email found")
        if exact_name:
            reasons.append("Exact full name found")
        if exact_username:
            reasons.append("Exact username found")
        return "Confirmed", 100, reasons

    if exact_name and exact_username:
        reasons.extend(["Exact full name found", "Exact username found"])
        if context_hits:
            reasons.append(f"Supporting context: {', '.join(context_hits)}")
        return "Strong", 94, reasons

    if exact_name and context_hits:
        reasons.append("Exact full name found")
        reasons.append(f"Supporting context: {', '.join(context_hits)}")
        return "Strong", min(92, 82 + 3 * len(context_hits)), reasons

    if (
        source.casefold() == "github"
        and exact_username
        and str(result.get("lookup_type") or "") == "exact_username"
    ):
        reasons.append("Exact GitHub username lookup")
        if exact_name:
            reasons.append("Exact full name found")
        return "Strong", 85, reasons

    if exact_name:
        reasons.append("Exact full name found without supporting identity context")
        return "Possible", 55, reasons

    if exact_username:
        reasons.append("Exact distinctive username found without supporting context")
        return "Possible", 45, reasons

    return "Rejected", 0, [
        "No exact name, email, or distinctive username match found in available content"
    ]


# -----------------------------
# Exposure extraction and risk
# -----------------------------

def extract_email_addresses(text: str) -> List[str]:
    matches = re.findall(
        r"(?<![a-zA-Z0-9._%+\-])"
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
        r"(?![a-zA-Z0-9._%+\-])",
        text or "",
    )
    return list(dict.fromkeys(match.lower() for match in matches))


def extract_phone_candidates(text: str) -> List[str]:
    raw_candidates = re.findall(
        r"(?:\+?\d[\d\s().\-]{7,}\d)",
        text or "",
    )

    normalized: List[str] = []

    for candidate in raw_candidates:
        digits = normalize_phone(candidate)
        if 10 <= len(digits) <= 11 and digits not in normalized:
            normalized.append(digits)

    return normalized


def result_text_fields(result: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Keep evidence fields separate so contact proximity remains meaningful."""
    fields: List[Tuple[str, str]] = []

    for field_name in (
        "title",
        "snippet",
        "channel_title",
        "extracted_content",
    ):
        value = str(result.get(field_name) or "")
        if value:
            fields.append((field_name, value))

    return fields


def phrase_spans(text: str, phrase: str) -> List[Tuple[int, int]]:
    phrase = normalize_spaces(phrase)
    if not text or not phrase:
        return []

    pattern = re.compile(
        rf"(?<!\w){re.escape(phrase)}(?!\w)",
        re.IGNORECASE,
    )
    return [(match.start(), match.end()) for match in pattern.finditer(text)]


def username_spans(text: str, username: str) -> List[Tuple[int, int]]:
    username = (username or "").strip()
    if not is_distinctive_username(username):
        return []

    pattern = re.compile(
        rf"(?<!\w){re.escape(username)}(?!\w)",
        re.IGNORECASE,
    )
    return [(match.start(), match.end()) for match in pattern.finditer(text)]


def is_generic_site_email(email_address: str, known_email: str = "") -> bool:
    """
    Ignore obvious website contacts such as support@site.com unless that is
    the exact email supplied by the user.
    """
    email_address = (email_address or "").strip().casefold()
    known_email = (known_email or "").strip().casefold()

    if email_address and known_email and email_address == known_email:
        return False

    local_part = email_address.split("@", 1)[0]
    return local_part in GENERIC_SITE_EMAIL_LOCAL_PARTS


def make_evidence_excerpt(
    text: str,
    match_start: int,
    match_end: int,
    radius: int = 150,
) -> str:
    start = max(0, match_start - radius)
    end = min(len(text), match_end + radius)
    return normalize_spaces(text[start:end])


def extract_identity_contact_evidence(
    result: Dict[str, Any],
    full_name: str = "",
    email: str = "",
    username: str = "",
    phone: str = "",
    window_chars: int = IDENTITY_CONTACT_WINDOW_CHARS,
) -> Dict[str, Any]:
    """
    Extract contact details only from text near an exact identity anchor.

    This prevents a site's support email or footer phone number from being
    incorrectly assigned to the person mentioned in an article.
    """
    known_email = (email or "").strip().casefold()
    known_phone = normalize_phone(phone)

    email_candidates: List[str] = []
    phone_candidates: List[str] = []
    evidence: List[Dict[str, Any]] = []
    seen_evidence = set()

    for field_name, field_text in result_text_fields(result):
        anchors: List[Tuple[int, int, str, str]] = []

        for start, end in phrase_spans(field_text, full_name):
            anchors.append((start, end, "full_name", full_name))

        if known_email:
            for start, end in phrase_spans(field_text, known_email):
                anchors.append((start, end, "known_email", known_email))

        for start, end in username_spans(field_text, username):
            anchors.append((start, end, "username", username))

        for anchor_start, anchor_end, anchor_type, anchor_value in anchors:
            window_start = max(0, anchor_start - window_chars)
            window_end = min(len(field_text), anchor_end + window_chars)
            window_text = field_text[window_start:window_end]

            for email_match in re.finditer(
                r"(?<![a-zA-Z0-9._%+\-])"
                r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
                r"(?![a-zA-Z0-9._%+\-])",
                window_text,
            ):
                value = email_match.group(0).casefold()

                if is_generic_site_email(value, known_email=known_email):
                    continue

                confidence = (
                    "High — exact supplied email"
                    if known_email and value == known_email
                    else "Candidate — near identity anchor"
                )

                absolute_start = window_start + email_match.start()
                absolute_end = window_start + email_match.end()
                evidence_key = ("email", value, field_name)

                if evidence_key not in seen_evidence:
                    seen_evidence.add(evidence_key)
                    email_candidates.append(value)
                    evidence.append({
                        "type": "email",
                        "value": value,
                        "confidence": confidence,
                        "source_field": field_name,
                        "identity_anchor": {
                            "type": anchor_type,
                            "value": anchor_value,
                        },
                        "evidence_excerpt": make_evidence_excerpt(
                            field_text,
                            absolute_start,
                            absolute_end,
                        ),
                    })

            phone_pattern = re.compile(r"(?:\+?\d[\d\s().\-]{7,}\d)")

            for phone_match in phone_pattern.finditer(window_text):
                value = normalize_phone(phone_match.group(0))

                if not (10 <= len(value) <= 11):
                    continue

                confidence = (
                    "High — exact supplied phone"
                    if known_phone and value == known_phone
                    else "Candidate — near identity anchor"
                )

                absolute_start = window_start + phone_match.start()
                absolute_end = window_start + phone_match.end()
                evidence_key = ("phone", value, field_name)

                if evidence_key not in seen_evidence:
                    seen_evidence.add(evidence_key)
                    phone_candidates.append(value)
                    evidence.append({
                        "type": "phone",
                        "value": value,
                        "confidence": confidence,
                        "source_field": field_name,
                        "identity_anchor": {
                            "type": anchor_type,
                            "value": anchor_value,
                        },
                        "evidence_excerpt": make_evidence_excerpt(
                            field_text,
                            absolute_start,
                            absolute_end,
                        ),
                    })

    return {
        "email_candidates_near_identity": list(dict.fromkeys(email_candidates)),
        "phone_candidates_near_identity": list(dict.fromkeys(phone_candidates)),
        "known_email_found_near_identity": bool(
            known_email and known_email in email_candidates
        ),
        "known_phone_found_near_identity": bool(
            known_phone and known_phone in phone_candidates
        ),
        "contact_evidence": evidence,
    }


def determine_analysis_basis(result: Dict[str, Any]) -> str:
    if result.get("source") in {"GitHub", "YouTube"}:
        return "API metadata"

    if result.get("fetch_status") == "success":
        if result.get("extracted_type") == "pdf":
            return "Fetched PDF text"
        return "Fetched webpage text"

    return "Search-result title/snippet only"


def detect_exposures(
    result: Dict[str, Any],
    identity_status: str,
    full_name: str = "",
    email: str = "",
    username: str = "",
    phone: str = "",
) -> Dict[str, Any]:
    """
    Extract candidate contacts even for Possible matches.

    Risk labels are applied only to Confirmed/Strong matches. Possible matches
    keep the evidence but wait for manual identity verification.
    """
    text = combine_result_text(result)
    labels: List[str] = []
    candidate_labels: List[str] = []

    contact_data = extract_identity_contact_evidence(
        result,
        full_name=full_name,
        email=email,
        username=username,
        phone=phone,
    )

    email_candidates = contact_data["email_candidates_near_identity"]
    phone_candidates = contact_data["phone_candidates_near_identity"]

    identity_verified = identity_status in {"Confirmed", "Strong"}

    if contains_exact_phrase(text, full_name):
        if identity_verified:
            labels.append("Full name")
        else:
            candidate_labels.append("Full name")

    if email_candidates:
        label = (
            "Known personal email"
            if contact_data["known_email_found_near_identity"]
            else "Email address near identity"
        )
        if identity_verified:
            labels.append(label)
        else:
            candidate_labels.append(label)

    if phone_candidates:
        if identity_verified:
            labels.append("Phone number near identity")
        else:
            candidate_labels.append("Phone number near identity")

    if re.search(r"\b(resume|curriculum vitae|cv)\b", text, re.IGNORECASE):
        if identity_verified:
            labels.append("Resume/CV context")
        else:
            candidate_labels.append("Resume/CV context")

    if re.search(
        r"\b(roll\s*(?:no|number)|sap\s*id|student\s*id|employee\s*id)\b",
        text,
        re.IGNORECASE,
    ):
        if identity_verified:
            labels.append("Student/employee identifier context")
        else:
            candidate_labels.append("Student/employee identifier context")

    if re.search(
        r"\b(home address|residential address|permanent address)\b",
        text,
        re.IGNORECASE,
    ):
        if identity_verified:
            labels.append("Address context")
        else:
            candidate_labels.append("Address context")

    return {
        "labels": list(dict.fromkeys(labels)),
        "candidate_labels": list(dict.fromkeys(candidate_labels)),
        "email_addresses": email_candidates,
        "phone_candidates": phone_candidates,
        "likely_identity_phone_candidates": phone_candidates,
        "known_email_found_near_identity": (
            contact_data["known_email_found_near_identity"]
        ),
        "known_phone_found_near_identity": (
            contact_data["known_phone_found_near_identity"]
        ),
        "contact_evidence": contact_data["contact_evidence"],
    }


def score_preliminary_risk(
    result: Dict[str, Any],
    identity_status: str,
    exposure_data: Dict[str, Any],
) -> Tuple[Optional[int], str, List[str]]:
    if identity_status == "Possible":
        return None, "Pending identity verification", [
            "Risk is withheld until the possible identity match is manually verified."
        ]

    if identity_status == "Rejected":
        return None, "Not applicable", ["Rejected identity match."]

    labels = exposure_data.get("labels", [])
    score = 0
    reasons: List[str] = []
    category = classify_source(str(result.get("url") or ""))

    weights = {
        "Full name": 5,
        "Known personal email": 30,
        "Email address near identity": 25,
        "Phone number near identity": 35,
        "Resume/CV context": 15,
        "Student/employee identifier context": 20,
        "Address context": 30,
    }

    for label in labels:
        weight = weights.get(label, 0)
        score += weight
        if weight:
            reasons.append(f"{label}: +{weight}")

    category_weights = {
        "Public document": 15,
        "Professional profile": 8,
        "Social profile": 10,
        "Developer profile": 6,
        "Public media/content": 6,
        "Blog/article": 8,
        "Web result": 5,
    }

    category_weight = category_weights.get(category, 0)
    score += category_weight
    reasons.append(f"{category}: +{category_weight}")

    score = min(score, 100)

    if score >= 70:
        level = "Very High"
    elif score >= 45:
        level = "High"
    elif score >= 20:
        level = "Moderate"
    else:
        level = "Low"

    return score, level, reasons


def suggest_removal(result: Dict[str, Any], identity_status: str) -> str:
    if identity_status == "Possible":
        return "Verify that this result belongs to the user before taking any removal action."

    category = classify_source(str(result.get("url") or ""))

    if category == "Developer profile":
        return (
            "If user-owned, sign in to GitHub and edit or remove the exposed "
            "profile/repository information. If third-party content, contact "
            "the repository owner or GitHub support."
        )

    if category == "Public media/content":
        return (
            "If user-owned, sign in to YouTube and edit, privatize, or delete "
            "the content. If uploaded by another party, contact the uploader "
            "or use YouTube's official privacy/reporting process."
        )

    if category == "Public document":
        return (
            "Contact the document publisher or website administrator and request "
            "removal or redaction. After the source changes, request a search-cache "
            "refresh if necessary."
        )

    if category in {"Professional profile", "Social profile"}:
        return (
            "If user-owned, edit privacy settings or remove the exposed fields/content. "
            "Otherwise, contact the account owner or use the platform's privacy/reporting route."
        )

    if category == "Blog/article":
        return (
            "Contact the author or site administrator and request correction, redaction, "
            "or removal. Preserve the URL and evidence for the request."
        )

    return (
        "Identify the page owner. If user-controlled, edit or delete the information; "
        "otherwise, send a removal/redaction request to the website administrator."
    )


def analyze_result(
    result: Dict[str, Any],
    full_name: str = "",
    email: str = "",
    username: str = "",
    phone: str = "",
    extra_keywords: str = "",
) -> Dict[str, Any]:
    analyzed = dict(result)
    analyzed["canonical_url"] = normalize_url(str(result.get("url") or ""))
    analyzed["category"] = classify_source(str(result.get("url") or ""))
    analyzed["analysis_basis"] = determine_analysis_basis(analyzed)

    status, identity_score, match_reasons = classify_identity_match(
        analyzed,
        full_name=full_name,
        email=email,
        username=username,
        extra_keywords=extra_keywords,
    )

    analyzed["identity_status"] = status
    analyzed["identity_score"] = identity_score
    analyzed["match_reasons"] = match_reasons

    exposure_data = detect_exposures(
        analyzed,
        identity_status=status,
        full_name=full_name,
        email=email,
        username=username,
        phone=phone,
    )

    analyzed["detected_exposures"] = exposure_data["labels"]
    analyzed["candidate_exposures"] = exposure_data["candidate_labels"]
    analyzed["extracted_email_addresses"] = exposure_data["email_addresses"]
    analyzed["phone_candidates"] = exposure_data["phone_candidates"]
    analyzed["likely_identity_phone_candidates"] = (
        exposure_data["likely_identity_phone_candidates"]
    )
    analyzed["known_email_found_near_identity"] = (
        exposure_data["known_email_found_near_identity"]
    )
    analyzed["known_phone_found_near_identity"] = (
        exposure_data["known_phone_found_near_identity"]
    )
    analyzed["contact_evidence"] = exposure_data["contact_evidence"]

    risk_score, risk_level, risk_reasons = score_preliminary_risk(
        analyzed,
        identity_status=status,
        exposure_data=exposure_data,
    )

    analyzed["risk_score"] = risk_score
    analyzed["risk_level"] = risk_level
    analyzed["risk_reasons"] = risk_reasons
    analyzed["removal_suggestion"] = suggest_removal(analyzed, status)

    return analyzed


def dedupe_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for result in results:
        source = str(result.get("source") or "").strip()
        canonical_url = normalize_url(str(result.get("url") or ""))
        fallback_key = str(result.get("title") or "").strip().casefold()
        key = (source.casefold(), canonical_url or fallback_key)

        query_used = result.get("query_used")

        if key not in merged:
            item = dict(result)
            item["queries_used"] = [query_used] if query_used else []
            merged[key] = item
        else:
            if query_used and query_used not in merged[key]["queries_used"]:
                merged[key]["queries_used"].append(query_used)

            existing_snippet = str(merged[key].get("snippet") or "")
            new_snippet = str(result.get("snippet") or "")

            if len(new_snippet) > len(existing_snippet):
                merged[key]["snippet"] = new_snippet

    return list(merged.values())


# -----------------------------
# Phase 2 pipeline
# -----------------------------

def run_pipeline(
    full_name: str = "",
    email: str = "",
    username: str = "",
    phone: str = "",
    extra_keywords: str = "",
    web_max_results: int = DEFAULT_WEB_RESULTS,
    youtube_max_results: int = DEFAULT_YOUTUBE_RESULTS,
) -> Dict[str, Any]:
    scan_id = uuid4().hex
    scan_time = utc_now_iso()
    selected_web_provider = choose_web_provider()

    web_query_plan = generate_web_query_plan(
        full_name=full_name,
        email=email,
        username=username,
    )
    youtube_query = generate_youtube_query(
        full_name=full_name,
        username=username,
    )

    all_results: List[Dict[str, Any]] = []
    warnings: List[str] = []
    executed_queries: List[Dict[str, Any]] = []

    connector_metrics = {
        "broad_web_provider": selected_web_provider,
        "broad_web_api_requests": 0,
        "broad_web_cache_hits": 0,
        "youtube_api_requests": 0,
        "github_api_requests": 0,
    }

    primary_web_query = (
        web_query_plan[0]["query"] if web_query_plan else ""
    )

    if primary_web_query:
        primary_record = {
            "connector": "broad_web",
            "provider": selected_web_provider,
            "purpose": web_query_plan[0]["purpose"],
            "query": primary_web_query,
            "includes_email": web_query_plan[0]["includes_email"],
            "status": "planned",
            "api_requests": 0,
            "cache_hits": 0,
        }

        try:
            web_results, web_metrics = search_broad_web(
                primary_web_query,
                max_results=web_max_results,
                provider=selected_web_provider,
            )
            all_results.extend(web_results)

            primary_record["status"] = (
                "cache_hit"
                if web_metrics.get("cache_hits", 0)
                else "success"
            )
            primary_record["api_requests"] = web_metrics.get("api_requests", 0)
            primary_record["cache_hits"] = web_metrics.get("cache_hits", 0)

            connector_metrics["broad_web_provider"] = web_metrics.get("provider")
            connector_metrics["broad_web_api_requests"] += web_metrics.get(
                "api_requests", 0
            )
            connector_metrics["broad_web_cache_hits"] += web_metrics.get(
                "cache_hits", 0
            )

            if web_metrics.get("warning"):
                warnings.append(str(web_metrics["warning"]))

        except Exception as exc:
            primary_record["status"] = "failed"
            primary_record["error"] = str(exc)
            warnings.append(f"Broad web search failed: {exc}")

            should_retry_without_email = (
                selected_web_provider == "tavily"
                and TAVILY_RETRY_WITHOUT_EMAIL
                and len(web_query_plan) > 1
                and is_probable_tavily_pii_rejection(exc)
            )

            if should_retry_without_email:
                fallback = web_query_plan[1]
                fallback_record = {
                    "connector": "broad_web",
                    "provider": selected_web_provider,
                    "purpose": fallback["purpose"],
                    "query": fallback["query"],
                    "includes_email": False,
                    "status": "planned",
                    "api_requests": 0,
                    "cache_hits": 0,
                }

                try:
                    web_results, web_metrics = search_broad_web(
                        fallback["query"],
                        max_results=web_max_results,
                        provider=selected_web_provider,
                    )
                    all_results.extend(web_results)

                    fallback_record["status"] = (
                        "cache_hit"
                        if web_metrics.get("cache_hits", 0)
                        else "success"
                    )
                    fallback_record["api_requests"] = web_metrics.get(
                        "api_requests", 0
                    )
                    fallback_record["cache_hits"] = web_metrics.get(
                        "cache_hits", 0
                    )

                    connector_metrics["broad_web_api_requests"] += (
                        web_metrics.get("api_requests", 0)
                    )
                    connector_metrics["broad_web_cache_hits"] += (
                        web_metrics.get("cache_hits", 0)
                    )

                    warnings.append(
                        "Tavily rejected the email-containing query; "
                        "the no-email fallback was used."
                    )

                except Exception as fallback_exc:
                    fallback_record["status"] = "failed"
                    fallback_record["error"] = str(fallback_exc)
                    warnings.append(
                        f"Broad web fallback failed: {fallback_exc}"
                    )

                executed_queries.append(fallback_record)

        executed_queries.insert(0, primary_record)

    else:
        warnings.append(
            "Broad web search skipped because no full name, email, "
            "or distinctive username was supplied."
        )

    if youtube_query:
        youtube_record = {
            "connector": "youtube",
            "provider": "YouTube Data API",
            "purpose": "name_or_username_media_search",
            "query": youtube_query,
            "includes_email": False,
            "status": "planned",
            "api_requests": 0,
            "cache_hits": 0,
        }

        if YOUTUBE_API_KEY:
            try:
                connector_metrics["youtube_api_requests"] = 1
                youtube_record["api_requests"] = 1
                all_results.extend(
                    search_youtube(
                        youtube_query,
                        max_results=youtube_max_results,
                    )
                )
                youtube_record["status"] = "success"
            except Exception as exc:
                youtube_record["status"] = "failed"
                youtube_record["error"] = str(exc)
                warnings.append(f"YouTube search failed: {exc}")
        else:
            youtube_record["status"] = "skipped"
            youtube_record["error"] = "YOUTUBE_API_KEY is not configured."
            warnings.append(
                "YouTube skipped because YOUTUBE_API_KEY is not configured."
            )

        executed_queries.append(youtube_record)

    if username:
        github_record = {
            "connector": "github",
            "provider": "GitHub REST API",
            "purpose": "exact_username_lookup",
            "query": username,
            "includes_email": False,
            "status": "planned",
            "api_requests": 1,
            "cache_hits": 0,
        }

        try:
            connector_metrics["github_api_requests"] = 1
            all_results.extend(lookup_github_user(username))
            github_record["status"] = "success"
        except Exception as exc:
            github_record["status"] = "failed"
            github_record["error"] = str(exc)
            warnings.append(f"GitHub lookup failed: {exc}")

        executed_queries.append(github_record)

    unique_results = dedupe_results(all_results)
    enriched_results, extraction_metrics = enrich_with_content(unique_results)

    analyzed_results = [
        analyze_result(
            result,
            full_name=full_name,
            email=email,
            username=username,
            phone=phone,
            extra_keywords=extra_keywords,
        )
        for result in enriched_results
    ]

    retained_results = [
        result
        for result in analyzed_results
        if result.get("identity_status") in {"Confirmed", "Strong", "Possible"}
    ]

    status_priority = {
        "Confirmed": 3,
        "Strong": 2,
        "Possible": 1,
    }

    retained_results.sort(
        key=lambda item: (
            status_priority.get(str(item.get("identity_status")), 0),
            item.get("risk_score") if item.get("risk_score") is not None else -1,
            item.get("identity_score", 0),
        ),
        reverse=True,
    )

    summary = {
        "raw_results": len(all_results),
        "unique_results": len(unique_results),
        "retained_matches": len(retained_results),
        "rejected_results": len(analyzed_results) - len(retained_results),
        "confirmed_matches": sum(
            1 for item in retained_results
            if item.get("identity_status") == "Confirmed"
        ),
        "strong_matches": sum(
            1 for item in retained_results
            if item.get("identity_status") == "Strong"
        ),
        "possible_matches": sum(
            1 for item in retained_results
            if item.get("identity_status") == "Possible"
        ),
        "results_with_contact_candidates": sum(
            1 for item in retained_results
            if (
                item.get("extracted_email_addresses")
                or item.get("phone_candidates")
            )
        ),
    }

    successful_web_queries = [
        record
        for record in executed_queries
        if (
            record.get("connector") == "broad_web"
            and record.get("status") in {"success", "cache_hit"}
        )
    ]

    return {
        "phase": 2,
        "version": 4,
        "scan_id": scan_id,
        "scan_time": scan_time,
        "input_profile": {
            "full_name": full_name,
            "email": email,
            "username": username,
            "phone": phone,
            "context_terms": parse_context_terms(extra_keywords),
        },
        "web_search_provider": selected_web_provider,
        "web_query_plan": web_query_plan,
        "web_search_queries": [
            record.get("query")
            for record in executed_queries
            if record.get("connector") == "broad_web"
        ],
        "email_used_for_web_search": any(
            record.get("includes_email")
            for record in successful_web_queries
        ),
        "youtube_search_query": youtube_query,
        "executed_queries": executed_queries,
        "summary": summary,
        "connector_metrics": connector_metrics,
        "extraction_metrics": extraction_metrics,
        "warnings": list(dict.fromkeys(warnings)),
        "results": retained_results,
    }


def safe_filename_component(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9_-]+", "_", value or "").strip("_")
    return value[:50] or "scan"


def append_json_line(path: Path, record: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(record, ensure_ascii=False) + "\n")


def save_report_bundle(report: Dict[str, Any]) -> Dict[str, str]:
    """
    Preserve every scan and query.

    - A timestamped report is never overwritten.
    - latest_report.json is a convenience copy only.
    - scan_history.jsonl appends one compact scan record.
    - query_history.jsonl appends every executed connector query.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    scan_time = datetime.fromisoformat(report["scan_time"])
    timestamp = scan_time.strftime("%Y%m%d_%H%M%S_%f")
    person_slug = safe_filename_component(
        report.get("input_profile", {}).get("full_name", "")
    )

    report_path = REPORTS_DIR / (
        f"footprint_report_{person_slug}_{timestamp}.json"
    )
    latest_path = REPORTS_DIR / "latest_report.json"
    scan_history_path = REPORTS_DIR / "scan_history.jsonl"
    query_history_path = REPORTS_DIR / "query_history.jsonl"

    file_manifest = {
        "timestamped_report": str(report_path),
        "latest_report": str(latest_path),
        "scan_history": str(scan_history_path),
        "query_history": str(query_history_path),
    }

    report["saved_files"] = file_manifest

    serialized = json.dumps(report, indent=2, ensure_ascii=False)
    report_path.write_text(serialized, encoding="utf-8")
    latest_path.write_text(serialized, encoding="utf-8")

    append_json_line(
        scan_history_path,
        {
            "scan_id": report.get("scan_id"),
            "scan_time": report.get("scan_time"),
            "input_profile": report.get("input_profile"),
            "summary": report.get("summary"),
            "executed_queries": report.get("executed_queries"),
            "report_file": str(report_path),
        },
    )

    for query_record in report.get("executed_queries", []):
        append_json_line(
            query_history_path,
            {
                "scan_id": report.get("scan_id"),
                "scan_time": report.get("scan_time"),
                "full_name": report.get("input_profile", {}).get(
                    "full_name", ""
                ),
                **query_record,
            },
        )

    return file_manifest


def print_report(report: Dict[str, Any]) -> None:
    print("\n=== Phase 2 Scan Summary ===")

    for key, value in report.get("summary", {}).items():
        print(f"{key.replace('_', ' ').title()}: {value}")

    print("\n=== Executed Queries ===")
    for query_record in report.get("executed_queries", []):
        print(
            f"- {query_record.get('connector')} | "
            f"{query_record.get('status')} | "
            f"{query_record.get('query')}"
        )

    print("\n=== Connector Usage ===")
    for key, value in report.get("connector_metrics", {}).items():
        print(f"{key.replace('_', ' ').title()}: {value}")

    print("\n=== Content Extraction ===")
    for key, value in report.get("extraction_metrics", {}).items():
        print(f"{key.replace('_', ' ').title()}: {value}")

    for warning in report.get("warnings", []):
        print(f"Warning: {warning}")

    print("\n=== Retained Matches ===")
    results = report.get("results", [])

    if not results:
        print(
            "No exact or reviewable identity matches were retained from "
            "the currently connected sources."
        )
        return

    for index, result in enumerate(results, 1):
        risk_score = result.get("risk_score")
        risk_display = (
            f"{risk_score}/100"
            if risk_score is not None
            else result.get("risk_level")
        )

        print(
            f"\n[{index}] {result.get('source')} | "
            f"{result.get('identity_status')} "
            f"(Identity {result.get('identity_score')}/100) | "
            f"Risk {risk_display}"
        )

        print("Title :", result.get("title", ""))
        print("URL   :", result.get("url", ""))
        print("Type  :", result.get("category", ""))
        print("Basis :", result.get("analysis_basis", "Unknown"))
        print("Fetch :", result.get("fetch_status", "not applicable"))
        print(
            "Why   :",
            ", ".join(result.get("match_reasons", []))
            or "No reason recorded",
        )
        print(
            "Data  :",
            ", ".join(result.get("detected_exposures", []))
            or "No verified sensitive exposure detected",
        )

        if result.get("candidate_exposures"):
            print(
                "Candidate data:",
                ", ".join(result["candidate_exposures"]),
            )

        if result.get("extracted_email_addresses"):
            print(
                "Identity-near emails:",
                ", ".join(result["extracted_email_addresses"][:10]),
            )

        if result.get("phone_candidates"):
            print(
                "Identity-near phones:",
                ", ".join(result["phone_candidates"][:10]),
            )

        if (
            not result.get("extracted_email_addresses")
            and not result.get("phone_candidates")
        ):
            print(
                "Contacts:",
                "No visible email/phone was found near the identity in "
                "the accessible title, snippet, or fetched content.",
            )

        print("Action:", result.get("removal_suggestion", ""))


if __name__ == "__main__":
    print("=== Digital Footprint Identification Module — Phase 2 v4 ===")
    print(
        "The broad-web query uses exact name/email/username anchors. "
        "Phone and context terms are used only after a candidate page is found.\n"
    )

    full_name_input = input("Full name: ").strip()
    email_input = input("Email: ").strip()
    username_input = input("Username: ").strip()
    phone_input = input("Phone (verification/exposure only): ").strip()
    context_input = input(
        "Context terms, comma-separated (verification only): "
    ).strip()

    report_data = run_pipeline(
        full_name=full_name_input,
        email=email_input,
        username=username_input,
        phone=phone_input,
        extra_keywords=context_input,
    )

    print_report(report_data)
    saved_files = save_report_bundle(report_data)

    print("\nSaved files:")
    for label, path in saved_files.items():
        print(f"- {label.replace('_', ' ').title()}: {path}")
