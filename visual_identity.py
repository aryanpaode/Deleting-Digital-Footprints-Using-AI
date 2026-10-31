"""Optional visual-identity matching for Phase 2A.

This module compares a user-supplied reference face with public images that
Phase 2A has already discovered.  It also keeps a short-lived local cache of
successfully fetched candidate images so the user can manually review them.

Privacy/safety properties:
- the raw reference image is processed locally and is not persisted;
- the face embedding is kept in memory only;
- no biometric embedding is written to Phase 2/3 reports;
- candidate images are cached only under reports/visual_cache for local review;
- no raw image is sent to the Phase 3 LLM;
- inaccessible/robots-disallowed candidate images are skipped;
- private/loopback/link-local image hosts are rejected;
- visual matching is optional and failure falls back to text-only discovery.
"""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import io
import ipaddress
import os
import re
import socket
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

import requests

import phase2_core_v4 as core


DEFAULT_SHAPE_MODEL = "models/shape_predictor_5_face_landmarks.dat"
DEFAULT_FACE_MODEL = "models/dlib_face_recognition_resnet_model_v1.dat"

MAX_IMAGE_BYTES = int(os.getenv("VISUAL_MAX_IMAGE_BYTES", str(4 * 1024 * 1024)))
MAX_IMAGES_PER_RESULT = int(os.getenv("VISUAL_MAX_IMAGES_PER_RESULT", "8"))
REQUEST_TIMEOUT = int(os.getenv("VISUAL_REQUEST_TIMEOUT_SECONDS", "15"))
MIN_IMAGE_SIDE = int(os.getenv("VISUAL_MIN_IMAGE_SIDE", "80"))
VISUAL_DISCOVERY_MAX_QUERIES = int(
    os.getenv("VISUAL_DISCOVERY_MAX_QUERIES", "9")
)
VISUAL_DISCOVERY_RESULTS_PER_QUERY = int(
    os.getenv("VISUAL_DISCOVERY_RESULTS_PER_QUERY", "5")
)
VISUAL_DISCOVERY_MAX_IMAGES = int(
    os.getenv("VISUAL_DISCOVERY_MAX_IMAGES", "30")
)
VISUAL_DISCOVERY_QUERY_WORKERS = max(
    1,
    min(int(os.getenv("VISUAL_DISCOVERY_QUERY_WORKERS", "3")), 4),
)
VISUAL_DOWNLOAD_WORKERS = max(
    1,
    min(int(os.getenv("VISUAL_DOWNLOAD_WORKERS", "6")), 8),
)

# Dlib's Euclidean face-descriptor distance is not a probability. These are
# conservative starting thresholds and should be calibrated on the project's
# own validation set before publication-quality claims are made.
STRONG_DISTANCE = float(os.getenv("VISUAL_STRONG_DISTANCE", "0.50"))
POSSIBLE_DISTANCE = float(os.getenv("VISUAL_POSSIBLE_DISTANCE", "0.60"))


def model_paths() -> Tuple[Path, Path]:
    shape = Path(
        os.getenv("DLIB_SHAPE_PREDICTOR_PATH", DEFAULT_SHAPE_MODEL).strip()
        or DEFAULT_SHAPE_MODEL
    )
    face = Path(
        os.getenv("DLIB_FACE_RECOGNITION_MODEL_PATH", DEFAULT_FACE_MODEL).strip()
        or DEFAULT_FACE_MODEL
    )
    return shape, face


def dependency_status() -> Dict[str, Any]:
    try:
        import dlib  # noqa: F401
        import numpy  # noqa: F401
        from PIL import Image  # noqa: F401
    except Exception as exc:
        return {
            "ready": False,
            "reason": f"Visual dependencies unavailable: {exc}",
        }

    shape, face = model_paths()
    missing = [str(path) for path in (shape, face) if not path.exists()]
    if missing:
        return {
            "ready": False,
            "reason": "Dlib model file(s) missing: " + ", ".join(missing),
            "shape_predictor_path": str(shape),
            "face_model_path": str(face),
        }

    return {
        "ready": True,
        "reason": "",
        "shape_predictor_path": str(shape),
        "face_model_path": str(face),
    }


@lru_cache(maxsize=1)
def _models():
    import dlib

    status = dependency_status()
    if not status.get("ready"):
        raise RuntimeError(status.get("reason") or "Visual models are unavailable.")

    shape_path, face_path = model_paths()
    detector = dlib.get_frontal_face_detector()
    predictor = dlib.shape_predictor(str(shape_path))
    recognizer = dlib.face_recognition_model_v1(str(face_path))
    return detector, predictor, recognizer


def _pil_image_from_bytes(data: bytes):
    from PIL import Image, ImageOps

    image = Image.open(io.BytesIO(data))
    image = ImageOps.exif_transpose(image).convert("RGB")
    return image


def _load_rgb_from_bytes(data: bytes):
    import numpy as np

    with _pil_image_from_bytes(data) as image:
        width, height = image.size
        if min(width, height) < MIN_IMAGE_SIDE:
            raise ValueError(
                f"Image is too small for reliable face analysis ({width}x{height})."
            )
        return np.asarray(image), width, height


def _load_rgb_from_path(path: Path):
    rgb, _width, _height = _load_rgb_from_bytes(path.read_bytes())
    return rgb


def _descriptors(rgb_image) -> List[Any]:
    import numpy as np

    detector, predictor, recognizer = _models()
    faces = detector(rgb_image, 1)
    descriptors: List[Any] = []

    for face in faces:
        shape = predictor(rgb_image, face)
        descriptor = recognizer.compute_face_descriptor(rgb_image, shape, 1)
        descriptors.append(np.asarray(descriptor, dtype="float64"))

    return descriptors


def prepare_reference(reference_path: str | Path) -> Dict[str, Any]:
    """Validate the reference image and return an in-memory descriptor.

    Exactly one detectable face is required because the system must not guess
    which person in a multi-person photograph is the scan subject.
    """
    path = Path(reference_path)
    status = dependency_status()

    if not status.get("ready"):
        return {
            "status": "unavailable",
            "reason": status.get("reason", "Visual matching unavailable."),
            "embedding": None,
            "face_count": 0,
        }

    if not path.exists():
        return {
            "status": "invalid_reference",
            "reason": "Reference image file was not found.",
            "embedding": None,
            "face_count": 0,
        }

    try:
        rgb = _load_rgb_from_path(path)
        descriptors = _descriptors(rgb)
    except Exception as exc:
        return {
            "status": "invalid_reference",
            "reason": f"Reference image could not be analysed: {exc}",
            "embedding": None,
            "face_count": 0,
        }

    if len(descriptors) == 0:
        return {
            "status": "invalid_reference",
            "reason": "No usable face was detected in the reference image.",
            "embedding": None,
            "face_count": 0,
        }

    if len(descriptors) != 1:
        return {
            "status": "invalid_reference",
            "reason": (
                "Multiple faces were detected. Use a reference image containing "
                "only the target person."
            ),
            "embedding": None,
            "face_count": len(descriptors),
        }

    return {
        "status": "ready",
        "reason": "",
        "embedding": descriptors[0],
        "face_count": 1,
        "model": "dlib_128d_face_descriptor",
        "strong_distance_threshold": STRONG_DISTANCE,
        "possible_distance_threshold": POSSIBLE_DISTANCE,
    }


def _host_is_public(hostname: str) -> bool:
    if not hostname:
        return False

    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    for info in addresses:
        address = info[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False

    return True


def is_safe_public_image_url(url: str) -> bool:
    try:
        parts = urlsplit(url or "")
    except ValueError:
        return False

    return (
        parts.scheme in {"http", "https"}
        and bool(parts.hostname)
        and _host_is_public(parts.hostname or "")
    )


def _download_candidate_image(url: str) -> bytes:
    if not is_safe_public_image_url(url):
        raise ValueError("Image URL is not a safe public HTTP(S) destination.")

    if not core.robots_allows(url):
        raise PermissionError("Image URL is disallowed or unverifiable by robots.txt.")

    response = requests.get(
        url,
        headers={
            "User-Agent": core.USER_AGENT,
            "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.1",
        },
        timeout=REQUEST_TIMEOUT,
        stream=True,
        allow_redirects=True,
    )
    response.raise_for_status()

    content_type = (response.headers.get("Content-Type") or "").casefold()
    if "image/" not in content_type:
        raise ValueError(
            f"Unsupported candidate content type: {content_type or 'unknown'}"
        )

    chunks: List[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=65536):
        if not chunk:
            continue
        total += len(chunk)
        if total > MAX_IMAGE_BYTES:
            raise ValueError("Candidate image exceeds VISUAL_MAX_IMAGE_BYTES.")
        chunks.append(chunk)

    return b"".join(chunks)


def distance_strength(distance: Optional[float]) -> str:
    if distance is None:
        return "No match"
    if distance <= STRONG_DISTANCE:
        return "Strong"
    if distance <= POSSIBLE_DISTANCE:
        return "Possible"
    return "No match"


def _cache_review_image(
    data: bytes,
    image_url: str,
    cache_dir: Optional[Path],
) -> str:
    """Store a browser-safe JPEG copy for local manual review.

    Returns a path relative to reports/visual_cache, for example:
        <scan_id>/a1b2c3d4.jpg
    """
    if cache_dir is None:
        return ""

    from PIL import Image

    cache_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(image_url.encode("utf-8") + data).hexdigest()[:20]
    filename = f"{digest}.jpg"
    destination = cache_dir / filename

    with _pil_image_from_bytes(data) as image:
        # Limit enormous display dimensions without altering matching input.
        display = image.copy()
        display.thumbnail((1600, 1600), Image.Resampling.LANCZOS)
        display.save(destination, format="JPEG", quality=88, optimize=True)

    return f"{cache_dir.name}/{filename}"


def _query_quote(value: str) -> str:
    value = re.sub(r"\s+", " ", str(value or "")).strip()
    value = value.replace('"', " ")
    return f'"{value}"' if value else ""


def build_independent_visual_query_plan(profile: Dict[str, Any]) -> List[Dict[str, str]]:
    """Build conservative identity-guided image queries.

    With context terms present we combine each context clue independently with
    the full name, username, and email. This avoids an overly restrictive
    single query containing every context term. When no context is supplied,
    a small name/username photo fallback is used.
    """
    full_name = str(profile.get("full_name") or "").strip()
    username = str(profile.get("username") or "").strip()
    email = str(profile.get("email") or "").strip()
    contexts = [
        re.sub(r"\s+", " ", str(term or "")).strip()
        for term in profile.get("context_terms", []) or []
        if str(term or "").strip()
    ]

    anchors = [
        ("name", full_name),
        ("username", username),
        ("email", email),
    ]
    plan: List[Dict[str, str]] = []

    if contexts:
        for context in contexts:
            for anchor_type, anchor_value in anchors:
                if not anchor_value:
                    continue
                query = f"{_query_quote(anchor_value)} {_query_quote(context)}"
                plan.append({
                    "query": query,
                    "anchor_type": anchor_type,
                    "anchor_value": anchor_value,
                    "context_term": context,
                })
    else:
        for anchor_type, anchor_value in anchors[:2]:
            if not anchor_value:
                continue
            plan.append({
                "query": f"{_query_quote(anchor_value)} photo profile",
                "anchor_type": anchor_type,
                "anchor_value": anchor_value,
                "context_term": "",
            })

    deduped: List[Dict[str, str]] = []
    seen = set()
    for item in plan:
        query = item["query"]
        if query in seen:
            continue
        seen.add(query)
        deduped.append(item)
        if len(deduped) >= VISUAL_DISCOVERY_MAX_QUERIES:
            break
    return deduped


def _looks_like_obvious_asset(url: str, description: str = "") -> bool:
    """Reject obvious UI/logo assets before spending face-analysis work.

    A person-oriented image description overrides filename heuristics because
    some genuine profile images live behind generic CDN filenames.
    """
    desc = str(description or "").casefold()
    person_words = (
        "person", "portrait", "headshot", "profile photo", "photograph of",
        "man", "woman", "speaker", "director", "executive", "ceo",
    )
    if any(word in desc for word in person_words):
        return False

    path = urlsplit(url or "").path.casefold()
    filename = path.rsplit("/", 1)[-1]
    if filename.endswith(".svg"):
        return True

    asset_terms = (
        "logo", "icon", "sprite", "favicon", "banner", "whatsapp", "menu",
        "cart", "cancel", "footer", "header", "placeholder", "sociallogo",
    )
    return any(term in filename for term in asset_terms)


def _download_image_batch(urls: List[str]) -> List[Tuple[Optional[bytes], Optional[Exception]]]:
    """Download a small image batch concurrently, preserving URL order.

    Face detection itself remains serial because the cached dlib model objects
    are intentionally not shared across worker calls.  This gains the network
    speed-up without introducing biometric-model thread-safety risk.
    """
    if not urls:
        return []

    outputs: List[Tuple[Optional[bytes], Optional[Exception]]] = [
        (None, None) for _ in urls
    ]
    worker_count = min(VISUAL_DOWNLOAD_WORKERS, len(urls))
    if worker_count <= 1:
        for index, url in enumerate(urls):
            try:
                outputs[index] = (_download_candidate_image(url), None)
            except Exception as exc:
                outputs[index] = (None, exc)
        return outputs

    with ThreadPoolExecutor(
        max_workers=worker_count,
        thread_name_prefix="visual-download",
    ) as executor:
        futures = {
            executor.submit(_download_candidate_image, url): index
            for index, url in enumerate(urls)
        }
        for future in as_completed(futures):
            index = futures[future]
            try:
                outputs[index] = (future.result(), None)
            except Exception as exc:
                outputs[index] = (None, exc)
    return outputs


def discover_independent_visual_candidates(
    profile: Dict[str, Any],
    *,
    allow_network: bool = True,
) -> Dict[str, Any]:
    """Run independent Tavily image discovery with bounded parallel queries."""
    plan = build_independent_visual_query_plan(profile)
    all_records: List[Dict[str, Any]] = []
    api_requests = 0
    cache_hits = 0
    warnings: List[str] = []

    def run_query(index: int, item: Dict[str, str]) -> Tuple[int, Dict[str, Any]]:
        query = item["query"]
        try:
            records, metrics = core.search_tavily_image_candidates(
                query,
                max_results=VISUAL_DISCOVERY_RESULTS_PER_QUERY,
                allow_network=allow_network,
            )
            enriched_records = []
            for record in records:
                enriched = dict(record)
                enriched["discovery_query"] = query
                enriched["discovery_anchor_type"] = item["anchor_type"]
                enriched["context_term"] = item["context_term"]
                enriched_records.append(enriched)
            return index, {
                "records": enriched_records,
                "log": {
                    **item,
                    "status": "cache_hit" if metrics.get("cache_hits") else (
                        "success" if records or metrics.get("api_requests") else "skipped"
                    ),
                    "image_candidates": len(records),
                    "api_requests": int(metrics.get("api_requests", 0) or 0),
                    "cache_hits": int(metrics.get("cache_hits", 0) or 0),
                },
                "warning": str(metrics.get("warning") or ""),
            }
        except Exception as exc:
            return index, {
                "records": [],
                "log": {
                    **item,
                    "status": "failed",
                    "image_candidates": 0,
                    "api_requests": 0,
                    "cache_hits": 0,
                    "error": f"{type(exc).__name__}: {exc}",
                },
                "warning": f"Independent image query failed ({query}): {exc}",
            }

    indexed_outputs: Dict[int, Dict[str, Any]] = {}
    worker_count = min(VISUAL_DISCOVERY_QUERY_WORKERS, len(plan))
    if worker_count <= 1:
        for index, item in enumerate(plan):
            out_index, output = run_query(index, item)
            indexed_outputs[out_index] = output
    else:
        with ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix="visual-query",
        ) as executor:
            futures = {
                executor.submit(run_query, index, item): index
                for index, item in enumerate(plan)
            }
            for future in as_completed(futures):
                index, output = future.result()
                indexed_outputs[index] = output

    query_log: List[Dict[str, Any]] = []
    for index in range(len(plan)):
        output = indexed_outputs.get(index, {})
        all_records.extend(output.get("records", []))
        if output.get("log"):
            query_log.append(output["log"])
            api_requests += int(output["log"].get("api_requests", 0) or 0)
            cache_hits += int(output["log"].get("cache_hits", 0) or 0)
        if output.get("warning"):
            warnings.append(str(output["warning"]))

    merged: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for record in all_records:
        url = str(record.get("image_url") or "").strip()
        if not url:
            continue
        if url not in merged:
            merged[url] = {
                **record,
                "discovery_queries": [record.get("discovery_query")],
                "discovery_anchor_types": [record.get("discovery_anchor_type")],
                "context_terms": [record.get("context_term")]
                if record.get("context_term") else [],
            }
            order.append(url)
        else:
            current = merged[url]
            for key, value in (
                ("discovery_queries", record.get("discovery_query")),
                ("discovery_anchor_types", record.get("discovery_anchor_type")),
                ("context_terms", record.get("context_term")),
            ):
                if value and value not in current[key]:
                    current[key].append(value)
            if not current.get("description") and record.get("description"):
                current["description"] = record.get("description")
            if not current.get("source_page_url") and record.get("source_page_url"):
                current["source_page_url"] = record.get("source_page_url")
                current["source_page_title"] = record.get("source_page_title", "")

    candidates: List[Dict[str, Any]] = []
    for url in order:
        record = merged[url]
        if _looks_like_obvious_asset(url, str(record.get("description") or "")):
            continue
        candidates.append(record)
        if len(candidates) >= VISUAL_DISCOVERY_MAX_IMAGES:
            break

    return {
        "query_plan": plan,
        "query_log": query_log,
        "raw_candidate_count": len(all_records),
        "unique_candidate_count": len(merged),
        "filtered_candidate_count": len(candidates),
        "api_requests": api_requests,
        "cache_hits": cache_hits,
        "query_workers": VISUAL_DISCOVERY_QUERY_WORKERS,
        "warnings": list(dict.fromkeys(warnings)),
        "candidates": candidates,
    }


def analyze_independent_visual_candidates(
    records: Iterable[Dict[str, Any]],
    reference_embedding,
    *,
    cache_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    import numpy as np

    selected = list(records)[:VISUAL_DISCOVERY_MAX_IMAGES]
    checked = 0
    faces_checked = 0
    failed = 0
    auto_matches = 0
    evidence: List[Dict[str, Any]] = []

    # Download in bounded batches to avoid holding dozens of multi-MB images in
    # memory at once. Dlib analysis stays serial for deterministic model use.
    batch_size = max(1, VISUAL_DOWNLOAD_WORKERS)
    for offset in range(0, len(selected), batch_size):
        batch = selected[offset: offset + batch_size]
        urls = [str(record.get("image_url") or "").strip() for record in batch]
        downloads = _download_image_batch(urls)

        for record, image_url, (data, download_error) in zip(batch, urls, downloads):
            if not image_url:
                continue
            try:
                if download_error is not None:
                    raise download_error
                if data is None:
                    raise RuntimeError("Image download returned no data.")

                rgb, width, height = _load_rgb_from_bytes(data)
                ratio = (width / height) if height else 999.0
                if ratio > 4.5 or ratio < 0.22:
                    raise ValueError(
                        f"Image aspect ratio is not portrait/review friendly ({width}x{height})."
                    )

                descriptors = _descriptors(rgb)
                checked += 1
                faces_checked += len(descriptors)

                best: Optional[float] = None
                for descriptor in descriptors:
                    distance = float(np.linalg.norm(reference_embedding - descriptor))
                    if best is None or distance < best:
                        best = distance

                strength = distance_strength(best)
                if strength in {"Strong", "Possible"}:
                    auto_matches += 1

                cache_file = _cache_review_image(data, image_url, cache_dir)
                evidence.append({
                    "image_id": hashlib.sha256(image_url.encode("utf-8")).hexdigest()[:16],
                    "source_image_url": image_url,
                    "cache_file": cache_file,
                    "width": width,
                    "height": height,
                    "faces_detected": len(descriptors),
                    "automated_best_face_distance": round(best, 4) if best is not None else None,
                    "automated_match_strength": strength,
                    "manual_verification": "unreviewed",
                    "discovery_method": "independent_tavily_image_search",
                    "discovery_queries": list(record.get("discovery_queries") or []),
                    "discovery_anchor_types": list(record.get("discovery_anchor_types") or []),
                    "context_terms": list(record.get("context_terms") or []),
                    "image_description": str(record.get("description") or ""),
                    "source_page_url": str(record.get("source_page_url") or ""),
                    "source_page_title": str(record.get("source_page_title") or ""),
                    "retrieval_scope": str(record.get("retrieval_scope") or "query_image"),
                })
            except Exception as exc:
                failed += 1
                evidence.append({
                    "image_id": hashlib.sha256(image_url.encode("utf-8")).hexdigest()[:16],
                    "source_image_url": image_url,
                    "cache_file": "",
                    "faces_detected": 0,
                    "automated_best_face_distance": None,
                    "automated_match_strength": "Unavailable",
                    "manual_verification": "not_available",
                    "discovery_method": "independent_tavily_image_search",
                    "discovery_queries": list(record.get("discovery_queries") or []),
                    "discovery_anchor_types": list(record.get("discovery_anchor_types") or []),
                    "context_terms": list(record.get("context_terms") or []),
                    "image_description": str(record.get("description") or ""),
                    "source_page_url": str(record.get("source_page_url") or ""),
                    "source_page_title": str(record.get("source_page_title") or ""),
                    "fetch_error": f"{type(exc).__name__}: {exc}",
                })

    return {
        "candidate_images_checked": checked,
        "candidate_images_failed": failed,
        "candidate_faces_checked": faces_checked,
        "visual_match_count": auto_matches,
        "reviewable_images": sum(1 for item in evidence if item.get("cache_file")),
        "download_workers": VISUAL_DOWNLOAD_WORKERS,
        "image_evidence": evidence,
    }


def run_independent_visual_discovery(
    profile: Dict[str, Any],
    reference_path: str | Path,
    *,
    cache_dir: Optional[str | Path] = None,
    allow_network: bool = True,
) -> Dict[str, Any]:
    """Discover candidate images independently from already-fetched pages."""
    reference = prepare_reference(reference_path)
    if reference.get("status") != "ready":
        return {
            "status": reference.get("status", "unavailable"),
            "reason": reference.get("reason", ""),
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

    discovery = discover_independent_visual_candidates(
        profile,
        allow_network=allow_network,
    )
    analysis = analyze_independent_visual_candidates(
        discovery.get("candidates", []),
        reference["embedding"],
        cache_dir=Path(cache_dir) if cache_dir else None,
    )

    return {
        "status": "completed",
        "reason": "",
        "query_count": len(discovery.get("query_plan", [])),
        "query_log": discovery.get("query_log", []),
        "api_requests": discovery.get("api_requests", 0),
        "cache_hits": discovery.get("cache_hits", 0),
        "raw_image_candidates": discovery.get("raw_candidate_count", 0),
        "unique_image_candidates": discovery.get("unique_candidate_count", 0),
        "images_discovered": discovery.get("filtered_candidate_count", 0),
        "candidate_images_checked": analysis.get("candidate_images_checked", 0),
        "candidate_images_failed": analysis.get("candidate_images_failed", 0),
        "candidate_faces_checked": analysis.get("candidate_faces_checked", 0),
        "visual_match_count": analysis.get("visual_match_count", 0),
        "reviewable_images": analysis.get("reviewable_images", 0),
        "image_evidence": analysis.get("image_evidence", []),
        "warnings": discovery.get("warnings", []),
    }


def analyze_candidate_images(
    candidate_image_urls: Iterable[str],
    reference_embedding,
    *,
    cache_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Compare public candidate images after concurrent network download.

    Only image retrieval is parallel. Face descriptor computation remains
    serial, preserving the existing dlib behaviour and thresholds.
    """
    import numpy as np

    unique_urls = list(dict.fromkeys(
        str(url).strip() for url in candidate_image_urls if str(url).strip()
    ))[:MAX_IMAGES_PER_RESULT]

    checked = 0
    faces_checked = 0
    failed = 0
    best_distance: Optional[float] = None
    best_image_url = ""
    image_evidence: List[Dict[str, Any]] = []

    batch_size = max(1, VISUAL_DOWNLOAD_WORKERS)
    for offset in range(0, len(unique_urls), batch_size):
        batch_urls = unique_urls[offset: offset + batch_size]
        downloads = _download_image_batch(batch_urls)

        for image_url, (data, download_error) in zip(batch_urls, downloads):
            try:
                if download_error is not None:
                    raise download_error
                if data is None:
                    raise RuntimeError("Image download returned no data.")

                rgb, width, height = _load_rgb_from_bytes(data)
                descriptors = _descriptors(rgb)
                checked += 1
                faces_checked += len(descriptors)

                image_best: Optional[float] = None
                for descriptor in descriptors:
                    distance = float(np.linalg.norm(reference_embedding - descriptor))
                    if image_best is None or distance < image_best:
                        image_best = distance
                    if best_distance is None or distance < best_distance:
                        best_distance = distance
                        best_image_url = image_url

                cache_file = _cache_review_image(data, image_url, cache_dir)
                image_id = hashlib.sha256(image_url.encode("utf-8")).hexdigest()[:16]
                image_evidence.append({
                    "image_id": image_id,
                    "source_image_url": image_url,
                    "cache_file": cache_file,
                    "width": width,
                    "height": height,
                    "faces_detected": len(descriptors),
                    "automated_best_face_distance": (
                        round(image_best, 4) if image_best is not None else None
                    ),
                    "automated_match_strength": distance_strength(image_best),
                    "manual_verification": "unreviewed",
                })
            except Exception as exc:
                failed += 1
                image_evidence.append({
                    "image_id": hashlib.sha256(image_url.encode("utf-8")).hexdigest()[:16],
                    "source_image_url": image_url,
                    "cache_file": "",
                    "faces_detected": 0,
                    "automated_best_face_distance": None,
                    "automated_match_strength": "Unavailable",
                    "manual_verification": "not_available",
                    "fetch_error": f"{type(exc).__name__}: {exc}",
                })

    strength = distance_strength(best_distance)
    matched = strength in {"Strong", "Possible"}

    return {
        "status": "completed",
        "candidate_images_found": len(unique_urls),
        "candidate_images_checked": checked,
        "candidate_images_failed": failed,
        "candidate_faces_checked": faces_checked,
        "face_match_found": matched,
        "match_strength": strength,
        "best_face_distance": (
            round(best_distance, 4) if best_distance is not None else None
        ),
        "matched_image_url": best_image_url if matched else "",
        "distance_metric": "euclidean_dlib_128d",
        "strong_distance_threshold": STRONG_DISTANCE,
        "possible_distance_threshold": POSSIBLE_DISTANCE,
        "manual_verification_status": "unreviewed",
        "manual_confirmed_image_count": 0,
        "download_workers": VISUAL_DOWNLOAD_WORKERS,
        "image_evidence": image_evidence,
    }


def apply_visual_matching_to_candidates(
    candidates: List[Dict[str, Any]],
    reference_path: str | Path,
    *,
    cache_dir: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """Attach safe visual-match metadata to Phase 2A candidates."""
    reference = prepare_reference(reference_path)
    if reference.get("status") != "ready":
        return {
            "status": reference.get("status", "unavailable"),
            "reason": reference.get("reason", ""),
            "reference_face_count": reference.get("face_count", 0),
            "model": "dlib_128d_face_descriptor",
            "candidate_results_checked": 0,
            "candidate_images_checked": 0,
            "candidate_faces_checked": 0,
            "visual_match_count": 0,
            "manual_review_available": False,
            "raw_reference_image_retained": False,
            "embedding_persisted": False,
        }

    resolved_cache_dir = Path(cache_dir) if cache_dir else None
    embedding = reference["embedding"]
    result_count = 0
    images_checked = 0
    faces_checked = 0
    match_count = 0
    reviewable_images = 0

    for candidate in candidates:
        urls = list(candidate.get("candidate_image_urls") or [])
        if not urls:
            candidate["visual_identity"] = {
                "status": "no_candidate_images",
                "candidate_images_found": 0,
                "candidate_images_checked": 0,
                "candidate_images_failed": 0,
                "candidate_faces_checked": 0,
                "face_match_found": False,
                "match_strength": "No match",
                "best_face_distance": None,
                "matched_image_url": "",
                "manual_verification_status": "not_available",
                "manual_confirmed_image_count": 0,
                "image_evidence": [],
            }
            continue

        result = analyze_candidate_images(
            urls,
            embedding,
            cache_dir=resolved_cache_dir,
        )
        candidate["visual_identity"] = result
        result_count += 1
        images_checked += int(result.get("candidate_images_checked") or 0)
        faces_checked += int(result.get("candidate_faces_checked") or 0)
        match_count += int(bool(result.get("face_match_found")))
        reviewable_images += sum(
            1
            for image in result.get("image_evidence", [])
            if image.get("cache_file")
        )

    return {
        "status": "completed",
        "reason": "",
        "reference_face_count": 1,
        "model": reference.get("model"),
        "candidate_results_checked": result_count,
        "candidate_images_checked": images_checked,
        "candidate_faces_checked": faces_checked,
        "visual_match_count": match_count,
        "reviewable_images": reviewable_images,
        "manual_review_available": bool(reviewable_images),
        "strong_distance_threshold": STRONG_DISTANCE,
        "possible_distance_threshold": POSSIBLE_DISTANCE,
        "raw_reference_image_retained": False,
        "embedding_persisted": False,
    }
