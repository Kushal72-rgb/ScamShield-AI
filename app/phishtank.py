import logging
import os
import threading
import time
from typing import Dict, Optional, Tuple
import requests
from app.config import PHISHTANK_API_KEY
from app.models import PhishTankReputationStatus, PhishTankResult

logger = logging.getLogger(__name__)

PHISHTANK_CHECK_URL = "https://checkurl.phishtank.com/checkurl/"
USER_Agent = "phishtank/ScamShieldAI-ForgeHacks2026"

# Low-latency timeout: fail quickly rather than hanging user threads
DEFAULT_REQUEST_TIMEOUT = 2.5  # seconds
REQUEST_TIMEOUT = float(os.getenv("PHISHTANK_TIMEOUT", DEFAULT_REQUEST_TIMEOUT))

# Cache TTL durations (seconds)
CACHE_TTL_KNOWN_PHISHING = 3600.0   # 1 hour for confirmed threats
CACHE_TTL_NO_MATCH = 600.0          # 10 minutes for unindexed (allows re-checking for emerging zero-days)
CACHE_TTL_UNAVAILABLE = 60.0        # 1 minute for transient network errors

# In-memory thread-safe TTL cache: normalized_url -> (expiry_timestamp, PhishTankResult)
_PHISHTANK_CACHE: Dict[str, Tuple[float, PhishTankResult]] = {}
_CACHE_LOCK = threading.Lock()

CAUTION_NOTE_NOT_FOUND = (
    "Caution: A URL not appearing in PhishTank does NOT prove it is safe. "
    "Newly deployed zero-day phishing pages or targeted spear-phishing links often evade public databases."
)
CAUTION_NOTE_KNOWN = (
    "Warning: This URL is an actively cataloged phishing threat in the PhishTank community database."
)
CAUTION_NOTE_INACTIVE = (
    "This URL was historically submitted to PhishTank but is currently marked as invalid or inactive. "
    "Exercise caution with unverified links."
)
CAUTION_NOTE_ERROR = (
    "Reputation check could not be completed at this moment. Rely on local heuristic indicators."
)


def _normalize_cache_url(url: str) -> str:
    """Normalize URL string for consistent cache key lookups."""
    cleaned = url.strip()
    if cleaned.endswith("/") and len(cleaned) > 8:
        cleaned = cleaned[:-1]
    return cleaned.lower()


def get_cached_phishtank_result(url: str) -> Optional[PhishTankResult]:
    """Retrieve non-expired cached reputation result if available."""
    key = _normalize_cache_url(url)
    now = time.time()
    with _CACHE_LOCK:
        entry = _PHISHTANK_CACHE.get(key)
        if entry:
            expiry, result = entry
            if now < expiry:
                return result
            # Expired entry, remove lazily
            del _PHISHTANK_CACHE[key]
    return None


def cache_phishtank_result(url: str, result: PhishTankResult, ttl: Optional[float] = None) -> None:
    """Store reputation result in TTL cache."""
    key = _normalize_cache_url(url)
    if ttl is None:
        if result.status == PhishTankReputationStatus.KNOWN_PHISHING:
            ttl = CACHE_TTL_KNOWN_PHISHING
        elif result.status == PhishTankReputationStatus.NO_MATCH:
            ttl = CACHE_TTL_NO_MATCH
        else:
            ttl = CACHE_TTL_UNAVAILABLE

    expiry = time.time() + ttl
    with _CACHE_LOCK:
        _PHISHTANK_CACHE[key] = (expiry, result)


def clear_phishtank_cache() -> None:
    """Clear all in-memory PhishTank cached entries (useful for testing)."""
    with _CACHE_LOCK:
        _PHISHTANK_CACHE.clear()


def get_phishtank_cache_stats() -> dict:
    """Return cache size and active entries count."""
    now = time.time()
    with _CACHE_LOCK:
        active = sum(1 for exp, _ in _PHISHTANK_CACHE.values() if exp > now)
        total = len(_PHISHTANK_CACHE)
    return {"total_entries": total, "active_entries": active}


def check_url_phishtank(url: str, use_cache: bool = True) -> PhishTankResult:
    """Perform a reputation lookup for a URL against the official PhishTank API.

    Features:
    - In-memory thread-safe TTL caching for minimal latency on repeated links
    - Low-latency timeout (2.5s) to prevent pipeline stalls
    - Zero-day awareness (NO_MATCH is treated as unverified, not safe)

    Distinguishes:
    - KNOWN_PHISHING: Confirmed, verified phishing site in PhishTank
    - NO_MATCH: No matching record found in PhishTank
    - UNAVAILABLE: Request timed out, connection failed, or API returned an error
    """
    if use_cache:
        cached = get_cached_phishtank_result(url)
        if cached is not None:
            return cached

    payload = {
        "url": url,
        "format": "json",
    }

    # Only attach PhishTank app key if configured by the user
    # NEVER pass Gemini API key or other credentials
    if PHISHTANK_API_KEY:
        payload["app_key"] = PHISHTANK_API_KEY

    headers = {
        "User-Agent": USER_Agent,
    }

    result: PhishTankResult
    try:
        response = requests.post(
            PHISHTANK_CHECK_URL,
            data=payload,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code != 200:
            result = PhishTankResult(
                status=PhishTankReputationStatus.UNAVAILABLE,
                in_database=None,
                is_valid_phish=None,
                verified=None,
                phish_id=None,
                phish_detail_url=None,
                message=f"PhishTank service returned HTTP {response.status_code}.",
                caution_note=CAUTION_NOTE_ERROR,
            )
            cache_phishtank_result(url, result)
            return result

        data = response.json()
        results = data.get("results", {})

        in_database = bool(results.get("in_database", False))

        if not in_database:
            result = PhishTankResult(
                status=PhishTankReputationStatus.NO_MATCH,
                in_database=False,
                is_valid_phish=False,
                verified=False,
                phish_id=None,
                phish_detail_url=None,
                message="No matching phishing record found in PhishTank database.",
                caution_note=CAUTION_NOTE_NOT_FOUND,
            )
            cache_phishtank_result(url, result)
            return result

        # URL was found in database
        phish_id = results.get("phish_id")
        phish_detail_url = results.get("phish_detail_page")
        is_verified = bool(results.get("verified", False))
        is_valid = bool(results.get("valid", False))

        if is_valid and is_verified:
            result = PhishTankResult(
                status=PhishTankReputationStatus.KNOWN_PHISHING,
                in_database=True,
                is_valid_phish=True,
                verified=True,
                phish_id=phish_id,
                phish_detail_url=phish_detail_url,
                message=f"Reported & verified active phishing threat (Phish ID #{phish_id}).",
                caution_note=CAUTION_NOTE_KNOWN,
            )
        elif in_database and not is_valid:
            # Historical or unverified record
            result = PhishTankResult(
                status=PhishTankReputationStatus.NO_MATCH,
                in_database=True,
                is_valid_phish=False,
                verified=is_verified,
                phish_id=phish_id,
                phish_detail_url=phish_detail_url,
                message=f"Indexed in PhishTank (ID #{phish_id}) but currently flagged as inactive or invalid phish.",
                caution_note=CAUTION_NOTE_INACTIVE,
            )
        else:
            result = PhishTankResult(
                status=PhishTankReputationStatus.KNOWN_PHISHING if is_valid else PhishTankReputationStatus.NO_MATCH,
                in_database=True,
                is_valid_phish=is_valid,
                verified=is_verified,
                phish_id=phish_id,
                phish_detail_url=phish_detail_url,
                message=f"Submitted to PhishTank (ID #{phish_id}). Verification pending.",
                caution_note=CAUTION_NOTE_NOT_FOUND,
            )

        cache_phishtank_result(url, result)
        return result

    except requests.Timeout:
        logger.warning(f"PhishTank lookup timed out for {url}")
        result = PhishTankResult(
            status=PhishTankReputationStatus.UNAVAILABLE,
            in_database=None,
            is_valid_phish=None,
            verified=None,
            phish_id=None,
            phish_detail_url=None,
            message="PhishTank lookup timed out.",
            caution_note=CAUTION_NOTE_ERROR,
        )
        cache_phishtank_result(url, result)
        return result
    except Exception as exc:
        logger.warning(f"PhishTank lookup error for {url}: {exc}")
        result = PhishTankResult(
            status=PhishTankReputationStatus.UNAVAILABLE,
            in_database=None,
            is_valid_phish=None,
            verified=None,
            phish_id=None,
            phish_detail_url=None,
            message=f"Reputation lookup failed ({type(exc).__name__}).",
            caution_note=CAUTION_NOTE_ERROR,
        )
        cache_phishtank_result(url, result)
        return result
