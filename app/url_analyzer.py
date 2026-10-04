import re
import ipaddress
import socket
from urllib.parse import urlparse, parse_qs, unquote, urljoin
from typing import List, Optional, Tuple
import requests
from app.models import UrlSignal

# Common URL shortening services frequently abused to mask destination hosts
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "rb.gy", "cutt.ly", "shorturl.at",
    "t.ly", "lnkd.in", "tiny.cc", "soo.gd", "s.id", "clck.ru",
    "bc.vc", "adf.ly", "bl.ink", "v.gd", "qr.ae", "trib.al"
}

USER_AGENT = "ScamShieldAI-SafeUrlInspector/1.0"

# Common brands targeted by phishing and impersonation
TARGET_BRANDS = {
    "paypal": "paypal.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "citi": "citi.com",
    "apple": "apple.com",
    "icloud": "icloud.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "netflix": "netflix.com",
    "amazon": "amazon.com",
    "usps": "usps.com",
    "fedex": "fedex.com",
    "dhl": "dhl.com",
    "ups": "ups.com",
    "irs": "irs.gov",
    "meta": "meta.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "telegram": "telegram.org",
    "binance": "binance.com",
    "coinbase": "coinbase.com",
}

# Brand official domain aliases (e.g. enterprise identity providers and regional domains)
TARGET_BRAND_ALIASES = {
    "microsoft": ["microsoft.com", "microsoftonline.com", "live.com", "office.com"],
    "google": ["google.com", "googleblog.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
}

# Suspicious keywords frequently paired with brand names in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "security",
    "update",
    "verify",
    "verification",
    "login",
    "signin",
    "auth",
    "authenticate",
    "portal",
    "alert",
    "restore",
    "account",
    "support",
    "wallet",
    "claim",
    "confirm",
    "validation",
    "tracking",
    "redelivery",
]

# TLDs frequently abused in phishing campaigns
SUSPICIOUS_TLDS = {
    "cc", "xyz", "top", "tk", "ml", "ga", "cf", "gq",
    "buzz", "work", "click", "monster", "fit", "rest", "cam", "kim"
}

# Dynamic DNS & tunneling providers commonly abused in zero-day phishing kits
DYNAMIC_DNS_TUNNELS = {
    "duckdns.org",
    "ngrok-free.app",
    "ngrok.io",
    "localtunnel.me",
    "trycloudflare.com",
    "pagekite.me",
    "serveo.net",
    "hopto.org",
    "no-ip.org",
    "zapto.org",
}

# Free form-builders, doc sharing, and cloud hosting abused as phishing drop/lure sites
FREE_HOSTING_PLATFORMS = {
    "forms.gle": "Google Forms",
    "docs.google.com": "Google Docs",
    "drive.google.com": "Google Drive",
    "sites.google.com": "Google Sites",
    "forms.office.com": "Microsoft Forms",
    "1drv.ms": "Microsoft OneDrive",
    "sharepoint.com": "SharePoint",
    "notion.site": "Notion",
    "notion.so": "Notion",
    "canva.site": "Canva",
    "typeform.com": "Typeform",
    "formstack.com": "Formstack",
    "weebly.com": "Weebly",
    "wixsite.com": "Wix",
    "wix.com": "Wix",
    "glitch.me": "Glitch",
    "firebaseapp.com": "Firebase",
    "web.app": "Firebase Hosting",
    "pages.dev": "Cloudflare Pages",
    "vercel.app": "Vercel",
    "netlify.app": "Netlify",
}

# Executable or trojan payload file extensions
MALICIOUS_FILE_EXTENSIONS = {
    ".apk", ".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".iso", ".msi"
}

# Leetspeak / typosquatting character substitutions
TYPOSQUAT_SUBSTITUTIONS = {
    "0": "o",
    "1": "l",
    "rn": "m",
    "vv": "w",
    "3": "e",
    "5": "s",
    "8": "b",
}

# Sensitive actions that should never be conducted via public free cloud forms
SENSITIVE_ACTION_TERMS = [
    "verify", "verification", "password", "login", "signin", "credential",
    "ssn", "social security", "card", "debit", "credit", "pin", "otp",
    "account locked", "suspended", "security alert", "tax refund", "billing update"
]

# Regex to detect URLs (http, https, or bare www.)
URL_REGEX = re.compile(
    r"(?i)\b((?:https?://|www\.)[^\s<>'\"`(){}\[\]]+)",
    re.IGNORECASE,
)


def extract_urls(text: str) -> List[str]:
    """Find and normalize all URLs in a message string."""
    raw_urls = URL_REGEX.findall(text)
    clean_urls = []
    seen = set()

    for url in raw_urls:
        # Strip trailing punctuation that might have attached from sentences
        cleaned = re.sub(r"[.,;:!?)]+$", "", url).strip()
        if not cleaned:
            continue

        # Add http scheme if starts with www.
        if cleaned.lower().startswith("www."):
            cleaned = "http://" + cleaned

        if cleaned not in seen:
            seen.add(cleaned)
            clean_urls.append(cleaned)

    return clean_urls


def check_typosquatting(hostname: str) -> List[str]:
    """Detect zero-day lookalike domains using leetspeak and character substitution."""
    normalized = hostname.lower()
    for char, repl in TYPOSQUAT_SUBSTITUTIONS.items():
        normalized = normalized.replace(char, repl)

    flags = []
    for brand in TARGET_BRANDS:
        if brand in normalized and brand not in hostname.lower():
            flags.append(
                f"Typosquatting/Homoglyph attack: Domain mimics '{brand}' with lookalike character substitution"
            )
    return flags


def is_ssrf_forbidden_ip(ip_str: str) -> bool:
    """Check if an IP string belongs to private, loopback, link-local, multicast, or cloud metadata ranges."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return True  # If invalid, treat as unsafe


def decode_obfuscated_ip_host(hostname: str) -> Optional[Tuple[str, str]]:
    """Detect and decode obfuscated IPv4 representations (dword/integer, hex, octal, mixed).

    Returns:
        (canonical_dotted_decimal_ip, format_type) or None if hostname is a regular domain.
    """
    raw_host = hostname.strip().lower()

    # 1. Single integer / dword representation (e.g., 2130706433 -> 127.0.0.1)
    if raw_host.isdigit():
        try:
            val = int(raw_host, 10)
            if 0 <= val <= 4294967295:
                ip = ipaddress.IPv4Address(val)
                return (str(ip), "dword_integer_ip")
        except Exception:
            pass

    # 2. Single hex integer (e.g., 0x7f000001 -> 127.0.0.1)
    if (raw_host.startswith("0x") or raw_host.startswith("0X")) and "." not in raw_host:
        try:
            val = int(raw_host, 16)
            if 0 <= val <= 4294967295:
                ip = ipaddress.IPv4Address(val)
                return (str(ip), "hex_integer_ip")
        except Exception:
            pass

    # 3. Dotted components with hex, octal, or mixed encoding (e.g., 0177.0.0.1, 0x7f.0.0.1)
    parts = raw_host.split(".")
    if len(parts) == 4:
        is_encoded = False
        decoded_bytes = []
        try:
            for p in parts:
                p_clean = p.strip()
                if p_clean.startswith("0x") or p_clean.startswith("0X"):
                    val = int(p_clean, 16)
                    is_encoded = True
                elif p_clean.startswith("0") and len(p_clean) > 1 and p_clean.isdigit():
                    val = int(p_clean, 8)
                    is_encoded = True
                elif p_clean.isdigit():
                    val = int(p_clean, 10)
                else:
                    return None
                if not (0 <= val <= 255):
                    return None
                decoded_bytes.append(str(val))
            canonical = ".".join(decoded_bytes)
            if is_encoded:
                return (canonical, "dotted_obfuscated_ip")
        except Exception:
            return None

    return None


def safe_resolve_shortener(short_url: str, timeout: float = 1.5) -> Tuple[Optional[str], Optional[str]]:
    """Safely resolve a known shortened URL using a strict HTTP HEAD request.

    Security & Privacy Controls (NO arbitrary crawling):
    - Strictly resolves ONLY known shortener domains in KNOWN_SHORTENERS
    - Validates DNS resolution to block SSRF against private/loopback/metadata IPs
    - Disallows body downloads, script execution, or arbitrary recursive crawling
    - Validates the Location destination header against SSRF forbidden ranges

    Returns:
        (resolved_target_url, error_message_or_reason)
    """
    try:
        parsed = urlparse(short_url)
        host = (parsed.hostname or "").lower()
        if host not in KNOWN_SHORTENERS:
            return None, "Host is not a recognized URL shortener"

        # Pre-flight DNS check: ensure shortener itself is not an SSRF decoy
        try:
            dns_ips = socket.gethostbyname_ex(host)[2]
            if any(is_ssrf_forbidden_ip(ip) for ip in dns_ips):
                return None, "SSRF Blocked: Shortener domain resolves to internal/private IP"
        except Exception as dns_err:
            return None, f"DNS check failed: {dns_err}"

        # Safe HEAD request with no body download and disabled automatic redirection
        resp = requests.head(
            short_url,
            allow_redirects=False,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
        )

        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location")
            if not loc:
                return None, "Redirection status returned without Location header"

            resolved = urljoin(short_url, loc.strip())
            dest_parsed = urlparse(resolved)

            # Protocol restriction
            if dest_parsed.scheme.lower() not in ("http", "https"):
                return None, f"Dangerous redirection protocol ({dest_parsed.scheme})"

            dest_host = (dest_parsed.hostname or "").lower()
            if not dest_host:
                return None, "Empty destination host in Location header"

            # Post-redirection SSRF check: ensure destination host does not point to internal resources
            if is_ssrf_forbidden_ip(dest_host):
                return None, "SSRF Blocked: Redirection targets internal/private IP address"
            try:
                dest_ips = socket.gethostbyname_ex(dest_host)[2]
                if any(is_ssrf_forbidden_ip(ip) for ip in dest_ips):
                    return None, "SSRF Blocked: Redirection targets internal/private IP address"
            except Exception:
                # If destination cannot be resolved, safe to return the string without fetching
                pass

            return resolved, None
        else:
            return None, f"Shortener returned non-redirect status HTTP {resp.status_code}"

    except requests.Timeout:
        return None, "Resolution timed out"
    except Exception as exc:
        return None, f"Resolution error: {type(exc).__name__}"


def analyze_url(
    url: str,
    context_text: Optional[str] = None,
    resolve_shorteners: bool = True,
) -> UrlSignal:
    """Perform local security heuristics on a single URL without external APIs.

    Enhanced for zero-day phishing resilience, shortener handling, and obfuscation defense:
    - Safe shortener detection & SSRF-protected HEAD resolution
    - Obfuscated IP formats (dword/integer, hex, octal, mixed)
    - Percent-encoded and deceptive hostnames
    - Punycode / IDN homographs
    - Typosquatting & character substitutions
    - Non-standard port evasion
    - Dynamic DNS & Tunneling services
    - Dangerous payload / executable downloads
    - Compromised CMS paths
    - Open redirect chaining
    - Contextual mismatch detection (claimed entity vs actual domain)
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower() if parsed.scheme else "http"
    is_https = scheme == "https"
    raw_host = (parsed.hostname or parsed.netloc.split(":")[0])
    hostname = raw_host.lower()
    path_lower = parsed.path.lower()
    query_lower = parsed.query.lower()

    signals: List[str] = []
    zero_day_indicators: List[str] = []
    is_obfuscated = False
    is_shortened = False
    resolved_url: Optional[str] = None

    # 1. Protocol check: Insecure HTTP
    if not is_https:
        signals.append("Insecure protocol: Uses unencrypted HTTP instead of HTTPS")

    # 2. Check for raw or obfuscated IP address as host
    obfuscated_ip = decode_obfuscated_ip_host(hostname)
    if obfuscated_ip:
        canonical_ip, fmt_type = obfuscated_ip
        is_obfuscated = True
        signals.append(
            f"Obfuscated IP host encoding ({fmt_type}): Host uses encoded/non-standard IP '{hostname}' "
            f"(canonical: {canonical_ip}) to evade domain reputation filters"
        )
        zero_day_indicators.append(f"Obfuscated IP representation: {hostname} ({canonical_ip})")
        if is_ssrf_forbidden_ip(canonical_ip):
            signals.append(f"Forbidden internal/private IP destination ({canonical_ip}) detected (SSRF / internal network threat)")
            zero_day_indicators.append(f"Internal IP / SSRF threat ({canonical_ip})")
    else:
        try:
            ipaddress.ip_address(hostname)
            signals.append("Host is a raw IP address rather than a registered domain name")
            zero_day_indicators.append(f"Raw IP hosting ({hostname})")
            if is_ssrf_forbidden_ip(hostname):
                signals.append(f"Forbidden internal/private IP destination ({hostname}) detected (SSRF / internal network threat)")
                zero_day_indicators.append(f"Internal IP / SSRF threat ({hostname})")
        except ValueError:
            pass

    # 3. Check for percent-encoded hostname obfuscation
    unquoted_host = unquote(hostname)
    if unquoted_host != hostname:
        is_obfuscated = True
        signals.append(f"Obfuscated hostname: Contains percent-encoded characters ('{hostname}' -> '{unquoted_host}') concealing true host")
        zero_day_indicators.append(f"Percent-encoded host concealment ({unquoted_host})")

    # 4. Check for URL Shortening services & safe non-invasive expansion
    if hostname in KNOWN_SHORTENERS:
        is_shortened = True
        zero_day_indicators.append(f"Shortened/cloaked URL via shortening service ({hostname})")

        if resolve_shorteners:
            res_url, res_err = safe_resolve_shortener(url)
            if res_url:
                resolved_url = res_url
                signals.append(f"Shortened URL ({hostname}) safely expanded to destination: {res_url}")
                # Recursively evaluate the target URL's heuristics without re-resolving shorteners
                target_signal = analyze_url(res_url, context_text=context_text, resolve_shorteners=False)
                for tsig in target_signal.suspicious_signals:
                    signals.append(f"Expanded target URL flag: {tsig}")
                zero_day_indicators.extend(target_signal.zero_day_indicators)
            else:
                signals.append(
                    f"Shortened/cloaked URL ({hostname}): Destination host cannot be safely expanded or verified "
                    f"without risk ({res_err or 'unresolved'}). Concealed destination quarantined with elevated caution."
                )
        else:
            signals.append(
                f"Shortened/cloaked URL ({hostname}): Concealed destination via URL shortening service masks true destination host to evade filters."
            )

    # 5. Check for credentials or '@' in netloc (deceptive userinfo routing)
    if "@" in parsed.netloc:
        signals.append("Deceptive URL structure: Contains '@' symbol which can conceal the actual destination")
        zero_day_indicators.append("Deceptive userinfo '@' destination routing")

    # 6. Excessive hyphens in domain name (common evasion/impersonation indicator)
    hyphen_count = hostname.count("-")
    if hyphen_count >= 2:
        signals.append(f"Excessive hyphenation in hostname ({hyphen_count} hyphens) typical of phishing domains")
        if hyphen_count >= 3:
            zero_day_indicators.append(f"Heavy hyphen-chaining domain structure ({hyphen_count} hyphens)")

    # 7. Suspicious TLD check
    tld = hostname.split(".")[-1] if "." in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        signals.append(f"Uses top-level domain (.{tld}) with elevated fraud/phishing association")
        zero_day_indicators.append(f"High-risk abuse TLD (.{tld})")

    # 8. Brand impersonation detection (direct keyword)
    for brand, legit_domain in TARGET_BRANDS.items():
        if brand in hostname:
            legit_domains = TARGET_BRAND_ALIASES.get(brand, [legit_domain])
            is_legit = any(hostname == dom or hostname.endswith("." + dom) for dom in legit_domains)
            if not is_legit:
                matching_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in hostname]
                if matching_keywords:
                    signals.append(
                        f"Brand impersonation: Mentions '{brand}' combined with security/action keywords ({', '.join(matching_keywords)}) but does not belong to {legit_domain}"
                    )
                    zero_day_indicators.append(f"Unregistered brand impersonation lure ({brand} + {matching_keywords[0]})")
                else:
                    signals.append(
                        f"Potential brand mimicry: Mentions '{brand}' but domain is not official {legit_domain}"
                    )

    # 9. Multiple subdomain trick (e.g. paypal.com.evil-server.net)
    parts = hostname.split(".")
    if len(parts) >= 4 and not parts[-1].isdigit():
        signals.append(f"High number of subdomain levels ({len(parts)} levels) used to disguise true host")
        zero_day_indicators.append(f"Deep subdomain nesting ({len(parts)} levels)")

    # --- ZERO-DAY RESILIENCE ADDITIONS ---

    # 10. Punycode / IDN homograph attack (e.g. xn--pple-43d.com)
    if "xn--" in hostname:
        signals.append("Punycode/IDN homograph domain detected (xn--) frequently used to spoof legitimate brand characters")
        zero_day_indicators.append("Punycode/IDN homoglyph spoofing")

    # 11. Typosquatting / Character substitution (e.g. amaz0n, paypa1, netf1ix)
    typosquat_flags = check_typosquatting(hostname)
    signals.extend(typosquat_flags)
    if typosquat_flags:
        zero_day_indicators.append("Typosquatting / leetspeak brand substitution")

    # 12. Non-standard web port (e.g. :8080, :8443, :8888)
    if parsed.port and parsed.port not in (80, 443):
        signals.append(f"Non-standard web port (:{parsed.port}) commonly used in temporary zero-day phishing kits")
        zero_day_indicators.append(f"Non-standard web port (:{parsed.port})")

    # 13. Dynamic DNS / Tunneling service abuse (e.g. duckdns.org, ngrok.io)
    for ddns in DYNAMIC_DNS_TUNNELS:
        if hostname == ddns or hostname.endswith("." + ddns):
            signals.append(f"Disposable tunneling/dynamic DNS domain ({ddns}) frequently abused for zero-day phishing staging")
            zero_day_indicators.append(f"Disposable tunneling/dynamic DNS ({ddns})")
            break

    # 14. Direct executable / trojan payload download in URL path
    for ext in MALICIOUS_FILE_EXTENSIONS:
        if path_lower.endswith(ext) or ext + "/" in path_lower or ext + "?" in query_lower:
            signals.append(f"URL targets executable/malware payload download ({ext}) typical of smishing trojans")
            zero_day_indicators.append(f"Malicious executable payload ({ext})")
            break

    # 15. Compromised CMS directory dropper (e.g. WordPress /wp-content/ phish drops)
    if any(cms_dir in path_lower for cms_dir in ("/wp-content/", "/wp-includes/", "/wp-admin/", "/administrator/")):
        signals.append("URL targets compromised CMS/WordPress directory path typical of compromised-site zero-day phishing drops")
        zero_day_indicators.append("Compromised CMS upload path")

    # 16. Open redirect chaining
    if any(param in query_lower for param in ("url=http", "redirect=http", "r=http", "dest=http", "target=http", "link=http", "next=http")):
        signals.append("Contains open redirector parameter used to chain through legitimate domains to zero-day phishing targets")
        zero_day_indicators.append("Open redirect parameter chain")

    # --- CONTEXTUAL MISMATCH DETECTION (if context_text provided) ---
    if context_text:
        mismatch_signals = detect_contextual_mismatches(context_text, hostname)
        signals.extend(mismatch_signals)
        if mismatch_signals:
            zero_day_indicators.append("Contextual entity-to-domain mismatch")

    # Classification Threshold:
    # A URL is suspicious if any strong threat signal is present, or if it is unencrypted HTTP,
    # or if it uses concealed shorteners / obfuscation / zero-day evasion
    is_suspicious = len(signals) > 0 and (
        not is_https
        or is_shortened
        or is_obfuscated
        or len(zero_day_indicators) > 0
        or any(
            "impersonation" in s
            or "IP address" in s
            or "Excessive" in s
            or "mimicry" in s
            or "@" in s
            or "Deceptive URL structure" in s
            or "Punycode" in s
            or "Typosquatting" in s
            or "Non-standard web port" in s
            or "Disposable tunneling" in s
            or "malware payload" in s
            or "compromised CMS" in s
            or "open redirector" in s
            or "Contextual Mismatch" in s
            or "Concealed destination" in s
            for s in signals
        )
    )

    return UrlSignal(
        url=url,
        scheme=scheme,
        is_https=is_https,
        domain=hostname,
        is_suspicious=is_suspicious,
        suspicious_signals=signals,
        is_shortened=is_shortened,
        resolved_url=resolved_url,
        is_obfuscated=is_obfuscated,
        zero_day_indicators=zero_day_indicators,
    )


def detect_contextual_mismatches(text: str, hostname: str) -> List[str]:
    """Detect contextual discrepancies between claimed organizations, requested actions, and destination domain."""
    text_lower = text.lower()
    signals: List[str] = []

    # 1. Identify claimed organizations in the text
    claimed_orgs = []
    for brand, legit_domain in TARGET_BRANDS.items():
        # Match standalone brand mention
        if re.search(r"\b" + re.escape(brand) + r"\b", text_lower):
            claimed_orgs.append((brand, legit_domain))

    # Also detect common Indian / Global institutions
    extra_orgs = [
        ("irs", "irs.gov"),
        ("chase", "chase.com"),
        ("wells fargo", "wellsfargo.com"),
        ("bank of america", "bankofamerica.com"),
        ("sbi", "onlinesbi.sbi"),
        ("hdfc", "hdfcbank.com"),
        ("icici", "icicibank.com"),
        ("usps", "usps.com"),
    ]
    for brand_name, legit_dom in extra_orgs:
        if re.search(r"\b" + re.escape(brand_name) + r"\b", text_lower):
            if not any(b[0] == brand_name for b in claimed_orgs):
                claimed_orgs.append((brand_name, legit_dom))

    # Check for sensitive action requests
    has_sensitive_action = any(term in text_lower for term in SENSITIVE_ACTION_TERMS)

    # Contextual Mismatch A: Free-hosting / public form builders used for institutional security
    matched_platform = None
    for platform_domain, platform_name in FREE_HOSTING_PLATFORMS.items():
        if hostname == platform_domain or hostname.endswith("." + platform_domain):
            matched_platform = (platform_name, platform_domain)
            break

    if matched_platform and claimed_orgs:
        claimed_names = ", ".join(f"'{org[0].title()}'" for org in claimed_orgs[:2])
        signals.append(
            f"Contextual Mismatch: Message claims to represent {claimed_names} but directs user to a public cloud/form hosting service ({matched_platform[0]}: {hostname}) for sensitive actions. Legitimate financial/service institutions never use public form builders or cloud docs for security verification."
        )

    # Contextual Mismatch B: Message claims to be Brand A, but destination domain belongs to an unrelated entity
    if claimed_orgs and not matched_platform:
        for brand_name, legit_dom in claimed_orgs:
            # If the domain is neither the legitimate domain nor a known sub-service
            is_official = hostname == legit_dom or hostname.endswith("." + legit_dom)
            if not is_official and has_sensitive_action:
                # Check if it directs to another recognizable unrelated brand
                redirected_brand = False
                for other_brand, other_dom in TARGET_BRANDS.items():
                    if other_brand != brand_name and (hostname == other_dom or hostname.endswith("." + other_dom)):
                        signals.append(
                            f"Contextual Mismatch: Message explicitly claims to represent '{brand_name.title()}' but directs recipient to an unrelated official domain '{other_dom}'. This cross-brand redirection is characteristic of credential phishing or account redirection."
                        )
                        redirected_brand = True
                        break
                if not redirected_brand:
                    signals.append(
                        f"Contextual Mismatch: Message claims to represent '{brand_name.title()}' regarding sensitive account activity, but directs user to unrelated domain '{hostname}' instead of official '{legit_dom}'."
                    )

    # Contextual Mismatch C: Official government authority claimed, but domain is not .gov
    if any(gov_word in text_lower for gov_word in ("irs", "tax refund", "internal revenue", "law enforcement", "court summons")):
        if not hostname.endswith(".gov") and not hostname.endswith(".gov.in"):
            signals.append(
                f"Contextual Mismatch: Official government/tax authority claimed in message, but domain '{hostname}' is not an official government (.gov) domain"
            )

    return signals


def analyze_all_urls(text: str) -> List[UrlSignal]:
    """Extract all URLs from text and analyze each with contextual mismatch detection."""
    urls = extract_urls(text)
    return [analyze_url(u, context_text=text) for u in urls]
