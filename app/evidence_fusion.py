import logging
import re
from typing import List, Optional

from app.models import (
    AnalysisResponse,
    CONTROLLED_ATTACK_TYPES,
    ConversationTactics,
    EvidenceSummary,
    PhishTankReputationStatus,
    RiskLevel,
    STANDARD_SCAM_CATEGORIES,
    UrlSignal,
)

logger = logging.getLogger(__name__)

ATTACK_TYPE_SYNONYMS = {
    # Bank Impersonation
    "bank impersonation": "Bank Impersonation",
    "bank fraud": "Bank Impersonation",
    "financial impersonation": "Bank Impersonation",
    "financial institution impersonation": "Bank Impersonation",
    "bank/financial impersonation": "Bank Impersonation",
    "bank alert": "Bank Impersonation",
    "banking smishing": "Bank Impersonation",
    # Credential Phishing
    "credential phishing": "Credential Phishing",
    "phishing": "Credential Phishing",
    "fake login": "Credential Phishing",
    "login phishing": "Credential Phishing",
    "account verification phishing": "Credential Phishing",
    # UPI/Payment Fraud
    "upi payment fraud": "UPI/Payment Fraud",
    "upi/payment fraud": "UPI/Payment Fraud",
    "upi fraud": "UPI/Payment Fraud",
    "payment fraud": "UPI/Payment Fraud",
    "instant payment fraud": "UPI/Payment Fraud",
    "payment demand": "UPI/Payment Fraud",
    "fake cashback": "UPI/Payment Fraud",
    "wire fraud": "UPI/Payment Fraud",
    # OTP Theft
    "otp theft": "OTP Theft",
    "otp harvesting": "OTP Theft",
    "one-time passcode theft": "OTP Theft",
    "one-time password theft": "OTP Theft",
    "one-time-password theft": "OTP Theft",
    "otp interception": "OTP Theft",
    "otp extraction": "OTP Theft",
    "otp phishing": "OTP Theft",
    "2fa bypass": "OTP Theft",
    # Password/Account Credential Theft
    "password/account credential theft": "Password/Account Credential Theft",
    "password credential theft": "Password/Account Credential Theft",
    "account credential theft": "Password/Account Credential Theft",
    "password theft": "Password/Account Credential Theft",
    "credential theft": "Password/Account Credential Theft",
    "login credential theft": "Password/Account Credential Theft",
    "password harvesting": "Password/Account Credential Theft",
    # Malicious Download
    "malicious download": "Malicious Download",
    "executable download": "Malicious Download",
    "trojan download": "Malicious Download",
    "malware download": "Malicious Download",
    "payload download": "Malicious Download",
    "malicious payload": "Malicious Download",
    "trojan payload": "Malicious Download",
    # Malicious Link
    "malicious link": "Malicious Link",
    "suspicious link": "Malicious Link",
    "phishing link": "Malicious Link",
    "fake url": "Malicious Link",
    "dangerous link": "Malicious Link",
    "deceptive url": "Malicious Link",
    "untrusted link": "Malicious Link",
    # Typosquatting
    "typosquatting": "Typosquatting",
    "leetspeak domain": "Typosquatting",
    "character substitution": "Typosquatting",
    "combosquatting": "Typosquatting",
    "lookalike domain": "Typosquatting",
    # Punycode/IDN Homograph
    "punycode/idn homograph": "Punycode/IDN Homograph",
    "punycode": "Punycode/IDN Homograph",
    "idn homograph": "Punycode/IDN Homograph",
    "homoglyph attack": "Punycode/IDN Homograph",
    "punycode spoofing": "Punycode/IDN Homograph",
    "idn homograph attack": "Punycode/IDN Homograph",
    # URL Obfuscation
    "url obfuscation": "URL Obfuscation",
    "obfuscated ip": "URL Obfuscation",
    "hex ip": "URL Obfuscation",
    "dword ip": "URL Obfuscation",
    "octal ip": "URL Obfuscation",
    "ip obfuscation": "URL Obfuscation",
    "hostname obfuscation": "URL Obfuscation",
    # Open Redirect Abuse
    "open redirect abuse": "Open Redirect Abuse",
    "open redirect": "Open Redirect Abuse",
    "open redirector": "Open Redirect Abuse",
    "redirect parameter chain": "Open Redirect Abuse",
    # Suspicious Shortened URL
    "suspicious shortened url": "Suspicious Shortened URL",
    "shortened url": "Suspicious Shortened URL",
    "url shortener": "Suspicious Shortened URL",
    "cloaked url": "Suspicious Shortened URL",
    "unresolved shortener": "Suspicious Shortened URL",
    # Brand Impersonation
    "brand impersonation": "Brand Impersonation",
    "brand mimicry": "Brand Impersonation",
    "company impersonation": "Brand Impersonation",
    "logo spoofing": "Brand Impersonation",
    "corporate impersonation": "Brand Impersonation",
    # Government Impersonation
    "government impersonation": "Government Impersonation",
    "government/identity impersonation": "Government Impersonation",
    "tax fraud": "Government Impersonation",
    "irs impersonation": "Government Impersonation",
    "law enforcement impersonation": "Government Impersonation",
    "police impersonation": "Government Impersonation",
    # Delivery Scam
    "delivery scam": "Delivery Scam",
    "delivery smishing": "Delivery Scam",
    "courier scam": "Delivery Scam",
    "postal scam": "Delivery Scam",
    "package scam": "Delivery Scam",
    "shipping scam": "Delivery Scam",
    # Fake Job Scam
    "fake job scam": "Fake Job Scam",
    "fake job offer": "Fake Job Scam",
    "job scam": "Fake Job Scam",
    "recruitment scam": "Fake Job Scam",
    "employment scam": "Fake Job Scam",
    # Lottery/Prize Scam
    "lottery/prize scam": "Lottery/Prize Scam",
    "lottery/prize fraud": "Lottery/Prize Scam",
    "lottery scam": "Lottery/Prize Scam",
    "prize scam": "Lottery/Prize Scam",
    "advance fee scam": "Lottery/Prize Scam",
    "advance-fee scam": "Lottery/Prize Scam",
    "lottery fraud": "Lottery/Prize Scam",
    # Investment/Crypto Scam
    "investment/crypto scam": "Investment/Crypto Scam",
    "investment scam": "Investment/Crypto Scam",
    "crypto scam": "Investment/Crypto Scam",
    "cryptocurrency fraud": "Investment/Crypto Scam",
    "pig butchering": "Investment/Crypto Scam",
    "pig-butchering": "Investment/Crypto Scam",
    "crypto investment scam": "Investment/Crypto Scam",
    # Tech Support Scam
    "tech support scam": "Tech Support Scam",
    "tech support": "Tech Support Scam",
    "fake antivirus": "Tech Support Scam",
    "fake renewal": "Tech Support Scam",
    # Friend/Family Impersonation
    "friend/family impersonation": "Friend/Family Impersonation",
    "family impersonation": "Friend/Family Impersonation",
    "friend impersonation": "Friend/Family Impersonation",
    "distressed relative": "Friend/Family Impersonation",
    "grandparent scam": "Friend/Family Impersonation",
    # Social Engineering
    "social engineering": "Social Engineering",
    "manipulation": "Social Engineering",
    "pretexting": "Social Engineering",
    "rapport exploitation": "Social Engineering",
    # Urgency/Threat Manipulation
    "urgency/threat manipulation": "Urgency/Threat Manipulation",
    "urgency manipulation": "Urgency/Threat Manipulation",
    "threat manipulation": "Urgency/Threat Manipulation",
    "artificial urgency": "Urgency/Threat Manipulation",
    "intimidation": "Urgency/Threat Manipulation",
    "time pressure": "Urgency/Threat Manipulation",
    "coercion": "Urgency/Threat Manipulation",
    # Trust/Grooming Manipulation
    "trust/grooming manipulation": "Trust/Grooming Manipulation",
    "trust manipulation": "Trust/Grooming Manipulation",
    "grooming manipulation": "Trust/Grooming Manipulation",
    "grooming": "Trust/Grooming Manipulation",
    "trust building": "Trust/Grooming Manipulation",
    "rapport building": "Trust/Grooming Manipulation",
}


def normalize_attack_type(attack: str) -> Optional[str]:
    """Normalize an attack technique string to one of the controlled taxonomy values."""
    if not attack:
        return None
    raw = attack.strip()
    raw_lower = raw.lower()

    # Exact match in controlled taxonomy
    for standard in CONTROLLED_ATTACK_TYPES:
        if standard.lower() == raw_lower:
            return standard

    # Lookup in synonym dictionary
    if raw_lower in ATTACK_TYPE_SYNONYMS:
        return ATTACK_TYPE_SYNONYMS[raw_lower]

    # Partial substring matching
    for syn_key, standard_val in ATTACK_TYPE_SYNONYMS.items():
        if syn_key in raw_lower:
            return standard_val

    return None


def has_payment_evidence(
    raw_message: str = "",
    urls_detected: Optional[List[UrlSignal]] = None,
    conversation_tactics: Optional[ConversationTactics] = None,
) -> bool:
    """Verify whether explicit payment or financial-transfer evidence is present.

    UPI/Payment Fraud requires explicit financial-transfer evidence such as:
    - UPI
    - payment / pay
    - transfer / bank transfer
    - send money
    - deposit
    - transaction (in payment context)
    - QR code
    - wallet
    - beneficiary
    - account number when used in a payment context

    Do NOT classify these alone as UPI/Payment Fraud:
    - OTP request
    - password request
    - ATM PIN request
    - account verification
    - login credentials
    """
    msg_lower = (raw_message or "").lower()

    # 1. Explicit UPI markers (standalone 'upi' or handles like @paytm, @okaxis, etc.)
    if re.search(r"\bupi\b|@(paytm|okaxis|oksbi|okhdfcbank|ybl|axl|ibl|upi)\b", msg_lower):
        return True

    # 2. Payment apps / platforms
    if re.search(r"\b(paytm|phonepe|gpay|google\s*pay|zelle|cashapp|venmo)\b", msg_lower):
        return True

    # 3. QR code
    if re.search(r"\bqr\s*code\b|\bscan\s+(?:the\s+|this\s+)?qr\b", msg_lower):
        return True

    # 4. Explicit pay / payment words (avoid false positives like "pay attention" or "password")
    if re.search(r"\b(payment|pay|paying|paid|payable)\b", msg_lower):
        if "pay attention" in msg_lower and not re.search(r"\b(payment|fee|amount|money|cash|bill|due|fine|rs|₹|\$)\b", msg_lower):
            pass
        else:
            return True

    # 5. Money transfer terms
    if re.search(r"\b(transfer|transferred|transferring|wire|bank\s*transfer|wire\s*transfer|remit|remittance)\b", msg_lower):
        return True

    # 6. Send money / Send cash / Send funds / Send currency
    if re.search(r"\bsend\s+(?:money|cash|funds|amount|\$|₹|rs\.?|inr|usd|\d+)", msg_lower):
        return True

    # 7. Deposit terms
    if re.search(r"\b(deposit|depositing|deposited)\b", msg_lower):
        return True

    # 8. Wallet terms
    if re.search(r"\b(wallet|e-wallet|crypto\s*wallet)\b", msg_lower):
        return True

    # 9. Beneficiary terms
    if re.search(r"\bbeneficiary\b", msg_lower):
        return True

    # 10. Transaction when used in payment context
    if "transaction" in msg_lower and any(w in msg_lower for w in ["fee", "charge", "reverse", "failed", "pending", "amount", "debit", "credit", "unauthorized transaction", "transaction of"]):
        return True

    # 11. Account number when used in a payment context
    if "account number" in msg_lower and any(w in msg_lower for w in ["transfer", "send", "deposit", "pay", "credit", "beneficiary", "wire", "remit"]):
        return True

    # 12. Specific payment demand patterns with amounts: e.g. "send 5000", "pay $50", "settle $1,500"
    if re.search(r"\b(?:pay|send|wire|transfer|settle|deposit|remit)\s+(?:₹|rs\.?|\$|inr|usd)?\s*[\d,]+", msg_lower):
        return True
    if re.search(r"(?:₹|rs\.?|\$|inr|usd)\s*[\d,]+\s*(?:fee|charge|penalty|due|fine|redelivery|registration|deposit)", msg_lower):
        return True

    # 13. Specific fee demands: redelivery fee, registration fee, courier fee
    if re.search(r"\b(redelivery\s+fee|registration\s+fee|courier\s+fee|processing\s+fee|redelivery\s+charge|unpaid\s+bill)\b", msg_lower):
        return True

    # 14. Conversation tactics explicitly demanding payment
    if conversation_tactics and conversation_tactics.payment_or_credential_demanded:
        if any(term in msg_lower for term in ["$", "₹", "rs", "pay", "deposit", "wire", "transfer", "crypto", "card", "gift", "fee"]):
            return True

    return False


def merge_attack_types(
    deterministic_attacks: List[str],
    gemini_attacks: Optional[List[str]] = None,
    raw_message: str = "",
    urls_detected: Optional[List[UrlSignal]] = None,
    conversation_tactics: Optional[ConversationTactics] = None,
) -> List[str]:
    """Merge deterministic and Gemini attack types, normalizing synonyms and eliminating duplicates."""
    seen = set()
    result = []

    # If raw_message is provided, evaluate whether explicit payment/transfer evidence exists
    payment_allowed = True
    if raw_message:
        payment_allowed = has_payment_evidence(
            raw_message=raw_message,
            urls_detected=urls_detected,
            conversation_tactics=conversation_tactics,
        )

    # Deterministic signals take precedence to prevent LLM omissions
    for attack in deterministic_attacks:
        norm = normalize_attack_type(attack)
        if norm and norm not in seen and norm in CONTROLLED_ATTACK_TYPES:
            if norm == "UPI/Payment Fraud" and not payment_allowed:
                continue
            seen.add(norm)
            result.append(norm)

    # Incorporate Gemini attack types
    if gemini_attacks:
        for attack in gemini_attacks:
            norm = normalize_attack_type(attack)
            if norm and norm not in seen and norm in CONTROLLED_ATTACK_TYPES:
                if norm == "UPI/Payment Fraud" and not payment_allowed:
                    continue
                seen.add(norm)
                result.append(norm)

    return result


def detect_attack_types(
    raw_message: str = "",
    urls_detected: Optional[List[UrlSignal]] = None,
    conversation_tactics: Optional[ConversationTactics] = None,
    offline_assessment: Optional[dict] = None,
) -> List[str]:
    """Deterministically detect multiple distinct attack techniques from raw text, URLs, and tactics."""
    attacks: List[str] = []
    msg_lower = (raw_message or "").lower()

    # 1. Text-Based Attack Techniques

    # OTP Theft
    otp_terms = [
        "otp", "one-time passcode", "one-time password", "one time passcode",
        "one time password", "verification code", "security passcode", "6-digit code",
        "authorization code"
    ]
    if any(t in msg_lower for t in otp_terms):
        attacks.append("OTP Theft")

    # Password/Account Credential Theft
    pwd_terms = [
        "password", "login credentials", "current password", "enter credentials",
        "account credentials", "atm pin", "debit card pin", "credit card pin",
        "account pin", "enter your pin", "enter pin"
    ]
    if any(p in msg_lower for p in pwd_terms):
        attacks.append("Password/Account Credential Theft")

    # Bank Impersonation
    bank_entities = [
        "chase", "wells fargo", "wellsfargo", "bank of america", "citi",
        "sbi", "hdfc", "icici", "debit card", "credit card", "bank account",
        "checking account", "bank alert"
    ]
    bank_actions = [
        "unusual", "unauthorized", "blocked", "suspended", "locked", "unfreeze",
        "verify", "fraud", "card activity", "compromised", "wire transfer", "atm"
    ]
    if any(e in msg_lower for e in bank_entities) and any(a in msg_lower for a in bank_actions):
        attacks.append("Bank Impersonation")

    # Government Impersonation
    gov_terms = [
        "internal revenue service", "irs", "tax refund", "arrest warrant",
        "federal investigation", "court summons", "social security administration",
        "tax notice", "federal marshals"
    ]
    if any(g in msg_lower for g in gov_terms):
        attacks.append("Government Impersonation")

    # Delivery Scam
    deliv_entities = ["usps", "fedex", "dhl", "ups", "postal", "package", "shipment", "parcel"]
    deliv_traps = [
        "cannot be delivered", "redelivery", "missing street address", "customs",
        "unpaid duty", "delivery fee", "held at warehouse", "reschedule"
    ]
    if any(e in msg_lower for e in deliv_entities) and any(t in msg_lower for t in deliv_traps):
        attacks.append("Delivery Scam")

    # Fake Job Scam
    job_terms = [
        "remote data entry", "$40/hr", "no interview needed", "telegram for interview",
        "work from home $300", "work kit", "youtube video reviewer", "registration fee",
        "part-time job", "earn $500", "shortlisted for part-time"
    ]
    if any(j in msg_lower for j in job_terms):
        attacks.append("Fake Job Scam")

    # Lottery/Prize Scam
    lottery_terms = [
        "won the international lottery", "claim your prize", "selected as the lucky winner",
        "consignment trunk", "lottery winnings", "cashback reward of rs", "sweepstakes",
        "mega uk lottery"
    ]
    if any(l in msg_lower for l in lottery_terms):
        attacks.append("Lottery/Prize Scam")

    # Investment / Crypto Scam
    crypto_terms = [
        "crypto", "bitcoin", "btc", "arbitrage pool", "trading bot",
        "guaranteed 15%", "guaranteed daily", "high yield", "crypto trading",
        "deposit bitcoin", "vip platform", "crypto staking", "deposit $500 now"
    ]
    if any(c in msg_lower for c in crypto_terms):
        attacks.append("Investment/Crypto Scam")

    # Tech Support Scam
    tech_terms = [
        "windows defender", "trojan spyware", "0x800", "financial files are compromised",
        "call microsoft certified", "geek squad", "auto-renewed", "total tech", "virus detected"
    ]
    if any(t in msg_lower for t in tech_terms):
        attacks.append("Tech Support Scam")

    # Friend / Family Impersonation
    distress_terms = [
        "broke my phone", "lost my wallet at the airport", "friend's whatsapp",
        "stranded and my flight", "send $650 via zelle", "hi mom", "hi dad"
    ]
    if any(d in msg_lower for d in distress_terms):
        attacks.append("Friend/Family Impersonation")

    # UPI / Payment Fraud
    # Tightened: requires explicit payment / financial-transfer evidence.
    # Requests for OTP, password, ATM PIN, or account verification alone
    # must NEVER be classified as UPI/Payment Fraud.
    if has_payment_evidence(raw_message, urls_detected, conversation_tactics):
        attacks.append("UPI/Payment Fraud")

    # Malicious Download (text cues)
    download_cues = [
        "download the security", "download app", "download apk", "install app",
        "download the tool", "download security tool", "install the tool",
        "download update", "download software", "download attachment", "download file"
    ]
    if any(dc in msg_lower for dc in download_cues):
        attacks.append("Malicious Download")

    # Urgency / Threat Manipulation
    urgency_terms = [
        "immediately", "urgent", "within 24 hours", "within 12 hours", "within 2 hours",
        "permanent suspension", "permanently blocked", "permanently closed",
        "face immediate arrest", "arrest warrant", "final notice", "expire today",
        "disconnected tonight", "action required", "act now", "unfreeze your card immediately",
        "arrest by federal"
    ]
    if any(u in msg_lower for u in urgency_terms):
        attacks.append("Urgency/Threat Manipulation")

    # Trust / Grooming Manipulation
    trust_terms = [
        "wrong number", "kind person", "sorry to bother you", "meeting for coffee",
        "are we meeting", "you seem so kind", "let's be friends"
    ]
    if any(tr in msg_lower for tr in trust_terms):
        attacks.append("Trust/Grooming Manipulation")

    # 2. Conversation Tactics Integration
    if conversation_tactics:
        if conversation_tactics.trust_building_observed:
            attacks.append("Trust/Grooming Manipulation")
            attacks.append("Social Engineering")
        if conversation_tactics.urgency_escalation_observed:
            attacks.append("Urgency/Threat Manipulation")
            attacks.append("Social Engineering")
        if conversation_tactics.payment_or_credential_demanded:
            if has_payment_evidence(raw_message, urls_detected, conversation_tactics):
                attacks.append("UPI/Payment Fraud")
            attacks.append("Social Engineering")
        if conversation_tactics.grooming_pattern:
            attacks.append("Social Engineering")

    # 3. URL-Based Attack Techniques
    if urls_detected:
        for u in urls_detected:
            # Malicious Link
            if u.is_suspicious or (u.reputation and u.reputation.status == PhishTankReputationStatus.KNOWN_PHISHING):
                attacks.append("Malicious Link")

            # Shortened URL
            if u.is_shortened or any("shorten" in s.lower() for s in u.suspicious_signals):
                attacks.append("Suspicious Shortened URL")

            # URL Obfuscation
            if u.is_obfuscated or any(
                "obfuscat" in s.lower() or "percent-encoded" in s.lower() or "raw ip" in s.lower()
                or "dword" in s.lower() or "hex" in s.lower() or "octal" in s.lower()
                for s in u.suspicious_signals + u.zero_day_indicators
            ):
                attacks.append("URL Obfuscation")

            # Punycode / Homograph
            if any("punycode" in s.lower() or "xn--" in s.lower() for s in u.suspicious_signals + u.zero_day_indicators) or ("xn--" in (u.domain or "")):
                attacks.append("Punycode/IDN Homograph")

            # Typosquatting
            if any("typosquat" in s.lower() or "substitution" in s.lower() for s in u.suspicious_signals + u.zero_day_indicators):
                attacks.append("Typosquatting")
                # If domain mimics bank brand, also trigger Bank Impersonation
                host_l = (u.domain or "").lower()
                if any(b in host_l for b in ["chase", "wellsfargo", "paypa1", "paypal", "citi", "bank"]):
                    attacks.append("Bank Impersonation")

            # Open Redirect
            if any("open redirect" in s.lower() for s in u.suspicious_signals + u.zero_day_indicators) or re.search(r"[?&](?:redirect|url|dest|destination|return|next|goto|target|rdir|link)=https?://", u.url or "", re.IGNORECASE):
                attacks.append("Open Redirect Abuse")

            # Malicious Download
            if any("executable" in s.lower() or "payload" in s.lower() or ".exe" in s.lower() or ".apk" in s.lower() or ".scr" in s.lower() for s in u.suspicious_signals + u.zero_day_indicators):
                attacks.append("Malicious Download")

            # Brand vs Bank Impersonation from URL mimicry
            if any("impersonat" in s.lower() or "mimic" in s.lower() for s in u.suspicious_signals):
                host_l = (u.domain or "").lower()
                if any(b in host_l for b in ["chase", "wellsfargo", "bankofamerica", "citi", "paypal", "paypa1"]):
                    attacks.append("Bank Impersonation")
                else:
                    attacks.append("Brand Impersonation")

    # 4. Credential Phishing Composite Check
    if "OTP Theft" in attacks or "Password/Account Credential Theft" in attacks:
        attacks.append("Credential Phishing")
    if "Malicious Link" in attacks and any(k in (u.url or "").lower() for u in (urls_detected or []) for k in ["login", "signin", "auth", "verify", "account", "portal", "password"]):
        attacks.append("Credential Phishing")

    # 5. Offline Assessment Fallback Integration
    if offline_assessment:
        cat = offline_assessment.get("scam_category", "")
        norm_cat = normalize_attack_type(cat)
        if norm_cat:
            if norm_cat == "UPI/Payment Fraud" and not has_payment_evidence(raw_message, urls_detected, conversation_tactics):
                pass  # Suppress false positive UPI/Payment Fraud from offline assessment
            else:
                attacks.append(norm_cat)

    # 6. Social Engineering Composite Check
    if "Trust/Grooming Manipulation" in attacks or "Urgency/Threat Manipulation" in attacks:
        attacks.append("Social Engineering")

    # Deduplicate preserving order
    return merge_attack_types(
        attacks,
        None,
        raw_message=raw_message,
        urls_detected=urls_detected,
        conversation_tactics=conversation_tactics,
    )


def normalize_category(category: str, is_safe: bool = False) -> str:
    """Normalize a category string to one of the standardized categories where appropriate."""
    if not category:
        return "Routine / Legitimate Communication" if is_safe else "Suspicious Message"

    cat_lower = category.lower().strip()

    if is_safe or "legitimate" in cat_lower or "routine" in cat_lower or "normal" in cat_lower or "safe" in cat_lower:
        return "Routine / Legitimate Communication"

    if "upi" in cat_lower or "paytm" in cat_lower or "phonepe" in cat_lower or "gpay" in cat_lower:
        return "UPI Payment Fraud"
    if "bank" in cat_lower or "financial" in cat_lower or "chase" in cat_lower or "wells" in cat_lower:
        return "Bank/Financial Impersonation"
    if "phish" in cat_lower or "credential" in cat_lower or "login" in cat_lower:
        return "Credential Phishing"
    if "delivery" in cat_lower or "package" in cat_lower or "postal" in cat_lower or "usps" in cat_lower or "fedex" in cat_lower:
        return "Delivery Smishing"
    if "job" in cat_lower or "recruitment" in cat_lower or "career" in cat_lower:
        return "Fake Job Offer"
    if "lottery" in cat_lower or "prize" in cat_lower or "winner" in cat_lower or "reward" in cat_lower:
        return "Lottery/Prize Fraud"
    if "gov" in cat_lower or "tax" in cat_lower or "irs" in cat_lower or "police" in cat_lower or "identity" in cat_lower:
        return "Government/Identity Impersonation"
    if "friend" in cat_lower or "family" in cat_lower or "relative" in cat_lower or "distress" in cat_lower:
        return "Friend/Family Impersonation"
    if "tech support" in cat_lower or "geek squad" in cat_lower or "microsoft support" in cat_lower:
        return "Tech Support Scam"
    if "crypto" in cat_lower or "invest" in cat_lower or "bitcoin" in cat_lower:
        return "Investment/Crypto Scam"

    # Return closest exact match or title-cased original
    for standard in STANDARD_SCAM_CATEGORIES:
        if standard.lower() == cat_lower:
            return standard

    return category


def fuse_evidence(
    gemini_response: Optional[AnalysisResponse],
    urls_detected: List[UrlSignal],
    raw_message: str = "",
    gemini_error: Optional[str] = None,
    conversation_tactics: Optional[ConversationTactics] = None,
    offline_assessment: Optional[dict] = None,
) -> AnalysisResponse:
    """Deterministic Multi-Source Evidence Fusion Layer.

    Reconciles evidence from:
    1. Gemini AI text / multimodal semantic reasoning (or offline deterministic screener when degraded)
    2. Local URL security heuristics (including zero-day indicators, shorteners, and obfuscated IPs)
    3. PhishTank community threat intelligence

    Core Principles:
    - KNOWN_PHISHING from PhishTank is treated as strong threat evidence (elevates to HIGH).
    - Local suspicious URL signals contribute threat evidence (prevents LOW if deceptive).
    - Zero-day indicators (punycode, dynamic DNS, typosquatting, non-standard ports, payloads, obfuscated IPs)
      elevate risk to HIGH even when PhishTank has NO_MATCH or is UNAVAILABLE.
    - NO_MATCH from PhishTank is NEVER treated as proof of safety (does not downgrade risk).
    - UNAVAILABLE from PhishTank is treated neutrally (relies on AI and local signals).
    - Gemini's HIGH risk evaluation is preserved (heuristics cannot override strong social engineering).
    - If Gemini fails or API is unconfigured, gracefully falls back to deterministic offline screening.
    """
    # 1. Analyze PhishTank Findings
    has_known_phish = any(
        u.reputation and u.reputation.status == PhishTankReputationStatus.KNOWN_PHISHING
        for u in urls_detected
    )
    all_reputations_no_match = (
        len(urls_detected) > 0
        and all(
            u.reputation and u.reputation.status == PhishTankReputationStatus.NO_MATCH
            for u in urls_detected
        )
    )
    has_reputation_unavailable = any(
        u.reputation and u.reputation.status == PhishTankReputationStatus.UNAVAILABLE
        for u in urls_detected
    )

    # 2. Analyze Local URL Heuristic Signals and Zero-Day Markers
    suspicious_urls = [u for u in urls_detected if u.is_suspicious]
    has_zero_day_markers = any(len(u.zero_day_indicators) > 0 for u in urls_detected)
    has_obfuscated_urls = any(u.is_obfuscated for u in urls_detected)
    has_shortened_urls = any(u.is_shortened for u in urls_detected)

    has_severe_url_signals = any(
        any(
            "impersonation" in sig.lower()
            or "ip address" in sig.lower()
            or "obfuscated ip" in sig.lower()
            or "@" in sig
            or "deceptive url structure" in sig.lower()
            or "punycode" in sig.lower()
            or "typosquatting" in sig.lower()
            or "contextual mismatch" in sig.lower()
            or "disposable tunneling" in sig.lower()
            or "malware payload" in sig.lower()
            or "compromised cms" in sig.lower()
            or "open redirector" in sig.lower()
            or "concealed destination" in sig.lower()
            for sig in u.suspicious_signals
        )
        for u in suspicious_urls
    ) or has_zero_day_markers or has_obfuscated_urls

    # Extract deterministic multi-attack indicators across text, URLs, and tactics
    active_tactics = conversation_tactics or (gemini_response.conversation_tactics if gemini_response else None)
    det_attack_types = detect_attack_types(
        raw_message=raw_message,
        urls_detected=urls_detected,
        conversation_tactics=active_tactics,
        offline_assessment=offline_assessment,
    )

    # =========================================================================
    # CASE A: Graceful Degradation (Gemini Failed, Unconfigured, or Offline)
    # =========================================================================
    if gemini_response is None:
        err_msg = gemini_error or "AI service temporarily unavailable"
        rationale_items: List[str] = []

        if offline_assessment:
            # Deterministic heuristic engine evaluated the message text
            final_risk = offline_assessment.get("risk_level", RiskLevel.MEDIUM)
            category = offline_assessment.get("scam_category", "Suspicious Message")
            indicators = list(offline_assessment.get("suspicious_indicators") or offline_assessment.get("indicators") or [])
            base_exp = offline_assessment.get("explanation") or "Evaluated via offline heuristics."
            explanation = f"Gemini AI was temporarily unavailable ({err_msg}). {base_exp}"
            recommended_action = offline_assessment.get("recommended_action", "Exercise caution.")
            rationale_items.append("Offline deterministic heuristic engine screened message text in degraded mode.")
            heuristic_conf = "HIGH (Degraded Mode - Offline Deterministic Heuristic Engine)"

            # Corroborate with PhishTank
            if has_known_phish:
                final_risk = RiskLevel.HIGH
                category = "Credential Phishing"
                phish_indicator = "Confirmed active phishing URL cataloged in PhishTank community database"
                if not any("phishtank" in ind.lower() for ind in indicators):
                    indicators.insert(0, phish_indicator)
                rationale_items.append("Confirmed PhishTank threat elevated risk to HIGH.")
            elif suspicious_urls:
                for u in suspicious_urls:
                    for sig in u.suspicious_signals:
                        if sig not in indicators:
                            indicators.append(f"URL Red Flag: {sig}")
                if has_severe_url_signals:
                    final_risk = RiskLevel.HIGH
                    if "routine" in category.lower() or "legitimate" in category.lower():
                        category = "Credential Phishing"
                    rationale_items.append("Severe local URL structural threat / zero-day evasion elevated risk to HIGH.")
                elif final_risk == RiskLevel.LOW:
                    final_risk = RiskLevel.MEDIUM
                    rationale_items.append("Local URL heuristic signals elevated risk from LOW to MEDIUM.")

            if has_shortened_urls:
                rationale_items.append("Concealed shortener URL evaluated under safe non-invasive heuristics.")
            if has_obfuscated_urls:
                rationale_items.append("Obfuscated IP host encoding identified.")

            rationale = " ".join(rationale_items)

        elif has_known_phish:
            phish_id = next(
                (u.reputation.phish_id for u in urls_detected if u.reputation and u.reputation.phish_id),
                None,
            )
            final_risk = RiskLevel.HIGH
            category = "Credential Phishing"
            explanation = (
                f"Gemini AI was temporarily unavailable ({err_msg}), but PhishTank threat intelligence "
                f"definitively verified an active phishing threat in the detected link"
                + (f" (Phish ID #{phish_id})." if phish_id else ".")
            )
            indicators = [
                "Confirmed active phishing URL cataloged in PhishTank community database",
                "High threat of credential theft and account takeover",
            ]
            for u in suspicious_urls:
                indicators.extend(u.suspicious_signals)
            recommended_action = (
                "Do NOT click or open the link. Delete the message and block the sender immediately."
            )
            rationale = "Direct threat intelligence confirmation from PhishTank elevated risk to HIGH despite Gemini being offline."
            heuristic_conf = "HIGH (Confirmed Threat Intelligence)"

        elif suspicious_urls:
            final_risk = RiskLevel.HIGH if has_severe_url_signals else RiskLevel.MEDIUM
            category = "Credential Phishing" if has_severe_url_signals else "Suspicious Message"
            explanation = (
                f"Gemini AI was temporarily unavailable ({err_msg}). However, local security heuristics "
                f"flagged structural anomalies in the embedded link(s), such as deceptive routing, "
                f"brand mimicry, or high-risk domain structures."
            )
            indicators = []
            for u in suspicious_urls:
                indicators.extend(u.suspicious_signals)
            if all_reputations_no_match:
                indicators.append(
                    "Note: PhishTank returned NO_MATCH for the link, but unindexed/new phishing links often evade public blacklists."
                )
            recommended_action = (
                "Do not click any unverified links. Contact the purported service directly using known official contact channels."
            )
            rationale = "Deterministic local URL heuristics identified high-risk anomalies while Gemini was unavailable."
            heuristic_conf = "MEDIUM (Local Structural Heuristics)"

        elif urls_detected:
            # URLs present, but no local heuristic flags, and no PhishTank match
            final_risk = RiskLevel.MEDIUM  # Cautionary because AI didn't vet it and no_match != safe
            category = "Unverified Communication"
            explanation = (
                f"Gemini AI was temporarily unavailable ({err_msg}). While the detected URL(s) did not trigger "
                f"basic local structural rules, lack of a PhishTank match does NOT prove safety. Caution is advised."
            )
            indicators = [
                f"AI inspection degraded: {err_msg}",
                "Link has not been confirmed safe by full contextual reasoning",
                "PhishTank unindexed status cannot guarantee safety",
            ]
            recommended_action = (
                "Exercise caution before clicking links from unsolicited messages until you verify the sender's identity."
            )
            rationale = "Cautionary MEDIUM risk assigned in degraded mode because link safety cannot be confirmed without AI or external whitelist."
            heuristic_conf = "CAUTIONARY (Unverified Link)"

        else:
            # No URLs and no Gemini and no offline assessment
            final_risk = RiskLevel.MEDIUM
            category = "Unverified Communication"
            explanation = (
                f"Gemini AI is temporarily unavailable ({err_msg}). No links were present for offline heuristic inspection. "
                f"The message could not be fully analyzed."
            )
            indicators = [f"Analysis degraded: {err_msg}"]
            recommended_action = (
                "Exercise standard caution. Avoid sharing sensitive personal information or OTPs until the service is restored."
            )
            rationale = "Default cautionary MEDIUM assigned because AI analysis was unavailable and no offline signals were present."
            heuristic_conf = "LOW (Degraded Mode - AI Offline)"

        # Assemble Evidence Summary for Degraded Mode
        pt_summary = (
            "Confirmed phishing threat cataloged"
            if has_known_phish
            else ("No match found (does not prove safety)" if all_reputations_no_match else ("Lookup unavailable" if has_reputation_unavailable else "No URLs evaluated"))
        )
        url_summary = (
            f"Flagged {len(suspicious_urls)} suspicious URL(s)"
            if suspicious_urls
            else (f"{len(urls_detected)} URL(s) detected with no local structural red flags" if urls_detected else "No URLs detected")
        )

        final_attack_types = [] if final_risk == RiskLevel.LOW else merge_attack_types(
            det_attack_types,
            None,
            raw_message=raw_message,
            urls_detected=urls_detected,
            conversation_tactics=conversation_tactics,
        )

        return AnalysisResponse(
            risk_level=final_risk,
            scam_category=category,
            suspicious_indicators=indicators,
            explanation=explanation,
            recommended_action=recommended_action,
            urls_detected=urls_detected,
            evidence_summary=EvidenceSummary(
                gemini_assessment=f"Unavailable / Degraded Mode ({err_msg})",
                local_url_findings=url_summary,
                phishtank_findings=pt_summary,
                fusion_rationale=rationale,
                heuristic_confidence=heuristic_conf,
            ),
            conversation_tactics=conversation_tactics,
            attack_types=final_attack_types,
        )

    # =========================================================================
    # CASE B: Standard Fusion (Gemini Response Available)
    # =========================================================================
    gemini_risk = gemini_response.risk_level
    final_risk = gemini_risk
    category = gemini_response.scam_category
    indicators = list(gemini_response.suspicious_indicators)
    explanation = gemini_response.explanation
    action = gemini_response.recommended_action
    fusion_notes: List[str] = []
    heuristic_conf = "MEDIUM (AI Analysis)"

    # Rule 1: KNOWN_PHISHING from PhishTank is strong threat evidence
    if has_known_phish:
        final_risk = RiskLevel.HIGH
        if "legitimate" in category.lower() or "routine" in category.lower() or "safe" in category.lower():
            category = "Credential Phishing"
        phish_indicator = "Confirmed active phishing threat cataloged in PhishTank community database"
        if not any("phishtank" in ind.lower() for ind in indicators):
            indicators.insert(0, phish_indicator)
        fusion_notes.append("Elevated to HIGH based on verified PhishTank threat intelligence.")
        heuristic_conf = "HIGH (Confirmed Threat Intelligence)"

    # Rule 2: Local suspicious URL signals, zero-day indicators, and obfuscation
    elif suspicious_urls or has_zero_day_markers or has_obfuscated_urls:
        for u in suspicious_urls:
            for sig in u.suspicious_signals:
                if sig not in indicators:
                    indicators.append(f"URL Red Flag: {sig}")
            for z_sig in u.zero_day_indicators:
                z_text = f"Zero-Day Threat Indicator: {z_sig}"
                if z_text not in indicators:
                    indicators.append(z_text)

        if gemini_risk == RiskLevel.LOW:
            # Overrule false negative if heuristics detected severe impersonation, raw/obfuscated IP, or zero-day markers
            if has_severe_url_signals:
                final_risk = RiskLevel.HIGH
                category = "Credential Phishing"
                fusion_notes.append("Elevated from LOW to HIGH due to severe structural URL impersonation, zero-day evasion, or obfuscated IP signals.")
                heuristic_conf = "HIGH (Zero-Day Heuristic Override)"
            else:
                final_risk = RiskLevel.MEDIUM
                fusion_notes.append("Elevated from LOW to MEDIUM due to suspicious local URL patterns or unverified shortener.")
                heuristic_conf = "MEDIUM (Local Structural Signals)"
        elif gemini_risk == RiskLevel.MEDIUM and has_severe_url_signals:
            final_risk = RiskLevel.HIGH
            fusion_notes.append("Elevated from MEDIUM to HIGH due to severe structural URL threat / zero-day evasion.")
            heuristic_conf = "HIGH (Severe Heuristic Corroboration)"
        else:
            fusion_notes.append("Local URL heuristic and zero-day indicators corroborated Gemini's risk evaluation.")
            heuristic_conf = "HIGH (Multi-Source Corroboration)"

    # Rule 3: PhishTank NO_MATCH must NEVER be treated as safe
    elif all_reputations_no_match:
        # Gemini assessment stands. If Gemini flagged HIGH/MEDIUM, maintain it!
        fusion_notes.append("PhishTank returned NO_MATCH (unindexed zero-day). Note: absence from blacklist does NOT prove safety; risk determined by Gemini analysis.")
        if gemini_risk == RiskLevel.HIGH:
            heuristic_conf = "HIGH (AI Reasoning with Unindexed Link)"
        else:
            heuristic_conf = "CAUTIONARY (Single Source / Unindexed Link)"

    # Rule 4: PhishTank UNAVAILABLE is neutral
    elif has_reputation_unavailable:
        fusion_notes.append("PhishTank lookup was unavailable; risk determined solely by Gemini reasoning and local heuristics.")
        heuristic_conf = "MEDIUM (Gemini + Local Only)"

    else:
        # Clean / legitimate or text-only without URLs
        if gemini_risk == RiskLevel.LOW:
            fusion_notes.append("Consistent across all sources: no social engineering markers, clean URL heuristics, and no threat intelligence records.")
            heuristic_conf = "HIGH (Consistent Multi-Source Agreement)"
        else:
            fusion_notes.append("Risk determined by Gemini textual and social engineering reasoning.")
            heuristic_conf = "HIGH (AI Reasoning)"

    # Normalize category where appropriate
    normalized_cat = normalize_category(category, is_safe=(final_risk == RiskLevel.LOW))

    # Build Transparent Evidence Summaries
    gemini_summary = (
        f"Assessed as {gemini_risk.value} risk. Category: {category}."
    )
    url_summary = (
        f"{len(suspicious_urls)} suspicious URL(s) flagged: " + "; ".join(s for u in suspicious_urls for s in u.suspicious_signals[:2])
        if suspicious_urls
        else (f"{len(urls_detected)} URL(s) inspected: standard domain structures and protocols" if urls_detected else "No URLs detected in message")
    )
    if has_known_phish:
        pt_summary = "ALERT: Confirmed active phishing threat in PhishTank database"
    elif all_reputations_no_match:
        pt_summary = "No matching records found in PhishTank (Caution: does not guarantee safety)"
    elif has_reputation_unavailable:
        pt_summary = "Service unavailable or timed out (treated as neutral evidence)"
    elif urls_detected:
        pt_summary = "All detected URLs verified or unindexed without known phish flags"
    else:
        pt_summary = "N/A (No URLs in message)"

    rationale_str = " ".join(fusion_notes) if fusion_notes else "Synthesized findings across Gemini, local heuristics, and threat intelligence."

    evidence_summary = EvidenceSummary(
        gemini_assessment=gemini_summary,
        local_url_findings=url_summary,
        phishtank_findings=pt_summary,
        fusion_rationale=rationale_str,
        heuristic_confidence=heuristic_conf,
    )

    gemini_attacks = list(gemini_response.attack_types) if hasattr(gemini_response, "attack_types") and gemini_response.attack_types else []
    final_attack_types = [] if final_risk == RiskLevel.LOW else merge_attack_types(
        det_attack_types,
        gemini_attacks,
        raw_message=raw_message,
        urls_detected=urls_detected,
        conversation_tactics=conversation_tactics,
    )

    return AnalysisResponse(
        risk_level=final_risk,
        scam_category=normalized_cat,
        suspicious_indicators=indicators,
        explanation=explanation,
        recommended_action=action,
        urls_detected=urls_detected,
        evidence_summary=evidence_summary,
        conversation_tactics=conversation_tactics or (gemini_response.conversation_tactics if gemini_response else None),
        attack_types=final_attack_types,
    )
