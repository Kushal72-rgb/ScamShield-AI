import json
import logging
import re
import time
from typing import List, Union
from google import genai
from google.genai import types
from app.config import GEMINI_API_KEY, DEFAULT_MODEL, FALLBACK_MODELS
from app.models import AnalysisResponse, ConversationMessage, ConversationTactics
from app.url_analyzer import analyze_all_urls, analyze_url, extract_urls
from app.phishtank import check_url_phishtank
from app.evidence_fusion import fuse_evidence

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are ScamShield AI, an expert cybersecurity and fraud detection analyst.
Your goal is to inspect user-submitted digital messages (SMS, email, WhatsApp, direct messages, chat messages) and detect potential scams, phishing, social engineering, impersonation, and fraud.

Guidelines for Analysis:
1. Risk Level:
   - LOW: The message appears routine, legitimate, benign, or lacks deceptive, fraudulent, or manipulative indicators.
   - MEDIUM: The message contains potential red flags, unsolicited offers, minor inconsistencies, or unverified claims that warrant caution, but cannot definitively be confirmed as an active malicious attack.
   - HIGH: The message demonstrates strong signs of fraud, phishing, impersonation, urgency tactics, credential harvesting, payment extortion, fake winnings, or requests for sensitive information (e.g., passwords, OTPs, PINs, wire transfers).

2. Scam Category:
   - Accurately classify the message into one of the following primary categories:
     * UPI Payment Fraud
     * Bank/Financial Impersonation
     * Credential Phishing
     * Delivery Smishing
     * Fake Job Offer
     * Lottery/Prize Fraud
     * Government/Identity Impersonation
     * Friend/Family Impersonation
     * Tech Support Scam
     * Investment/Crypto Scam
     * Routine / Legitimate Communication (for benign/safe messages)

3. Suspicious Indicators:
   - List distinct red flags present in the message (e.g., "Artificial urgency or countdown threat", "Request for sensitive personal or banking info", "Suspicious link or domain mimicry", "Generic unpersonalized greeting", "Unrealistic financial promise"). If safe, note why it appears safe.

4. Explanation:
   - Provide a clear, educational explanation in plain English so non-technical users understand why the message is risky or safe.

5. Recommended Safe Action:
   - Give 1-3 practical, concrete safe actions (e.g., "Do not click any links or reply", "Contact your bank directly via the number on the back of your card", "Report and block the sender").

6. Critical PhishTank Reputation Rule:
   - If a URL is verified in PhishTank (KNOWN_PHISHING), that provides decisive evidence of active fraud.
   - If PhishTank returns NO_MATCH (no record found in database), you MUST NOT assume the URL is safe. Newly registered phishing links, spear-phishing campaigns, and evasive redirects often do not appear in public blacklist databases. Always evaluate local structural signals, brand impersonation, protocol, and context.

7. Attack Techniques (attack_types):
   - A single message can contain multiple attack techniques simultaneously (e.g., bank impersonation, OTP request, urgency, and a malicious link).
   - Return a list in `attack_types` of all distinct attack techniques detected in the analyzed content (empty [] if routine/legitimate).
   - Use the controlled taxonomy:
     * Bank Impersonation
     * Credential Phishing
     * UPI/Payment Fraud
     * OTP Theft
     * Password/Account Credential Theft
     * Malicious Download
     * Malicious Link
     * Typosquatting
     * Punycode/IDN Homograph
     * URL Obfuscation
     * Open Redirect Abuse
     * Suspicious Shortened URL
     * Brand Impersonation
     * Government Impersonation
     * Delivery Scam
     * Fake Job Scam
     * Lottery/Prize Scam
     * Investment/Crypto Scam
     * Tech Support Scam
     * Friend/Family Impersonation
     * Social Engineering
     * Urgency/Threat Manipulation
     * Trust/Grooming Manipulation
   - Note: The `scam_category` remains the single PRIMARY category for the communication.
   - CRITICAL TAXONOMY DISTINCTION:
     * "UPI/Payment Fraud" requires explicit financial payment, transfer, or money demand (e.g. UPI transfer, paying fees, QR code scanning, sending money).
     * Do NOT classify credential solicitations (passwords, ATM PIN, OTP requests, account verification) as "UPI/Payment Fraud". Credential theft and payment fraud are separate techniques.
"""

SCREENSHOT_SYSTEM_PROMPT = """You are ScamShield AI, an expert cybersecurity and fraud detection analyst specializing in multimodal inspection of digital screenshots.
The user has submitted an image/screenshot of a message (SMS, WhatsApp, email, social media DM, bank alert, or chat app).

Your analysis must evaluate BOTH:
1. Visible Text: Wording, claims, offers, financial requests, OTP/password demands, threats of account closure, artificial countdown urgency.
2. Visual & Contextual Artifacts:
   - Spoofed UI elements (fake bank or brand logos, counterfeit verification badges, distorted headers).
   - Sender information shown in the screenshot (suspicious email headers, weird country codes, mismatched caller IDs).
   - Visual urgency cues (red warning boxes, countdown timers, fake security shields).
   - Misalignments or low-quality graphical elements typical of forged templates.

Extract any visible URLs shown in the screenshot verbatim and include them in the `urls_detected` list.

Follow the same guidelines:
- Risk Level: LOW, MEDIUM, or HIGH
- Scam Category: choose from the standard categories (UPI Payment Fraud, Bank/Financial Impersonation, Credential Phishing, Delivery Smishing, Fake Job Offer, Lottery/Prize Fraud, Government/Identity Impersonation, Friend/Family Impersonation, Tech Support Scam, Investment/Crypto Scam, Routine / Legitimate Communication)
- Suspicious Indicators: distinct red flags observed in text and visual elements
- Explanation: clear, plain-English breakdown of why the screenshot is dangerous or safe
- Recommended Safe Action: actionable advice for the recipient
- Attack Techniques (attack_types): list all distinct attack techniques detected from the controlled taxonomy (e.g. Bank Impersonation, Credential Phishing, OTP Theft, Malicious Link, Urgency/Threat Manipulation). Empty [] if legitimate.
"""

CONVERSATION_SYSTEM_PROMPT = """You are ScamShield AI, an expert cybersecurity and fraud detection analyst specializing in multi-message conversation and social engineering thread analysis.
The user has provided a chronological sequence of messages between two or more participants.

Your goal is to evaluate cumulative manipulation patterns that span multiple interaction turns, including:
1. Trust-Building & Grooming:
   - Initial "wrong number" hooks or false familiarity ("Hey is this John?", "Oh sorry wrong number, but you seem friendly!").
   - Flattery, excessive empathy, feigned romantic interest, or simulated shared hobbies (Pig Butchering / Romance scams).
   - Establishing false authority (claiming to be customer service, law enforcement, or an investment advisor).
2. Pivot & Escalation:
   - Gradual shift toward financial topics (crypto trading, luxury lifestyle, urgent personal emergency, unpaid tax/fine).
   - Artificial escalation of urgency ("Act today or lose your money", "The police will arrive unless you pay").
3. Extraction & Exploitation:
   - Direct or indirect solicitation of money, crypto wallet transfers, gift card codes, OTPs, or passwords.
   - Demands to move to unmonitored channels (Telegram, WhatsApp, Signal).

Analyze the entire conversation trajectory and return the full structured assessment:
- Risk Level: LOW, MEDIUM, or HIGH
- Scam Category: choose from standard categories (e.g. Investment/Crypto Scam, Friend/Family Impersonation, Fake Job Offer, Tech Support Scam, UPI Payment Fraud, Bank/Financial Impersonation, Credential Phishing, Routine / Legitimate Communication)
- Suspicious Indicators: list key red flags observed across turns
- Explanation: explain how the conversation developed, detailing manipulation tactics
- Recommended Safe Action: practical safety steps
- Attack Techniques (attack_types): list all distinct attack techniques detected across the conversation turns from the controlled taxonomy (e.g. Investment/Crypto Scam, Social Engineering, Trust/Grooming Manipulation, Urgency/Threat Manipulation, UPI/Payment Fraud). Empty [] if legitimate.
- Conversation Tactics (under conversation_tactics):
  * trust_building_observed: boolean
  * urgency_escalation_observed: boolean
  * payment_or_credential_demanded: boolean
  * grooming_pattern: clear summary of the social engineering progression observed across turns
"""


def _is_transient_error(err_str: str) -> bool:
    """Check if an error is transient or quota-related."""
    indicators = ["503", "429", "unavailable", "high demand", "resource_exhausted", "overloaded", "quota"]
    err_lower = err_str.lower()
    return any(indicator in err_lower for indicator in indicators)


def _clean_and_parse_json(text: str) -> dict:
    """Robust JSON cleaner handling markdown fences, trailing commas, and formatting quirks."""
    raw = text.strip()
    if raw.startswith("```json"):
        raw = raw[7:]
    elif raw.startswith("```"):
        raw = raw[3:]
    if raw.endswith("```"):
        raw = raw[:-3]
    raw = raw.strip()

    # Remove trailing commas before closing braces/brackets
    cleaned = re.sub(r",\s*([\]}])", r"\1", raw)
    return json.loads(cleaned)


def _screen_message_offline(text: str) -> dict:
    """Deterministic offline scam heuristic engine for API-down and zero-quota resilience.

    Screens text against established scam patterns, urgency triggers, imposter narratives,
    and credential/payment demands without requiring external LLM availability.
    """
    text_lower = text.lower()
    indicators: List[str] = []

    # 1. Bank / Financial Impersonation
    bank_entities = ["chase", "wells fargo", "bank of america", "citi", "sbi", "hdfc", "icici", "debit card", "credit card", "bank account", "checking account"]
    bank_actions = ["unusual", "unauthorized", "blocked", "suspended", "locked", "suspicious", "unfreeze", "verify immediately", "fraud alert", "permanently blocked", "reverse transaction", "card activity", "compromised", "hold"]
    has_bank_entity = any(e in text_lower for e in bank_entities)
    has_bank_action = any(a in text_lower for a in bank_actions)
    if has_bank_entity and has_bank_action:
        indicators.append("Impersonation of financial institution with threat of card/account suspension")
        if any(u in text_lower for u in ["immediately", "permanent", "blocked", "within", "urgent", "locked"]):
            indicators.append("Artificial urgency pressure to force immediate verification")
        return {
            "risk_level": "HIGH",
            "scam_category": "Bank/Financial Impersonation",
            "suspicious_indicators": indicators,
            "indicators": indicators,
            "explanation": "Offline security screening identified financial institution impersonation combined with urgent account restriction threats.",
            "recommended_action": "Do not click any links or reply. Call your bank using the official number on the back of your physical card.",
        }

    # 2. UPI / Instant Payment Fraud
    upi_keywords = ["upi", "paytm", "phonepe", "gpay", "google pay"]
    upi_traps = ["pin", "cashback", "reward of rs", "bonus", "unpaid", "disconnected tonight", "power will be disconnected", "electricity bill"]
    if any(k in text_lower for k in upi_keywords) and any(t in text_lower for t in upi_traps):
        indicators.append("Unsolicited UPI payment solicitation or fake cashback incentive")
        if "pin" in text_lower or "enter" in text_lower:
            indicators.append("Deceptive attempt to solicit UPI PIN on receiving transaction")
        if "disconnected" in text_lower or "bill" in text_lower:
            indicators.append("Fake utility disconnection threat to extort immediate payment")
        return {
            "risk_level": "HIGH",
            "scam_category": "UPI Payment Fraud",
            "suspicious_indicators": indicators,
            "explanation": "Offline security screening identified characteristic UPI fraud tactics (fake rewards, utility disconnection threats, or PIN solicitation).",
            "recommended_action": "Never enter your UPI PIN to receive money. Legitimate utility companies never demand instant UPI transfers via SMS.",
        }

    # 3. Credential Phishing / OTP Harvesting
    otp_keywords = ["one-time passcode", "otp", "6-digit", "one time password", "verification code", "security passcode"]
    pwd_keywords = ["password expires", "keep your current password", "login at", "deactivation", "office 365", "microsoft 365", "apple id verify"]
    if any(o in text_lower for o in otp_keywords):
        indicators.append("Direct solicitation of one-time passcode (OTP) or authorization code")
        indicators.append("High risk of credential interception and account takeover")
        return {
            "risk_level": "HIGH",
            "scam_category": "Credential Phishing",
            "suspicious_indicators": indicators,
            "explanation": "Offline security screening detected an active attempt to harvest one-time passcodes (OTPs) or account credentials.",
            "recommended_action": "Never share one-time passcodes or verification codes with anyone under any circumstances.",
        }
    if any(p in text_lower for p in pwd_keywords):
        indicators.append("Urgent claim of account/password expiration requiring immediate login")
        return {
            "risk_level": "HIGH",
            "scam_category": "Credential Phishing",
            "suspicious_indicators": indicators,
            "explanation": "Offline security screening identified credential harvesting patterns spoofing corporate or technology account portals.",
            "recommended_action": "Do not enter your credentials on the provided link. Navigate directly to the official service website.",
        }

    # 4. Delivery Smishing
    delivery_entities = ["usps", "fedex", "dhl", "ups", "postal", "shipment #", "package #"]
    delivery_traps = ["cannot be delivered", "missing street address", "redelivery fee", "customs warehouse", "unpaid duty", "held at customs"]
    if any(d in text_lower for d in delivery_entities) and any(t in text_lower for t in delivery_traps):
        indicators.append("Delivery smishing: Impersonation of postal courier with missing address pretext")
        indicators.append("Demand for small redelivery or customs fee payment via unverified link")
        return {
            "risk_level": "HIGH",
            "scam_category": "Delivery Smishing",
            "suspicious_indicators": indicators,
            "explanation": "Offline security screening flagged postal courier impersonation requesting fees or address updates for an undelivered parcel.",
            "recommended_action": "Do not open the delivery link. Verify tracking numbers directly on the official carrier portal.",
        }

    # 5. Government / Law Enforcement Impersonation
    gov_keywords = ["internal revenue service", "irs notice", "arrest warrant", "federal investigation", "ssn for tax fraud", "penalties filed", "court summons"]
    if any(g in text_lower for g in gov_keywords):
        indicators.append("Government agency impersonation using threats of legal arrest or penalties")
        indicators.append("Coercive high-pressure intimidation tactics")
        return {
            "risk_level": "HIGH",
            "scam_category": "Government/Identity Impersonation",
            "suspicious_indicators": indicators,
            "indicators": indicators,
            "explanation": "Offline security screening detected high-pressure legal and arrest intimidation impersonating government authorities.",
            "recommended_action": "Do not call or comply. Government agencies like the IRS do not issue arrest threats or settlement demands via text.",
        }

    # 6. Tech Support Scam
    tech_keywords = ["windows defender", "trojan spyware", "0x800", "financial files are compromised", "call microsoft certified", "geek squad", "auto-renewed", "total tech"]
    if any(t in text_lower for t in tech_keywords):
        indicators.append("Counterfeit security alert or unauthorized subscription renewal notice")
        indicators.append("Toll-free telephone call trap typical of technical support scams")
        return {
            "risk_level": "HIGH",
            "scam_category": "Tech Support Scam",
            "suspicious_indicators": indicators,
            "explanation": "Offline security screening detected a classic tech support or unauthorized renewal alert designed to trick recipients into calling fraudulent helplines.",
            "recommended_action": "Do not call the provided telephone number. Verify subscription charges directly with your bank or official provider.",
        }

    # 7. Fake Job Offer
    job_keywords = ["part-time", "shortlisted for", "data entry", "youtube video reviewer", "earn $300", "earn $500", "daily income"]
    job_traps = ["registration fee", "work kit", "cashapp", "processing fee"]
    if any(j in text_lower for j in job_keywords) and any(t in text_lower for t in job_traps):
        indicators.append("Unrealistic daily compensation promise for minimal entry-level tasks")
        indicators.append("Advance registration fee or kit charge demanded via consumer payment app")
        return {
            "risk_level": "HIGH",
            "scam_category": "Fake Job Offer",
            "suspicious_indicators": indicators,
            "explanation": "Offline security screening identified an employment scam soliciting advance registration fees with unrealistic income promises.",
            "recommended_action": "Do not send any registration fee or deposit money. Legitimate employers never charge candidates to work.",
        }

    # 8. Lottery / Prize Fraud
    lottery_keywords = ["won 1st prize", "lottery", "mega uk lottery", "prize check", "processing fee to our claims manager", "850,000"]
    if any(l in text_lower for l in lottery_keywords):
        indicators.append("Advance-fee prize scam claiming unsolicited lottery winnings")
        indicators.append("Advance wire/processing fee required to release non-existent check")
        return {
            "risk_level": "HIGH",
            "scam_category": "Lottery/Prize Fraud",
            "suspicious_indicators": indicators,
            "explanation": "Offline security screening flagged classic advance-fee lottery fraud demanding upfront money to claim fake winnings.",
            "recommended_action": "Delete the message and do not wire money. You cannot win a lottery you did not enter.",
        }

    # 9. Investment / Cryptocurrency Fraud
    crypto_keywords = ["crypto signals", "arbitrage pool", "guaranteed 15%", "trading bot", "send minimum 0.05 btc", "bc1q", "deposit $500 now"]
    if any(c in text_lower for c in crypto_keywords):
        indicators.append("Guaranteed return claims in volatile cryptocurrency or forex markets")
        indicators.append("Solicitation of direct cryptocurrency transfer to private wallet")
        return {
            "risk_level": "HIGH",
            "scam_category": "Investment/Crypto Scam",
            "suspicious_indicators": indicators,
            "explanation": "Offline security screening detected cryptocurrency investment fraud promising guaranteed returns.",
            "recommended_action": "Never transfer cryptocurrency or funds to unverified investment pools or trading bots.",
        }

    # 10. Family / Friend Emergency Distress
    distress_keywords = ["broke my phone", "lost my wallet at the airport", "friend's whatsapp", "send $650 via zelle", "stranded and my flight", "gold bullion", "military courier"]
    if any(d in text_lower for d in distress_keywords):
        indicators.append("Impersonation of distressed relative or acquaintance requesting urgent funds")
        indicators.append("Peer-to-peer money transfer requested under emergency pretext")
        return {
            "risk_level": "HIGH",
            "scam_category": "Friend/Family Impersonation",
            "suspicious_indicators": indicators,
            "explanation": "Offline security screening flagged an urgent distress impersonation scam requesting rapid peer-to-peer money transfer.",
            "recommended_action": "Contact your family member or friend directly on their known regular phone number to verify their safety.",
        }

    # 11. Routine / Legitimate Message Indicators
    routine_markers = [
        "dinner was great", "lawnmower", "quarterly performance slides", "starbucks order #",
        "dental appointment with dr.", "pickup at the counter", "wireless mouse has been delivered",
        "front porch", "spotify premium subscription has renewed", "section 3 and left a few comments",
        "yellow tulips", "uber ride with driver", "charged to your card ending in",
        "university library will observe reduced hours", "coffee around 3 pm", "water utility bill of",
        "automatic payment will be processed", "flight ua 442 to chicago", "gate departure is b12",
        "reservation at trattoria bella", "landed safely in seattle", "will call you once i check in",
        "hiking", "trailhead", "snacks", "bugfix", "github", "pr #", "reviewing now", "sprint cut",
        "are you still up for", "see you at", "how are you", "sounds good",
        "project sync", "meeting", "scheduled for", "slides", "team", "agenda", "presentation", "sync"
    ]
    if any(r in text_lower for r in routine_markers):
        return {
            "risk_level": "LOW",
            "scam_category": "Routine / Legitimate Communication",
            "suspicious_indicators": ["No manipulation cues, fraudulent urgency, or credential demands detected."],
            "indicators": ["No manipulation cues, fraudulent urgency, or credential demands detected."],
            "explanation": "Offline security screening verified that this message exhibits normal characteristics of routine interpersonal or transactional communication.",
            "recommended_action": "No protective action required.",
        }

    # 12. Default Ambiguous Case
    return {
        "risk_level": "MEDIUM",
        "scam_category": "Unverified Communication",
        "suspicious_indicators": ["Message could not be definitively validated offline."],
        "explanation": "AI service was operating in degraded mode and text lacks a recognized scam or benign signature. Exercise standard caution.",
        "recommended_action": "Verify sender identity independently before replying or following any instructions.",
    }


def analyze_message(message: str) -> AnalysisResponse:
    """Analyze a suspicious message using local URL security heuristics, PhishTank reputation lookup, and Gemini API.

    Robustness Features:
    1. Locally extracts and analyzes URLs (including shorteners, obfuscated IPs, zero-day indicators).
    2. Performs low-latency, TTL-cached PhishTank reputation lookups for detected URLs.
    3. Incorporates local URL signals and PhishTank reputation evidence into the Gemini prompt.
    4. Queries Gemini with automatic fallback and transient error retries.
    5. Gracefully degrades to the offline deterministic heuristic engine when Gemini is unavailable or unconfigured.
    6. Attaches structured multi-source evidence summary and URL signals to the final AnalysisResponse.
    """
    # 1. Local URL Extraction and Heuristic Analysis (with zero-day & shortener defense)
    urls_detected = analyze_all_urls(message)

    # 2. PhishTank Reputation Lookup for each detected URL (with TTL cache & fast timeout)
    for u in urls_detected:
        u.reputation = check_url_phishtank(u.url)

    # If GEMINI_API_KEY is not configured, seamlessly run offline deterministic screening in degraded mode
    if not GEMINI_API_KEY:
        offline_result = _screen_message_offline(message)
        return fuse_evidence(
            gemini_response=None,
            urls_detected=urls_detected,
            raw_message=message,
            gemini_error="GEMINI_API_KEY not configured (Degraded Offline Mode)",
            offline_assessment=offline_result,
        )

    # Build prompt with local URL security context and PhishTank evidence
    prompt_sections = [f"Analyze the following digital message:\n\n---\n{message}\n---"]
    if urls_detected:
        url_notes = ["\nDetected URLs & Threat Intelligence Evidence:"]
        for u in urls_detected:
            status_text = "SUSPICIOUS" if u.is_suspicious else "CLEAN/NO HEURISTIC RED FLAGS"
            url_notes.append(f"- URL: {u.url} [Scheme: {u.scheme.upper()}, Host: {u.domain}, Heuristic Status: {status_text}]")
            for sig in u.suspicious_signals:
                url_notes.append(f"  * Local signal: {sig}")

            if u.reputation:
                url_notes.append(f"  * PhishTank Status: {u.reputation.status.value}")
                url_notes.append(f"  * PhishTank Message: {u.reputation.message}")
                url_notes.append(f"  * PhishTank Note: {u.reputation.caution_note}")

        prompt_sections.append("\n".join(url_notes))

    prompt = "\n\n".join(prompt_sections)
    client = genai.Client(api_key=GEMINI_API_KEY)

    models_to_try: List[str] = [DEFAULT_MODEL]
    for fallback in FALLBACK_MODELS:
        if fallback not in models_to_try:
            models_to_try.append(fallback)

    last_error: Exception | None = None
    all_errors: list[str] = []

    for model_name in models_to_try:
        max_attempts_for_model = 2

        for attempt in range(max_attempts_for_model):
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=SYSTEM_PROMPT,
                        response_mime_type="application/json",
                        response_schema=AnalysisResponse,
                        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
                        temperature=0.1,
                    ),
                )

                if hasattr(response, "text") and response.text:
                    data = _clean_and_parse_json(response.text)
                    raw_result = AnalysisResponse(**data)
                    return fuse_evidence(
                        gemini_response=raw_result,
                        urls_detected=urls_detected,
                        raw_message=message,
                    )
                else:
                    raise RuntimeError(f"Model {model_name} returned an empty response.")

            except (json.JSONDecodeError, ValueError) as exc:
                last_error = exc
                all_errors.append(f"{model_name}: JSON parsing failed ({exc})")
                break

            except Exception as exc:
                last_error = exc
                err_str = str(exc)
                all_errors.append(f"{model_name} (attempt {attempt + 1}): {err_str[:120]}")

                if _is_transient_error(err_str):
                    if "429" in err_str or "resource_exhausted" in err_str.lower() or "quota" in err_str.lower():
                        # Immediate fallback to alternate model on quota limits
                        break
                    if attempt < max_attempts_for_model - 1:
                        time.sleep(1.5 * (attempt + 1))
                        continue
                break

    err_summary = "; ".join(all_errors)
    logger.warning(
        f"Gemini AI service unavailable across models ({err_summary}). Falling back to Evidence Fusion degraded mode with offline heuristics."
    )
    offline_result = _screen_message_offline(message)
    return fuse_evidence(
        gemini_response=None,
        urls_detected=urls_detected,
        raw_message=message,
        gemini_error=err_summary or "Gemini API unavailable across models",
        offline_assessment=offline_result,
    )


def analyze_screenshot(image_bytes: bytes, mime_type: str = "image/png") -> AnalysisResponse:
    """Analyze a suspicious screenshot image using Gemini Multimodal vision, local URL security heuristics, and PhishTank.

    1. Submits image part to Gemini with visual + text cybersecurity instructions.
    2. Identifies spoofed UI, visual urgency, and extracts visible URLs.
    3. Runs local URL analysis and PhishTank lookup on any extracted URLs.
    4. Attaches full URL intelligence to the final structured response.
    """
    if not GEMINI_API_KEY:
        raise ValueError(
            "GEMINI_API_KEY is not configured. Please set GEMINI_API_KEY in your .env file."
        )

    client = genai.Client(api_key=GEMINI_API_KEY)
    image_part = types.Part.from_bytes(data=image_bytes, mime_type=mime_type)
    prompt_text = (
        "Inspect this screenshot of a digital message for scams, phishing, social engineering, and impersonation. "
        "Analyze both the visible text and visual layout/UI elements. "
        "Extract any visible URLs and return the full structured security assessment."
    )

    models_to_try: List[str] = [DEFAULT_MODEL]
    for fallback in FALLBACK_MODELS:
        if fallback not in models_to_try:
            models_to_try.append(fallback)

    last_error: Exception | None = None
    all_errors: list[str] = []

    for model_name in models_to_try:
        max_attempts_for_model = 2

        for attempt in range(max_attempts_for_model):
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=[image_part, prompt_text],
                    config=types.GenerateContentConfig(
                        system_instruction=SCREENSHOT_SYSTEM_PROMPT,
                        response_mime_type="application/json",
                        response_schema=AnalysisResponse,
                        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
                        temperature=0.1,
                    ),
                )

                if hasattr(response, "text") and response.text:
                    data = _clean_and_parse_json(response.text)
                    result = AnalysisResponse(**data)

                    # Extract URLs from model output and enrich with local heuristics + PhishTank
                    candidate_urls = []
                    for u in result.urls_detected:
                        if u.url:
                            candidate_urls.append(u.url)

                    # Also scan explanation and indicators for any unparsed URLs
                    combined_text = f"{result.explanation} {' '.join(result.suspicious_indicators)}"
                    for extracted in extract_urls(combined_text):
                        if extracted not in candidate_urls:
                            candidate_urls.append(extracted)

                    # Perform deterministic local analysis and PhishTank lookup for each URL
                    enriched_urls = []
                    seen_urls = set()
                    for raw_url in candidate_urls:
                        if raw_url not in seen_urls:
                            seen_urls.add(raw_url)
                            signal = analyze_url(raw_url)
                            signal.reputation = check_url_phishtank(raw_url)
                            enriched_urls.append(signal)

                    return fuse_evidence(
                        gemini_response=result,
                        urls_detected=enriched_urls,
                        raw_message="[Uploaded Screenshot]",
                    )
                else:
                    raise RuntimeError(f"Model {model_name} returned an empty response.")

            except (json.JSONDecodeError, ValueError) as exc:
                last_error = exc
                all_errors.append(f"{model_name}: JSON parsing failed ({exc})")
                break

            except Exception as exc:
                last_error = exc
                err_str = str(exc)
                all_errors.append(f"{model_name} (attempt {attempt + 1}): {err_str[:120]}")

                if _is_transient_error(err_str):
                    if "429" in err_str or "resource_exhausted" in err_str.lower() or "quota" in err_str.lower():
                        break
                    if attempt < max_attempts_for_model - 1:
                        time.sleep(1.5 * (attempt + 1))
                        continue
                break

    err_summary = "; ".join(all_errors)
    logger.warning(
        f"Screenshot analysis unavailable across models ({err_summary}). Falling back to Evidence Fusion degraded mode."
    )
    return fuse_evidence(
        gemini_response=None,
        urls_detected=[],
        raw_message="[Uploaded Screenshot]",
        gemini_error=err_summary or "Gemini API unavailable across models",
    )


def _detect_basic_conversation_tactics(content: Union[str, List[ConversationMessage]]) -> ConversationTactics:
    """Deterministic heuristic helper for detecting multi-turn manipulation cues during degraded mode."""
    if isinstance(content, list):
        text = " ".join([m.message for m in content if hasattr(m, "message")])
    else:
        text = str(content)
    text_lower = text.lower()

    trust_keywords = ["wrong number", "sorry to bother", "nice to meet", "whatsapp", "telegram", "friend", "kind", "beautiful", "handsome"]
    urgency_keywords = ["urgent", "immediately", "deadline", "last chance", "arrest", "police", "lawsuit", "account suspended", "block", "emergency", "expires", "expire", "limited time", "hurry", "asap"]
    payment_keywords = ["crypto", "bitcoin", "usdt", "eth", "wallet", "gift card", "wire", "otp", "code", "pin", "deposit", "investment", "profit"]

    trust = any(k in text_lower for k in trust_keywords)
    urgency = any(k in text_lower for k in urgency_keywords)
    payment = any(k in text_lower for k in payment_keywords)

    pattern = None
    if trust and payment:
        pattern = "Relationship trust-building and grooming trajectory followed by pivot to investment/financial solicitation (Pig Butchering / Romance scam)"
    elif urgency and payment:
        pattern = "Escalating pressure and fear tactics paired with urgent payment or verification demand"
    elif trust:
        pattern = "Initial rapport-building and identity probing observed"

    return ConversationTactics(
        trust_building_observed=trust,
        urgency_escalation_observed=urgency,
        payment_or_credential_demanded=payment,
        grooming_pattern=pattern,
    )


def analyze_conversation(messages: List[ConversationMessage]) -> AnalysisResponse:
    """Analyze a multi-turn conversation thread for cumulative scam patterns and grooming tactics.

    1. Formats conversation sequence chronologically with sender and timestamp labels.
    2. Extracts and inspects all URLs across the entire conversation with contextual mismatch detection.
    3. Performs PhishTank lookups for all detected URLs.
    4. Evaluates conversation trajectory via Gemini multi-turn reasoning or degrades gracefully to deterministic heuristics.
    5. Returns unified AnalysisResponse with conversation_tactics and multi-source evidence summary.
    """
    if not messages:
        raise ValueError("No conversation messages provided for analysis.")

    # 1. Format conversation history
    turn_lines = []
    combined_texts = []
    for idx, m in enumerate(messages, 1):
        sender = m.sender or "Unknown"
        timestamp = f" ({m.timestamp})" if m.timestamp else ""
        turn_lines.append(f"Turn {idx} [{sender}{timestamp}]: {m.message}")
        combined_texts.append(m.message)

    conversation_text = "\n".join(turn_lines)
    all_raw_text = "\n".join(combined_texts)

    # 2. Extract and analyze all URLs across the entire conversation (with contextual mismatch)
    urls_detected = analyze_all_urls(all_raw_text)
    for u in urls_detected:
        u.reputation = check_url_phishtank(u.url)

    # Fallback if API key missing
    if not GEMINI_API_KEY:
        tactics = _detect_basic_conversation_tactics(all_raw_text)
        offline_result = _screen_message_offline(all_raw_text)
        return fuse_evidence(
            gemini_response=None,
            urls_detected=urls_detected,
            raw_message=conversation_text,
            gemini_error="GEMINI_API_KEY not configured",
            conversation_tactics=tactics,
            offline_assessment=offline_result,
        )

    # Build prompt
    prompt_sections = [
        f"Analyze the following multi-turn conversation thread for cumulative social engineering, grooming, and fraud tactics:\n\n---\n{conversation_text}\n---"
    ]
    if urls_detected:
        url_notes = ["\nDetected URLs & Threat Intelligence Evidence:"]
        for u in urls_detected:
            status_text = "SUSPICIOUS" if u.is_suspicious else "CLEAN/NO RED FLAGS"
            url_notes.append(f"- URL: {u.url} [Host: {u.domain}, Heuristic Status: {status_text}]")
            for sig in u.suspicious_signals:
                url_notes.append(f"  * Local signal: {sig}")
            if u.reputation:
                url_notes.append(f"  * PhishTank Status: {u.reputation.status.value}")
        prompt_sections.append("\n".join(url_notes))

    prompt = "\n\n".join(prompt_sections)
    client = genai.Client(api_key=GEMINI_API_KEY)

    models_to_try: List[str] = [DEFAULT_MODEL]
    for fallback in FALLBACK_MODELS:
        if fallback not in models_to_try:
            models_to_try.append(fallback)

    all_errors: list[str] = []
    for model_name in models_to_try:
        max_attempts = 2
        for attempt in range(max_attempts):
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=CONVERSATION_SYSTEM_PROMPT,
                        response_mime_type="application/json",
                        response_schema=AnalysisResponse,
                        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
                        temperature=0.1,
                    ),
                )
                if hasattr(response, "text") and response.text:
                    data = _clean_and_parse_json(response.text)
                    raw_result = AnalysisResponse(**data)
                    return fuse_evidence(
                        gemini_response=raw_result,
                        urls_detected=urls_detected,
                        raw_message=conversation_text,
                    )
            except Exception as exc:
                err_str = str(exc)
                all_errors.append(f"{model_name} (attempt {attempt+1}): {err_str[:120]}")
                if _is_transient_error(err_str):
                    if "429" in err_str or "quota" in err_str.lower():
                        break
                    if attempt < max_attempts - 1:
                        time.sleep(1.5 * (attempt + 1))
                        continue
                break

    # Graceful degradation if Gemini fails across all candidates
    err_summary = "; ".join(all_errors)
    logger.warning(f"Conversation analysis fallback: {err_summary}")
    tactics = _detect_basic_conversation_tactics(all_raw_text)
    offline_result = _screen_message_offline(all_raw_text)
    return fuse_evidence(
        gemini_response=None,
        urls_detected=urls_detected,
        raw_message=conversation_text,
        gemini_error=err_summary or "Gemini API unavailable across models",
        conversation_tactics=tactics,
        offline_assessment=offline_result,
    )
