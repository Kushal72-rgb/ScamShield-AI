import logging
from typing import List, Optional

from app.models import (
    AnalysisResponse,
    ConversationTactics,
    EvidenceSummary,
    PhishTankReputationStatus,
    RiskLevel,
    STANDARD_SCAM_CATEGORIES,
    UrlSignal,
)

logger = logging.getLogger(__name__)


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

    return AnalysisResponse(
        risk_level=final_risk,
        scam_category=normalized_cat,
        suspicious_indicators=indicators,
        explanation=explanation,
        recommended_action=action,
        urls_detected=urls_detected,
        evidence_summary=evidence_summary,
        conversation_tactics=conversation_tactics or (gemini_response.conversation_tactics if gemini_response else None),
    )
