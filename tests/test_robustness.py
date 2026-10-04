import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure root directory is on the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models import (
    AnalysisResponse,
    ConversationMessage,
    ConversationTactics,
    PhishTankReputationStatus,
    PhishTankResult,
    RiskLevel,
    UrlSignal,
)
from app.url_analyzer import analyze_url, detect_contextual_mismatches
from app.evidence_fusion import fuse_evidence
from app.analyzer import (
    analyze_conversation,
    analyze_message,
    _detect_basic_conversation_tactics,
    _screen_message_offline,
)
from app.phishtank import (
    check_url_phishtank,
    clear_phishtank_cache,
    get_cached_phishtank_result,
    cache_phishtank_result,
    get_phishtank_cache_stats,
    REQUEST_TIMEOUT,
)


class TestZeroDayPhishingResilience(unittest.TestCase):
    """Tests for zero-day phishing indicators (punycode, typosquatting, non-standard ports, dynamic DNS, payloads)."""

    def test_punycode_idn_homograph_detection(self):
        """Punycode (xn--) domains must be flagged as suspicious homograph threats."""
        url = "https://xn--pypal-4ve.com/signin"
        analysis = analyze_url(url)
        self.assertTrue(analysis.is_suspicious)
        self.assertTrue(
            any("punycode" in s.lower() or "internationalized" in s.lower() for s in analysis.suspicious_signals),
            f"Expected punycode indicator, got: {analysis.suspicious_signals}",
        )

    def test_typosquatting_character_substitution(self):
        """Domains using leetspeak substitutions (e.g. paypa1, micros0ft) must be flagged."""
        url = "https://paypa1-security.com/account"
        analysis = analyze_url(url)
        self.assertTrue(analysis.is_suspicious)
        self.assertTrue(
            any("character substitution" in s.lower() or "paypa1" in s.lower() for s in analysis.suspicious_signals),
            f"Expected typosquatting indicator, got: {analysis.suspicious_signals}",
        )

    def test_non_standard_web_port(self):
        """Phishing URLs using suspicious non-standard ports (e.g. 8080, 8443) must be flagged."""
        url = "http://secure-update-portal.com:8080/auth"
        analysis = analyze_url(url)
        self.assertTrue(analysis.is_suspicious)
        self.assertTrue(
            any(":8080" in s for s in analysis.suspicious_signals),
            f"Expected non-standard port indicator, got: {analysis.suspicious_signals}",
        )

    def test_dynamic_dns_and_tunneling_services(self):
        """Free dynamic DNS and developer tunneling services must be flagged."""
        duckdns_url = "https://bank-verification.duckdns.org/login"
        analysis_duck = analyze_url(duckdns_url)
        self.assertTrue(analysis_duck.is_suspicious)
        self.assertTrue(
            any("dynamic dns" in s.lower() or "duckdns.org" in s.lower() for s in analysis_duck.suspicious_signals),
            f"Expected dynamic DNS signal, got: {analysis_duck.suspicious_signals}",
        )

        ngrok_url = "https://urgent-payroll-update.ngrok-free.app/signin"
        analysis_ngrok = analyze_url(ngrok_url)
        self.assertTrue(analysis_ngrok.is_suspicious)
        self.assertTrue(
            any("tunneling" in s.lower() or "ngrok-free.app" in s.lower() for s in analysis_ngrok.suspicious_signals),
            f"Expected tunneling signal, got: {analysis_ngrok.suspicious_signals}",
        )

    def test_malicious_executable_payload_extension(self):
        """URLs linking directly to executable or script files (.exe, .scr, .iso) must be flagged."""
        url = "http://shipping-documents-download.org/invoice_details.pdf.exe"
        analysis = analyze_url(url)
        self.assertTrue(analysis.is_suspicious)
        self.assertTrue(
            any("executable" in s.lower() or ".exe" in s.lower() for s in analysis.suspicious_signals),
            f"Expected payload indicator, got: {analysis.suspicious_signals}",
        )

    def test_zero_day_url_with_phishtank_no_match_remains_high_threat(self):
        """Zero-day structural red flags must elevate risk even when PhishTank has NO_MATCH."""
        url = "http://paypa1-verify-account.duckdns.org:8080/login.exe"
        url_signal = analyze_url(url)
        url_signal.reputation = PhishTankResult(
            status=PhishTankReputationStatus.NO_MATCH,
            in_database=False,
            is_valid_phish=False,
            verified=False,
            phish_id=None,
            phish_detail_url=None,
            message="No matching phishing record found in PhishTank database.",
            caution_note="Caution: A URL not appearing in PhishTank does NOT prove it is safe.",
        )

        # Gemini might naively think it's a routine message
        gemini_mock = AnalysisResponse(
            risk_level=RiskLevel.LOW,
            scam_category="Routine / Legitimate Communication",
            suspicious_indicators=[],
            explanation="The message text appears harmless.",
            recommended_action="None",
            urls_detected=[],
        )

        fused = fuse_evidence(
            gemini_response=gemini_mock,
            urls_detected=[url_signal],
            raw_message="Please download your statement at http://paypa1-verify-account.duckdns.org:8080/login.exe",
        )

        self.assertEqual(fused.risk_level, RiskLevel.HIGH)
        self.assertEqual(fused.scam_category, "Credential Phishing")
        self.assertTrue(any("duckdns.org" in ind.lower() or "port 8080" in ind.lower() or "paypa1" in ind.lower() for ind in fused.suspicious_indicators))


class TestContextualMismatchDetection(unittest.TestCase):
    """Tests for mismatch detection between claimed organization and destination domain/action."""

    def test_bank_alert_directing_to_google_form(self):
        """Chase Bank security alert directing to a Google Form must trigger contextual mismatch."""
        message = "Urgent from Chase Bank: Unauthorized card activity detected. Fill this form immediately to verify: https://forms.gle/X7y9Zabc"
        mismatches = detect_contextual_mismatches(message, "forms.gle")
        self.assertTrue(len(mismatches) > 0)
        self.assertTrue(
            any("chase" in m.lower() and "google form" in m.lower() for m in mismatches),
            f"Expected Chase-Google Form mismatch, got: {mismatches}",
        )

    def test_irs_tax_refund_directing_to_notion_site(self):
        """IRS refund notification directing to Notion / Canva site must trigger contextual mismatch."""
        message = "IRS Notification: Your tax refund of $1,420 is pending disbursement. Claim it here: https://tax-claim.notion.site/refund"
        mismatches = detect_contextual_mismatches(message, "tax-claim.notion.site")
        self.assertTrue(len(mismatches) > 0)
        self.assertTrue(
            any("internal revenue service" in m.lower() or "irs" in m.lower() for m in mismatches),
            f"Expected IRS mismatch, got: {mismatches}",
        )

    def test_bank_alert_to_unrelated_domain(self):
        """Bank of America message sending user to an unrelated generic domain must trigger mismatch."""
        message = "Bank of America Alert: Suspicious login detected. Secure your account at https://unrelated-domain.com/secure"
        mismatches = detect_contextual_mismatches(message, "unrelated-domain.com")
        self.assertTrue(len(mismatches) > 0)
        self.assertTrue(
            any("bank of america" in m.lower() for m in mismatches),
            f"Expected BoA mismatch, got: {mismatches}",
        )

    def test_legitimate_institution_domain_no_mismatch(self):
        """Chase Bank message directing to chase.com must NOT trigger mismatch."""
        message = "Chase Bank: View your monthly statement at https://secure.chase.com/statement"
        mismatches = detect_contextual_mismatches(message, "secure.chase.com")
        self.assertEqual(len(mismatches), 0)

    def test_contextual_mismatch_elevates_risk_in_fusion(self):
        """Even with HTTPS and PhishTank NO_MATCH, contextual mismatch elevates risk."""
        url = "https://forms.gle/AbCdEf123"
        url_signal = analyze_url(url, context_text="Urgent from Chase Bank: verify card immediately")
        url_signal.reputation = PhishTankResult(
            status=PhishTankReputationStatus.NO_MATCH,
            in_database=False,
            is_valid_phish=False,
            verified=False,
            phish_id=None,
            phish_detail_url=None,
            message="No matching record in PhishTank.",
            caution_note="Absence from PhishTank does not prove safe.",
        )

        gemini_mock = AnalysisResponse(
            risk_level=RiskLevel.MEDIUM,
            scam_category="Bank/Financial Impersonation",
            suspicious_indicators=["Urgent tone"],
            explanation="Urgent bank message.",
            recommended_action="Contact bank.",
            urls_detected=[],
        )

        fused = fuse_evidence(
            gemini_response=gemini_mock,
            urls_detected=[url_signal],
            raw_message="Urgent from Chase Bank: verify card immediately https://forms.gle/AbCdEf123",
        )

        self.assertEqual(fused.risk_level, RiskLevel.HIGH)
        self.assertTrue(any("mismatch" in ind.lower() for ind in fused.suspicious_indicators))


class TestMultiMessageConversationAnalysis(unittest.TestCase):
    """Tests for multi-turn conversation scam analysis, tactics detection, and degraded mode."""

    def test_detect_basic_conversation_tactics_pig_butchering(self):
        """Conversation heuristic correctly detects trust-building, urgency escalation, and payment requests."""
        messages = [
            ConversationMessage(sender="Stranger", message="Hi Anna! Are we meeting for coffee today?"),
            ConversationMessage(sender="Target", message="Wrong number, sorry."),
            ConversationMessage(sender="Stranger", message="Oh I'm so sorry! You seem like such a kind person though. I'm Lisa from Singapore."),
            ConversationMessage(sender="Stranger", message="I invest in high yield crypto staking. Earned 30% today! Deposit $500 now at https://fake-crypto-yield.com before the bonus expires!"),
        ]

        tactics = _detect_basic_conversation_tactics(messages)
        self.assertTrue(tactics.trust_building_observed)
        self.assertTrue(tactics.urgency_escalation_observed)
        self.assertTrue(tactics.payment_or_credential_demanded)
        self.assertIn("grooming", tactics.grooming_pattern.lower())

    def test_detect_basic_conversation_tactics_clean_thread(self):
        """Legitimate conversation thread does not trip scam tactics."""
        messages = [
            ConversationMessage(sender="Friend", message="Hey! Did you get the recipe for dinner tomorrow?"),
            ConversationMessage(sender="You", message="Yes, just bought the ingredients. See you at 7pm!"),
        ]

        tactics = _detect_basic_conversation_tactics(messages)
        self.assertFalse(tactics.trust_building_observed)
        self.assertFalse(tactics.urgency_escalation_observed)
        self.assertFalse(tactics.payment_or_credential_demanded)

    @patch("app.analyzer.genai.Client")
    def test_analyze_conversation_success(self, mock_client_cls):
        """Verifies full conversation analysis pipeline with Gemini response and tactics attached."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_response = MagicMock()
        mock_response.text = json.dumps({
            "risk_level": "HIGH",
            "scam_category": "Investment / Cryptocurrency Fraud",
            "suspicious_indicators": [
                "Wrong-number contact strategy (Pig Butchering precursor)",
                "Rapid rapport building",
                "Unsolicited cryptocurrency investment advice",
            ],
            "explanation": "Multi-turn conversation displays a classic pig-butchering romance/crypto investment grooming pattern.",
            "recommended_action": "Block the sender immediately and do not transfer any funds.",
            "conversation_tactics": {
                "trust_building_observed": True,
                "urgency_escalation_observed": False,
                "payment_or_credential_demanded": True,
                "grooming_pattern": "Wrong-number pretext -> personal rapport -> crypto investment pitch.",
            },
        })
        mock_client.models.generate_content.return_value = mock_response

        messages = [
            ConversationMessage(sender="Stranger", message="Hey Sarah, are you still free for tennis?"),
            ConversationMessage(sender="You", message="Wrong number."),
            ConversationMessage(sender="Stranger", message="My apologies! I trade crypto on a VIP platform. Want to join my group?"),
        ]

        response = analyze_conversation(messages)

        self.assertEqual(response.risk_level, RiskLevel.HIGH)
        self.assertEqual(response.scam_category, "Investment/Crypto Scam")
        self.assertIsNotNone(response.conversation_tactics)
        self.assertTrue(response.conversation_tactics.trust_building_observed)
        self.assertTrue(response.conversation_tactics.payment_or_credential_demanded)
        self.assertIsNotNone(response.evidence_summary)

    @patch("app.analyzer.genai.Client")
    def test_analyze_conversation_degraded_mode_on_gemini_failure(self, mock_client_cls):
        """When Gemini is unavailable, conversation analysis must fall back gracefully to deterministic heuristics."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.models.generate_content.side_effect = RuntimeError("All models unavailable (503 Service Unavailable)")

        messages = [
            ConversationMessage(sender="Agent", message="Your account is suspended due to fraud!"),
            ConversationMessage(sender="Victim", message="How can I fix it?"),
            ConversationMessage(sender="Agent", message="Send an urgent wire transfer or gift card PIN right now to prevent legal arrest!"),
        ]

        response = analyze_conversation(messages)

        # Degraded fallback must return a valid AnalysisResponse
        self.assertIn(response.risk_level, [RiskLevel.MEDIUM, RiskLevel.HIGH])
        self.assertIsNotNone(response.conversation_tactics)
        self.assertTrue(response.conversation_tactics.payment_or_credential_demanded)
        self.assertTrue(response.conversation_tactics.urgency_escalation_observed)
        self.assertIn("temporarily unavailable", response.explanation)
        self.assertIn("Degraded Mode", response.evidence_summary.heuristic_confidence)


class TestPhishTankCacheAndTimeout(unittest.TestCase):
    """Tests for PhishTank thread-safe TTL caching and latency/timeout protections."""

    def setUp(self):
        clear_phishtank_cache()

    def tearDown(self):
        clear_phishtank_cache()

    def test_cache_hit_and_stats(self):
        """Verifies that cache records results and returns hits on subsequent queries."""
        sample_url = "https://test-phish-cache-item.org/login"
        res = PhishTankResult(
            status=PhishTankReputationStatus.KNOWN_PHISHING,
            in_database=True,
            is_valid_phish=True,
            verified=True,
            phish_id=12345,
            phish_detail_url="https://phishtank.org/phish_detail.php?phish_id=12345",
            message="Verified threat",
            caution_note="Caution note",
        )
        cache_phishtank_result(sample_url, res)
        cached = get_cached_phishtank_result(sample_url)
        self.assertIsNotNone(cached)
        self.assertEqual(cached.status, PhishTankReputationStatus.KNOWN_PHISHING)
        self.assertEqual(cached.phish_id, 12345)

        stats = get_phishtank_cache_stats()
        self.assertEqual(stats["total_entries"], 1)

    def test_reduced_timeout_constant(self):
        """Verifies that the network timeout is tightened to mitigate latency bottlenecks."""
        self.assertLessEqual(REQUEST_TIMEOUT, 3.0)

    @patch("app.phishtank.requests.post")
    def test_check_url_reputation_uses_cache(self, mock_post):
        """Second call to check_url_reputation must hit cache without network request."""
        sample_url = "https://cached-domain.com/secure"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": {
                "in_database": True,
                "verified": True,
                "valid": True,
                "phish_id": 9999,
                "phish_detail_page": "https://phishtank.org/phish_detail.php?phish_id=9999",
            }
        }
        mock_post.return_value = mock_response

        # First call triggers network
        first_result = check_url_phishtank(sample_url)
        self.assertEqual(first_result.status, PhishTankReputationStatus.KNOWN_PHISHING)
        self.assertEqual(mock_post.call_count, 1)

        # Second call should serve from cache
        second_result = check_url_phishtank(sample_url)
        self.assertEqual(second_result.status, PhishTankReputationStatus.KNOWN_PHISHING)
        self.assertEqual(mock_post.call_count, 1)  # No extra network call


class TestOfflineDegradedModeScamScreening(unittest.TestCase):
    """Tests for deterministic offline message heuristics when Gemini API fails."""

    def test_offline_screening_irs_tax_fraud(self):
        text = "INTERNAL REVENUE SERVICE: Urgent final tax notice. Pay $500 in gift cards or face immediate arrest by federal marshals."
        assessment = _screen_message_offline(text)
        self.assertEqual(assessment["risk_level"], RiskLevel.HIGH)
        self.assertIn("Government", assessment["scam_category"])
        self.assertTrue(len(assessment["indicators"]) > 0)

    def test_offline_screening_bank_fraud_alert(self):
        text = "Wells Fargo Alert: Suspicious transaction detected. Reply with your one time passcode (OTP) to unfreeze your card immediately."
        assessment = _screen_message_offline(text)
        self.assertEqual(assessment["risk_level"], RiskLevel.HIGH)
        self.assertIn("Bank", assessment["scam_category"])

    def test_offline_screening_cryptocurrency_guarantee(self):
        text = "Guaranteed daily 50% ROI with automated crypto trading bots! Deposit Bitcoin to get rich quick today."
        assessment = _screen_message_offline(text)
        self.assertEqual(assessment["risk_level"], RiskLevel.HIGH)
        self.assertIn("Crypto", assessment["scam_category"])

    def test_offline_screening_routine_meeting(self):
        text = "Hi team, the project sync is scheduled for 3 PM today. Please review the shared slides beforehand."
        assessment = _screen_message_offline(text)
        self.assertEqual(assessment["risk_level"], RiskLevel.LOW)
        self.assertIn("Routine", assessment["scam_category"])

    @patch("app.analyzer.genai.Client")
    def test_analyze_message_fallback_on_gemini_api_error(self, mock_client_cls):
        """When Gemini fails completely, analyze_message falls back to offline screener without 500 error."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.models.generate_content.side_effect = RuntimeError("503 Service Unavailable across all models")

        message = "Urgent: Your Chase account is locked. Pay $200 via wire transfer immediately."
        res = analyze_message(message)

        self.assertIsInstance(res, AnalysisResponse)
        self.assertIn(res.risk_level, [RiskLevel.MEDIUM, RiskLevel.HIGH])
        self.assertIn("Bank", res.scam_category)
        self.assertIn("temporarily unavailable", res.explanation)
        self.assertIsNotNone(res.evidence_summary)
        self.assertIn("Degraded Mode", res.evidence_summary.heuristic_confidence)


if __name__ == "__main__":
    unittest.main()

