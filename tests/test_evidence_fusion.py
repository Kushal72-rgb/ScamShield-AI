import os
import sys
import unittest

# Ensure root directory is on the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models import (
    AnalysisResponse,
    PhishTankReputationStatus,
    PhishTankResult,
    RiskLevel,
    UrlSignal,
)
from app.url_analyzer import analyze_url
from app.evidence_fusion import fuse_evidence, normalize_category


class TestEvidenceFusion(unittest.TestCase):
    """Regression and unit test suite for the Multi-Source Evidence Fusion Layer."""

    def test_1_known_phishing_url_elevates_to_high_risk(self):
        """1. Known phishing URL:
        If PhishTank confirms KNOWN_PHISHING, the fusion layer MUST treat it as
        strong threat evidence and elevate the final assessment to HIGH risk,
        even if Gemini or other signals suggested a lower risk level.
        """
        raw_url = "http://verified-phishing-threat.com/login"
        url_signal = analyze_url(raw_url)
        url_signal.reputation = PhishTankResult(
            status=PhishTankReputationStatus.KNOWN_PHISHING,
            in_database=True,
            is_valid_phish=True,
            verified=True,
            phish_id=9876543,
            phish_detail_url="https://phishtank.org/phish_detail.php?phish_id=9876543",
            message="Reported & verified active phishing threat (Phish ID #9876543).",
            caution_note="Warning: This URL is an actively cataloged phishing threat.",
        )

        # Simulate Gemini mistakenly rating as LOW
        gemini_mock = AnalysisResponse(
            risk_level=RiskLevel.LOW,
            scam_category="Routine / Legitimate Communication",
            suspicious_indicators=["No obvious red flags in text."],
            explanation="The text appears innocent.",
            recommended_action="No action needed.",
            urls_detected=[],
        )

        fused = fuse_evidence(
            gemini_response=gemini_mock,
            urls_detected=[url_signal],
            raw_message="Check your account: http://verified-phishing-threat.com/login",
        )

        self.assertEqual(fused.risk_level, RiskLevel.HIGH)
        self.assertEqual(fused.scam_category, "Credential Phishing")
        self.assertTrue(
            any("phishtank" in ind.lower() for ind in fused.suspicious_indicators),
            f"Expected PhishTank threat in indicators, got: {fused.suspicious_indicators}",
        )
        self.assertIsNotNone(fused.evidence_summary)
        self.assertIn("PhishTank", fused.evidence_summary.fusion_rationale)
        self.assertIn("HIGH", fused.evidence_summary.heuristic_confidence)

    def test_2_suspicious_url_with_phishtank_no_match(self):
        """2. Suspicious URL with PhishTank NO_MATCH:
        A suspicious URL that is NOT in PhishTank must NOT be excused or treated as safe.
        Local heuristic red flags and Gemini threat assessments must be preserved.
        """
        raw_url = "http://paypal-security-update.com"
        url_signal = analyze_url(raw_url)
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

        gemini_mock = AnalysisResponse(
            risk_level=RiskLevel.HIGH,
            scam_category="Bank/Financial Impersonation",
            suspicious_indicators=["Fake security alert", "Insecure HTTP link"],
            explanation="This is an urgent phishing attempt impersonating PayPal.",
            recommended_action="Do not open the link.",
            urls_detected=[],
        )

        fused = fuse_evidence(
            gemini_response=gemini_mock,
            urls_detected=[url_signal],
            raw_message="PayPal alert: verify at http://paypal-security-update.com",
        )

        self.assertEqual(fused.risk_level, RiskLevel.HIGH)
        self.assertTrue(url_signal.is_suspicious)
        self.assertIsNotNone(fused.evidence_summary)
        # Verify NO_MATCH disclaimer is noted
        self.assertIn("does not", fused.evidence_summary.phishtank_findings.lower())

    def test_3_legitimate_url(self):
        """3. Legitimate URL:
        Clean URL (e.g., https://www.google.com) with PhishTank NO_MATCH and Gemini LOW
        must produce a clean LOW risk assessment across all evidence channels.
        """
        raw_url = "https://www.google.com"
        url_signal = analyze_url(raw_url)
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

        gemini_mock = AnalysisResponse(
            risk_level=RiskLevel.LOW,
            scam_category="Routine / Legitimate Communication",
            suspicious_indicators=[],
            explanation="The message is routine with no deceptive intent.",
            recommended_action="No specific precautions required.",
            urls_detected=[],
        )

        fused = fuse_evidence(
            gemini_response=gemini_mock,
            urls_detected=[url_signal],
            raw_message="Search it here: https://www.google.com",
        )

        self.assertEqual(fused.risk_level, RiskLevel.LOW)
        self.assertEqual(fused.scam_category, "Routine / Legitimate Communication")
        self.assertIsNotNone(fused.evidence_summary)
        self.assertIn("LOW", fused.evidence_summary.gemini_assessment)

    def test_4_phishtank_unavailable(self):
        """4. PhishTank unavailable:
        If PhishTank lookup fails (timeout or network error), the pipeline must continue
        smoothly without crashing. UNAVAILABLE must NOT be treated as safe or malicious.
        """
        raw_url = "https://www.wikipedia.org"
        url_signal = analyze_url(raw_url)
        url_signal.reputation = PhishTankResult(
            status=PhishTankReputationStatus.UNAVAILABLE,
            in_database=None,
            is_valid_phish=None,
            verified=None,
            phish_id=None,
            phish_detail_url=None,
            message="PhishTank service returned HTTP 503.",
            caution_note="Reputation check could not be completed. Rely on local heuristic indicators.",
        )

        gemini_mock = AnalysisResponse(
            risk_level=RiskLevel.LOW,
            scam_category="Routine / Legitimate Communication",
            suspicious_indicators=[],
            explanation="Routine confirmation message.",
            recommended_action="Safe to proceed.",
            urls_detected=[],
        )

        fused = fuse_evidence(
            gemini_response=gemini_mock,
            urls_detected=[url_signal],
            raw_message="Order receipt at https://example-test-site.org",
        )

        # Must not crash, status preserved from Gemini, PhishTank marked unavailable
        self.assertEqual(fused.risk_level, RiskLevel.LOW)
        self.assertIsNotNone(fused.evidence_summary)
        self.assertIn("unavailable", fused.evidence_summary.phishtank_findings.lower())

    def test_5_gemini_failure_with_url_evidence_available(self):
        """5. Gemini failure with URL evidence available:
        If Gemini encounters 503/429/downtime and fails, but URLs are present:
        The pipeline must NOT crash. It must return deterministic local heuristic
        and PhishTank evidence clearly in degraded mode.
        """
        raw_url = "http://chase-security-verify.net"
        url_signal = analyze_url(raw_url)
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

        fused = fuse_evidence(
            gemini_response=None,
            urls_detected=[url_signal],
            raw_message="Verify your card now: http://chase-security-verify.net",
            gemini_error="503 UNAVAILABLE: Model experiencing high demand",
        )

        # Severe local impersonation flags must produce HIGH risk in degraded mode
        self.assertEqual(fused.risk_level, RiskLevel.HIGH)
        self.assertEqual(fused.scam_category, "Credential Phishing")
        self.assertTrue(len(fused.suspicious_indicators) > 0)
        self.assertIn("Gemini AI was temporarily unavailable", fused.explanation)
        self.assertIsNotNone(fused.evidence_summary)
        self.assertIn("Unavailable", fused.evidence_summary.gemini_assessment)
        self.assertIn("suspicious URL", fused.evidence_summary.local_url_findings)

    def test_6_gemini_failure_no_urls(self):
        """6. Gemini failure with no URLs:
        When Gemini fails and no offline URL signals exist, return a clear
        degraded assessment with cautionary guidance without raising unhandled exceptions.
        """
        fused = fuse_evidence(
            gemini_response=None,
            urls_detected=[],
            raw_message="Urgent: Your account is suspended.",
            gemini_error="429 Resource Exhausted",
        )

        self.assertEqual(fused.risk_level, RiskLevel.MEDIUM)
        self.assertEqual(fused.scam_category, "Unverified Communication")
        self.assertIn("temporarily unavailable", fused.explanation)
        self.assertIsNotNone(fused.evidence_summary)
        self.assertIn("Unavailable", fused.evidence_summary.gemini_assessment)

    def test_7_gemini_failure_with_offline_assessment_high_risk(self):
        """7. Gemini failure with offline heuristic assessment:
        When Gemini is unavailable, offline_assessment provides high-confidence category
        and indicators rather than generic fallback.
        """
        offline = {
            "risk_level": RiskLevel.HIGH,
            "scam_category": "Government Impersonation / Tax Fraud",
            "indicators": ["IRS / Tax refund lure", "Urgent deadline threat"],
        }
        fused = fuse_evidence(
            gemini_response=None,
            urls_detected=[],
            raw_message="IRS Notice: Pay $1,000 immediately or face arrest.",
            gemini_error="503 Model Unavailable",
            offline_assessment=offline,
        )

        self.assertEqual(fused.risk_level, RiskLevel.HIGH)
        self.assertEqual(fused.scam_category, "Government Impersonation / Tax Fraud")
        self.assertTrue(any("IRS" in ind for ind in fused.suspicious_indicators))
        self.assertIn("Degraded Mode", fused.evidence_summary.heuristic_confidence)

    def test_8_shortened_unresolved_url_elevates_threat(self):
        """8. Shortened/unresolved URL:
        An unverified shortened link with PhishTank NO_MATCH must be elevated to HIGH risk
        due to destination cloaking.
        """
        raw_url = "https://bit.ly/3xyzSecret"
        url_signal = analyze_url(raw_url)
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

        gemini_mock = AnalysisResponse(
            risk_level=RiskLevel.LOW,
            scam_category="Routine / Legitimate Communication",
            suspicious_indicators=[],
            explanation="Short message.",
            recommended_action="None",
            urls_detected=[],
        )

        fused = fuse_evidence(
            gemini_response=gemini_mock,
            urls_detected=[url_signal],
            raw_message="Click here: https://bit.ly/3xyzSecret",
        )

        self.assertEqual(fused.risk_level, RiskLevel.HIGH)
        self.assertTrue(any("shortened" in ind.lower() or "cloaked" in ind.lower() for ind in fused.suspicious_indicators))

    def test_9_obfuscated_ip_elevates_threat_even_with_phishtank_no_match(self):
        """9. Obfuscated IP host URL:
        A URL utilizing a numeric/hex/dword IP representation must be elevated to HIGH risk
        regardless of PhishTank unindexed status.
        """
        raw_url = "http://0x7f000001/payload"
        url_signal = analyze_url(raw_url)
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

        gemini_mock = AnalysisResponse(
            risk_level=RiskLevel.MEDIUM,
            scam_category="Suspicious Link",
            suspicious_indicators=[],
            explanation="Unusual link structure.",
            recommended_action="Caution advised.",
            urls_detected=[],
        )

        fused = fuse_evidence(
            gemini_response=gemini_mock,
            urls_detected=[url_signal],
            raw_message="Check this server: http://0x7f000001/payload",
        )

        self.assertEqual(fused.risk_level, RiskLevel.HIGH)
        self.assertTrue(any("obfuscated" in ind.lower() or "hex" in ind.lower() for ind in fused.suspicious_indicators))


if __name__ == "__main__":
    unittest.main()

