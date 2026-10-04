import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure root directory is on the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models import (
    AnalysisResponse,
    CONTROLLED_ATTACK_TYPES,
    ConversationMessage,
    ConversationTactics,
    PhishTankReputationStatus,
    PhishTankResult,
    RiskLevel,
    UrlSignal,
)
from app.url_analyzer import analyze_url
from app.evidence_fusion import (
    detect_attack_types,
    fuse_evidence,
    merge_attack_types,
    normalize_attack_type,
)
from app.analyzer import analyze_conversation, analyze_message


class TestMultiAttackDetection(unittest.TestCase):
    """Regression and unit test suite for multi-attack classification and deterministic extraction."""

    def test_1_bank_phishing_otp_suspicious_url(self):
        """TEST 1: A bank phishing message requesting OTP through a suspicious URL.
        Expected attack_types contains:
        - Bank Impersonation
        - OTP Theft
        - Malicious Link
        - Credential Phishing or Password/Account Credential Theft
        """
        raw_msg = (
            "Chase Alert: Unusual debit card activity detected. "
            "Please verify your identity and enter your OTP immediately at "
            "http://chase-security-verify.net/auth to prevent account freeze."
        )
        url_signal = analyze_url("http://chase-security-verify.net/auth")

        gemini_mock = AnalysisResponse(
            risk_level=RiskLevel.HIGH,
            scam_category="Bank/Financial Impersonation",
            suspicious_indicators=["Bank alert", "OTP requested", "Suspicious link"],
            explanation="Fraudulent bank message seeking OTP.",
            recommended_action="Do not enter OTP.",
            urls_detected=[url_signal],
            attack_types=["Bank Impersonation", "OTP Theft", "Credential Phishing"],
        )

        fused = fuse_evidence(
            gemini_response=gemini_mock,
            urls_detected=[url_signal],
            raw_message=raw_msg,
        )

        self.assertIn("Bank Impersonation", fused.attack_types)
        self.assertIn("OTP Theft", fused.attack_types)
        self.assertIn("Malicious Link", fused.attack_types)
        self.assertTrue(
            "Credential Phishing" in fused.attack_types
            or "Password/Account Credential Theft" in fused.attack_types
        )
        # Verify deduplication
        self.assertEqual(len(fused.attack_types), len(set(fused.attack_types)))
        # Verify all attack_types conform to the controlled taxonomy
        for at in fused.attack_types:
            self.assertIn(at, CONTROLLED_ATTACK_TYPES)

    def test_2_executable_download_with_urgency(self):
        """TEST 2: A message containing a suspicious executable download plus urgency.
        Expected:
        - Malicious Download
        - Urgency/Threat Manipulation
        - Malicious Link
        """
        raw_msg = (
            "FINAL WARNING: Your payroll invoice must be confirmed immediately within 2 hours: "
            "http://shipping-documents-download.org/invoice_details.pdf.exe or legal action follows!"
        )
        url_signal = analyze_url(
            "http://shipping-documents-download.org/invoice_details.pdf.exe"
        )

        fused = fuse_evidence(
            gemini_response=None,
            urls_detected=[url_signal],
            raw_message=raw_msg,
            gemini_error="503 Service Unavailable",
        )

        self.assertIn("Malicious Download", fused.attack_types)
        self.assertIn("Urgency/Threat Manipulation", fused.attack_types)
        self.assertIn("Malicious Link", fused.attack_types)
        for at in fused.attack_types:
            self.assertIn(at, CONTROLLED_ATTACK_TYPES)

    def test_3_typosquatted_bank_url_with_otp(self):
        """TEST 3: A typosquatted bank URL with an OTP request.
        Expected:
        - Bank Impersonation
        - Typosquatting
        - OTP Theft
        """
        raw_msg = "PayPal Security: Please enter your verification OTP at https://paypa1-security.com/account to secure your login."
        url_signal = analyze_url("https://paypa1-security.com/account")

        fused = fuse_evidence(
            gemini_response=None,
            urls_detected=[url_signal],
            raw_message=raw_msg,
            gemini_error="429 Quota Exhausted",
        )

        self.assertIn("Bank Impersonation", fused.attack_types)
        self.assertIn("Typosquatting", fused.attack_types)
        self.assertIn("OTP Theft", fused.attack_types)
        for at in fused.attack_types:
            self.assertIn(at, CONTROLLED_ATTACK_TYPES)

    @patch("app.analyzer.genai.Client")
    def test_4_crypto_investment_grooming_conversation(self, mock_client_cls):
        """TEST 4: A crypto investment grooming conversation.
        Expected multiple attack types including:
        - Investment/Crypto Scam
        - Social Engineering
        - Trust/Grooming Manipulation
        - UPI/Payment Fraud or equivalent payment-demand type
        """
        import json

        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_response = MagicMock()
        mock_response.text = json.dumps(
            {
                "risk_level": "HIGH",
                "scam_category": "Investment/Crypto Scam",
                "suspicious_indicators": [
                    "Wrong-number contact strategy",
                    "Rapid rapport building",
                    "Unsolicited cryptocurrency investment advice",
                ],
                "explanation": "Multi-turn conversation displays a classic pig-butchering romance/crypto investment grooming pattern.",
                "recommended_action": "Block the sender immediately and do not transfer any funds.",
                "conversation_tactics": {
                    "trust_building_observed": True,
                    "urgency_escalation_observed": True,
                    "payment_or_credential_demanded": True,
                    "grooming_pattern": "Wrong-number pretext -> personal rapport -> crypto investment pitch.",
                },
                "attack_types": [
                    "Investment/Crypto Scam",
                    "Social Engineering",
                    "Trust/Grooming Manipulation",
                    "UPI/Payment Fraud",
                ],
            }
        )
        mock_client.models.generate_content.return_value = mock_response

        messages = [
            ConversationMessage(
                sender="Stranger",
                message="Hi Anna! Are we meeting for coffee today?",
            ),
            ConversationMessage(sender="Target", message="Wrong number, sorry."),
            ConversationMessage(
                sender="Stranger",
                message="Oh I'm so sorry! You seem like such a kind person though. I'm Lisa from Singapore.",
            ),
            ConversationMessage(
                sender="Stranger",
                message="I invest in high yield crypto staking. Earned 30% today! Deposit $500 now via wire transfer to my VIP crypto pool before the bonus expires!",
            ),
        ]

        response = analyze_conversation(messages)

        self.assertIn("Investment/Crypto Scam", response.attack_types)
        self.assertIn("Social Engineering", response.attack_types)
        self.assertIn("Trust/Grooming Manipulation", response.attack_types)
        self.assertIn("UPI/Payment Fraud", response.attack_types)
        for at in response.attack_types:
            self.assertIn(at, CONTROLLED_ATTACK_TYPES)

    def test_5_legitimate_message_empty_attack_types(self):
        """TEST 5: A legitimate message.
        Expected:
        attack_types == []
        """
        raw_msg = "Hi team, the quarterly performance slides are attached for our project sync meeting today. See you at 3 PM!"
        gemini_mock = AnalysisResponse(
            risk_level=RiskLevel.LOW,
            scam_category="Routine / Legitimate Communication",
            suspicious_indicators=[],
            explanation="Normal work email.",
            recommended_action="No action required.",
            urls_detected=[],
            attack_types=[],
        )

        fused = fuse_evidence(
            gemini_response=gemini_mock,
            urls_detected=[],
            raw_message=raw_msg,
        )

        self.assertEqual(fused.risk_level, RiskLevel.LOW)
        self.assertEqual(fused.attack_types, [])

    @patch("app.analyzer.genai.Client")
    def test_6_gemini_failure_offline_mode_retains_deterministic_attacks(
        self, mock_client_cls
    ):
        """TEST 6: Gemini failure / offline mode.
        Expected deterministic attack_types are still returned.
        """
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.models.generate_content.side_effect = RuntimeError(
            "503 Service Unavailable across all models"
        )

        raw_msg = (
            "URGENT from Wells Fargo: Your account is locked. "
            "Enter your one-time passcode (OTP) at http://wells-fraud-alert.net/login immediately to avoid permanent suspension."
        )

        response = analyze_message(raw_msg)

        self.assertIsInstance(response, AnalysisResponse)
        self.assertIn(response.risk_level, [RiskLevel.MEDIUM, RiskLevel.HIGH])
        # Deterministic attack types must be preserved
        self.assertIn("Bank Impersonation", response.attack_types)
        self.assertIn("OTP Theft", response.attack_types)
        self.assertIn("Malicious Link", response.attack_types)
        self.assertIn("Urgency/Threat Manipulation", response.attack_types)
        self.assertIn("Credential Phishing", response.attack_types)
        for at in response.attack_types:
            self.assertIn(at, CONTROLLED_ATTACK_TYPES)

    def test_synonym_normalization(self):
        """Verify normalization maps synonyms to canonical taxonomy values."""
        self.assertEqual(
            normalize_attack_type("otp harvesting"), "OTP Theft"
        )
        self.assertEqual(
            normalize_attack_type("bank fraud"), "Bank Impersonation"
        )
        self.assertEqual(
            normalize_attack_type("financial institution impersonation"),
            "Bank Impersonation",
        )
        self.assertEqual(
            normalize_attack_type("pig-butchering"), "Investment/Crypto Scam"
        )
        self.assertEqual(
            normalize_attack_type("2fa bypass"), "OTP Theft"
        )

    def test_merge_attack_types_deduplication(self):
        """Verify merging removes duplicates and respects canonical order."""
        det = ["Bank Impersonation", "OTP Theft"]
        gemini = ["otp harvesting", "Bank fraud", "Urgency/Threat Manipulation"]
        merged = merge_attack_types(det, gemini)
        self.assertEqual(
            merged,
            ["Bank Impersonation", "OTP Theft", "Urgency/Threat Manipulation"],
        )

    def test_7_bank_credentials_otp_redirect_no_upi_fraud(self):
        """Regression Test 1: Bank + password + ATM PIN + OTP + suspicious URL with open redirect.
        Expected:
        - Bank Impersonation
        - OTP Theft
        - Password/Account Credential Theft
        - Credential Phishing
        - Malicious Link
        - Open Redirect Abuse
        - Urgency/Threat Manipulation
        Must NOT contain:
        - UPI/Payment Fraud
        """
        raw_msg = (
            "URGENT: Your SBI account is restricted. Verify immediately at "
            "http://sbi.co.in.auth-verify.top/login?redirect=http://attacker.top/stealer. "
            "Enter your password, ATM PIN and OTP to restore access."
        )
        url_signal = analyze_url(
            "http://sbi.co.in.auth-verify.top/login?redirect=http://attacker.top/stealer"
        )

        # Test deterministic detection directly
        det = detect_attack_types(raw_message=raw_msg, urls_detected=[url_signal])
        self.assertIn("Bank Impersonation", det)
        self.assertIn("OTP Theft", det)
        self.assertIn("Password/Account Credential Theft", det)
        self.assertIn("Credential Phishing", det)
        self.assertIn("Malicious Link", det)
        self.assertIn("Open Redirect Abuse", det)
        self.assertIn("Urgency/Threat Manipulation", det)
        self.assertNotIn("UPI/Payment Fraud", det)

        # Also test fuse_evidence (even if gemini hallucinated UPI/Payment Fraud)
        gemini_mock = AnalysisResponse(
            risk_level=RiskLevel.HIGH,
            scam_category="Bank/Financial Impersonation",
            suspicious_indicators=["Bank alert", "OTP requested", "ATM PIN requested"],
            explanation="Phishing lure harvesting bank credentials.",
            recommended_action="Do not enter credentials.",
            urls_detected=[url_signal],
            attack_types=["Bank Impersonation", "UPI/Payment Fraud", "OTP Theft"],
        )
        fused = fuse_evidence(
            gemini_response=gemini_mock,
            urls_detected=[url_signal],
            raw_message=raw_msg,
        )
        self.assertIn("Bank Impersonation", fused.attack_types)
        self.assertIn("OTP Theft", fused.attack_types)
        self.assertIn("Password/Account Credential Theft", fused.attack_types)
        self.assertIn("Credential Phishing", fused.attack_types)
        self.assertIn("Malicious Link", fused.attack_types)
        self.assertIn("Open Redirect Abuse", fused.attack_types)
        self.assertIn("Urgency/Threat Manipulation", fused.attack_types)
        self.assertNotIn("UPI/Payment Fraud", fused.attack_types)

    def test_8_actual_payment_scam_has_upi_payment_fraud(self):
        """Regression Test 2: Actual payment scam.
        'Send ₹5,000 via UPI to this QR code immediately.'
        Expected:
        - UPI/Payment Fraud
        """
        raw_msg = "Send ₹5,000 via UPI to this QR code immediately."
        det = detect_attack_types(raw_message=raw_msg, urls_detected=[])
        self.assertIn("UPI/Payment Fraud", det)

        fused = fuse_evidence(
            gemini_response=None,
            urls_detected=[],
            raw_message=raw_msg,
            gemini_error="503 Service Unavailable",
        )
        self.assertIn("UPI/Payment Fraud", fused.attack_types)

    def test_9_credential_only_scam_no_payment_fraud(self):
        """Regression Test 3: Credential-only scam.
        'Enter your password and OTP to verify your account.'
        Expected credential/OTP techniques but NOT UPI/Payment Fraud.
        """
        raw_msg = "Enter your password and OTP to verify your account."
        det = detect_attack_types(raw_message=raw_msg, urls_detected=[])
        self.assertIn("OTP Theft", det)
        self.assertIn("Password/Account Credential Theft", det)
        self.assertIn("Credential Phishing", det)
        self.assertNotIn("UPI/Payment Fraud", det)

        fused = fuse_evidence(
            gemini_response=None,
            urls_detected=[],
            raw_message=raw_msg,
            gemini_error="503 Service Unavailable",
        )
        self.assertIn("OTP Theft", fused.attack_types)
        self.assertIn("Password/Account Credential Theft", fused.attack_types)
        self.assertIn("Credential Phishing", fused.attack_types)
        self.assertNotIn("UPI/Payment Fraud", fused.attack_types)

    def test_10_legitimate_message_empty_attack_types_regression(self):
        """Regression Test 4: Legitimate message.
        Expected:
        attack_types == []
        """
        raw_msg = "Good morning! Are we still having our weekly team standup at 10 AM today?"
        fused = fuse_evidence(
            gemini_response=None,
            urls_detected=[],
            raw_message=raw_msg,
            offline_assessment={
                "risk_level": "LOW",
                "scam_category": "Routine / Legitimate Communication",
            },
        )
        self.assertEqual(fused.risk_level, RiskLevel.LOW)
        self.assertEqual(fused.attack_types, [])


if __name__ == "__main__":
    unittest.main()
