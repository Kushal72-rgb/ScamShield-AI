import unittest
import os
import sys

# Ensure root directory is on the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.url_analyzer import analyze_url


class TestUrlAnalyzer(unittest.TestCase):
    """Unit and regression tests for local deterministic URL analyzer."""

    def test_u10_deceptive_userinfo_routing_regression(self):
        """
        Regression test for U10:
        https://google.com@phishingserver.top/login
        The '@' symbol in the URL authority section is used to disguise the destination
        host (phishingserver.top) behind a legitimate-looking prefix (google.com).
        Even over HTTPS and without a known brand in the actual destination domain,
        deceptive '@' routing must classify is_suspicious as True.
        """
        target_url = "https://google.com@phishingserver.top/login"
        analysis = analyze_url(target_url)

        self.assertTrue(
            analysis.is_suspicious,
            f"Expected {target_url} to be classified as suspicious, got is_suspicious=False",
        )
        self.assertTrue(
            any("Deceptive URL structure" in s or "@" in s for s in analysis.suspicious_signals),
            f"Expected suspicious signal mentioning '@' or deceptive URL structure, got: {analysis.suspicious_signals}",
        )
        self.assertEqual(analysis.domain, "phishingserver.top")

    def test_legitimate_url_clean(self):
        """Ensure standard legitimate URLs are not falsely flagged as suspicious."""
        analysis = analyze_url("https://www.google.com")
        self.assertFalse(analysis.is_suspicious)
        self.assertEqual(len(analysis.suspicious_signals), 0)

    def test_brand_impersonation_detection(self):
        """Ensure HTTP + keyword impersonation is classified as suspicious."""
        analysis = analyze_url("http://paypal-security-update.com")
        self.assertTrue(analysis.is_suspicious)
        self.assertTrue(any("paypal" in s.lower() for s in analysis.suspicious_signals))

    def test_shortened_url_detection_and_quarantine(self):
        """Shortened URLs (e.g. bit.ly, tinyurl) must be detected and quarantined as suspicious."""
        analysis = analyze_url("https://bit.ly/3xVerifyAccount", resolve_shorteners=False)
        self.assertTrue(analysis.is_shortened)
        self.assertTrue(analysis.is_suspicious)
        self.assertTrue(any("shorten" in s.lower() for s in analysis.suspicious_signals))

    def test_obfuscated_hex_ip_detection(self):
        """Hexadecimal encoded IP host (0x7f000001) must be decoded and flagged for obfuscation & SSRF."""
        analysis = analyze_url("http://0x7f000001/bank/auth.php")
        self.assertTrue(analysis.is_obfuscated)
        self.assertTrue(analysis.is_suspicious)
        self.assertTrue(any("obfuscated ip" in s.lower() for s in analysis.suspicious_signals))
        self.assertTrue(any("127.0.0.1" in s for s in analysis.suspicious_signals))
        self.assertTrue(any("ssrf" in s.lower() or "internal" in s.lower() for s in analysis.suspicious_signals))

    def test_obfuscated_dword_ip_detection(self):
        """Dword/integer encoded IP host (2130706433) must be decoded and flagged."""
        analysis = analyze_url("http://2130706433/login")
        self.assertTrue(analysis.is_obfuscated)
        self.assertTrue(analysis.is_suspicious)
        self.assertTrue(any("dword" in s.lower() or "127.0.0.1" in s for s in analysis.suspicious_signals))

    def test_obfuscated_octal_ip_detection(self):
        """Octal encoded dotted quad (0177.0.0.1) must be decoded and flagged."""
        analysis = analyze_url("http://0177.0.0.1/verify")
        self.assertTrue(analysis.is_obfuscated)
        self.assertTrue(analysis.is_suspicious)
        self.assertTrue(any("obfuscated ip" in s.lower() for s in analysis.suspicious_signals))

    def test_percent_encoded_hostname_detection(self):
        """Percent-encoded characters in domain must be flagged as obfuscation."""
        analysis = analyze_url("http://%77%77%77%2E%70%61%79%70%61%6C%2E%63%6F%6D/login")
        self.assertTrue(analysis.is_obfuscated)
        self.assertTrue(analysis.is_suspicious)
        self.assertTrue(any("percent-encoded" in s.lower() for s in analysis.suspicious_signals))

    def test_safe_resolve_shortener_ssrf_blocking(self):
        """Safe shortener resolution must block redirections pointing to private/cloud metadata IPs."""
        from unittest.mock import patch, MagicMock

        # Mock HEAD response redirecting to cloud metadata IP
        mock_resp = MagicMock()
        mock_resp.status_code = 301
        mock_resp.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}

        with patch("app.url_analyzer.requests.head", return_value=mock_resp):
            with patch("app.url_analyzer.socket.gethostbyname_ex", return_value=("bit.ly", [], ["93.184.216.34"])):
                from app.url_analyzer import safe_resolve_shortener
                resolved, err = safe_resolve_shortener("https://bit.ly/test-ssrf")
                self.assertIsNone(resolved)
                self.assertIn("SSRF Blocked", err)

    def test_legitimate_microsoft_alias_not_flagged(self):
        """Official Microsoft identity domain login.microsoftonline.com must NOT be flagged as impersonation."""
        analysis = analyze_url("https://login.microsoftonline.com")
        self.assertFalse(analysis.is_suspicious)
        self.assertEqual(len(analysis.suspicious_signals), 0)

    def test_legitimate_cloud_docs_not_flagged(self):
        """Legitimate docs.google.com link without suspicious context must NOT be flagged."""
        analysis = analyze_url("https://docs.google.com/document/d/1abc123/edit")
        self.assertFalse(analysis.is_suspicious)
        self.assertEqual(len(analysis.suspicious_signals), 0)


if __name__ == "__main__":
    unittest.main()
