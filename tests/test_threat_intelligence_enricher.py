import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_intel.ioc_threat_enricher import (
    ThreatIntelParser,
    ThreatIndicator,
    IOCType,
    TLPLevel,
)


class TestThreatIntelligenceEnricher(unittest.TestCase):

    def setUp(self):
        self.parser = ThreatIntelParser()

    def test_refang_and_defang(self):
        raw_defanged = "hxxps://adversary[.]com/c2/beacon?id=42"
        refanged = self.parser.refang(raw_defanged)
        self.assertEqual(refanged, "https://adversary.com/c2/beacon?id=42")

        defanged_again = self.parser.defang(refanged)
        self.assertIn("hxxps://", defanged_again)
        self.assertIn("[.]", defanged_again)

    def test_bogon_ip_filtering(self):
        # RFC 1918 / Loopback / Link-local IPs should be detected as bogons
        self.assertTrue(self.parser.is_private_or_bogon_ip("192.168.1.1"))
        self.assertTrue(self.parser.is_private_or_bogon_ip("10.240.0.5"))
        self.assertTrue(self.parser.is_private_or_bogon_ip("127.0.0.1"))
        self.assertTrue(self.parser.is_private_or_bogon_ip("169.254.169.254"))

        # Public routable IPs should NOT be bogons
        self.assertFalse(self.parser.is_private_or_bogon_ip("185.220.101.5"))
        self.assertFalse(self.parser.is_private_or_bogon_ip("45.33.32.156"))

    def test_extract_iocs_from_threat_report(self):
        sample_report = """
        INCIDENT BRIEF: APT-29 Infrastructure Analysis
        Adversary utilized malicious C2 at hxxps://c2-stage[.]apt29-ops[.]net/gate.php.
        Observed beaconing out to primary external IP: 185.220.101.5 and backup 45.33.32.156.
        Internal testing host was 10.0.4.15 (do not block).
        Payload Dropper SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        Legacy implant MD5: 44046cd336052e46a363e84860473062
        """
        indicators = self.parser.extract_iocs_from_text(
            raw_text=sample_report,
            default_threat_type="APT C2 Infrastructure",
            default_confidence=90,
            filter_bogons=True,
            tlp=TLPLevel.AMBER,
        )

        extracted_types = {ind.ioc_type for ind in indicators}
        extracted_values = {ind.value for ind in indicators}

        self.assertIn(IOCType.URL, extracted_types)
        self.assertIn(IOCType.SHA256, extracted_types)
        self.assertIn(IOCType.MD5, extracted_types)
        self.assertIn(IOCType.IPV4, extracted_types)

        # Public IPs extracted
        self.assertIn("185.220.101.5", extracted_values)
        self.assertIn("45.33.32.156", extracted_values)
        # Private IP must be suppressed
        self.assertNotIn("10.0.4.15", extracted_values)

        # Hash extracted
        self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", extracted_values)

    def test_sentinel_watchlist_csv_export(self):
        indicators = [
            ThreatIndicator(
                value="198.51.100.99",
                ioc_type=IOCType.IPV4,
                threat_type="CobaltStrike",
                confidence_score=95,
                tlp=TLPLevel.AMBER,
                description="Active C2 beacon destination",
                tags=["c2", "cobalt_strike"],
            )
        ]
        csv_data = self.parser.export_sentinel_watchlist_csv(indicators)
        self.assertIn("SearchKey,IOCType,ThreatType,ConfidenceScore,TLP,Description,Tags,ValidUntil", csv_data)
        self.assertIn("198.51.100.99,ipv4,CobaltStrike,95,TLP:AMBER", csv_data)

    def test_sentinel_ti_api_payload_export(self):
        indicators = [
            ThreatIndicator(
                value="203.0.113.200",
                ioc_type=IOCType.IPV4,
                threat_type="Botnet C2",
                confidence_score=85,
                tlp=TLPLevel.GREEN,
                description="Mirai controller IP",
                tags=["botnet", "mirai"],
            )
        ]
        payload = self.parser.export_sentinel_ti_api_payload(indicators, source_name="UnitTestSource")
        self.assertEqual(payload["totalCount"], 1)
        item = payload["indicators"][0]
        self.assertEqual(item["properties"]["confidence"], 85)
        self.assertEqual(item["properties"]["pattern"], "[ipv4:value = '203.0.113.200']")
        self.assertEqual(item["properties"]["tlpLevel"], "green")

    def test_risk_priority_scoring(self):
        high_ip = ThreatIndicator(
            value="198.51.100.1",
            ioc_type=IOCType.IPV4,
            threat_type="C2",
            confidence_score=90,
        )
        self.assertEqual(self.parser.compute_risk_priority(high_ip), "P1-CRITICAL")

        med_domain = ThreatIndicator(
            value="suspicious-domain.xyz",
            ioc_type=IOCType.DOMAIN,
            threat_type="Phishing",
            confidence_score=75,
        )
        self.assertEqual(self.parser.compute_risk_priority(med_domain), "P2-HIGH")


if __name__ == "__main__":
    unittest.main()
