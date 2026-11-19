import os
import glob
import json
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestDetections(unittest.TestCase):

    def test_azure_kql_detection_files(self):
        kql_files = glob.glob(os.path.join(BASE_DIR, "detections", "azure", "kql", "**", "*.kql"), recursive=True)
        self.assertGreaterEqual(len(kql_files), 4, f"Expected at least 4 KQL detections, found {len(kql_files)}")

        required_headers = ["Title:", "Description:", "Author:", "MITRE ATT&CK:", "Severity:"]

        for filepath in kql_files:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertGreater(len(content.strip()), 50, f"KQL file {filepath} is suspiciously empty")
            for header in required_headers:
                self.assertIn(header, content, f"Missing '{header}' in {os.path.basename(filepath)}")
            self.assertIn("|", content, f"KQL file {os.path.basename(filepath)} must contain pipe operators")

    def test_aws_cloudtrail_detection_files(self):
        json_files = glob.glob(os.path.join(BASE_DIR, "detections", "aws", "cloudtrail", "*.json"))
        self.assertGreaterEqual(len(json_files), 2, f"Expected at least 2 AWS detections, found {len(json_files)}")

        for filepath in json_files:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertIn("rule_id", data)
            self.assertIn("title", data)
            self.assertIn("severity", data)
            self.assertIn("mitre_attack", data)
            self.assertIsInstance(data["mitre_attack"], list)


if __name__ == "__main__":
    unittest.main()
