import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compliance.cis_azure_benchmark_audit import AzureCISAuditor
from remediation.python.remediate_storage_exposure import StorageRemediator
from remediation.python.quarantine_compromised_instance import InstanceQuarantiner


class TestRemediationAndCompliance(unittest.TestCase):

    def test_cis_auditor_pass_fail(self):
        auditor = AzureCISAuditor()
        inventory = {
            "storage_accounts": [
                {"name": "compliant-sa", "supports_https_traffic_only": True, "allow_blob_public_access": False},
                {"name": "vulnerable-sa", "supports_https_traffic_only": False, "allow_blob_public_access": True}
            ],
            "nsg_rules": [
                {"name": "bad-rule", "access": "Allow", "direction": "Inbound", "source_address_prefix": "*", "destination_port_range": "22"},
                {"name": "good-rule", "access": "Allow", "direction": "Inbound", "source_address_prefix": "10.0.0.0/24", "destination_port_range": "22"}
            ]
        }
        findings = auditor.run_audit(inventory)
        self.assertEqual(len(findings), 6)

        passes = [f for f in findings if f.status == "PASS"]
        fails = [f for f in findings if f.status == "FAIL"]

        self.assertEqual(len(passes), 3)
        self.assertEqual(len(fails), 3)

    def test_storage_remediator(self):
        exposed = {
            "id": "sa-test-1",
            "allow_blob_public_access": True,
            "supports_https_traffic_only": False
        }
        res = StorageRemediator.remediate_blob_public_access(exposed)
        self.assertTrue(res.success)
        self.assertFalse(res.changes_applied["allow_blob_public_access"])
        self.assertTrue(res.changes_applied["supports_https_traffic_only"])

    def test_instance_quarantine(self):
        res = InstanceQuarantiner.isolate_azure_vm(
            vm_id="vm-compromised-01",
            current_nsg_ids=["nsg-allow-all"]
        )
        self.assertEqual(res.status, "ISOLATED")
        self.assertIn("quarantine", res.quarantine_group.lower())


if __name__ == "__main__":
    unittest.main()
