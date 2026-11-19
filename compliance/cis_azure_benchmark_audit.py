"""
CIS Microsoft Azure Foundations Benchmark Automated Assessment Module.
Audits configuration against CIS v2.0 recommendations for Identity, Storage, and Networking.
"""

from dataclasses import dataclass
from typing import Dict, List, Any


@dataclass
class AuditFinding:
    rule_id: str
    title: str
    severity: str
    status: str  # "PASS" or "FAIL"
    resource_id: str
    details: str
    remediation_guidance: str


class AzureCISAuditor:
    """Evaluates Azure resource configurations against CIS controls."""

    def __init__(self, subscription_id: str = "00000000-0000-0000-0000-000000000000"):
        self.subscription_id = subscription_id

    def check_storage_account_secure_transfer(self, storage_account: Dict[str, Any]) -> AuditFinding:
        """CIS 3.1: Ensure 'Secure transfer required' is set to 'Enabled'."""
        name = storage_account.get("name", "unknown")
        supports_https = storage_account.get("supports_https_traffic_only", True)
        status = "PASS" if supports_https else "FAIL"
        return AuditFinding(
            rule_id="CIS-AZ-3.1",
            title="Ensure 'Secure transfer required' is Enabled for Storage Accounts",
            severity="High",
            status=status,
            resource_id=f"/subscriptions/{self.subscription_id}/storageAccounts/{name}",
            details=f"supports_https_traffic_only is {supports_https}",
            remediation_guidance="Set enableHttpsTrafficOnly to true on Microsoft.Storage/storageAccounts."
        )

    def check_storage_account_public_access(self, storage_account: Dict[str, Any]) -> AuditFinding:
        """CIS 3.6: Ensure public access level is set to Private for Blob Service."""
        name = storage_account.get("name", "unknown")
        allow_blob_public = storage_account.get("allow_blob_public_access", False)
        status = "PASS" if not allow_blob_public else "FAIL"
        return AuditFinding(
            rule_id="CIS-AZ-3.6",
            title="Ensure default public access to blobs is Disabled",
            severity="Critical",
            status=status,
            resource_id=f"/subscriptions/{self.subscription_id}/storageAccounts/{name}",
            details=f"allow_blob_public_access is {allow_blob_public}",
            remediation_guidance="Set properties.allowBlobPublicAccess to false."
        )

    def check_nsg_ssh_restriction(self, nsg_rule: Dict[str, Any]) -> AuditFinding:
        """CIS 6.1: Ensure that RDP and SSH access is restricted from the internet."""
        name = nsg_rule.get("name", "unknown")
        access = nsg_rule.get("access", "").lower()
        direction = nsg_rule.get("direction", "").lower()
        source_prefix = nsg_rule.get("source_address_prefix", "")
        dest_ports = str(nsg_rule.get("destination_port_range", ""))

        is_open_source = source_prefix in ["*", "0.0.0.0/0", "Internet"]
        is_risky_port = any(p in dest_ports for p in ["22", "3389", "*"])
        failed = (access == "allow" and direction == "inbound" and is_open_source and is_risky_port)

        return AuditFinding(
            rule_id="CIS-AZ-6.1",
            title="Ensure that RDP and SSH access is restricted from the internet",
            severity="High",
            status="FAIL" if failed else "PASS",
            resource_id=f"NSG-Rule/{name}",
            details=f"Access={access}, Source={source_prefix}, DestPorts={dest_ports}",
            remediation_guidance="Update NSG rule to limit source IP prefix to authorized corporate CIDRs."
        )

    def run_audit(self, inventory: Dict[str, List[Dict[str, Any]]]) -> List[AuditFinding]:
        """Runs full suite over provided Azure resource configuration inventory."""
        findings = []
        for sa in inventory.get("storage_accounts", []):
            findings.append(self.check_storage_account_secure_transfer(sa))
            findings.append(self.check_storage_account_public_access(sa))
        for rule in inventory.get("nsg_rules", []):
            findings.append(self.check_nsg_ssh_restriction(rule))
        return findings


if __name__ == "__main__":
    mock_inventory = {
        "storage_accounts": [
            {"name": "prodsecstore01", "supports_https_traffic_only": True, "allow_blob_public_access": False},
            {"name": "legacydev02", "supports_https_traffic_only": False, "allow_blob_public_access": True},
        ],
        "nsg_rules": [
            {"name": "Allow-SSH-Any", "access": "Allow", "direction": "Inbound", "source_address_prefix": "*", "destination_port_range": "22"},
            {"name": "Allow-HTTPS", "access": "Allow", "direction": "Inbound", "source_address_prefix": "0.0.0.0/0", "destination_port_range": "443"}
        ]
    }
    auditor = AzureCISAuditor()
    results = auditor.run_audit(mock_inventory)
    print("=== CIS Azure Benchmark Audit Summary ===")
    for f in results:
        badge = "[✓ PASS]" if f.status == "PASS" else "[✗ FAIL]"
        print(f"{badge} {f.rule_id} ({f.severity}): {f.title} -> {f.status}")
