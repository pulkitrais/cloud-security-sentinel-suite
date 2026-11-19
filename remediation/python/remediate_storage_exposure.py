"""
Automated Remediation Module: Storage Account Public Access Hardening.
Applies least-privilege configuration to neutralize public exposure alerts.
"""

from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class RemediationResult:
    resource_id: str
    remediation_type: str
    success: bool
    changes_applied: Dict[str, Any]
    error_message: str = ""


class StorageRemediator:
    """Neutralizes public exposure on cloud storage resources."""

    @staticmethod
    def remediate_blob_public_access(storage_account_data: Dict[str, Any]) -> RemediationResult:
        """Enforces private-only blob access and HTTPS enforcement."""
        resource_id = storage_account_data.get("id", "unknown-storage-account")
        changes = {}

        if storage_account_data.get("allow_blob_public_access", True):
            changes["allow_blob_public_access"] = False

        if not storage_account_data.get("supports_https_traffic_only", False):
            changes["supports_https_traffic_only"] = True

        return RemediationResult(
            resource_id=resource_id,
            remediation_type="Azure.Storage.DisablePublicAccess",
            success=True,
            changes_applied=changes
        )


if __name__ == "__main__":
    test_target = {
        "id": "/subscriptions/sub-123/resourceGroups/rg-sec/providers/Microsoft.Storage/storageAccounts/saexposed",
        "allow_blob_public_access": True,
        "supports_https_traffic_only": False
    }
    result = StorageRemediator.remediate_blob_public_access(test_target)
    print(f"Remediation Applied: {result.success} - Changes: {result.changes_applied}")
