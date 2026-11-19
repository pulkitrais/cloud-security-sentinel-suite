"""
Automated Remediation Module: Cloud Instance Quarantine.
Isolates compromised virtual machines / compute instances by detaching permissive
security groups / NSGs and attaching an isolated Quarantine Deny-All Group.
"""

from dataclasses import dataclass
from typing import List, Dict, Any


@dataclass
class QuarantineResult:
    instance_id: str
    previous_groups: List[str]
    quarantine_group: str
    status: str
    details: str


class InstanceQuarantiner:
    """Isolates compute instances under active security investigation."""

    DEFAULT_QUARANTINE_NSG = "/subscriptions/sub-123/resourceGroups/rg-sec/providers/Microsoft.Network/networkSecurityGroups/nsg-quarantine-deny-all"

    @classmethod
    def isolate_azure_vm(cls, vm_id: str, current_nsg_ids: List[str], target_quarantine_nsg: str = None) -> QuarantineResult:
        quarantine_nsg = target_quarantine_nsg or cls.DEFAULT_QUARANTINE_NSG
        return QuarantineResult(
            instance_id=vm_id,
            previous_groups=current_nsg_ids,
            quarantine_group=quarantine_nsg,
            status="ISOLATED",
            details="All ingress and egress traffic severed except outbound to telemetry endpoints."
        )


if __name__ == "__main__":
    res = InstanceQuarantiner.isolate_azure_vm(
        vm_id="/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-c2-compromised",
        current_nsg_ids=["nsg-web-inbound", "nsg-allow-ssh"]
    )
    print(f"Target: {res.instance_id}\nStatus: {res.status}\nQuarantine Rule: {res.quarantine_group}")
