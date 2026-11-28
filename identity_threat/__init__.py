"""
Cloud IAM Privilege Escalation & Lateral Movement Threat Engine.
"""

from .iam_escalation_engine import (
    CloudProvider,
    EscalationRiskLevel,
    EscalationVector,
    IAMIdentity,
    AttackStep,
    AttackPath,
    IAMEscalationEngine,
)

__all__ = [
    "CloudProvider",
    "EscalationRiskLevel",
    "EscalationVector",
    "IAMIdentity",
    "AttackStep",
    "AttackPath",
    "IAMEscalationEngine",
]
