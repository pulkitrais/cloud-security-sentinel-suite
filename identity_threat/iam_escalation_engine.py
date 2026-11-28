"""
Cloud IAM Privilege Escalation & Lateral Movement Threat Engine.

Analyzes Identity and Access Management (IAM) permissions, role assumptions,
trust relationships, and custom role definitions across AWS and Microsoft Azure.
Identifies toxic permission combinations, models attack graphs, uncovers multi-hop
privilege escalation paths from low-privilege identities to administrative control,
and synthesizes automated least-privilege remediation guardrails.
"""

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
import fnmatch
import json
import re
from typing import List, Dict, Any, Optional, Set, Tuple


class CloudProvider(Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    HYBRID = "HYBRID"


class EscalationRiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class EscalationVector:
    vector_id: str
    name: str
    provider: CloudProvider
    mitre_attack: str
    required_permissions: List[str]
    description: str
    exploit_mechanism: str
    remediation_recommendation: str
    risk_score: float  # 0.0 to 10.0
    risk_level: EscalationRiskLevel

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vector_id": self.vector_id,
            "name": self.name,
            "provider": self.provider.value,
            "mitre_attack": self.mitre_attack,
            "required_permissions": self.required_permissions,
            "description": self.description,
            "exploit_mechanism": self.exploit_mechanism,
            "remediation_recommendation": self.remediation_recommendation,
            "risk_score": round(self.risk_score, 2),
            "risk_level": self.risk_level.value,
        }


@dataclass
class IAMIdentity:
    identity_id: str
    name: str
    identity_type: str  # "user", "role", "group", "service_principal"
    provider: CloudProvider
    policies: List[Dict[str, Any]] = field(default_factory=list)
    assumable_roles: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    is_admin: bool = False
    tags: Dict[str, str] = field(default_factory=dict)

    def get_allowed_actions(self) -> Set[str]:
        """Extracts allowed actions across all attached policies."""
        allowed = set()
        for policy in self.policies:
            statements = policy.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            for stmt in statements:
                if stmt.get("Effect") == "Allow":
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    for act in actions:
                        allowed.add(act)
        return allowed


@dataclass
class AttackStep:
    step_number: int
    source_entity: str
    target_entity: str
    vector_id: str
    vector_name: str
    mechanism: str
    permissions_used: List[str]
    risk_level: EscalationRiskLevel

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_number": self.step_number,
            "source_entity": self.source_entity,
            "target_entity": self.target_entity,
            "vector_id": self.vector_id,
            "vector_name": self.vector_name,
            "mechanism": self.mechanism,
            "permissions_used": self.permissions_used,
            "risk_level": self.risk_level.value,
        }


@dataclass
class AttackPath:
    path_id: str
    source_identity: str
    target_identity: str
    steps: List[AttackStep]
    total_risk_score: float
    risk_level: EscalationRiskLevel
    is_critical: bool
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "source_identity": self.source_identity,
            "target_identity": self.target_identity,
            "step_count": len(self.steps),
            "steps": [s.to_dict() for s in self.steps],
            "total_risk_score": round(self.total_risk_score, 2),
            "risk_level": self.risk_level.value,
            "is_critical": self.is_critical,
            "summary": self.summary,
        }


# Standard Known Cloud IAM Escalation Vectors
STANDARD_VECTORS: List[EscalationVector] = [
    # AWS Vectors
    EscalationVector(
        vector_id="AWS-VEC-01",
        name="PassRole with EC2 RunInstances",
        provider=CloudProvider.AWS,
        mitre_attack="T1548.005",
        required_permissions=["iam:PassRole", "ec2:RunInstances"],
        description="Adversary passes an administrative IAM role to a newly launched EC2 instance and retrieves temporary credentials via IMDSv2 metadata.",
        exploit_mechanism="Launch an EC2 instance with an attached instance profile containing AdministratorAccess, then execute commands via user-data or SSH to exfiltrate role credentials.",
        remediation_recommendation="Restrict iam:PassRole using Resource ARNs and conditions on iam:PassedToService ('ec2.amazonaws.com'). Enforce IMDSv2 with hop count 1.",
        risk_score=9.5,
        risk_level=EscalationRiskLevel.CRITICAL,
    ),
    EscalationVector(
        vector_id="AWS-VEC-02",
        name="PassRole with Lambda Function Creation",
        provider=CloudProvider.AWS,
        mitre_attack="T1548.005",
        required_permissions=["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        description="Adversary assigns a privileged execution role to a newly created Lambda function and triggers execution to execute administrative actions.",
        exploit_mechanism="Create a Python Lambda function with administrative execution role, execute lambda:InvokeFunction, and execute arbitrary privileged API calls.",
        remediation_recommendation="Scope iam:PassRole strictly to specific role ARNs and enforce Service Control Policies (SCPs) preventing unauthorized Lambda role attachments.",
        risk_score=9.2,
        risk_level=EscalationRiskLevel.CRITICAL,
    ),
    EscalationVector(
        vector_id="AWS-VEC-03",
        name="Direct User Policy Attachment",
        provider=CloudProvider.AWS,
        mitre_attack="T1098.001",
        required_permissions=["iam:AttachUserPolicy"],
        description="Adversary directly attaches a high-privilege managed policy (such as AdministratorAccess) to their own IAM user entity.",
        exploit_mechanism="Invoke iam:AttachUserPolicy targeting self or another controlled entity with PolicyArn 'arn:aws:iam::aws:policy/AdministratorAccess'.",
        remediation_recommendation="Enforce IAM Permission Boundaries on non-administrative users and monitor CloudTrail for AttachUserPolicy API calls.",
        risk_score=9.8,
        risk_level=EscalationRiskLevel.CRITICAL,
    ),
    EscalationVector(
        vector_id="AWS-VEC-04",
        name="Inline Policy Injection",
        provider=CloudProvider.AWS,
        mitre_attack="T1098.001",
        required_permissions=["iam:PutUserPolicy"],
        description="Adversary injects an inline policy document with wildcard permissions ('*') directly into their user identity.",
        exploit_mechanism="Invoke iam:PutUserPolicy with an Allow statement granting full administrative actions on all resources.",
        remediation_recommendation="Deny iam:PutUserPolicy via SCP or permission boundaries and mandate centrally managed IAM roles.",
        risk_score=9.7,
        risk_level=EscalationRiskLevel.CRITICAL,
    ),
    EscalationVector(
        vector_id="AWS-VEC-05",
        name="Access Key Minting on Target User",
        provider=CloudProvider.AWS,
        mitre_attack="T1078.004",
        required_permissions=["iam:CreateAccessKey"],
        description="Adversary generates access key pairs on another high-privilege user account without changing passwords.",
        exploit_mechanism="Invoke iam:CreateAccessKey with UserName targeting an administrator account and use the returned secret key for persistent access.",
        remediation_recommendation="Restrict iam:CreateAccessKey so users can only create keys for their own entity (aws:username condition).",
        risk_score=8.8,
        risk_level=EscalationRiskLevel.HIGH,
    ),
    EscalationVector(
        vector_id="AWS-VEC-06",
        name="Console Login Profile Creation or Reset",
        provider=CloudProvider.AWS,
        mitre_attack="T1078.004",
        required_permissions=["iam:CreateLoginProfile"],
        description="Adversary creates a console password for an API-only or administrative user lacking a console password.",
        exploit_mechanism="Invoke iam:CreateLoginProfile with UserName of a high-privilege account, setting a chosen password to sign in to the AWS Management Console.",
        remediation_recommendation="Enforce MFA and restrict iam:CreateLoginProfile to dedicated identity administrators. Alert on login profile creations.",
        risk_score=8.5,
        risk_level=EscalationRiskLevel.HIGH,
    ),
    EscalationVector(
        vector_id="AWS-VEC-07",
        name="Default Policy Version Tampering",
        provider=CloudProvider.AWS,
        mitre_attack="T1098.001",
        required_permissions=["iam:SetDefaultPolicyVersion"],
        description="Adversary reverts a customer-managed policy to a previously created permissive version that was left in the policy history.",
        exploit_mechanism="Scan existing policy versions for an overly permissive policy revision and invoke iam:SetDefaultPolicyVersion to activate it.",
        remediation_recommendation="Prune historical policy versions and restrict iam:SetDefaultPolicyVersion to cloud security leads.",
        risk_score=8.2,
        risk_level=EscalationRiskLevel.HIGH,
    ),
    EscalationVector(
        vector_id="AWS-VEC-08",
        name="Assume Role Trust Policy Backdoor",
        provider=CloudProvider.AWS,
        mitre_attack="T1098.001",
        required_permissions=["iam:UpdateAssumeRolePolicy"],
        description="Adversary modifies the trust policy of an administrative role to allow assumption by their own user or external attacker account.",
        exploit_mechanism="Call iam:UpdateAssumeRolePolicy to append attacker Principal ARN to the AssumeRolePolicyDocument, then execute sts:AssumeRole.",
        remediation_recommendation="Enforce SCP restricting iam:UpdateAssumeRolePolicy on sensitive roles and validate external trust relationships.",
        risk_score=9.3,
        risk_level=EscalationRiskLevel.CRITICAL,
    ),
    EscalationVector(
        vector_id="AWS-VEC-09",
        name="Add User to Privileged Group",
        provider=CloudProvider.AWS,
        mitre_attack="T1098.001",
        required_permissions=["iam:AddUserToGroup"],
        description="Adversary adds an unprivileged user to an existing administrative group (e.g. 'CloudAdmins').",
        exploit_mechanism="Invoke iam:AddUserToGroup with GroupName='Administrators' and UserName='attacker'.",
        remediation_recommendation="Restrict group membership mutation APIs and mandate approval workflows for privileged group additions.",
        risk_score=9.0,
        risk_level=EscalationRiskLevel.CRITICAL,
    ),

    # Azure Vectors
    EscalationVector(
        vector_id="AZURE-VEC-01",
        name="Azure RBAC Role Assignment Write",
        provider=CloudProvider.AZURE,
        mitre_attack="T1098.001",
        required_permissions=["Microsoft.Authorization/roleAssignments/write"],
        description="Adversary grants themselves or an identity the Owner, Contributor, or User Access Administrator role at subscription or management group scope.",
        exploit_mechanism="PUT request to Microsoft.Authorization/roleAssignments to bind target principal to the built-in Owner role definition ID.",
        remediation_recommendation="Restrict roleAssignments/write using Azure Policy Deny effects and Privileged Identity Management (PIM) with mandatory MFA and justification.",
        risk_score=9.9,
        risk_level=EscalationRiskLevel.CRITICAL,
    ),
    EscalationVector(
        vector_id="AZURE-VEC-02",
        name="Azure Custom Role Definition Modification",
        provider=CloudProvider.AZURE,
        mitre_attack="T1548.005",
        required_permissions=["Microsoft.Authorization/roleDefinitions/write"],
        description="Adversary updates an assigned custom role definition to include wildcard actions ('*') or assigns a backdoor custom role.",
        exploit_mechanism="Invoke roleDefinitions/write to append '*' to Actions in an existing custom role currently assigned to the adversary.",
        remediation_recommendation="Protect custom role definitions at the root tenant level and trigger real-time Sentinel KQL alerts on role definition modifications.",
        risk_score=9.6,
        risk_level=EscalationRiskLevel.CRITICAL,
    ),
    EscalationVector(
        vector_id="AZURE-VEC-03",
        name="Azure Automation Runbook Code Execution",
        provider=CloudProvider.AZURE,
        mitre_attack="T1059.001",
        required_permissions=["Microsoft.Automation/automationAccounts/runbooks/write", "Microsoft.Automation/automationAccounts/runbooks/publish/action"],
        description="Adversary modifies an Azure Automation Runbook executed by a system-assigned Managed Identity with Subscription Contributor rights.",
        exploit_mechanism="Publish PowerShell payload to an existing Automation Runbook and trigger execution to run arbitrary commands under the Managed Identity's token.",
        remediation_recommendation="Decouple Managed Identities from Automation Accounts and apply least-privilege scoping to runbook authors.",
        risk_score=8.7,
        risk_level=EscalationRiskLevel.HIGH,
    ),
    EscalationVector(
        vector_id="AZURE-VEC-04",
        name="Azure ARM Template Deployment Write",
        provider=CloudProvider.AZURE,
        mitre_attack="T1548.005",
        required_permissions=["Microsoft.Resources/deployments/write"],
        description="Adversary deploys nested ARM templates utilizing cross-resource privileges or managed identity delegation to elevate permissions.",
        exploit_mechanism="Submit ARM deployment specifying privileged extensions or nested role assignment templates at subscription scope.",
        remediation_recommendation="Scope deployments/write to specific resource groups and require template validation in CI/CD before deployment.",
        risk_score=8.4,
        risk_level=EscalationRiskLevel.HIGH,
    ),
    EscalationVector(
        vector_id="AZURE-VEC-05",
        name="Key Vault Secret Exfiltration",
        provider=CloudProvider.AZURE,
        mitre_attack="T1552.004",
        required_permissions=["Microsoft.KeyVault/vaults/secrets/read", "Microsoft.KeyVault/vaults/secrets/getSecret/action"],
        description="Adversary reads administrative credentials, certificates, or connection strings stored in Azure Key Vault to laterally move.",
        exploit_mechanism="Invoke GET on Key Vault secret endpoints to harvest database credentials and service principal secrets.",
        remediation_recommendation="Use Azure RBAC for Key Vault data plane instead of legacy access policies. Enable private endpoints and Key Vault audit logging.",
        risk_score=8.0,
        risk_level=EscalationRiskLevel.HIGH,
    ),
]


class IAMEscalationEngine:
    """
    Threat modeling engine that builds attack graphs across cloud IAM entities,
    identifying direct privilege escalation vectors, lateral movement paths,
    and multi-hop paths to administrative takeover.
    """

    def __init__(self, custom_vectors: Optional[List[EscalationVector]] = None):
        self.vectors: List[EscalationVector] = list(STANDARD_VECTORS)
        if custom_vectors:
            self.vectors.extend(custom_vectors)
        self.identities: Dict[str, IAMIdentity] = {}
        self.groups: Dict[str, Set[str]] = {}  # group_name -> set of identity_ids

    def register_identity(self, identity: IAMIdentity) -> None:
        """Registers an IAM identity (User, Role, Service Principal) into the engine."""
        self.identities[identity.identity_id] = identity
        for grp in identity.groups:
            if grp not in self.groups:
                self.groups[grp] = set()
            self.groups[grp].add(identity.identity_id)

    def register_identities(self, identities: List[IAMIdentity]) -> None:
        for ident in identities:
            self.register_identity(ident)

    def _matches_action(self, pattern: str, action: str) -> bool:
        """Matches permission strings supporting wildcards (e.g. 'iam:*', '*', 'Microsoft.Authorization/*')."""
        if pattern == "*":
            return True
        pattern_lower = pattern.lower()
        action_lower = action.lower()
        if pattern_lower == action_lower:
            return True
        return fnmatch.fnmatch(action_lower, pattern_lower)

    def evaluate_direct_vectors(self, identity_id: str) -> List[EscalationVector]:
        """Evaluates whether an identity has permissions to trigger direct privilege escalation vectors."""
        if identity_id not in self.identities:
            return []

        identity = self.identities[identity_id]
        allowed_actions = identity.get_allowed_actions()
        triggered_vectors: List[EscalationVector] = []

        for vector in self.vectors:
            # Check provider match
            if vector.provider != CloudProvider.HYBRID and vector.provider != identity.provider:
                continue

            # Check if all required permissions for this vector are satisfied
            all_satisfied = True
            for req_perm in vector.required_permissions:
                perm_matched = False
                for allowed in allowed_actions:
                    if self._matches_action(allowed, req_perm):
                        perm_matched = True
                        break
                if not perm_matched:
                    all_satisfied = False
                    break

            if all_satisfied:
                triggered_vectors.append(vector)

        return triggered_vectors

    def find_attack_paths(
        self,
        source_id: str,
        target_admin_only: bool = True,
        max_depth: int = 5,
    ) -> List[AttackPath]:
        """
        Executes Breadth-First-Search (BFS) across the identity graph to discover
        multi-hop escalation paths from source_id to target administrative entities.
        Handles circular dependencies and graph cycles robustly.
        """
        if source_id not in self.identities:
            return []

        discovered_paths: List[AttackPath] = []
        source_identity = self.identities[source_id]

        # Queue contains: (current_entity_id, list_of_steps, visited_entity_ids)
        queue: deque = deque()
        queue.append((source_id, [], {source_id}))

        while queue:
            curr_id, steps, visited = queue.popleft()

            if len(steps) >= max_depth:
                continue

            curr_identity = self.identities.get(curr_id)
            if not curr_identity:
                continue

            # Check direct escalation vectors from current entity
            direct_vectors = self.evaluate_direct_vectors(curr_id)
            for vec in direct_vectors:
                # If this vector directly grants full administrative access
                step = AttackStep(
                    step_number=len(steps) + 1,
                    source_entity=curr_id,
                    target_entity="FullAdministrator",
                    vector_id=vec.vector_id,
                    vector_name=vec.name,
                    mechanism=vec.exploit_mechanism,
                    permissions_used=vec.required_permissions,
                    risk_level=vec.risk_level,
                )
                full_steps = steps + [step]
                total_score = sum(s.risk_level == EscalationRiskLevel.CRITICAL and 9.5 or 8.0 for s in full_steps) / len(full_steps)
                path = AttackPath(
                    path_id=f"PATH-{source_id}-TO-ADMIN-{len(discovered_paths)+1}",
                    source_identity=source_id,
                    target_identity="FullAdministrator",
                    steps=full_steps,
                    total_risk_score=min(10.0, total_score + (10.0 - len(full_steps) * 0.5)),
                    risk_level=EscalationRiskLevel.CRITICAL,
                    is_critical=True,
                    summary=f"Identity '{source_id}' escalates to FullAdministrator via {len(full_steps)} steps culminating in {vec.name}.",
                )
                discovered_paths.append(path)

            # Check AssumeRole lateral movement / elevation edges
            for target_role_id in curr_identity.assumable_roles:
                if target_role_id in visited:
                    continue  # Prevent cycles
                if target_role_id not in self.identities:
                    continue

                target_identity = self.identities[target_role_id]
                step = AttackStep(
                    step_number=len(steps) + 1,
                    source_entity=curr_id,
                    target_entity=target_role_id,
                    vector_id="ASSUME-ROLE-EDGE",
                    vector_name="AssumeRole Trust Hop",
                    mechanism=f"sts:AssumeRole or Managed Identity token assumption into '{target_role_id}'.",
                    permissions_used=["sts:AssumeRole"],
                    risk_level=EscalationRiskLevel.HIGH if target_identity.is_admin else EscalationRiskLevel.MEDIUM,
                )
                next_steps = steps + [step]
                next_visited = set(visited)
                next_visited.add(target_role_id)

                if target_identity.is_admin:
                    total_score = 9.4 - (len(next_steps) - 1) * 0.4
                    path = AttackPath(
                        path_id=f"PATH-{source_id}-TO-{target_role_id}-{len(discovered_paths)+1}",
                        source_identity=source_id,
                        target_identity=target_role_id,
                        steps=next_steps,
                        total_risk_score=max(5.0, min(10.0, total_score)),
                        risk_level=EscalationRiskLevel.CRITICAL if target_identity.is_admin else EscalationRiskLevel.HIGH,
                        is_critical=target_identity.is_admin,
                        summary=f"Identity '{source_id}' reaches administrative role '{target_role_id}' via {len(next_steps)} role assumption hop(s).",
                    )
                    discovered_paths.append(path)

                # Continue searching from target_role
                queue.append((target_role_id, next_steps, next_visited))

        return discovered_paths

    def find_all_escalation_paths(self) -> List[AttackPath]:
        """Scans all non-admin identities across the organization for viable escalation paths."""
        all_paths: List[AttackPath] = []
        for ident_id, ident in self.identities.items():
            if not ident.is_admin:
                paths = self.find_attack_paths(ident_id, target_admin_only=True)
                all_paths.extend(paths)
        return all_paths

    def calculate_blast_radius(self, identity_id: str) -> Dict[str, Any]:
        """
        Quantifies the potential blast radius if the target identity is compromised.
        Returns reachable identities, critical paths, risk score, and severity tier.
        """
        if identity_id not in self.identities:
            return {"error": f"Identity '{identity_id}' not found."}

        identity = self.identities[identity_id]
        direct_vectors = self.evaluate_direct_vectors(identity_id)
        paths = self.find_attack_paths(identity_id)

        reachable_roles = set(identity.assumable_roles)
        can_reach_admin = identity.is_admin or any(p.is_critical for p in paths) or len(direct_vectors) > 0
        has_critical_vector = any(v.risk_level == EscalationRiskLevel.CRITICAL for v in direct_vectors)

        # Calculate numerical score: 0 to 100
        score = 15.0  # Baseline
        if identity.is_admin:
            score = 100.0
        else:
            if can_reach_admin:
                score += 50.0
            if has_critical_vector:
                score += 15.0
            score += min(20.0, len(direct_vectors) * 5.0)
            score += min(10.0, len(reachable_roles) * 3.0)

        score = min(100.0, score)

        if score >= 80.0:
            tier = EscalationRiskLevel.CRITICAL
        elif score >= 60.0:
            tier = EscalationRiskLevel.HIGH
        elif score >= 35.0:
            tier = EscalationRiskLevel.MEDIUM
        else:
            tier = EscalationRiskLevel.LOW

        return {
            "identity_id": identity_id,
            "identity_name": identity.name,
            "identity_type": identity.identity_type,
            "provider": identity.provider.value,
            "is_admin": identity.is_admin,
            "can_escalate_to_admin": can_reach_admin,
            "direct_vectors_count": len(direct_vectors),
            "direct_vectors": [v.vector_id for v in direct_vectors],
            "attack_paths_count": len(paths),
            "reachable_roles": list(reachable_roles),
            "blast_radius_score": round(score, 1),
            "risk_tier": tier.value,
        }

    def generate_remediation_guardrail(self, path: AttackPath) -> Dict[str, Any]:
        """
        Synthesizes an automated least-privilege remediation policy (AWS SCP or Azure Deny Assignment)
        specifically targeting the vulnerable edges in the attack path.
        """
        remediation_actions = set()
        for step in path.steps:
            for perm in step.permissions_used:
                remediation_actions.add(perm)

        first_step = path.steps[0] if path.steps else None
        source_id = path.source_identity

        aws_actions = [a for a in remediation_actions if not a.startswith("Microsoft.")]
        azure_actions = [a for a in remediation_actions if a.startswith("Microsoft.")]

        scp_policy = None
        if aws_actions:
            scp_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": f"DenyEscalationGuardrail{re.sub(r'[^a-zA-Z0-9]', '', source_id)}",
                        "Effect": "Deny",
                        "Action": sorted(list(aws_actions)),
                        "Resource": "*",
                        "Condition": {
                            "ArnNotEquals": {
                                "aws:PrincipalArn": [
                                    "arn:aws:iam::*:role/CloudSecurityAdminRole",
                                    "arn:aws:iam::*:role/aws-service-role/*"
                                ]
                            }
                        }
                    }
                ]
            }

        azure_policy = None
        if azure_actions:
            azure_policy = {
                "policyDefinition": {
                    "displayName": f"Deny High-Risk Privilege Escalation - {source_id}",
                    "mode": "All",
                    "policyRule": {
                        "if": {
                            "field": "type",
                            "equals": "Microsoft.Authorization/roleAssignments"
                        },
                        "then": {
                            "effect": "deny"
                        }
                    }
                }
            }

        return {
            "path_id": path.path_id,
            "targeted_identity": source_id,
            "mitigated_vectors": [s.vector_id for s in path.steps],
            "blocked_actions": sorted(list(remediation_actions)),
            "aws_scp_policy": scp_policy,
            "azure_policy_guardrail": azure_policy,
            "recommended_controls": [
                "Deploy Service Control Policy (SCP) at AWS Organizations root/OU level to prevent unauthorized PassRole.",
                "Enforce Azure Privileged Identity Management (PIM) with approval workflow and step-up authentication.",
                "Enforce AWS IAM Permission Boundaries across all non-admin IAM users and execution roles."
            ]
        }

    def export_graph_topology(self) -> Dict[str, Any]:
        """Exports the full graph nodes and directed edges for SIEM ingestion and topology rendering."""
        nodes = []
        edges = []

        for ident_id, ident in self.identities.items():
            nodes.append({
                "id": ident_id,
                "label": ident.name,
                "type": ident.identity_type,
                "provider": ident.provider.value,
                "is_admin": ident.is_admin,
            })

            # Assume role edges
            for target_role in ident.assumable_roles:
                edges.append({
                    "from": ident_id,
                    "to": target_role,
                    "type": "ASSUME_ROLE",
                    "risk": "HIGH" if (target_role in self.identities and self.identities[target_role].is_admin) else "MEDIUM"
                })

            # Escalation vector edges
            direct_vecs = self.evaluate_direct_vectors(ident_id)
            for vec in direct_vecs:
                edges.append({
                    "from": ident_id,
                    "to": "FullAdministrator",
                    "type": "ESCALATION_VECTOR",
                    "vector_id": vec.vector_id,
                    "risk": vec.risk_level.value,
                })

        return {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "nodes": nodes,
            "edges": edges,
        }
