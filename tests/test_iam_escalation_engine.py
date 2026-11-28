"""
Unit tests for Cloud IAM Privilege Escalation & Lateral Movement Threat Engine.
"""

import unittest
from identity_threat.iam_escalation_engine import (
    CloudProvider,
    EscalationRiskLevel,
    EscalationVector,
    IAMIdentity,
    IAMEscalationEngine,
)


class TestIAMEscalationEngine(unittest.TestCase):

    def setUp(self):
        self.engine = IAMEscalationEngine()

    def test_benign_user_no_escalation(self):
        """Verify an unprivileged read-only identity triggers zero escalation vectors."""
        read_only_user = IAMIdentity(
            identity_id="user-auditor-101",
            name="SecurityAuditor",
            identity_type="user",
            provider=CloudProvider.AWS,
            policies=[
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject", "s3:ListBucket", "ec2:DescribeInstances"],
                            "Resource": "*",
                        }
                    ],
                }
            ],
            assumable_roles=[],
            is_admin=False,
        )
        self.engine.register_identity(read_only_user)
        vectors = self.engine.evaluate_direct_vectors(read_only_user.identity_id)
        self.assertEqual(len(vectors), 0)

        paths = self.engine.find_attack_paths(read_only_user.identity_id)
        self.assertEqual(len(paths), 0)

        blast = self.engine.calculate_blast_radius(read_only_user.identity_id)
        self.assertEqual(blast["risk_tier"], EscalationRiskLevel.LOW.value)
        self.assertFalse(blast["can_escalate_to_admin"])

    def test_aws_direct_passrole_ec2_vector(self):
        """Verify detection of the classic PassRole + EC2 RunInstances privilege escalation primitive."""
        dev_user = IAMIdentity(
            identity_id="user-dev-202",
            name="BackendDeveloper",
            identity_type="user",
            provider=CloudProvider.AWS,
            policies=[
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["iam:PassRole", "ec2:RunInstances"],
                            "Resource": "*",
                        }
                    ]
                }
            ],
            is_admin=False,
        )
        self.engine.register_identity(dev_user)
        vectors = self.engine.evaluate_direct_vectors(dev_user.identity_id)
        vector_ids = [v.vector_id for v in vectors]

        self.assertIn("AWS-VEC-01", vector_ids)
        vec = next(v for v in vectors if v.vector_id == "AWS-VEC-01")
        self.assertEqual(vec.mitre_attack, "T1548.005")
        self.assertEqual(vec.risk_level, EscalationRiskLevel.CRITICAL)

        paths = self.engine.find_attack_paths(dev_user.identity_id)
        self.assertGreaterEqual(len(paths), 1)
        self.assertTrue(paths[0].is_critical)
        self.assertEqual(paths[0].target_identity, "FullAdministrator")

    def test_aws_wildcard_permission_expansion(self):
        """Verify that wildcards like 'iam:*' properly match specific sub-actions."""
        wildcard_user = IAMIdentity(
            identity_id="user-iam-manager",
            name="IAMManager",
            identity_type="user",
            provider=CloudProvider.AWS,
            policies=[
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["iam:*"],
                            "Resource": "*",
                        }
                    ]
                }
            ],
            is_admin=False,
        )
        self.engine.register_identity(wildcard_user)
        vectors = self.engine.evaluate_direct_vectors(wildcard_user.identity_id)
        vector_ids = [v.vector_id for v in vectors]

        # Should match AttachUserPolicy, PutUserPolicy, CreateAccessKey, CreateLoginProfile, SetDefaultPolicyVersion, etc.
        self.assertIn("AWS-VEC-03", vector_ids)
        self.assertIn("AWS-VEC-04", vector_ids)
        self.assertIn("AWS-VEC-05", vector_ids)
        self.assertIn("AWS-VEC-06", vector_ids)
        self.assertIn("AWS-VEC-07", vector_ids)

    def test_azure_role_assignments_write_escalation(self):
        """Verify detection of Azure RBAC role assignment direct privilege escalation."""
        azure_sp = IAMIdentity(
            identity_id="sp-devops-pipeline",
            name="DevOpsAutomationSP",
            identity_type="service_principal",
            provider=CloudProvider.AZURE,
            policies=[
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["Microsoft.Authorization/roleAssignments/write"],
                            "Resource": "*",
                        }
                    ]
                }
            ],
            is_admin=False,
        )
        self.engine.register_identity(azure_sp)
        vectors = self.engine.evaluate_direct_vectors(azure_sp.identity_id)
        vector_ids = [v.vector_id for v in vectors]

        self.assertIn("AZURE-VEC-01", vector_ids)
        blast = self.engine.calculate_blast_radius(azure_sp.identity_id)
        self.assertEqual(blast["risk_tier"], EscalationRiskLevel.CRITICAL.value)
        self.assertTrue(blast["can_escalate_to_admin"])

    def test_azure_custom_role_wildcard_matching(self):
        """Verify detection of Azure custom role definition tampering permissions."""
        azure_user = IAMIdentity(
            identity_id="user-azure-secops",
            name="AzureSecOpsUser",
            identity_type="user",
            provider=CloudProvider.AZURE,
            policies=[
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["Microsoft.Authorization/*"],
                            "Resource": "*",
                        }
                    ]
                }
            ],
            is_admin=False,
        )
        self.engine.register_identity(azure_user)
        vectors = self.engine.evaluate_direct_vectors(azure_user.identity_id)
        vector_ids = [v.vector_id for v in vectors]

        self.assertIn("AZURE-VEC-01", vector_ids)
        self.assertIn("AZURE-VEC-02", vector_ids)

    def test_multi_hop_attack_path_via_assume_role(self):
        """Verify multi-hop path finding: Intern -> Intermediate Tier Role -> Cloud Admin Role."""
        intern_user = IAMIdentity(
            identity_id="user-intern-01",
            name="EngineeringIntern",
            identity_type="user",
            provider=CloudProvider.AWS,
            policies=[
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["sts:AssumeRole"],
                            "Resource": "arn:aws:iam::123456789012:role/DataPipelineDeployer",
                        }
                    ]
                }
            ],
            assumable_roles=["role-data-deployer"],
            is_admin=False,
        )
        deployer_role = IAMIdentity(
            identity_id="role-data-deployer",
            name="DataPipelineDeployer",
            identity_type="role",
            provider=CloudProvider.AWS,
            policies=[
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["sts:AssumeRole"],
                            "Resource": "arn:aws:iam::123456789012:role/CloudInfrastructureAdmin",
                        }
                    ]
                }
            ],
            assumable_roles=["role-infra-admin"],
            is_admin=False,
        )
        admin_role = IAMIdentity(
            identity_id="role-infra-admin",
            name="CloudInfrastructureAdmin",
            identity_type="role",
            provider=CloudProvider.AWS,
            policies=[
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["*"],
                            "Resource": "*",
                        }
                    ]
                }
            ],
            assumable_roles=[],
            is_admin=True,
        )

        self.engine.register_identities([intern_user, deployer_role, admin_role])
        paths = self.engine.find_attack_paths(intern_user.identity_id)

        self.assertGreaterEqual(len(paths), 1)
        critical_path = next(p for p in paths if p.target_identity == "role-infra-admin")
        self.assertEqual(len(critical_path.steps), 2)
        self.assertEqual(critical_path.steps[0].source_entity, "user-intern-01")
        self.assertEqual(critical_path.steps[0].target_entity, "role-data-deployer")
        self.assertEqual(critical_path.steps[1].source_entity, "role-data-deployer")
        self.assertEqual(critical_path.steps[1].target_entity, "role-infra-admin")
        self.assertTrue(critical_path.is_critical)

    def test_graph_cycle_handling(self):
        """Verify engine does not enter infinite recursion when assume role cycles exist."""
        role_a = IAMIdentity(
            identity_id="role-service-a",
            name="ServiceA",
            identity_type="role",
            provider=CloudProvider.AWS,
            assumable_roles=["role-service-b"],
            is_admin=False,
        )
        role_b = IAMIdentity(
            identity_id="role-service-b",
            name="ServiceB",
            identity_type="role",
            provider=CloudProvider.AWS,
            assumable_roles=["role-service-a"],  # Direct mutual cycle
            is_admin=False,
        )

        self.engine.register_identities([role_a, role_b])
        # Should terminate immediately without error
        paths = self.engine.find_attack_paths(role_a.identity_id)
        self.assertEqual(len(paths), 0)

    def test_blast_radius_admin_identity(self):
        """Verify blast radius calculation for a full administrator identity."""
        admin_identity = IAMIdentity(
            identity_id="role-global-admin",
            name="GlobalAdministrator",
            identity_type="role",
            provider=CloudProvider.AWS,
            is_admin=True,
        )
        self.engine.register_identity(admin_identity)
        blast = self.engine.calculate_blast_radius(admin_identity.identity_id)

        self.assertEqual(blast["blast_radius_score"], 100.0)
        self.assertEqual(blast["risk_tier"], EscalationRiskLevel.CRITICAL.value)
        self.assertTrue(blast["can_escalate_to_admin"])

    def test_remediation_guardrail_generation(self):
        """Verify generation of AWS Service Control Policy (SCP) and Azure policy guardrails."""
        attacker = IAMIdentity(
            identity_id="user-contractor-99",
            name="ExternalContractor",
            identity_type="user",
            provider=CloudProvider.AWS,
            policies=[
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["iam:PassRole", "ec2:RunInstances"],
                            "Resource": "*",
                        }
                    ]
                }
            ],
            is_admin=False,
        )
        self.engine.register_identity(attacker)
        paths = self.engine.find_attack_paths(attacker.identity_id)
        self.assertGreaterEqual(len(paths), 1)

        guardrail = self.engine.generate_remediation_guardrail(paths[0])
        self.assertEqual(guardrail["targeted_identity"], attacker.identity_id)
        self.assertIn("ec2:RunInstances", guardrail["blocked_actions"])
        self.assertIn("iam:PassRole", guardrail["blocked_actions"])
        self.assertIsNotNone(guardrail["aws_scp_policy"])
        self.assertEqual(guardrail["aws_scp_policy"]["Statement"][0]["Effect"], "Deny")

    def test_export_graph_topology(self):
        """Verify graph topology export with nodes and directed edges for SIEM visualization."""
        user = IAMIdentity(
            identity_id="user-test-node",
            name="TestNodeUser",
            identity_type="user",
            provider=CloudProvider.AWS,
            assumable_roles=["role-target-node"],
        )
        role = IAMIdentity(
            identity_id="role-target-node",
            name="TargetNodeRole",
            identity_type="role",
            provider=CloudProvider.AWS,
            is_admin=True,
        )
        self.engine.register_identities([user, role])
        topology = self.engine.export_graph_topology()

        self.assertEqual(topology["total_nodes"], 2)
        self.assertGreaterEqual(topology["total_edges"], 1)
        edge = topology["edges"][0]
        self.assertEqual(edge["from"], "user-test-node")
        self.assertEqual(edge["to"], "role-target-node")
        self.assertEqual(edge["type"], "ASSUME_ROLE")


if __name__ == "__main__":
    unittest.main()
