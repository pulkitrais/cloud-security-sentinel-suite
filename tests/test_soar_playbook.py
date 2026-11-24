import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soar.incident_playbook_orchestrator import (
    EntityType,
    ActionType,
    ExecutionMode,
    ActionStatus,
    IncidentEntity,
    IncidentContext,
    AccountCompromisePlaybook,
    ThreatFeedNetworkIsolationPlaybook,
    ServicePrincipalPersistencePlaybook,
    SOAREngine,
)


class TestSOARPlaybookEngine(unittest.TestCase):

    def setUp(self):
        self.engine = SOAREngine()

    def test_blast_radius_calculation(self):
        incident = IncidentContext(
            incident_id="INC-TEST-001",
            title="Mass Token Exfiltration and Account Compromise",
            severity="Critical",
            mitre_tactics=["Credential Access", "Exfiltration"],
            mitre_techniques=["T1550.001", "T1539"],
            entities=[
                IncidentEntity(EntityType.USER, "compromised_admin@corp.com", risk_weight=3.0),
                IncidentEntity(EntityType.IP_ADDRESS, "198.51.100.44", risk_weight=2.0),
            ],
            raw_alert_source="Microsoft Sentinel",
        )
        score = self.engine.calculate_blast_radius(incident)
        self.assertGreaterEqual(score, 6.0)
        self.assertLessEqual(score, 10.0)

    def test_account_compromise_playbook_simulation(self):
        incident = IncidentContext(
            incident_id="INC-IDENTITY-99",
            title="Suspicious PIM Elevation and Token Theft",
            severity="High",
            mitre_tactics=["Credential Access", "Privilege Escalation"],
            mitre_techniques=["T1078.004"],
            entities=[
                IncidentEntity(EntityType.USER, "victim_user@cloudcorp.com", risk_weight=2.5),
            ],
            raw_alert_source="Microsoft Entra ID Protection",
        )

        reports = self.engine.triage_and_respond(incident, mode=ExecutionMode.SIMULATION)
        self.assertEqual(len(reports), 1)

        rep = reports[0]
        self.assertEqual(rep.playbook_name, "AccountCompromisePlaybook")
        self.assertEqual(rep.overall_status, "COMPLETED")
        self.assertEqual(rep.execution_mode, ExecutionMode.SIMULATION)

        # Actions: Revoke session + Notify SOC
        action_types = [a.action_type for a in rep.actions_executed]
        self.assertIn(ActionType.REVOKE_USER_SESSIONS, action_types)
        self.assertIn(ActionType.NOTIFY_SOC_CHANNEL, action_types)

        revoke_action = next(a for a in rep.actions_executed if a.action_type == ActionType.REVOKE_USER_SESSIONS)
        self.assertEqual(revoke_action.status, ActionStatus.SIMULATED)
        self.assertIsNotNone(revoke_action.rollback_token)

    def test_threat_feed_isolation_playbook_live(self):
        incident = IncidentContext(
            incident_id="INC-C2-404",
            title="C2 Beaconing to Cobalt Strike External Infrastructure",
            severity="High",
            mitre_tactics=["Command and Control"],
            mitre_techniques=["T1071.001"],
            entities=[
                IncidentEntity(EntityType.IP_ADDRESS, "185.220.101.5", risk_weight=3.0),
                IncidentEntity(EntityType.HOST_VM, "vm-prod-app-01", risk_weight=2.0),
            ],
            raw_alert_source="Palo Alto Firewall via CommonSecurityLog",
        )

        reports = self.engine.triage_and_respond(incident, mode=ExecutionMode.LIVE)
        self.assertEqual(len(reports), 1)

        rep = reports[0]
        self.assertEqual(rep.playbook_name, "ThreatFeedNetworkIsolationPlaybook")
        self.assertEqual(rep.overall_status, "COMPLETED")

        action_types = [a.action_type for a in rep.actions_executed]
        self.assertIn(ActionType.BLOCK_MALICIOUS_IP, action_types)
        self.assertIn(ActionType.ISOLATE_HOST, action_types)

        # Check live execution status
        for act in rep.actions_executed:
            self.assertEqual(act.status, ActionStatus.SUCCESS)
            self.assertIsNotNone(act.rollback_token)

    def test_service_principal_persistence_playbook(self):
        incident = IncidentContext(
            incident_id="INC-SP-77",
            title="Rogue Secret Added to Production Enterprise App",
            severity="High",
            mitre_tactics=["Persistence"],
            mitre_techniques=["T1098.001"],
            entities=[
                IncidentEntity(
                    EntityType.SERVICE_PRINCIPAL,
                    "sp-reporting-engine-uuid",
                    risk_weight=2.0,
                    metadata={"key_id": "key-secret-rogue-001"}
                ),
            ],
            raw_alert_source="Microsoft Sentinel AuditLogs",
        )

        reports = self.engine.triage_and_respond(incident, mode=ExecutionMode.LIVE)
        self.assertEqual(len(reports), 1)
        rep = reports[0]
        self.assertEqual(rep.playbook_name, "ServicePrincipalPersistencePlaybook")
        self.assertEqual(rep.actions_executed[0].action_type, ActionType.DISABLE_SERVICE_PRINCIPAL_KEY)
        self.assertEqual(rep.actions_executed[0].status, ActionStatus.SUCCESS)

    def test_rollback_mechanism(self):
        incident = IncidentContext(
            incident_id="INC-ROLLBACK-01",
            title="Temporary Test Containment",
            severity="High",
            mitre_tactics=["Command and Control"],
            mitre_techniques=["T1071.001"],
            entities=[IncidentEntity(EntityType.IP_ADDRESS, "203.0.113.88", risk_weight=1.0)],
            raw_alert_source="Sentinel TI Feed",
        )
        reports = self.engine.triage_and_respond(incident, mode=ExecutionMode.LIVE)
        token = reports[0].actions_executed[0].rollback_token
        self.assertIsNotNone(token)

        # Successful rollback
        self.assertTrue(self.engine.rollback(token))
        # Non-existent token fails
        self.assertFalse(self.engine.rollback("invalid-token-12345"))

    def test_markdown_report_generation(self):
        incident = IncidentContext(
            incident_id="INC-REPORT-123",
            title="Multi-Vector Lateral Movement and Token Theft",
            severity="Critical",
            mitre_tactics=["Credential Access", "Command and Control"],
            mitre_techniques=["T1550.001", "T1071.001"],
            entities=[
                IncidentEntity(EntityType.USER, "victim_engineer@corp.io", risk_weight=2.0),
                IncidentEntity(EntityType.IP_ADDRESS, "198.51.100.77", risk_weight=2.0),
            ],
            raw_alert_source="Microsoft Sentinel SecurityIncident",
        )
        reports = self.engine.triage_and_respond(incident, mode=ExecutionMode.SIMULATION)
        md = self.engine.generate_markdown_incident_report(incident, reports)

        self.assertIn("# SOAR Incident Response Report: INC-REPORT-123", md)
        self.assertIn("Blast Radius Score", md)
        self.assertIn("victim_engineer@corp.io", md)
        self.assertIn("revoke_user_sessions", md)
        self.assertIn("block_malicious_ip", md)


if __name__ == "__main__":
    unittest.main()
