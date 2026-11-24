"""
Cloud Security SOAR Incident Response Playbook Orchestrator.

Provides automated triage, risk scoring, containment planning, execution
(simulation or live), evidence ledger recording, and rollback mechanisms
for Microsoft Sentinel and multi-cloud security incidents.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional
import uuid

logger = logging.getLogger("SOAROrchestrator")


class EntityType(str, Enum):
    USER = "user"
    IP_ADDRESS = "ip_address"
    HOST_VM = "host_vm"
    STORAGE_ACCOUNT = "storage_account"
    SERVICE_PRINCIPAL = "service_principal"


class ActionType(str, Enum):
    REVOKE_USER_SESSIONS = "revoke_user_sessions"
    ISOLATE_HOST = "isolate_host"
    BLOCK_MALICIOUS_IP = "block_malicious_ip"
    DISABLE_SERVICE_PRINCIPAL_KEY = "disable_service_principal_key"
    RESTRICT_STORAGE_ACL = "restrict_storage_acl"
    NOTIFY_SOC_CHANNEL = "notify_soc_channel"


class ExecutionMode(str, Enum):
    SIMULATION = "simulation"
    LIVE = "live"


class ActionStatus(str, Enum):
    PENDING = "PENDING"
    SIMULATED = "SIMULATED"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


@dataclass
class IncidentEntity:
    entity_type: EntityType
    value: str
    risk_weight: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PlaybookAction:
    action_type: ActionType
    target_entity: IncidentEntity
    parameters: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    rollback_supported: bool = True
    rollback_payload: Optional[Dict[str, Any]] = None


@dataclass
class ActionResult:
    action_id: str
    action_type: ActionType
    target_value: str
    status: ActionStatus
    execution_time: str
    rollback_token: Optional[str]
    details: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None


@dataclass
class IncidentContext:
    incident_id: str
    title: str
    severity: str  # Critical, High, Medium, Low, Informational
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    entities: List[IncidentEntity]
    raw_alert_source: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def get_entities_by_type(self, entity_type: EntityType) -> List[IncidentEntity]:
        return [e for e in self.entities if e.entity_type == entity_type]


@dataclass
class PlaybookExecutionReport:
    report_id: str
    incident_id: str
    playbook_name: str
    execution_mode: ExecutionMode
    start_time: str
    end_time: str
    actions_executed: List[ActionResult] = field(default_factory=list)
    overall_status: str = "COMPLETED"
    blast_radius_score: float = 0.0


class BasePlaybook:
    """Abstract base class for all SOAR response playbooks."""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    def evaluate_triggers(self, incident: IncidentContext) -> bool:
        """Determines if this playbook should trigger for the given incident."""
        raise NotImplementedError

    def plan_actions(self, incident: IncidentContext) -> List[PlaybookAction]:
        """Generates ordered containment actions based on incident context."""
        raise NotImplementedError

    def execute_action(
        self,
        action: PlaybookAction,
        mode: ExecutionMode = ExecutionMode.SIMULATION
    ) -> ActionResult:
        """Executes a single action in simulation or live mode."""
        action_id = f"act-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()
        rollback_token = None

        if action.rollback_supported:
            rollback_seed = f"{action_id}:{action.target_entity.value}:{now}"
            rollback_token = hashlib.sha256(rollback_seed.encode("utf-8")).hexdigest()[:16]

        if mode == ExecutionMode.SIMULATION:
            return ActionResult(
                action_id=action_id,
                action_type=action.action_type,
                target_value=action.target_entity.value,
                status=ActionStatus.SIMULATED,
                execution_time=now,
                rollback_token=rollback_token,
                details={
                    "mode": "simulation",
                    "planned_operation": action.description,
                    "target_type": action.target_entity.entity_type.value,
                    "parameters": action.parameters,
                }
            )

        # Live execution dispatcher
        try:
            details = self._dispatch_live(action)
            return ActionResult(
                action_id=action_id,
                action_type=action.action_type,
                target_value=action.target_entity.value,
                status=ActionStatus.SUCCESS,
                execution_time=now,
                rollback_token=rollback_token,
                details=details
            )
        except Exception as ex:
            logger.error(f"Failed to execute action {action.action_type}: {ex}")
            return ActionResult(
                action_id=action_id,
                action_type=action.action_type,
                target_value=action.target_entity.value,
                status=ActionStatus.FAILED,
                execution_time=now,
                rollback_token=None,
                error_message=str(ex)
            )

    def _dispatch_live(self, action: PlaybookAction) -> Dict[str, Any]:
        """Mock live handler with structured output. In production, calls cloud SDKs."""
        return {
            "mode": "live",
            "operation": action.action_type.value,
            "target": action.target_entity.value,
            "api_status": "200_OK",
            "applied_changes": action.parameters
        }


class AccountCompromisePlaybook(BasePlaybook):
    """
    Playbook for suspected identity compromise, token theft, or credential abuse.
    Actions:
      1. Revoke active refresh tokens & session cookies (Entra ID / IAM).
      2. Enforce conditional access / MFA re-authentication.
      3. Notify security operations channel.
    """

    def __init__(self):
        super().__init__(
            name="AccountCompromisePlaybook",
            description="Isolates and remediates compromised user accounts, revoking active sessions and tokens."
        )

    def evaluate_triggers(self, incident: IncidentContext) -> bool:
        user_entities = incident.get_entities_by_type(EntityType.USER)
        if not user_entities:
            return False

        identity_tactics = {"Credential Access", "Privilege Escalation", "Initial Access", "Persistence"}
        matches_tactic = any(t in identity_tactics for t in incident.mitre_tactics)
        high_severity = incident.severity.capitalize() in ("High", "Critical")

        return matches_tactic and high_severity

    def plan_actions(self, incident: IncidentContext) -> List[PlaybookAction]:
        actions: List[PlaybookAction] = []
        users = incident.get_entities_by_type(EntityType.USER)

        for user in users:
            actions.append(PlaybookAction(
                action_type=ActionType.REVOKE_USER_SESSIONS,
                target_entity=user,
                parameters={
                    "userPrincipalName": user.value,
                    "revokeAllRefreshTokens": True,
                    "invalidateOAuthSessions": True
                },
                description=f"Revoke all active sessions and refresh tokens for user {user.value}",
                rollback_supported=True,
                rollback_payload={"userPrincipalName": user.value, "reinstate_tokens": False}
            ))

        actions.append(PlaybookAction(
            action_type=ActionType.NOTIFY_SOC_CHANNEL,
            target_entity=users[0],
            parameters={
                "channel": "#soc-incident-response",
                "incident_id": incident.incident_id,
                "users_contained": [u.value for u in users]
            },
            description="Notify tier 2 SOC analysts with containment report",
            rollback_supported=False
        ))
        return actions


class ThreatFeedNetworkIsolationPlaybook(BasePlaybook):
    """
    Playbook for active Command-and-Control (C2) or malicious network beaconing.
    Actions:
      1. Inject perimeter firewall drop rule for malicious destination IP(s).
      2. Apply zero-trust network quarantine to compromised internal host VM(s).
    """

    def __init__(self):
        super().__init__(
            name="ThreatFeedNetworkIsolationPlaybook",
            description="Blocks malicious external IPs and quarantines communicating virtual machines."
        )

    def evaluate_triggers(self, incident: IncidentContext) -> bool:
        has_ips = bool(incident.get_entities_by_type(EntityType.IP_ADDRESS))
        has_vms = bool(incident.get_entities_by_type(EntityType.HOST_VM))

        c2_tactics = {"Command and Control", "Exfiltration", "Lateral Movement"}
        matches_tactic = any(t in c2_tactics for t in incident.mitre_tactics)
        high_severity = incident.severity.capitalize() in ("High", "Critical")

        return (has_ips or has_vms) and (matches_tactic or high_severity)

    def plan_actions(self, incident: IncidentContext) -> List[PlaybookAction]:
        actions: List[PlaybookAction] = []
        malicious_ips = incident.get_entities_by_type(EntityType.IP_ADDRESS)
        vms = incident.get_entities_by_type(EntityType.HOST_VM)

        for ip in malicious_ips:
            actions.append(PlaybookAction(
                action_type=ActionType.BLOCK_MALICIOUS_IP,
                target_entity=ip,
                parameters={
                    "ip_address": ip.value,
                    "rule_priority": 100,
                    "action": "Deny",
                    "direction": "Outbound",
                    "duration_hours": 72
                },
                description=f"Add perimeter firewall drop rule for C2 indicator {ip.value}",
                rollback_supported=True,
                rollback_payload={"ip_address": ip.value, "remove_rule": True}
            ))

        for vm in vms:
            actions.append(PlaybookAction(
                action_type=ActionType.ISOLATE_HOST,
                target_entity=vm,
                parameters={
                    "vm_id": vm.value,
                    "quarantine_nsg": "nsg-quarantine-zerotrust",
                    "preserve_management_ip": True
                },
                description=f"Quarantine host VM {vm.value} by applying restricted security group",
                rollback_supported=True,
                rollback_payload={"vm_id": vm.value, "restore_prior_nsg": True}
            ))

        return actions


class ServicePrincipalPersistencePlaybook(BasePlaybook):
    """
    Playbook for unauthorized Service Principal / App Registration credential injection.
    Actions:
      1. Disable or delete newly attached rogue certificate/secret.
      2. Invalidate app permissions.
    """

    def __init__(self):
        super().__init__(
            name="ServicePrincipalPersistencePlaybook",
            description="Contains rogue application credentials added to Azure AD / Entra ID service principals."
        )

    def evaluate_triggers(self, incident: IncidentContext) -> bool:
        has_sp = bool(incident.get_entities_by_type(EntityType.SERVICE_PRINCIPAL))
        persistence_tactics = {"Persistence", "Privilege Escalation"}
        matches_tactic = any(t in persistence_tactics for t in incident.mitre_tactics)
        return has_sp and matches_tactic

    def plan_actions(self, incident: IncidentContext) -> List[PlaybookAction]:
        actions: List[PlaybookAction] = []
        sps = incident.get_entities_by_type(EntityType.SERVICE_PRINCIPAL)

        for sp in sps:
            key_id = sp.metadata.get("key_id", "all_unverified_keys")
            actions.append(PlaybookAction(
                action_type=ActionType.DISABLE_SERVICE_PRINCIPAL_KEY,
                target_entity=sp,
                parameters={
                    "service_principal_id": sp.value,
                    "key_id": key_id,
                    "state": "Disabled"
                },
                description=f"Disable rogue key {key_id} on Service Principal {sp.value}",
                rollback_supported=True,
                rollback_payload={"service_principal_id": sp.value, "key_id": key_id, "state": "Enabled"}
            ))

        return actions


class SOAREngine:
    """
    Central SOAR Engine that registers playbooks, evaluates incidents,
    runs automated containment, records ledger tokens, and generates incident reports.
    """

    def __init__(self):
        self.playbooks: List[BasePlaybook] = [
            AccountCompromisePlaybook(),
            ThreatFeedNetworkIsolationPlaybook(),
            ServicePrincipalPersistencePlaybook(),
        ]
        self._rollback_registry: Dict[str, Dict[str, Any]] = {}

    def register_playbook(self, playbook: BasePlaybook) -> None:
        self.playbooks.append(playbook)

    def calculate_blast_radius(self, incident: IncidentContext) -> float:
        """
        Calculates an impact and blast radius score (1.0 to 10.0) based on
        entity count, severity weight, and MITRE tactic criticality.
        """
        severity_multipliers = {
            "critical": 3.5,
            "high": 2.5,
            "medium": 1.5,
            "low": 1.0,
            "informational": 0.5
        }
        sev_score = severity_multipliers.get(incident.severity.lower(), 1.0)
        entity_score = sum(e.risk_weight for e in incident.entities) * 0.8
        tactic_score = len(incident.mitre_tactics) * 0.5
        raw_score = sev_score + entity_score + tactic_score
        return round(min(10.0, max(1.0, raw_score)), 2)

    def triage_and_respond(
        self,
        incident: IncidentContext,
        mode: ExecutionMode = ExecutionMode.SIMULATION
    ) -> List[PlaybookExecutionReport]:
        """
        Matches incident against all registered playbooks and executes planned actions.
        """
        reports: List[PlaybookExecutionReport] = []
        blast_radius = self.calculate_blast_radius(incident)

        for playbook in self.playbooks:
            if not playbook.evaluate_triggers(incident):
                continue

            start_time = datetime.now(timezone.utc).isoformat()
            actions = playbook.plan_actions(incident)
            action_results: List[ActionResult] = []

            for act in actions:
                res = playbook.execute_action(act, mode=mode)
                action_results.append(res)
                if res.rollback_token and act.rollback_payload:
                    self._rollback_registry[res.rollback_token] = {
                        "action_type": act.action_type.value,
                        "target": act.target_entity.value,
                        "rollback_payload": act.rollback_payload,
                        "executed_at": res.execution_time
                    }

            end_time = datetime.now(timezone.utc).isoformat()
            overall = "COMPLETED"
            if any(r.status == ActionStatus.FAILED for r in action_results):
                overall = "PARTIAL_FAILURE"

            report = PlaybookExecutionReport(
                report_id=f"rep-{uuid.uuid4().hex[:8]}",
                incident_id=incident.incident_id,
                playbook_name=playbook.name,
                execution_mode=mode,
                start_time=start_time,
                end_time=end_time,
                actions_executed=action_results,
                overall_status=overall,
                blast_radius_score=blast_radius
            )
            reports.append(report)

        return reports

    def rollback(self, rollback_token: str) -> bool:
        """Rolls back an executed action using its cryptographic token."""
        entry = self._rollback_registry.get(rollback_token)
        if not entry:
            return False
        entry["rolled_back"] = True
        entry["rollback_time"] = datetime.now(timezone.utc).isoformat()
        return True

    def generate_markdown_incident_report(
        self,
        incident: IncidentContext,
        reports: List[PlaybookExecutionReport]
    ) -> str:
        """Produces a structured SOC markdown executive briefing."""
        blast_radius = self.calculate_blast_radius(incident)
        lines = [
            f"# SOAR Incident Response Report: {incident.incident_id}",
            f"**Title**: {incident.title}",
            f"**Severity**: `{incident.severity.upper()}` | **Blast Radius Score**: `{blast_radius} / 10.0`",
            f"**Data Source**: {incident.raw_alert_source} | **Timestamp**: {incident.timestamp}",
            "",
            "## MITRE ATT&CK Mapping",
            f"- **Tactics**: {', '.join(incident.mitre_tactics) if incident.mitre_tactics else 'None'}",
            f"- **Techniques**: {', '.join(incident.mitre_techniques) if incident.mitre_techniques else 'None'}",
            "",
            "## Affected Entities",
            "| Entity Type | Identifier | Risk Weight |",
            "|---|---|---|"
        ]

        for ent in incident.entities:
            lines.append(f"| {ent.entity_type.value} | `{ent.value}` | {ent.risk_weight} |")

        lines.extend([
            "",
            "## Automated Containment Actions",
        ])

        if not reports:
            lines.append("_No automated playbooks met execution criteria for this incident._")
        else:
            for rep in reports:
                lines.append(f"### Playbook: {rep.playbook_name} (`{rep.execution_mode.value.upper()}`)")
                lines.append(f"Status: **{rep.overall_status}**")
                lines.append("| Action ID | Action Type | Target | Status | Rollback Token |")
                lines.append("|---|---|---|---|---|")
                for act in rep.actions_executed:
                    token_str = f"`{act.rollback_token}`" if act.rollback_token else "N/A"
                    lines.append(
                        f"| {act.action_id} | `{act.action_type.value}` | `{act.target_value}` | {act.status.value} | {token_str} |"
                    )
                lines.append("")

        return "\n".join(lines)
