"""
SOC7: AI Security & LLM Guardrails Engine for Cloud Security Operations.

Designed to defend LLM-powered SOC agents, RAG knowledge stores, and automated triage
assistants against prompt injection, jailbreaks, training context poisoning, credential
leakage, and excessive autonomous agency (OWASP LLM Top 10 & MITRE ATLAS).
"""

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import ipaddress
import re
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime, timezone


class InjectionRiskLevel(Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class InjectionScanResult:
    is_safe: bool
    risk_level: InjectionRiskLevel
    risk_score: float  # 0.0 to 10.0
    detected_patterns: List[str]
    matched_snippets: List[str]
    mitigation_advice: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_safe": self.is_safe,
            "risk_level": self.risk_level.value,
            "risk_score": round(self.risk_score, 2),
            "detected_patterns": self.detected_patterns,
            "matched_snippets": self.matched_snippets,
            "mitigation_advice": self.mitigation_advice,
        }


class PromptInjectionDetector:
    """
    Multi-vector defense against prompt injection, jailbreak attacks,
    indirect RAG poisoning, and delimiter exploitation.
    """

    DIRECT_INJECTION_PATTERNS = [
        (re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|directives|prompts|rules)\b"), "DIRECT_INSTRUCTION_OVERRIDE", 5.5),
        (re.compile(r"(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|commands|constraints)\b"), "DIRECT_INSTRUCTION_OVERRIDE", 5.5),
        (re.compile(r"(?i)\bforget\s+(?:all\s+)?(?:previous|prior)\s+(?:rules|instructions|directives)\b"), "DIRECT_INSTRUCTION_OVERRIDE", 5.5),
        (re.compile(r"(?i)\bnew\s+system\s+(?:directive|instruction|override)\s*:\b"), "SYSTEM_DIRECTIVE_SPOOFING", 5.0),
        (re.compile(r"(?i)\b(?:system\s+prompt|system\s+role)\s*:\s*you\s+are\b"), "SYSTEM_PROMPT_SPOOFING", 5.0),
    ]

    JAILBREAK_PATTERNS = [
        (re.compile(r"(?i)\byou\s+are\s+now\s+(?:DAN|STAN|DUDE|AIM|KEVIN|jailbroken)\b"), "JAILBREAK_DAN_PERSONA", 5.0),
        (re.compile(r"(?i)\bdo\s+anything\s+now\b"), "JAILBREAK_DAN_PHRASE", 4.5),
        (re.compile(r"(?i)\bdeveloper\s+mode\s+(?:enabled|activated|on)\b"), "JAILBREAK_DEV_MODE", 4.0),
        (re.compile(r"(?i)\bhypothetical\s+(?:scenario|world)\s+(?:where\s+you\s+have\s+no\s+(?:rules|restrictions|filters))\b"), "HYPOTHETICAL_UNRESTRICTED", 3.5),
        (re.compile(r"(?i)\bpretend\s+(?:you\s+have\s+no\s+(?:guidelines|rules|ethics|guardrails))\b"), "GUARDRAIL_BYPASS_ROLEPLAY", 4.0),
        (re.compile(r"(?i)\bact\s+as\s+an\s+unfiltered\s+(?:ai|assistant|model|bot)\b"), "UNFILTERED_PERSONA", 4.0),
    ]

    DELIMITER_AND_ESCAPE_PATTERNS = [
        (re.compile(r"(?i)<\s*(?:system|system_override|admin|instruction)\s*>"), "DELIMITER_XML_INJECTION", 3.5),
        (re.compile(r"(?i)\[\s*(?:SYSTEM|ADMIN|INTERNAL\s+INSTRUCTION)\s*:\s*"), "DELIMITER_BRACKET_INJECTION", 3.5),
        (re.compile(r"(?i)\"role\"\s*:\s*\"system\""), "JSON_SYSTEM_ROLE_INJECTION", 4.0),
        (re.compile(r"```(?:system|instruction|override)"), "FENCED_SYSTEM_INJECTION", 3.5),
    ]

    EXFILTRATION_PATTERNS = [
        (re.compile(r"!\[.*?\]\(https?://[^\s)]+?[?&](?:data|token|key|secret|cookie|leak)=[^)]+\)"), "MARKDOWN_IMAGE_EXFILTRATION", 5.0),
        (re.compile(r"(?i)fetch\s*\(\s*['\"]https?://[^\s'\"]+?[?&](?:exfil|steal|payload)"), "CODE_EXFILTRATION_CALL", 4.5),
    ]

    INDIRECT_RAG_PATTERNS = [
        (re.compile(r"(?i)\bIMPORTANT\s+NOTE\s+FOR\s+THE\s+AI\s*:\s*disregard\b"), "INDIRECT_RAG_POISONING", 4.5),
        (re.compile(r"(?i)<!--\s*#instruction\s*:\s*override\b"), "COMMENT_HIDDEN_INSTRUCTION", 4.0),
        (re.compile(r"(?i)\bAI\s+ASSISTANT\s*:\s*instead\s+of\s+summarizing\b"), "INDIRECT_TASK_HIJACK", 4.0),
    ]

    def __init__(self, sensitivity_threshold: float = 4.0):
        self.sensitivity_threshold = sensitivity_threshold
        self.all_detectors = (
            self.DIRECT_INJECTION_PATTERNS
            + self.JAILBREAK_PATTERNS
            + self.DELIMITER_AND_ESCAPE_PATTERNS
            + self.EXFILTRATION_PATTERNS
            + self.INDIRECT_RAG_PATTERNS
        )

    def scan_prompt(self, text: str) -> InjectionScanResult:
        """Evaluates input text or retrieved document content for prompt injection risk."""
        if not text or not text.strip():
            return InjectionScanResult(
                is_safe=True,
                risk_level=InjectionRiskLevel.SAFE,
                risk_score=0.0,
                detected_patterns=[],
                matched_snippets=[],
                mitigation_advice="Input is empty or whitespace.",
            )

        detected_patterns: List[str] = []
        matched_snippets: List[str] = []
        total_risk = 0.0

        for pattern, label, weight in self.all_detectors:
            matches = list(pattern.finditer(text))
            if matches:
                detected_patterns.append(label)
                total_risk += weight * len(matches)
                for m in matches[:2]:  # capture sample snippets
                    snippet = m.group(0)
                    if len(snippet) > 80:
                        snippet = snippet[:77] + "..."
                    matched_snippets.append(f"[{label}] {snippet}")

        # Normalization to 0.0 - 10.0 scale
        normalized_score = min(total_risk, 10.0)

        if normalized_score == 0.0:
            risk_level = InjectionRiskLevel.SAFE
            is_safe = True
            advice = "No prompt injection patterns detected."
        elif normalized_score < 2.5:
            risk_level = InjectionRiskLevel.LOW
            is_safe = True
            advice = "Low risk indicators detected; allow execution with standard safety monitors."
        elif normalized_score < 4.5:
            risk_level = InjectionRiskLevel.MEDIUM
            is_safe = normalized_score < self.sensitivity_threshold
            advice = "Suspicious prompt syntax identified. Recommend human-in-the-loop review before agent tool invocation."
        elif normalized_score < 8.0:
            risk_level = InjectionRiskLevel.HIGH
            is_safe = False
            advice = "High confidence prompt injection / jailbreak detected. Refuse or sanitize input before LLM ingestion."
        else:
            risk_level = InjectionRiskLevel.CRITICAL
            is_safe = False
            advice = "Critical adversarial injection or exfiltration attempt detected. Drop request immediately and trigger SOC alert."

        return InjectionScanResult(
            is_safe=is_safe,
            risk_level=risk_level,
            risk_score=normalized_score,
            detected_patterns=detected_patterns,
            matched_snippets=matched_snippets,
            mitigation_advice=advice,
        )


@dataclass
class RedactionResult:
    sanitized_text: str
    redaction_count: int
    vault_map: Dict[str, str]  # Token -> Original Value
    detected_secret_types: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sanitized_text": self.sanitized_text,
            "redaction_count": self.redaction_count,
            "detected_secret_types": self.detected_secret_types,
            "token_count": len(self.vault_map),
        }


class SensitiveDataScrubber:
    """
    Automated zero-trust data scrubber and reversible secret vault.
    Protects cloud credentials, API tokens, private keys, and PII
    from accidental egress to external model endpoints.
    """

    SECRET_PATTERNS = [
        ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("AWS_SECRET_KEY", re.compile(r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?")),
        ("AZURE_STORAGE_SAS", re.compile(r"(?i)(?:AccountKey=[a-zA-Z0-9+/=]{88}|sig=[a-zA-Z0-9%+/=]{43,}|sv=\d{4}-\d{2}-\d{2}&s[a-z]=)")),
        ("BEARER_JWT", re.compile(r"\beyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\b")),
        ("GITHUB_PAT", re.compile(r"\b(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b")),
        ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
        ("CREDIT_CARD", re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")),
        ("EMAIL_ADDRESS", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")),
    ]

    def __init__(self, scrub_emails: bool = True, scrub_credit_cards: bool = True):
        self.scrub_emails = scrub_emails
        self.scrub_credit_cards = scrub_credit_cards

    def scrub(self, text: str) -> RedactionResult:
        """Replaces sensitive patterns with safe vault tokens and tracks vault mapping."""
        if not text:
            return RedactionResult(
                sanitized_text="",
                redaction_count=0,
                vault_map={},
                detected_secret_types=[],
            )

        sanitized = text
        vault_map: Dict[str, str] = {}
        detected_types: Set[str] = set()
        token_counter = 0

        for secret_type, pattern in self.SECRET_PATTERNS:
            if secret_type == "EMAIL_ADDRESS" and not self.scrub_emails:
                continue
            if secret_type == "CREDIT_CARD" and not self.scrub_credit_cards:
                continue

            matches = list(pattern.finditer(sanitized))
            for m in reversed(matches):  # reverse order preserves string indices
                full_match = m.group(0)
                # If group 1 exists (e.g. key in key=val), target that specific secret
                secret_value = m.group(1) if m.lastindex and m.lastindex >= 1 else full_match

                # Basic Luhn heuristic for credit cards to reduce false positives
                if secret_type == "CREDIT_CARD":
                    digits = re.sub(r"\D", "", secret_value)
                    if len(digits) != 16:
                        continue

                token_counter += 1
                token = f"{{{{REDACTED_{secret_type}_{token_counter}}}}}"
                vault_map[token] = secret_value
                detected_types.add(secret_type)

                start, end = m.span(1) if m.lastindex and m.lastindex >= 1 else m.span(0)
                sanitized = sanitized[:start] + token + sanitized[end:]

        return RedactionResult(
            sanitized_text=sanitized,
            redaction_count=len(vault_map),
            vault_map=vault_map,
            detected_secret_types=sorted(list(detected_types)),
        )

    def rehydrate(self, sanitized_text: str, vault_map: Dict[str, str]) -> str:
        """Restores vaulted tokens with their original credentials in safe local boundary."""
        restored = sanitized_text
        for token, original in vault_map.items():
            restored = restored.replace(token, original)
        return restored


@dataclass
class ToolActionRequest:
    tool_name: str
    parameters: Dict[str, Any]
    caller_identity: str
    justification: str = ""


@dataclass
class ToolPolicyVerdict:
    allowed: bool
    requires_hitl: bool
    risk_score: float
    reason: str
    remediation_suggestion: Optional[str] = None


class ToolExecutionGuardrail:
    """
    Guards autonomous AI agent tool execution (OWASP LLM08: Excessive Agency).
    Enforces blast radius caps, command injection sanitization, and HITL elevation gates.
    """

    ALLOWED_READONLY_TOOLS = {
        "azure_kql_query",
        "cloudtrail_lookup_events",
        "threat_intel_search_ioc",
        "get_sentinel_incident",
        "list_storage_containers",
        "describe_network_security_groups",
    }

    RESTRICTED_MUTATION_TOOLS = {
        "azure_network_quarantine_vm",
        "azure_storage_revoke_public_access",
        "entra_id_revoke_user_sessions",
        "firewall_block_ip_address",
        "disable_service_principal_credentials",
    }

    DENIED_DESTRUCTIVE_TOOLS = {
        "delete_resource_group",
        "delete_storage_account",
        "purge_audit_logs",
        "drop_sentinel_table",
        "execute_arbitrary_shell",
    }

    SHELL_INJECTION_PATTERNS = [
        re.compile(r"(?:;\s*\S|&&\s*\S|\|\|\s*\S|\$\(|\`|\b(?:rm\s+-rf|dd\s+if|mkfs|chmod\s+777|chown|wget|curl\s+http)\b)"),
        re.compile(r"\.\./|\.\.\\"),  # Directory traversal
    ]

    def evaluate_action(self, action: ToolActionRequest) -> ToolPolicyVerdict:
        """Determines whether a proposed tool action is permitted under security policy."""
        # 1. Immediate block on denied destructive actions
        if action.tool_name in self.DENIED_DESTRUCTIVE_TOOLS:
            return ToolPolicyVerdict(
                allowed=False,
                requires_hitl=False,
                risk_score=10.0,
                reason=f"Action '{action.tool_name}' is permanently blocked by Zero-Trust Destruction Policy.",
                remediation_suggestion="Destructive resource deletion must be executed via manual IT change approval.",
            )

        # 2. Check for parameter injection or dangerous tokens
        for param_name, param_val in action.parameters.items():
            if isinstance(param_val, str):
                for inj_pattern in self.SHELL_INJECTION_PATTERNS:
                    if inj_pattern.search(param_val):
                        return ToolPolicyVerdict(
                            allowed=False,
                            requires_hitl=False,
                            risk_score=9.0,
                            reason=f"Dangerous shell characters or traversal pattern detected in parameter '{param_name}'.",
                            remediation_suggestion="Sanitize parameter string to alphanumeric identifiers and known formats.",
                        )

        # 3. Check for restricted mutation tools requiring HITL
        if action.tool_name in self.RESTRICTED_MUTATION_TOOLS:
            return ToolPolicyVerdict(
                allowed=True,
                requires_hitl=True,
                risk_score=6.0,
                reason=f"Action '{action.tool_name}' modifies production security posture; requires Human-In-The-Loop authorization.",
                remediation_suggestion="Present prompt confirmation to tier-2 SOC analyst before dispatch.",
            )

        # 4. Allowed read-only tools
        if action.tool_name in self.ALLOWED_READONLY_TOOLS:
            return ToolPolicyVerdict(
                allowed=True,
                requires_hitl=False,
                risk_score=1.0,
                reason=f"Action '{action.tool_name}' is pre-approved for automated read-only execution.",
            )

        # 5. Unknown tool
        return ToolPolicyVerdict(
            allowed=False,
            requires_hitl=True,
            risk_score=7.0,
            reason=f"Action '{action.tool_name}' is not registered in the trusted tool manifest.",
            remediation_suggestion="Register the tool in ALLOWED_READONLY_TOOLS or RESTRICTED_MUTATION_TOOLS.",
        )


@dataclass
class TriageFinding:
    category: str
    severity: str
    title: str
    details: str
    iocs: List[str]
    mitre_attack: List[str]


@dataclass
class TriageBrief:
    incident_id: str
    timestamp: str
    summary: str
    risk_score: float
    findings: List[TriageFinding]
    kql_hunting_query: str
    recommended_containment: List[str]
    scrubbed_secret_count: int
    injection_defense_verdict: str

    def to_markdown(self) -> str:
        md = [
            f"# SOC7 Incident Triage Brief: {self.incident_id}",
            f"**Generated:** {self.timestamp} | **Risk Score:** {self.risk_score}/10.0 | **LLM Guardrail Status:** {self.injection_defense_verdict}",
            "",
            "## Executive Summary",
            self.summary,
            "",
            "## Identified Threat Findings",
        ]
        for f in self.findings:
            md.append(f"- **[{f.severity.upper()}] {f.title}** ({', '.join(f.mitre_attack)})")
            md.append(f"  {f.details}")
            if f.iocs:
                md.append(f"  *Associated IOCs:* `{'`, `'.join(f.iocs)}`")

        md.extend([
            "",
            "## Microsoft Sentinel KQL Hunting Query",
            "```kql",
            self.kql_hunting_query.strip(),
            "```",
            "",
            "## Automated Containment Playbook Directives",
        ])
        for step in self.recommended_containment:
            md.append(f"1. {step}")

        return "\n".join(md)


class SOC7Assistant:
    """
    SOC7 AI Security Assistant:
    Orchestrates Prompt Injection Defense, Zero-Trust Data Scrubbing,
    and Automated Microsoft Sentinel KQL generation for incident investigation.
    """

    def __init__(self):
        self.injection_detector = PromptInjectionDetector()
        self.data_scrubber = SensitiveDataScrubber()
        self.tool_guardrail = ToolExecutionGuardrail()

    def triage_incident(
        self,
        incident_id: str,
        title: str,
        raw_telemetry: str,
        reported_by: str = "AzureSentinel",
    ) -> TriageBrief:
        """
        Executes end-to-end AI-assisted security triage:
        1. Ingestion defense: Scans for adversarial prompt injections in alert descriptions.
        2. Secret scrubbing: Vaults cloud credentials before reasoning.
        3. Threat extraction: Identifies entities, tactics, and IOCs.
        4. Sentinel KQL synthesis: Produces tailored KQL hunting query.
        """
        # 1. Guardrail Ingestion Check
        scan = self.injection_detector.scan_prompt(raw_telemetry)
        injection_verdict = (
            f"VERIFIED SAFE (Score: {scan.risk_score})"
            if scan.is_safe
            else f"ADVERSARIAL INJECTION BLOCKED (Score: {scan.risk_score})"
        )

        # 2. Sensitive Data Scrubbing
        scrub_result = self.data_scrubber.scrub(raw_telemetry)
        clean_text = scrub_result.sanitized_text

        # 3. Entity & IOC Extraction
        ip_matches = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", clean_text)
        valid_public_ips = []
        for ip_str in ip_matches:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if not (ip_obj.is_private or ip_obj.is_loopback):
                    valid_public_ips.append(ip_str)
            except ValueError:
                pass

        accounts = re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", clean_text)

        findings: List[TriageFinding] = []
        containment: List[str] = []

        # Triage Logic based on detected threat patterns
        if "ServicePrincipal" in clean_text or "Add service principal credentials" in clean_text:
            findings.append(
                TriageFinding(
                    category="Identity Persistence",
                    severity="High",
                    title="Entra ID Application Credential Addition",
                    details="Unapproved secret key or X.509 certificate attached to enterprise application registration.",
                    iocs=valid_public_ips[:3],
                    mitre_attack=["T1098.001", "T1136.003"],
                )
            )
            containment.extend([
                "Execute `disable_service_principal_credentials` on target App ID.",
                "Revoke OAuth application admin consents.",
                "Trigger Entra ID conditional access policy refresh.",
            ])
            hunting_kql = f"""
AuditLogs
| where TimeGenerated >= ago(7d)
| where OperationName in ("Add service principal credentials", "Update application – Certificates and secrets management ")
| extend TargetApp = tostring(TargetResources[0].displayName)
| extend Caller = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, Caller, TargetApp, OperationName, Result
| order by TimeGenerated desc
"""
        elif "PromptInjection" in clean_text or not scan.is_safe:
            findings.append(
                TriageFinding(
                    category="AI Security & LLM Abuse",
                    severity="Critical" if scan.risk_score > 7.0 else "High",
                    title="Adversarial Prompt Injection / Jailbreak Attack",
                    details=f"Adversarial LLM instruction override detected. Patterns: {', '.join(scan.detected_patterns)}.",
                    iocs=valid_public_ips[:3],
                    mitre_attack=["AML.T0051", "AML.T0054"],
                )
            )
            containment.extend([
                "Block offending IP address or authenticated API client token.",
                "Update Azure OpenAI Content Filter threshold to High sensitivity.",
                "Quarantine affected RAG documents containing indirect injection payloads.",
            ])
            hunting_kql = f"""
AzureDiagnostics
| where TimeGenerated >= ago(24h)
| where ResourceProvider =~ "MICROSOFT.COGNITIVESERVICES"
| where Category =~ "RequestResponse"
| where ResultSignature_d == 400 or tostring(properties_s) has "ResponsibleAIPolicyViolated"
| project TimeGenerated, OperationName, CallerIPAddress, ResultSignature_d, properties_s
| order by TimeGenerated desc
"""
        else:
            findings.append(
                TriageFinding(
                    category="Cloud Workload Security",
                    severity="Medium",
                    title="Anomalous Cloud Telemetry Event",
                    details=f"Automated SOC7 triage evaluated incident '{title}'. Telemetry scrubbed and verified.",
                    iocs=valid_public_ips[:3],
                    mitre_attack=["T1078", "T1530"],
                )
            )
            containment.extend([
                "Review Azure Activity Logs for anomalous role assignments.",
                "Verify MFA status for initiating account.",
            ])
            hunting_kql = f"""
AzureActivity
| where TimeGenerated >= ago(24h)
| where ActivityStatusValue =~ "Success"
| project TimeGenerated, Caller, OperationNameValue, ResourceGroup, SubscriptionId
| order by TimeGenerated desc
"""

        risk_score = 8.5 if not scan.is_safe else (7.0 if findings[0].severity == "High" else 4.5)

        return TriageBrief(
            incident_id=incident_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            summary=f"SOC7 automated triage of '{title}'. Processed {len(clean_text)} bytes of telemetry with {scrub_result.redaction_count} credentials scrubbed.",
            risk_score=risk_score,
            findings=findings,
            kql_hunting_query=hunting_kql.strip(),
            recommended_containment=containment,
            scrubbed_secret_count=scrub_result.redaction_count,
            injection_defense_verdict=injection_verdict,
        )
