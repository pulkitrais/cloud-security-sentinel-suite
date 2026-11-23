"""
Microsoft Sentinel Threat Intelligence (TI) Indicator Parser and Enrichment Engine.
Ingests, normalizes, refangs, validates, and exports IOCs for Sentinel Watchlists and TI Tables.
"""

from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import re
import csv
import io
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta


class IOCType(Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class TLPLevel(Enum):
    CLEAR = "TLP:CLEAR"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    AMBER_STRICT = "TLP:AMBER+STRICT"
    RED = "TLP:RED"


@dataclass
class ThreatIndicator:
    value: str
    ioc_type: IOCType
    threat_type: str
    confidence_score: int
    tlp: TLPLevel = TLPLevel.AMBER
    description: str = ""
    tags: List[str] = field(default_factory=list)
    valid_until: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "ioc_type": self.ioc_type.value,
            "threat_type": self.threat_type,
            "confidence_score": self.confidence_score,
            "tlp": self.tlp.value,
            "description": self.description,
            "tags": self.tags,
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
        }


class ThreatIntelParser:
    """Core IOC parsing, defanging/refanging, enrichment, and formatting engine."""

    # Precompiled regex patterns for standard indicators
    IPV4_PATTERN = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )
    SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
    SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
    MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
    URL_PATTERN = re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*", re.IGNORECASE)
    DOMAIN_PATTERN = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,63})\b"
    )

    @staticmethod
    def refang(indicator: str) -> str:
        """Restores defanged IOC formats (e.g. hxxp, [.], [:], [at]) to canonical forms."""
        cleaned = indicator.strip()
        cleaned = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", cleaned)
        cleaned = re.sub(r"\[:\]|\(:\)|\{:\}", ":", cleaned)
        cleaned = re.sub(r"\[at\]|\(at\)", "@", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\bhxxps://", "https://", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\bhxxp://", "http://", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\bh__ps://", "https://", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\bh__p://", "http://", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\bhxxps\b", "https", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\bhxxp\b", "http", cleaned, flags=re.IGNORECASE)
        return cleaned

    @staticmethod
    def defang(indicator: str) -> str:
        """Defangs canonical IOCs to prevent accidental routing or hyperlinking in tickets."""
        cleaned = indicator.strip()
        cleaned = cleaned.replace("http://", "hxxp://").replace("https://", "hxxps://")
        cleaned = cleaned.replace(".", "[.]")
        return cleaned

    @staticmethod
    def is_private_or_bogon_ip(ip_str: str) -> bool:
        """Determines whether an IPv4 or IPv6 address is private, loopback, or non-routable bogon."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_link_local
                or ip_obj.is_unspecified
            )
        except ValueError:
            return True

    def extract_iocs_from_text(
        self,
        raw_text: str,
        default_threat_type: str = "Malicious Infrastructure",
        default_confidence: int = 80,
        filter_bogons: bool = True,
        ttl_days: int = 30,
        tlp: TLPLevel = TLPLevel.AMBER,
    ) -> List[ThreatIndicator]:
        """Extracts and normalizes all structured IOCs found within unstructured text."""
        refanged_text = self.refang(raw_text)
        indicators: List[ThreatIndicator] = []
        seen_values = set()
        expiry = datetime.now(timezone.utc) + timedelta(days=ttl_days)

        # 1. URLs
        for match in self.URL_PATTERN.finditer(refanged_text):
            val = match.group(0).rstrip(".,;)>'\"")
            if val not in seen_values:
                seen_values.add(val)
                indicators.append(
                    ThreatIndicator(
                        value=val,
                        ioc_type=IOCType.URL,
                        threat_type=default_threat_type,
                        confidence_score=default_confidence,
                        tlp=tlp,
                        description=f"Extracted URL indicator: {val}",
                        tags=["extracted_url", "threat_intel"],
                        valid_until=expiry,
                    )
                )

        # 2. SHA256
        for match in self.SHA256_PATTERN.finditer(refanged_text):
            val = match.group(0).lower()
            if val not in seen_values:
                seen_values.add(val)
                indicators.append(
                    ThreatIndicator(
                        value=val,
                        ioc_type=IOCType.SHA256,
                        threat_type=default_threat_type,
                        confidence_score=default_confidence,
                        tlp=tlp,
                        description=f"Extracted SHA256 file hash: {val}",
                        tags=["extracted_hash", "sha256"],
                        valid_until=expiry,
                    )
                )

        # 3. MD5 (ensure not substring of sha256)
        for match in self.MD5_PATTERN.finditer(refanged_text):
            val = match.group(0).lower()
            if val not in seen_values and not any(val in s for s in seen_values):
                seen_values.add(val)
                indicators.append(
                    ThreatIndicator(
                        value=val,
                        ioc_type=IOCType.MD5,
                        threat_type=default_threat_type,
                        confidence_score=default_confidence,
                        tlp=tlp,
                        description=f"Extracted MD5 file hash: {val}",
                        tags=["extracted_hash", "md5"],
                        valid_until=expiry,
                    )
                )

        # 4. IPv4
        for match in self.IPV4_PATTERN.finditer(refanged_text):
            val = match.group(0)
            if filter_bogons and self.is_private_or_bogon_ip(val):
                continue
            if val not in seen_values:
                seen_values.add(val)
                indicators.append(
                    ThreatIndicator(
                        value=val,
                        ioc_type=IOCType.IPV4,
                        threat_type=default_threat_type,
                        confidence_score=default_confidence,
                        tlp=tlp,
                        description=f"Extracted IPv4 address: {val}",
                        tags=["extracted_ip", "network_indicator"],
                        valid_until=expiry,
                    )
                )

        # 5. Domains (filter out already captured URLs and numeric IP overlaps)
        for match in self.DOMAIN_PATTERN.finditer(refanged_text):
            val = match.group(0).lower()
            # Exclude false-positive IP-like strings and common top-level domain-only false positives
            if not self.IPV4_PATTERN.match(val) and val not in seen_values:
                if not any(val in u for u in seen_values):
                    seen_values.add(val)
                    indicators.append(
                        ThreatIndicator(
                            value=val,
                            ioc_type=IOCType.DOMAIN,
                            threat_type=default_threat_type,
                            confidence_score=default_confidence,
                            tlp=tlp,
                            description=f"Extracted domain indicator: {val}",
                            tags=["extracted_domain", "dns_indicator"],
                            valid_until=expiry,
                        )
                    )

        return indicators

    @staticmethod
    def export_sentinel_watchlist_csv(indicators: List[ThreatIndicator]) -> str:
        """Exports indicators into a CSV string formatted for Microsoft Sentinel Watchlists."""
        output = io.StringIO()
        fieldnames = [
            "SearchKey",
            "IOCType",
            "ThreatType",
            "ConfidenceScore",
            "TLP",
            "Description",
            "Tags",
            "ValidUntil",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for ind in indicators:
            writer.writerow(
                {
                    "SearchKey": ind.value,
                    "IOCType": ind.ioc_type.value,
                    "ThreatType": ind.threat_type,
                    "ConfidenceScore": ind.confidence_score,
                    "TLP": ind.tlp.value,
                    "Description": ind.description,
                    "Tags": ";".join(ind.tags),
                    "ValidUntil": ind.valid_until.isoformat() if ind.valid_until else "",
                }
            )

        return output.getvalue()

    @staticmethod
    def export_sentinel_ti_api_payload(
        indicators: List[ThreatIndicator], source_name: str = "CloudSentinelParser"
    ) -> Dict[str, Any]:
        """Formats indicators into Microsoft Sentinel ThreatIntelligenceIndicator API format."""
        formatted_indicators = []
        for ind in indicators:
            formatted_indicators.append(
                {
                    "type": "Microsoft.SecurityInsights/threatIntelligence/indicators",
                    "properties": {
                        "source": source_name,
                        "pattern": f"[{ind.ioc_type.value}:value = '{ind.value}']",
                        "patternType": ind.ioc_type.value,
                        "threatTypes": [ind.threat_type],
                        "confidence": ind.confidence_score,
                        "description": ind.description,
                        "tlpLevel": ind.tlp.value.replace("TLP:", "").lower(),
                        "validUntil": ind.valid_until.isoformat() if ind.valid_until else None,
                        "labels": ind.tags,
                    },
                }
            )
        return {"indicators": formatted_indicators, "totalCount": len(formatted_indicators)}

    @staticmethod
    def compute_risk_priority(indicator: ThreatIndicator) -> str:
        """Determines triage priority based on confidence score and IOC type criticality."""
        score = indicator.confidence_score
        if score >= 85 and indicator.ioc_type in (IOCType.IPV4, IOCType.SHA256):
            return "P1-CRITICAL"
        elif score >= 70:
            return "P2-HIGH"
        elif score >= 50:
            return "P3-MEDIUM"
        return "P4-LOW"
