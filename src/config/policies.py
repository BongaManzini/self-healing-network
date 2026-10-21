from typing import Dict, List
from dataclasses import dataclass
from enum import Enum

class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"

class AnomalyType(Enum):
    MITM_ATTACK = "mitm_attack"
    DNS_ATTACK = "dns_attack"
    PORT_SCAN = "port_scan"
    MALWARE = "malware"
    DATA_EXFILTRATION = "data_exfiltration"

@dataclass
class RemediationAction:
    action_type: str
    target: str
    parameters: Dict = None

@dataclass
class RemediationPolicy:
    anomaly_type: AnomalyType
    severity: Severity
    actions: List[RemediationAction]
    description: str = ""

# Define remediation policies
REMEDIATION_POLICIES = {
    AnomalyType.MITM_ATTACK: {
        Severity.HIGH: RemediationPolicy(
            anomaly_type=AnomalyType.MITM_ATTACK,
            severity=Severity.HIGH,
            description="MITM Attack Detected - Immediate isolation required",
            actions=[
                RemediationAction("block_ip", "malicious_ip"),
                RemediationAction("isolate_device", "affected_device"),
                RemediationAction("update_firewall", "block_traffic"),
                RemediationAction("alert_admin", "security_team")
            ]
        )
    },
    AnomalyType.DNS_ATTACK: {
        Severity.MEDIUM: RemediationPolicy(
            anomaly_type=AnomalyType.DNS_ATTACK, 
            severity=Severity.MEDIUM,
            description="DNS Attack Detected - Redirect DNS queries",
            actions=[
                RemediationAction("redirect_dns", "affected_device"),
                RemediationAction("block_domain", "malicious_domain"),
                RemediationAction("alert_admin", "security_team")
            ]
        )
    }
}

def get_policy(anomaly_type: AnomalyType, severity: Severity) -> RemediationPolicy:
    """Get remediation policy for given anomaly type and severity"""
    return REMEDIATION_POLICIES.get(anomaly_type, {}).get(severity)