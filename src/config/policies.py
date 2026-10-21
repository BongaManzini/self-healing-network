"""
Security policies and automated remediation definitions for Self-Healing Network.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"

class AnomalyType(str, Enum):
    MITM_ATTACK = "mitm_attack"
    DNS_ATTACK = "dns_attack"
    PORT_SCAN = "port_scan"
    MALWARE = "malware"
    DATA_EXFILTRATION = "data_exfiltration"
    DDOS_FLOOD = "ddos_flood"
    BRUTE_FORCE = "brute_force"
    UNAUTHORIZED_ACCESS = "unauthorized_access"

@dataclass
class RemediationAction:
    action_type: str
    target: str
    parameters: Dict = field(default_factory=dict)

@dataclass
class RemediationPolicy:
    anomaly_type: AnomalyType
    severity: Severity
    actions: List[RemediationAction]
    description: str = ""

# Comprehensive remediation policy registry
REMEDIATION_POLICIES: Dict[AnomalyType, Dict[Severity, RemediationPolicy]] = {
    AnomalyType.MITM_ATTACK: {
        Severity.CRITICAL: RemediationPolicy(
            anomaly_type=AnomalyType.MITM_ATTACK,
            severity=Severity.CRITICAL,
            description="Active ARP Poisoning / MITM Attack - Urgent network healing and isolation",
            actions=[
                RemediationAction("block_ip", "malicious_ip"),
                RemediationAction("heal_arp", "gateway_ip"),
                RemediationAction("isolate_device", "affected_device"),
                RemediationAction("alert_admin", "security_team")
            ]
        ),
        Severity.HIGH: RemediationPolicy(
            anomaly_type=AnomalyType.MITM_ATTACK,
            severity=Severity.HIGH,
            description="MITM Attack Detected - Isolate device, purge ARP cache, block attacker",
            actions=[
                RemediationAction("block_ip", "malicious_ip"),
                RemediationAction("heal_arp", "gateway_ip"),
                RemediationAction("alert_admin", "security_team")
            ]
        ),
        Severity.MEDIUM: RemediationPolicy(
            anomaly_type=AnomalyType.MITM_ATTACK,
            severity=Severity.MEDIUM,
            description="Suspicious ARP anomaly detected - Purging ARP tables",
            actions=[
                RemediationAction("heal_arp", "gateway_ip"),
                RemediationAction("alert_admin", "security_team")
            ]
        )
    },
    
    AnomalyType.DNS_ATTACK: {
        Severity.HIGH: RemediationPolicy(
            anomaly_type=AnomalyType.DNS_ATTACK,
            severity=Severity.HIGH,
            description="Critical DNS Hijack/Poisoning - Flushing cache and enforcing verified resolver",
            actions=[
                RemediationAction("redirect_dns", "affected_device", {"safe_dns": "1.1.1.1"}),
                RemediationAction("block_ip", "malicious_ip"),
                RemediationAction("alert_admin", "security_team")
            ]
        ),
        Severity.MEDIUM: RemediationPolicy(
            anomaly_type=AnomalyType.DNS_ATTACK, 
            severity=Severity.MEDIUM,
            description="DNS Cache Poisoning Attempt - Purging DNS cache and restoring secure DNS",
            actions=[
                RemediationAction("redirect_dns", "affected_device", {"safe_dns": "1.1.1.1"}),
                RemediationAction("alert_admin", "security_team")
            ]
        )
    },
    
    AnomalyType.PORT_SCAN: {
        Severity.HIGH: RemediationPolicy(
            anomaly_type=AnomalyType.PORT_SCAN,
            severity=Severity.HIGH,
            description="Aggressive Port Scan - Instantly drop attacker IP and update firewall",
            actions=[
                RemediationAction("block_ip", "malicious_ip"),
                RemediationAction("update_firewall", "block_traffic"),
                RemediationAction("alert_admin", "security_team")
            ]
        ),
        Severity.MEDIUM: RemediationPolicy(
            anomaly_type=AnomalyType.PORT_SCAN,
            severity=Severity.MEDIUM,
            description="Reconnaissance Port Scanning - Block source IP address",
            actions=[
                RemediationAction("block_ip", "malicious_ip"),
                RemediationAction("alert_admin", "security_team")
            ]
        ),
        Severity.LOW: RemediationPolicy(
            anomaly_type=AnomalyType.PORT_SCAN,
            severity=Severity.LOW,
            description="Slow Port Probing - Block source IP",
            actions=[
                RemediationAction("block_ip", "malicious_ip")
            ]
        )
    },
    
    AnomalyType.MALWARE: {
        Severity.CRITICAL: RemediationPolicy(
            anomaly_type=AnomalyType.MALWARE,
            severity=Severity.CRITICAL,
            description="Malware C2 Communication - Kill rogue process, block C2, quarantine host",
            actions=[
                RemediationAction("kill_process", "pid"),
                RemediationAction("block_ip", "malicious_ip"),
                RemediationAction("isolate_device", "affected_device"),
                RemediationAction("alert_admin", "security_team")
            ]
        ),
        Severity.HIGH: RemediationPolicy(
            anomaly_type=AnomalyType.MALWARE,
            severity=Severity.HIGH,
            description="Malware Beaconing Detected - Block C2 server and quarantine host",
            actions=[
                RemediationAction("block_ip", "malicious_ip"),
                RemediationAction("isolate_device", "affected_device"),
                RemediationAction("alert_admin", "security_team")
            ]
        )
    },

    AnomalyType.DATA_EXFILTRATION: {
        Severity.CRITICAL: RemediationPolicy(
            anomaly_type=AnomalyType.DATA_EXFILTRATION,
            severity=Severity.CRITICAL,
            description="Massive Outbound Exfiltration - Immediate host quarantine and drop destination",
            actions=[
                RemediationAction("block_ip", "malicious_ip"),
                RemediationAction("isolate_device", "affected_device"),
                RemediationAction("alert_admin", "security_team")
            ]
        ),
        Severity.HIGH: RemediationPolicy(
            anomaly_type=AnomalyType.DATA_EXFILTRATION,
            severity=Severity.HIGH,
            description="Suspicious Outbound Data Burst - Drop remote destination IP",
            actions=[
                RemediationAction("block_ip", "malicious_ip"),
                RemediationAction("alert_admin", "security_team")
            ]
        )
    },

    AnomalyType.DDOS_FLOOD: {
        Severity.CRITICAL: RemediationPolicy(
            anomaly_type=AnomalyType.DDOS_FLOOD,
            severity=Severity.CRITICAL,
            description="Volumetric SYN/Connection Flood - Blackholing flood sources",
            actions=[
                RemediationAction("block_ip", "malicious_ip"),
                RemediationAction("update_firewall", "block_traffic"),
                RemediationAction("alert_admin", "security_team")
            ]
        ),
        Severity.HIGH: RemediationPolicy(
            anomaly_type=AnomalyType.DDOS_FLOOD,
            severity=Severity.HIGH,
            description="High connection rate flood - Block attacker IP",
            actions=[
                RemediationAction("block_ip", "malicious_ip")
            ]
        )
    },

    AnomalyType.BRUTE_FORCE: {
        Severity.HIGH: RemediationPolicy(
            anomaly_type=AnomalyType.BRUTE_FORCE,
            severity=Severity.HIGH,
            description="Brute Force Credential Attack - Block attacking host",
            actions=[
                RemediationAction("block_ip", "malicious_ip"),
                RemediationAction("alert_admin", "security_team")
            ]
        )
    }
}

def get_policy(anomaly_type: AnomalyType, severity: Severity) -> Optional[RemediationPolicy]:
    """
    Get remediation policy for given anomaly type and severity.
    Falls back gracefully to highest available severity for the threat type if exact match not found.
    """
    type_policies = REMEDIATION_POLICIES.get(anomaly_type)
    if not type_policies:
        return None
    
    if severity in type_policies:
        return type_policies[severity]
    
    # Fallback to closest available policy
    for s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        if s in type_policies:
            return type_policies[s]
            
    return None