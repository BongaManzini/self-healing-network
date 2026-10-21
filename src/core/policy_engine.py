"""
Policy Engine for autonomous threat evaluation, policy lookup, and self-healing execution.
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
from src.config.policies import get_policy, RemediationPolicy, AnomalyType, Severity, REMEDIATION_POLICIES
from src.actions.action_dispatcher import ActionDispatcher
from src.utils.logger import get_logger

logger = get_logger(__name__)

class PolicyEngine:
    """
    Central self-healing engine that evaluates anomalies,
    executes remediation action chains, and tracks network health.
    """
    
    def __init__(self, auto_remediate: bool = True):
        self.action_dispatcher = ActionDispatcher()
        self.auto_remediate = auto_remediate
        self.execution_history: List[Dict[str, Any]] = []
        self.active_incidents: List[Dict[str, Any]] = []
        self.pending_remediations: List[Dict[str, Any]] = []
        self.total_detected: int = 0
        self.total_healed: int = 0
        self.created_at = datetime.now()

    def get_health_score(self) -> Dict[str, Any]:
        """
        Calculates dynamic network health score (0-100%).
        Decreases when active, uncontained threats exist;
        recovers to 100% when threats are contained and network is healthy.
        """
        base = 100
        uncontained_count = sum(1 for inc in self.active_incidents if not inc.get("healed", False))
        
        # Deduct based on active uncontained threats
        penalty = min(uncontained_count * 25, 90)
        current_score = max(base - penalty, 10)
        
        status = "healthy"
        if current_score <= 40:
            status = "critical"
        elif current_score <= 75:
            status = "threat_contained" if self.total_healed > 0 else "under_attack"
            
        return {
            "score": current_score,
            "status": status,
            "total_detected": self.total_detected,
            "total_healed": self.total_healed,
            "active_uncontained": uncontained_count,
            "auto_remediate": self.auto_remediate
        }

    def _normalize_anomaly_type(self, raw_type: Any) -> AnomalyType:
        """Parse raw anomaly type string into AnomalyType enum safely"""
        if isinstance(raw_type, AnomalyType):
            return raw_type
        
        cleaned = str(raw_type or "").strip().lower().replace(" ", "_").replace("-", "_")
        for enum_val in AnomalyType:
            if enum_val.value == cleaned:
                return enum_val
                
        # Heuristic matching
        if "mitm" in cleaned or "arp" in cleaned:
            return AnomalyType.MITM_ATTACK
        if "dns" in cleaned:
            return AnomalyType.DNS_ATTACK
        if "scan" in cleaned or "probe" in cleaned:
            return AnomalyType.PORT_SCAN
        if "malware" in cleaned or "c2" in cleaned or "trojan" in cleaned or "ransom" in cleaned:
            return AnomalyType.MALWARE
        if "exfil" in cleaned or "leak" in cleaned:
            return AnomalyType.DATA_EXFILTRATION
        if "ddos" in cleaned or "flood" in cleaned or "syn" in cleaned:
            return AnomalyType.DDOS_FLOOD
        if "brute" in cleaned:
            return AnomalyType.BRUTE_FORCE
            
        return AnomalyType.PORT_SCAN

    def _normalize_severity(self, raw_severity: Any) -> Severity:
        """Parse raw severity string into Severity enum safely"""
        if isinstance(raw_severity, Severity):
            return raw_severity
        cleaned = str(raw_severity or "medium").strip().lower()
        for enum_val in Severity:
            if enum_val.value == cleaned:
                return enum_val
        return Severity.MEDIUM

    def evaluate_anomaly(self, anomaly_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate an anomaly signal and trigger self-healing remediation.
        """
        self.total_detected += 1
        raw_type = anomaly_data.get('anomaly_type') or anomaly_data.get('type', 'port_scan')
        raw_severity = anomaly_data.get('severity', 'medium')
        
        anomaly_type = self._normalize_anomaly_type(raw_type)
        severity = self._normalize_severity(raw_severity)
        
        # Extract and normalize targets dictionary
        targets = anomaly_data.get('targets', {})
        if not targets:
            targets = {}
        
        source_ip = anomaly_data.get('source_ip') or targets.get('malicious_ip') or targets.get('source_ip') or "unknown"
        target_ip = anomaly_data.get('target_ip') or targets.get('affected_device') or targets.get('target_ip') or "unknown"
        
        targets['malicious_ip'] = targets.get('malicious_ip', source_ip)
        targets['source_ip'] = targets.get('source_ip', source_ip)
        targets['affected_device'] = targets.get('affected_device', target_ip)
        targets['target_ip'] = targets.get('target_ip', target_ip)
        if 'pid' in anomaly_data and 'pid' not in targets:
            targets['pid'] = anomaly_data['pid']

        # Lookup policy
        policy = get_policy(anomaly_type, severity)
        
        if not policy:
            logger.warning(f"No specific policy found for {anomaly_type} / {severity}")
            return {
                "success": False,
                "error": f"No policy configured for anomaly type {anomaly_type}",
                "anomaly_type": anomaly_type.value,
                "severity": severity.value
            }

        incident_id = f"INC-{int(datetime.now().timestamp() * 1000)}"
        incident = {
            "id": incident_id,
            "timestamp": datetime.now().isoformat(),
            "anomaly_type": anomaly_type.value,
            "severity": severity.value,
            "source_ip": source_ip,
            "target_ip": target_ip,
            "description": anomaly_data.get("description", policy.description),
            "healed": False,
            "actions_executed": []
        }
        self.active_incidents.insert(0, incident)

        # Check if auto-remediation is enabled
        if not self.auto_remediate:
            pending_record = {
                "incident_id": incident_id,
                "policy": policy.description,
                "targets": targets,
                "policy_actions": [a.action_type for a in policy.actions]
            }
            self.pending_remediations.append(pending_record)
            return {
                "success": True,
                "auto_remediated": False,
                "status": "pending_manual_approval",
                "incident_id": incident_id,
                "policy": policy.description,
                "proposed_actions": [a.action_type for a in policy.actions]
            }

        # Execute policy self-healing chain
        results = self.execute_policy(policy, targets)
        
        if results.get("success", False):
            self.total_healed += 1
            incident["healed"] = True
            incident["actions_executed"] = results.get("actions", [])

        # Log audit trail
        self.log_execution(anomaly_data, policy, results)
        
        results["incident_id"] = incident_id
        results["healed"] = incident["healed"]
        results["health"] = self.get_health_score()
        return results

    def execute_policy(self, policy: RemediationPolicy, targets: Dict[str, Any]) -> Dict[str, Any]:
        """Execute all actions in a remediation policy sequentially"""
        results = {
            "policy_executed": policy.description,
            "anomaly_type": policy.anomaly_type.value,
            "severity": policy.severity.value,
            "actions": [],
            "success": True
        }
        
        for action in policy.actions:
            try:
                action_result = self.action_dispatcher.dispatch(action, targets)
                success = action_result.get("success", True)
                results["actions"].append({
                    "action": action.action_type,
                    "target": action.target,
                    "success": success,
                    "message": action_result.get("message", ""),
                    "mode": action_result.get("mode", "active")
                })
                
                if not success:
                    results["success"] = False
                    
            except Exception as e:
                logger.error(f"Failed to execute action {action.action_type}: {str(e)}")
                results["actions"].append({
                    "action": action.action_type,
                    "target": action.target, 
                    "success": False,
                    "message": str(e)
                })
                results["success"] = False
        
        return results

    def log_execution(self, anomaly_data: Dict, policy: RemediationPolicy, results: Dict):
        """Log policy execution for audit trail"""
        execution_record = {
            "timestamp": datetime.now().isoformat(),
            "anomaly": anomaly_data,
            "policy": policy.description,
            "results": results
        }
        self.execution_history.insert(0, execution_record)
        logger.info(f"Self-Healing Chain Complete: {policy.description} - Remediated: {results['success']}")

    def get_audit_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent audit logs"""
        return self.execution_history[:limit]

    def get_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent security incidents"""
        return self.active_incidents[:limit]