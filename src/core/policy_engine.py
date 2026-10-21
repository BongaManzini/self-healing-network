from typing import Dict, List
from src.config.policies import get_policy, RemediationPolicy, AnomalyType, Severity
from src.actions.action_dispatcher import ActionDispatcher
from src.utils.logger import get_logger

logger = get_logger(__name__)

class PolicyEngine:
    """Policy engine for managing and executing remediation policies"""
    
    def __init__(self):
        self.action_dispatcher = ActionDispatcher()
        self.execution_history = []
    
    def evaluate_anomaly(self, anomaly_data: Dict) -> Dict:
        """Evaluate anomaly and determine appropriate remediation"""
        
        # Parse anomaly data (placeholder - will integrate with AI later)
        anomaly_type = AnomalyType(anomaly_data.get('type', 'unknown'))
        severity = Severity(anomaly_data.get('severity', 'low'))
        targets = anomaly_data.get('targets', {})
        
        # Get appropriate policy
        policy = get_policy(anomaly_type, severity)
        
        if not policy:
            logger.warning(f"No policy found for {anomaly_type} with severity {severity}")
            return {"success": False, "error": "No policy found"}
        
        # Execute actions
        results = self.execute_policy(policy, targets)
        
        # Log execution
        self.log_execution(anomaly_data, policy, results)
        
        return results
    
    def execute_policy(self, policy: RemediationPolicy, targets: Dict) -> Dict:
        """Execute all actions in a policy"""
        results = {
            "policy_executed": policy.description,
            "actions": [],
            "success": True
        }
        
        for action in policy.actions:
            try:
                # Dispatch action to appropriate handler
                action_result = self.action_dispatcher.dispatch(action, targets)
                results["actions"].append({
                    "action": action.action_type,
                    "target": action.target,
                    "success": action_result.get("success", False),
                    "message": action_result.get("message", "")
                })
                
                if not action_result.get("success", False):
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
        """Log policy execution for audit and feedback"""
        execution_record = {
            "timestamp": datetime.now().isoformat(),
            "anomaly": anomaly_data,
            "policy": policy.description,
            "results": results
        }
        self.execution_history.append(execution_record)
        logger.info(f"Policy executed: {policy.description} - Success: {results['success']}")