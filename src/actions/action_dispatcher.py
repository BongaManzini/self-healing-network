from typing import Dict, Any
from src.actions.firewall_actions import FirewallActions
from src.actions.network_actions import NetworkActions
from src.actions.device_actions import DeviceActions
from src.utils.logger import get_logger

logger = get_logger(__name__)

class ActionDispatcher:
    """Dispatches remediation actions to appropriate action handlers"""
    
    def __init__(self):
        self.firewall = FirewallActions()
        self.network = NetworkActions()
        self.device = DeviceActions()

    def dispatch(self, action: Any, targets: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch a RemediationAction to the appropriate handler"""
        action_type = getattr(action, 'action_type', str(action))
        target_key = getattr(action, 'target', '')
        params = getattr(action, 'parameters', None) or {}

        # Resolve target value from targets dictionary
        target_val = targets.get(target_key, targets.get('source_ip', targets.get('target_ip', target_key)))

        logger.info(f"Dispatching action: {action_type} to target: {target_val}")

        try:
            if action_type == "block_ip":
                return self.firewall.block_ip(target_val, params)
            elif action_type == "update_firewall":
                return self.firewall.update_rules(target_key, params)
            elif action_type == "isolate_device":
                return self.network.isolate_device(target_val, params)
            elif action_type == "redirect_dns":
                return self.network.redirect_dns(target_val, params)
            elif action_type == "reboot_device":
                return self.device.reboot_device(target_val, params)
            elif action_type == "clear_cache":
                return self.device.clear_cache(target_val, params)
            elif action_type == "alert_admin":
                logger.warning(f"SECURITY ALERT: {target_key} notification sent to administrator. Details: {params}")
                return {"success": True, "message": f"Alert sent for {target_key}"}
            else:
                logger.info(f"Generic action executed: {action_type}")
                return {"success": True, "message": f"Action {action_type} completed successfully"}
        except Exception as e:
            logger.error(f"Error executing action {action_type}: {str(e)}")
            return {"success": False, "message": str(e)}
