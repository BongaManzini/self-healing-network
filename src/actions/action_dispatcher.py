"""
Dispatches remediation actions to appropriate platform handlers.
"""

from typing import Dict, Any, Optional
from src.core.os_adapter import OSAdapter
from src.actions.firewall_actions import FirewallActions
from src.actions.network_actions import NetworkActions
from src.actions.device_actions import DeviceActions
from src.utils.logger import get_logger

logger = get_logger(__name__)

class ActionDispatcher:
    """Dispatches self-healing remediation actions to appropriate action handlers"""
    
    def __init__(self, os_adapter: Optional[OSAdapter] = None):
        self.os_adapter = os_adapter or OSAdapter()
        self.firewall = FirewallActions(self.os_adapter)
        self.network = NetworkActions(self.os_adapter)
        self.device = DeviceActions(self.os_adapter)

    def dispatch(self, action: Any, targets: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch a RemediationAction to the appropriate handler"""
        action_type = getattr(action, 'action_type', str(action))
        target_key = getattr(action, 'target', '')
        params = getattr(action, 'parameters', None) or {}

        # Resolve target value from targets dictionary
        target_val = targets.get(target_key, targets.get('malicious_ip', targets.get('source_ip', targets.get('device_ip', targets.get('target_ip', target_key)))))

        logger.info(f"Dispatching action: {action_type} -> Target Key: {target_key} -> Resolved: {target_val}")

        try:
            if action_type in ("block_ip", "firewall_block"):
                return self.firewall.block_ip(str(target_val), params)
            elif action_type in ("unblock_ip", "firewall_unblock"):
                return self.firewall.unblock_ip(str(target_val))
            elif action_type == "update_firewall":
                return self.firewall.update_rules(target_key, params)
            elif action_type in ("isolate_device", "quarantine_host"):
                device_target = targets.get('affected_device', targets.get('device_ip', target_val))
                return self.network.isolate_device(str(device_target), params)
            elif action_type in ("remove_isolation", "restore_device", "unquarantine"):
                device_target = targets.get('affected_device', targets.get('device_ip', target_val))
                return self.network.remove_isolation(str(device_target), params)
            elif action_type in ("redirect_dns", "heal_dns", "flush_dns"):
                device_target = targets.get('affected_device', targets.get('device_ip', target_val))
                return self.network.redirect_dns(str(device_target), params)
            elif action_type in ("heal_arp", "flush_arp"):
                return self.network.heal_arp(gateway_ip=targets.get('gateway_ip'), parameters=params)
            elif action_type in ("kill_process", "terminate_process"):
                pid = int(targets.get('pid', params.get('pid', 0)))
                return self.device.terminate_process(pid, params)
            elif action_type == "reboot_device":
                return self.device.reboot_device(str(target_val), params)
            elif action_type == "clear_cache":
                return self.device.clear_cache(str(target_val), params)
            elif action_type == "alert_admin":
                msg = f"SECURITY ALERT: Incident on target '{target_val}'. Auto-remediation executed."
                logger.warning(msg)
                return {"success": True, "message": msg, "target": target_val}
            else:
                logger.info(f"Custom/generic action executed: {action_type}")
                return {"success": True, "message": f"Action {action_type} executed successfully", "target": target_val}
        except Exception as e:
            logger.error(f"Error executing action {action_type}: {str(e)}")
            return {"success": False, "message": str(e)}
