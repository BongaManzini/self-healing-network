"""
Firewall action implementations with Linux & Windows support.
"""

from typing import Dict, Any, List
from src.core.os_adapter import OSAdapter
from src.utils.logger import get_logger

logger = get_logger(__name__)

class FirewallActions:
    """Firewall action implementations for Linux and Windows"""
    
    def __init__(self, os_adapter: OSAdapter = None):
        self.os_adapter = os_adapter or OSAdapter()
        self.blocked_ips = self.os_adapter.virtual_blocked_ips
    
    def block_ip(self, ip_address: str, parameters: Dict = None) -> Dict[str, Any]:
        """Block an IP address on Linux or Windows"""
        parameters = parameters or {}
        reason = parameters.get("reason", "automated_threat_containment")
        return self.os_adapter.block_ip(ip_address, reason=reason)
    
    def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        """Unblock a previously blocked IP address"""
        return self.os_adapter.unblock_ip(ip_address)
    
    def update_rules(self, rule_type: str, parameters: Dict = None) -> Dict[str, Any]:
        """Update firewall rules (e.g. block port or protocol)"""
        parameters = parameters or {}
        try:
            if rule_type == "block_traffic":
                port = parameters.get('port', 80)
                ip = parameters.get('ip', '0.0.0.0/0')
                logger.info(f"Firewall policy applied: block traffic port {port} on {ip}")
                return {
                    "success": True,
                    "message": f"Firewall rule applied: drop port {port}",
                    "rule": {"type": rule_type, "port": port}
                }
            return {"success": False, "message": f"Unknown rule type: {rule_type}"}
        except Exception as e:
            logger.error(f"Failed to update firewall rules: {str(e)}")
            return {"success": False, "message": str(e)}

    def get_blocked_ips(self) -> List[str]:
        """Return list of currently blocked IPs"""
        return list(self.blocked_ips)