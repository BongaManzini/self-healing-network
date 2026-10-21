"""
Device and process level self-healing actions.
Supports Linux and Windows.
"""

from typing import Dict, Any, Optional
from src.core.os_adapter import OSAdapter
from src.utils.logger import get_logger

logger = get_logger(__name__)

class DeviceActions:
    """Device and host remediation actions"""
    
    def __init__(self, os_adapter: OSAdapter = None):
        self.os_adapter = os_adapter or OSAdapter()
    
    def terminate_process(self, pid: int, parameters: Dict = None) -> Dict[str, Any]:
        """Terminate a malicious process identified during an intrusion"""
        parameters = parameters or {}
        pname = parameters.get('process_name')
        return self.os_adapter.terminate_process_by_pid(pid, process_name=pname)
    
    def reboot_device(self, device_ip: str, parameters: Dict = None) -> Dict[str, Any]:
        """Simulate or signal device reboot for containment"""
        parameters = parameters or {}
        delay = parameters.get('delay', 5)
        logger.warning(f"Reboot signal dispatched for device {device_ip} (delay: {delay}s)")
        return {
            "success": True,
            "device_rebooted": device_ip,
            "message": f"Device {device_ip} reboot sequence scheduled",
            "delay": delay
        }
    
    def clear_cache(self, device_ip: str = "localhost", parameters: Dict = None) -> Dict[str, Any]:
        """Clear DNS or ARP cache depending on cache_type"""
        parameters = parameters or {}
        cache_type = parameters.get('cache_type', 'dns')
        
        if cache_type == 'dns':
            return self.os_adapter.flush_and_heal_dns()
        elif cache_type in ('arp', 'neighbor'):
            return self.os_adapter.flush_and_heal_arp()
        else:
            return {"success": False, "message": f"Unsupported cache type: {cache_type}"}