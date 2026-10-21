"""
Network-level self-healing actions (VLAN, Quarantine, DNS restoration, ARP Healing).
Works on Linux and Windows.
"""

from typing import Dict, Any, List
from src.core.os_adapter import OSAdapter
from src.utils.logger import get_logger

logger = get_logger(__name__)

class NetworkActions:
    """Network-level self-healing actions across platforms"""
    
    def __init__(self, os_adapter: OSAdapter = None):
        self.os_adapter = os_adapter or OSAdapter()
        self.isolated_devices = self.os_adapter.virtual_isolated_devices
    
    def isolate_device(self, device_ip: str, parameters: Dict = None) -> Dict[str, Any]:
        """Isolate a device to prevent lateral movement"""
        parameters = parameters or {}
        subnet = parameters.get('subnet', '192.168.0.0/16')
        return self.os_adapter.isolate_device(device_ip, subnet=subnet)
    
    def remove_isolation(self, device_ip: str, parameters: Dict = None) -> Dict[str, Any]:
        """Lift device quarantine"""
        parameters = parameters or {}
        subnet = parameters.get('subnet', '192.168.0.0/16')
        return self.os_adapter.restore_device(device_ip, subnet=subnet)
    
    def redirect_dns(self, device_ip: str, parameters: Dict = None) -> Dict[str, Any]:
        """Flush and heal DNS upstream to safe verified resolver"""
        parameters = parameters or {}
        safe_dns = parameters.get('safe_dns', '1.1.1.1')
        result = self.os_adapter.flush_and_heal_dns(safe_dns=safe_dns)
        result["device"] = device_ip
        return result
    
    def heal_arp(self, gateway_ip: str = None, parameters: Dict = None) -> Dict[str, Any]:
        """Purge ARP cache and heal ARP poisoning / MITM"""
        parameters = parameters or {}
        gw = gateway_ip or parameters.get('gateway_ip')
        return self.os_adapter.flush_and_heal_arp(gateway_ip=gw)
    
    def get_isolated_devices(self) -> List[str]:
        """Return currently quarantined devices"""
        return list(self.isolated_devices)