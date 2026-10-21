import subprocess
import socket
from typing import Dict
from src.utils.logger import get_logger

logger = get_logger(__name__)

class NetworkActions:
    """Network-level actions (VLAN, DNS, isolation)"""
    
    def __init__(self):
        self.isolated_devices = set()
    
    def isolate_device(self, device_ip: str, parameters: Dict = None) -> Dict:
        """Isolate a device by blocking its communications"""
        try:
            if not device_ip or device_ip == "unknown":
                return {"success": False, "message": "Invalid device IP"}
            
            # Block device from communicating with other network devices
            # This is a simplified approach - in production, you'd use VLAN changes
            
            # Block all outgoing traffic from this device to local network
            subprocess.run([
                'iptables', '-A', 'FORWARD', '-s', device_ip, 
                '-d', '192.168.0.0/16', '-j', 'DROP'
            ], check=True)
            
            # Block all incoming traffic to this device from local network
            subprocess.run([
                'iptables', '-A', 'FORWARD', '-d', device_ip,
                '-s', '192.168.0.0/16', '-j', 'DROP'  
            ], check=True)
            
            # Allow only DNS and essential traffic out to internet
            subprocess.run([
                'iptables', '-A', 'FORWARD', '-s', device_ip,
                '-p', 'udp', '--dport', '53', '-j', 'ACCEPT'
            ], check=True)
            
            self.isolated_devices.add(device_ip)
            logger.info(f"Successfully isolated device: {device_ip}")
            
            return {
                "success": True,
                "message": f"Isolated device {device_ip}",
                "device_isolated": device_ip
            }
            
        except Exception as e:
            logger.error(f"Failed to isolate device {device_ip}: {str(e)}")
            return {"success": False, "message": str(e)}
    
    def redirect_dns(self, device_ip: str, parameters: Dict = None) -> Dict:
        """Redirect DNS queries to safe resolver"""
        try:
            safe_dns = parameters.get('safe_dns', '8.8.8.8')
            
            # Redirect DNS queries from specific device to safe DNS
            subprocess.run([
                'iptables', '-t', 'nat', '-A', 'PREROUTING', 
                '-s', device_ip, '-p', 'udp', '--dport', '53',
                '-j', 'DNAT', '--to-destination', safe_dns + ':53'
            ], check=True)
            
            logger.info(f"Redirected DNS for {device_ip} to {safe_dns}")
            
            return {
                "success": True,
                "message": f"DNS redirected to {safe_dns}",
                "device": device_ip,
                "dns_server": safe_dns
            }
            
        except Exception as e:
            logger.error(f"Failed to redirect DNS for {device_ip}: {str(e)}")
            return {"success": False, "message": str(e)}
    
    def remove_isolation(self, device_ip: str) -> Dict:
        """Remove isolation from a device"""
        try:
            # Remove isolation rules
            subprocess.run([
                'iptables', '-D', 'FORWARD', '-s', device_ip,
                '-d', '192.168.0.0/16', '-j', 'DROP'
            ], check=False)
            
            subprocess.run([
                'iptables', '-D', 'FORWARD', '-d', device_ip, 
                '-s', '192.168.0.0/16', '-j', 'DROP'
            ], check=False)
            
            self.isolated_devices.discard(device_ip)
            logger.info(f"Removed isolation from device: {device_ip}")
            
            return {"success": True, "message": f"Removed isolation from {device_ip}"}
            
        except Exception as e:
            logger.error(f"Error removing isolation from {device_ip}: {str(e)}")
            return {"success": False, "message": str(e)}