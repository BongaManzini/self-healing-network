import subprocess
import logging
from typing import Dict, List
from src.utils.logger import get_logger

logger = get_logger(__name__)

class FirewallActions:
    """Firewall action implementations"""
    
    def __init__(self):
        self.blocked_ips = set()
    
    def block_ip(self, ip_address: str, parameters: Dict = None) -> Dict:
        """Block an IP address using iptables"""
        try:
            if not ip_address or ip_address == "unknown":
                return {"success": False, "message": "Invalid IP address"}
            
            # Check if already blocked
            if ip_address in self.blocked_ips:
                return {"success": True, "message": f"IP {ip_address} already blocked"}
            
            # Block incoming traffic
            subprocess.run([
                'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'
            ], check=True)
            
            # Block outgoing traffic  
            subprocess.run([
                'iptables', '-A', 'OUTPUT', '-d', ip_address, '-j', 'DROP'
            ], check=True)
            
            self.blocked_ips.add(ip_address)
            logger.info(f"Successfully blocked IP: {ip_address}")
            
            return {
                "success": True, 
                "message": f"Blocked IP {ip_address}",
                "ip_blocked": ip_address
            }
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block IP {ip_address}: {str(e)}")
            return {"success": False, "message": f"iptables command failed: {str(e)}"}
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {str(e)}")
            return {"success": False, "message": str(e)}
    
    def update_rules(self, rule_type: str, parameters: Dict = None) -> Dict:
        """Update firewall rules based on type"""
        try:
            if rule_type == "block_traffic":
                # Example: Block specific port traffic
                port = parameters.get('port', 80)
                subprocess.run([
                    'iptables', '-A', 'INPUT', '-p', 'tcp', 
                    '--dport', str(port), '-j', 'DROP'
                ], check=True)
                return {"success": True, "message": f"Blocked port {port}"}
            
            return {"success": False, "message": f"Unknown rule type: {rule_type}"}
            
        except Exception as e:
            logger.error(f"Failed to update firewall rules: {str(e)}")
            return {"success": False, "message": str(e)}
    
    def unblock_ip(self, ip_address: str) -> Dict:
        """Unblock a previously blocked IP address"""
        try:
            # Remove INPUT rule
            subprocess.run([
                'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'
            ], check=False)  # Don't check because rule might not exist
            
            # Remove OUTPUT rule  
            subprocess.run([
                'iptables', '-D', 'OUTPUT', '-d', ip_address, '-j', 'DROP'
            ], check=False)
            
            self.blocked_ips.discard(ip_address)
            logger.info(f"Unblocked IP: {ip_address}")
            
            return {"success": True, "message": f"Unblocked IP {ip_address}"}
            
        except Exception as e:
            logger.error(f"Error unblocking IP {ip_address}: {str(e)}")
            return {"success": False, "message": str(e)}