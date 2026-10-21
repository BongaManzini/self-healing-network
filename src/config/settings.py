import os
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class Settings:
    """Application configuration settings"""
    
    # Application settings
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", 5000))
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-key")
    
    # Network settings
    NETWORK_DEVICES: Dict = None
    DEFAULT_DNS: str = "8.8.8.8"
    QUARANTINE_VLAN: int = 999
    
    # Action settings
    AUTO_REMEDIATE: bool = True
    REQUIRE_APPROVAL: bool = False
    
    def __post_init__(self):
        if self.NETWORK_DEVICES is None:
            self.NETWORK_DEVICES = {
                "firewall": {
                    "ip": "192.168.1.1",
                    "type": "generic",
                    "credentials": {
                        "username": os.getenv("FIREWALL_USER"),
                        "password": os.getenv("FIREWALL_PASS")
                    }
                },
                "switch": {
                    "ip": "192.168.1.2", 
                    "type": "generic",
                    "credentials": {
                        "username": os.getenv("SWITCH_USER"),
                        "password": os.getenv("SWITCH_PASS")
                    }
                }
            }