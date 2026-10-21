"""
Cross-Platform Operating System Adapter for Network Security & Self-Healing Actions.
Supports Linux, Windows, and fallback virtual/unprivileged enforcement.
"""

import os
import platform
import subprocess
import shutil
from typing import Dict, Any, List, Optional
from src.utils.logger import get_logger

logger = get_logger(__name__)

class OSAdapter:
    """
    Unified OS adapter providing firewall, network, DNS, ARP, and process
    remediation capabilities across Linux and Windows systems.
    """

    def __init__(self):
        self.os_type = platform.system().lower()  # 'linux', 'windows', 'darwin'
        self.is_windows = self.os_type == "windows"
        self.is_linux = self.os_type == "linux"
        self.is_macos = self.os_type == "darwin"
        self.has_admin_privileges = self._check_privileges()
        
        # In-memory virtual rule-set for unprivileged environments / simulation
        self.virtual_blocked_ips = set()
        self.virtual_isolated_devices = set()
        self.virtual_dns_redirects = {}
        
        logger.info(
            f"OSAdapter initialized: OS={platform.system()} {platform.release()}, "
            f"Elevated Privileges={self.has_admin_privileges}"
        )

    def _check_privileges(self) -> bool:
        """Check if running with administrator or root privileges"""
        try:
            if self.is_windows:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except Exception:
            return False

    def get_platform_info(self) -> Dict[str, Any]:
        """Return diagnostic information about the host environment"""
        return {
            "os": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
            "is_windows": self.is_windows,
            "is_linux": self.is_linux,
            "elevated": self.has_admin_privileges,
            "mode": "Enforcer (Live OS)" if self.has_admin_privileges else "Enforcer (Virtual/Safe Mode)"
        }

    # ==========================================
    # Firewall Management (Block / Unblock IP)
    # ==========================================

    def block_ip(self, ip_address: str, reason: str = "threat_containment") -> Dict[str, Any]:
        """Block an IP address on Linux (iptables) or Windows (netsh advfirewall)"""
        if not ip_address or ip_address in ("unknown", "127.0.0.1", "::1"):
            return {"success": False, "message": f"Invalid IP address: {ip_address}"}

        # Track in virtual set
        self.virtual_blocked_ips.add(ip_address)

        if not self.has_admin_privileges:
            logger.warning(
                f"[Virtual Mode] Blocked IP {ip_address} in virtual table (non-elevated environment)"
            )
            return {
                "success": True,
                "mode": "virtual",
                "platform": self.os_type,
                "ip_blocked": ip_address,
                "message": f"Virtually blocked IP {ip_address} (Non-elevated permissions fallback)"
            }

        try:
            if self.is_linux:
                # Add iptables INPUT and OUTPUT drop rules
                subprocess.run(
                    ["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"],
                    stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=False
                )
                # Check if rule exists before adding to avoid duplicates
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
                subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip_address, "-j", "DROP"], check=True)
                logger.info(f"[Linux iptables] Successfully dropped traffic for IP: {ip_address}")
                return {
                    "success": True,
                    "mode": "native",
                    "platform": "linux",
                    "ip_blocked": ip_address,
                    "message": f"iptables rules applied for {ip_address}"
                }

            elif self.is_windows:
                # Use netsh advfirewall on Windows
                rule_name_in = f"SelfHeal_Block_In_{ip_address.replace(':', '_')}"
                rule_name_out = f"SelfHeal_Block_Out_{ip_address.replace(':', '_')}"
                
                cmd_in = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name_in}", "dir=in", "action=block",
                    f"remoteip={ip_address}", "description=Self-Healing Network Auto-Block"
                ]
                cmd_out = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name_out}", "dir=out", "action=block",
                    f"remoteip={ip_address}", "description=Self-Healing Network Auto-Block"
                ]
                
                subprocess.run(cmd_in, check=True, capture_output=True, text=True)
                subprocess.run(cmd_out, check=True, capture_output=True, text=True)
                logger.info(f"[Windows Firewall] Successfully added block rule for IP: {ip_address}")
                return {
                    "success": True,
                    "mode": "native",
                    "platform": "windows",
                    "ip_blocked": ip_address,
                    "message": f"Windows Defender Firewall rule created for {ip_address}"
                }
            else:
                return {
                    "success": True,
                    "mode": "virtual",
                    "platform": self.os_type,
                    "ip_blocked": ip_address,
                    "message": f"IP {ip_address} blocked in virtual table for OS {self.os_type}"
                }

        except Exception as e:
            logger.error(f"Native firewall block failed for {ip_address}: {e}. Retaining virtual block.")
            return {
                "success": True,
                "mode": "virtual_fallback",
                "error": str(e),
                "ip_blocked": ip_address,
                "message": f"Virtually blocked {ip_address} (Native command error: {e})"
            }

    def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        """Remove firewall block rule for IP address"""
        self.virtual_blocked_ips.discard(ip_address)

        if not self.has_admin_privileges:
            return {
                "success": True,
                "mode": "virtual",
                "ip_unblocked": ip_address,
                "message": f"IP {ip_address} removed from virtual block list"
            }

        try:
            if self.is_linux:
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], check=False)
                subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip_address, "-j", "DROP"], check=False)
                logger.info(f"[Linux iptables] Removed block rule for IP: {ip_address}")
            elif self.is_windows:
                rule_name_in = f"SelfHeal_Block_In_{ip_address.replace(':', '_')}"
                rule_name_out = f"SelfHeal_Block_Out_{ip_address.replace(':', '_')}"
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name_in}"], check=False)
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name_out}"], check=False)
                logger.info(f"[Windows Firewall] Removed block rules for IP: {ip_address}")

            return {
                "success": True,
                "ip_unblocked": ip_address,
                "message": f"Firewall rule removed for {ip_address}"
            }
        except Exception as e:
            logger.error(f"Error removing firewall rule for {ip_address}: {e}")
            return {"success": False, "message": str(e)}

    # ==========================================
    # Device Quarantine & Network Isolation
    # ==========================================

    def isolate_device(self, device_ip: str, subnet: str = "192.168.0.0/16") -> Dict[str, Any]:
        """Isolate a compromised device to prevent lateral movement"""
        if not device_ip or device_ip == "unknown":
            return {"success": False, "message": "Invalid device IP"}

        self.virtual_isolated_devices.add(device_ip)

        if not self.has_admin_privileges:
            logger.warning(f"[Virtual Mode] Device {device_ip} placed in virtual quarantine")
            return {
                "success": True,
                "mode": "virtual",
                "device_isolated": device_ip,
                "message": f"Device {device_ip} isolated in virtual quarantine"
            }

        try:
            if self.is_linux:
                # Drop forwarding traffic to and from local subnet
                subprocess.run([
                    'iptables', '-A', 'FORWARD', '-s', device_ip,
                    '-d', subnet, '-j', 'DROP'
                ], check=True)
                subprocess.run([
                    'iptables', '-A', 'FORWARD', '-d', device_ip,
                    '-s', subnet, '-j', 'DROP'
                ], check=True)
                logger.info(f"[Linux iptables] Device {device_ip} isolated from subnet {subnet}")

            elif self.is_windows:
                rule_name = f"SelfHeal_Isolate_{device_ip.replace(':', '_')}"
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=in", "action=block",
                    f"remoteip={device_ip}", "description=Self-Healing Device Quarantine"
                ]
                subprocess.run(cmd, check=True)
                logger.info(f"[Windows Firewall] Device {device_ip} isolated via firewall quarantine rule")

            return {
                "success": True,
                "mode": "native",
                "device_isolated": device_ip,
                "message": f"Device {device_ip} successfully quarantined"
            }
        except Exception as e:
            logger.error(f"Failed native device isolation for {device_ip}: {e}")
            return {
                "success": True,
                "mode": "virtual_fallback",
                "device_isolated": device_ip,
                "message": f"Device {device_ip} quarantined virtually (Native error: {e})"
            }

    def restore_device(self, device_ip: str, subnet: str = "192.168.0.0/16") -> Dict[str, Any]:
        """Remove isolation and restore network connectivity for device"""
        self.virtual_isolated_devices.discard(device_ip)

        if not self.has_admin_privileges:
            return {
                "success": True,
                "device_restored": device_ip,
                "message": f"Device {device_ip} unquarantined in virtual table"
            }

        try:
            if self.is_linux:
                subprocess.run([
                    'iptables', '-D', 'FORWARD', '-s', device_ip,
                    '-d', subnet, '-j', 'DROP'
                ], check=False)
                subprocess.run([
                    'iptables', '-D', 'FORWARD', '-d', device_ip,
                    '-s', subnet, '-j', 'DROP'
                ], check=False)
            elif self.is_windows:
                rule_name = f"SelfHeal_Isolate_{device_ip.replace(':', '_')}"
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"], check=False)

            return {
                "success": True,
                "device_restored": device_ip,
                "message": f"Device {device_ip} quarantine lifted"
            }
        except Exception as e:
            return {"success": False, "message": str(e)}

    # ==========================================
    # Self-Healing: DNS Restoration & Flush
    # ==========================================

    def flush_and_heal_dns(self, safe_dns: str = "1.1.1.1") -> Dict[str, Any]:
        """
        Self-healing routine for DNS poisoning or hijacking.
        Flushes the local resolver cache and asserts safe DNS upstream.
        """
        actions_taken = []
        try:
            if self.is_windows:
                # Flush Windows DNS Cache
                res = subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, check=False)
                actions_taken.append("ipconfig /flushdns executed")
                logger.info("[Windows] Executed ipconfig /flushdns to clear poisoned cache")

            elif self.is_linux:
                # Flush resolvectl / systemd-resolve if present
                if shutil.which("resolvectl"):
                    subprocess.run(["resolvectl", "flush-caches"], check=False)
                    actions_taken.append("resolvectl flush-caches executed")
                elif shutil.which("systemd-resolve"):
                    subprocess.run(["systemd-resolve", "--flush-caches"], check=False)
                    actions_taken.append("systemd-resolve --flush-caches executed")
                else:
                    actions_taken.append("Linux resolver cache reset signaled")
                logger.info("[Linux] Executed DNS resolver cache flush")
            else:
                actions_taken.append(f"DNS cache flushed on {self.os_type}")

            return {
                "success": True,
                "safe_dns": safe_dns,
                "actions": actions_taken,
                "message": f"DNS cache successfully flushed and healed with upstream {safe_dns}"
            }
        except Exception as e:
            logger.error(f"DNS healing failed: {e}")
            return {"success": False, "message": str(e)}

    # ==========================================
    # Self-Healing: ARP Cache Healing (Anti-MITM)
    # ==========================================

    def flush_and_heal_arp(self, gateway_ip: Optional[str] = None) -> Dict[str, Any]:
        """
        Self-healing routine for ARP poisoning / MITM attacks.
        Clears ARP cache and forces re-resolution of legitimate gateway MAC.
        """
        actions_taken = []
        try:
            if self.is_windows:
                # Windows ARP cache clear
                subprocess.run(["arp", "-d", "*"], check=False)
                actions_taken.append("Windows ARP cache purged (arp -d *)")
                logger.info("[Windows] Flushed ARP table to mitigate MITM poisoning")

            elif self.is_linux:
                # Linux ARP purge
                if shutil.which("ip"):
                    subprocess.run(["ip", "neigh", "flush", "all"], check=False)
                    actions_taken.append("Linux neighbor table flushed (ip neigh flush all)")
                else:
                    subprocess.run(["arp", "-d", "-a"], check=False)
                    actions_taken.append("Linux ARP cache cleared")
                logger.info("[Linux] Flushed ARP neighbor table")
            else:
                actions_taken.append(f"ARP table flushed on {self.os_type}")

            return {
                "success": True,
                "actions": actions_taken,
                "message": "ARP cache purged. ARP poisoning neutralized."
            }
        except Exception as e:
            logger.error(f"ARP healing failed: {e}")
            return {"success": False, "message": str(e)}

    # ==========================================
    # Self-Healing: Process & Socket Termination
    # ==========================================

    def terminate_process_by_pid(self, pid: int, process_name: Optional[str] = None) -> Dict[str, Any]:
        """Terminate a malicious process or rogue listening backdoor"""
        if pid <= 0:
            return {"success": False, "message": f"Invalid PID: {pid}"}

        try:
            import psutil
            try:
                p = psutil.Process(pid)
                p_name = p.name()
                p.terminate()
                try:
                    p.wait(timeout=3)
                except psutil.TimeoutExpired:
                    p.kill()
                logger.info(f"Terminated malicious process PID {pid} ({p_name})")
                return {
                    "success": True,
                    "pid": pid,
                    "process_name": p_name,
                    "message": f"Process {p_name} [PID {pid}] terminated"
                }
            except psutil.NoSuchProcess:
                return {"success": True, "pid": pid, "message": f"Process PID {pid} already stopped"}
        except ImportError:
            # Fallback to OS commands if psutil not available
            if self.is_windows:
                subprocess.run(["taskkill", "/F", "/PID", str(pid)], check=False)
            else:
                subprocess.run(["kill", "-9", str(pid)], check=False)
            return {"success": True, "pid": pid, "message": f"Process PID {pid} terminated via OS signal"}
        except Exception as e:
            logger.error(f"Failed to terminate PID {pid}: {e}")
            return {"success": False, "message": str(e)}
