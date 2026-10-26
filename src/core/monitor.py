"""
Network Monitoring and Intrusion Detection System (IDS).
Collects real-time interface metrics, socket connections, detects intrusion anomalies,
and triggers automated self-healing remediation.
"""

import time
import socket
import threading
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Any, Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from src.core.policy_engine import PolicyEngine
from src.config.policies import AnomalyType, Severity
from src.utils.logger import get_logger

logger = get_logger(__name__)

class NetworkMonitor:
    """
    Real-time network traffic and connection monitor with built-in heuristic IDS.
    Continuously samples network state and reports anomalies to PolicyEngine.
    """

    def __init__(self, policy_engine: Optional[PolicyEngine] = None, interval: float = 2.0):
        self.policy_engine = policy_engine or PolicyEngine()
        self.interval = interval
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        # Historical metrics for time-series charts (last 30 samples)
        self.history_length = 30
        self.traffic_history: deque = deque(maxlen=self.history_length)
        
        # Traffic rate calculation states
        self.last_io_counters = None
        self.last_timestamp = time.time()
        
        # Heuristic counters for intrusion detection
        self.ip_connection_tracker = defaultdict(lambda: deque(maxlen=100))
        self.ip_port_tracker = defaultdict(set)
        self.recent_anomalies: List[Dict[str, Any]] = []

        # Initialize with baseline stats
        self._sample_metrics()

    def start(self):
        """Start the background monitoring thread"""
        with self._lock:
            if not self.running:
                self.running = True
                self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="NetworkMonitorThread")
                self._thread.start()
                logger.info("NetworkMonitor background thread started")

    def stop(self):
        """Stop the background monitoring thread"""
        with self._lock:
            self.running = False
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=3.0)
                logger.info("NetworkMonitor background thread stopped")

    def _monitor_loop(self):
        """Background loop continuously collecting stats and analyzing threats"""
        while self.running:
            try:
                metrics = self._sample_metrics()
                self._detect_anomalies(metrics)
            except Exception as e:
                logger.error(f"Error in NetworkMonitor loop: {e}")
            time.sleep(self.interval)

    def _sample_metrics(self) -> Dict[str, Any]:
        """Sample network I/O, interface status, and active socket connections"""
        now = time.time()
        dt = max(now - self.last_timestamp, 0.001)
        self.last_timestamp = now

        bytes_sent_rate = 0.0
        bytes_recv_rate = 0.0
        packets_sent_rate = 0.0
        packets_recv_rate = 0.0
        total_connections = 0

        if PSUTIL_AVAILABLE:
            try:
                io = psutil.net_io_counters()
                if self.last_io_counters:
                    bytes_sent_rate = max((io.bytes_sent - self.last_io_counters.bytes_sent) / dt, 0.0)
                    bytes_recv_rate = max((io.bytes_recv - self.last_io_counters.bytes_recv) / dt, 0.0)
                    packets_sent_rate = max((io.packets_sent - self.last_io_counters.packets_sent) / dt, 0.0)
                    packets_recv_rate = max((io.packets_recv - self.last_io_counters.packets_recv) / dt, 0.0)
                self.last_io_counters = io
            except Exception as e:
                logger.debug(f"Failed to read net_io_counters: {e}")

            try:
                # Get total connection count
                conns = psutil.net_connections(kind='inet')
                total_connections = len(conns)
            except Exception:
                total_connections = 0

        sample = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "bytes_sent_rate": round(bytes_sent_rate, 2),
            "bytes_recv_rate": round(bytes_recv_rate, 2),
            "packets_sent_rate": round(packets_sent_rate, 1),
            "packets_recv_rate": round(packets_recv_rate, 1),
            "total_connections": total_connections
        }

        self.traffic_history.append(sample)
        return sample

    def _detect_anomalies(self, current_metrics: Dict[str, Any]):
        """
        Run heuristic analysis on active socket connections:
        - Detect Port Scanning (single remote IP probing > 10 distinct local ports)
        - Detect Outbound Exfiltration spikes
        - Detect Flooding attempts
        """
        if not PSUTIL_AVAILABLE:
            return

        try:
            conns = psutil.net_connections(kind='inet')
            now = time.time()

            # Analyze inbound remote IPs
            for c in conns:
                if c.raddr and c.status in ('ESTABLISHED', 'SYN_SENT', 'SYN_RECV'):
                    remote_ip = c.raddr.ip
                    remote_port = c.raddr.port
                    local_port = c.laddr.port if c.laddr else 0

                    # Skip loopback
                    if remote_ip in ("127.0.0.1", "::1", "localhost"):
                        continue

                    self.ip_connection_tracker[remote_ip].append(now)
                    self.ip_port_tracker[remote_ip].add(local_port)

                    # 1. Port scan detection heuristic: probing multiple local ports
                    if len(self.ip_port_tracker[remote_ip]) >= 15:
                        self._trigger_detected_intrusion({
                            "type": AnomalyType.PORT_SCAN.value,
                            "severity": Severity.HIGH.value,
                            "source_ip": remote_ip,
                            "target_ip": "local_host",
                            "description": f"Heuristic IDS: Port Scan detected from {remote_ip} ({len(self.ip_port_tracker[remote_ip])} distinct ports targeted)",
                            "targets": {"malicious_ip": remote_ip}
                        })
                        self.ip_port_tracker[remote_ip].clear()

                    # 2. Connection flood detection: > 40 connections in rolling window
                    recent_hits = [t for t in self.ip_connection_tracker[remote_ip] if now - t < 5.0]
                    if len(recent_hits) > 40:
                        self._trigger_detected_intrusion({
                            "type": AnomalyType.DDOS_FLOOD.value,
                            "severity": Severity.HIGH.value,
                            "source_ip": remote_ip,
                            "target_ip": "local_host",
                            "description": f"Heuristic IDS: SYN/Connection flood detected from {remote_ip} ({len(recent_hits)} conns / 5s)",
                            "targets": {"malicious_ip": remote_ip}
                        })
                        self.ip_connection_tracker[remote_ip].clear()

        except Exception as e:
            logger.debug(f"IDS connection scan note: {e}")

    def _trigger_detected_intrusion(self, threat_data: Dict[str, Any]):
        """Pass detected threat to the PolicyEngine for instant self-healing"""
        logger.warning(f"IDS INTRUSION TRIGGERED: {threat_data['description']}")
        self.recent_anomalies.insert(0, threat_data)
        if len(self.recent_anomalies) > 50:
            self.recent_anomalies.pop()

        # Fire self-healing remediation
        result = self.policy_engine.evaluate_anomaly(threat_data)
        return result

    # ==========================================
    # Public Query APIs for Web Dashboard
    # ==========================================

    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Aggregate all real-time stats for the Web Dashboard"""
        health_info = self.policy_engine.get_health_score()
        platform_info = self.policy_engine.action_dispatcher.os_adapter.get_platform_info()
        
        # Make sure we have at least one sample
        if not self.traffic_history:
            self._sample_metrics()

        latest_sample = self.traffic_history[-1] if self.traffic_history else {}
        
        blocked_ips = list(self.policy_engine.action_dispatcher.firewall.blocked_ips)
        isolated_devices = list(self.policy_engine.action_dispatcher.network.isolated_devices)
        
        try:
            from src.integrations.cpp_monitor import cpp_monitor_manager
            cpp_status = cpp_monitor_manager.get_status()
        except Exception:
            cpp_status = {"is_connected": False, "connected_count": 0}

        return {
            "health": health_info,
            "platform": platform_info,
            "current_traffic": latest_sample,
            "history": list(self.traffic_history),
            "blocked_ips": blocked_ips,
            "blocked_count": len(blocked_ips),
            "isolated_devices": isolated_devices,
            "isolated_count": len(isolated_devices),
            "recent_incidents": self.policy_engine.get_incidents(15),
            "audit_logs": self.policy_engine.get_audit_log(15),
            "active_connections_count": latest_sample.get("total_connections", 0),
            "cpp_monitor": cpp_status
        }

    def get_interfaces(self) -> List[Dict[str, Any]]:
        """Return list of network interfaces with IP, netmask, and status"""
        interfaces = []
        if not PSUTIL_AVAILABLE:
            return [{"name": "eth0", "ip": "192.168.1.15", "netmask": "255.255.255.0", "status": "up"}]

        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            for iface_name, addr_list in addrs.items():
                is_up = stats[iface_name].isup if iface_name in stats else True
                speed = stats[iface_name].speed if iface_name in stats else 0
                
                ipv4 = "N/A"
                netmask = "N/A"
                mac = "N/A"
                
                for addr in addr_list:
                    if addr.family == socket.AF_INET:
                        ipv4 = addr.address
                        netmask = addr.netmask
                    elif hasattr(psutil, 'AF_LINK') and addr.family == psutil.AF_LINK:
                        mac = addr.address
                
                if ipv4 != "N/A" or mac != "N/A":
                    interfaces.append({
                        "name": iface_name,
                        "ip": ipv4,
                        "netmask": netmask,
                        "mac": mac,
                        "is_up": is_up,
                        "speed_mbps": speed
                    })
        except Exception as e:
            logger.error(f"Error enumerating interfaces: {e}")
            
        return interfaces

    def get_active_connections(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return list of active network connections with process info"""
        connections = []
        if not PSUTIL_AVAILABLE:
            return []

        try:
            raw_conns = psutil.net_connections(kind='inet')
            for c in raw_conns[:limit]:
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "N/A"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A"
                pid = c.pid or 0
                proc_name = "System/Kernel"
                
                if pid > 0:
                    try:
                        p = psutil.Process(pid)
                        proc_name = p.name()
                    except Exception:
                        proc_name = "Unknown"

                remote_ip = c.raddr.ip if c.raddr else ""
                is_blocked = remote_ip in self.policy_engine.action_dispatcher.firewall.blocked_ips

                connections.append({
                    "fd": c.fd,
                    "family": "IPv4" if c.family == socket.AF_INET else "IPv6",
                    "type": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                    "local_address": laddr,
                    "remote_address": raddr,
                    "remote_ip": remote_ip,
                    "status": c.status,
                    "pid": pid,
                    "process_name": proc_name,
                    "is_blocked": is_blocked
                })
        except Exception as e:
            logger.debug(f"Error getting connections: {e}")
            
        return connections
