"""
C++ Network Monitor Integration Module for AEGIS Self-Healing Network.
Receives real-time telemetry, packet statistics, and threat alerts from the
C++ Network Monitor agent (running on Linux or Windows), and triggers autonomous
self-healing remediation chains across host firewalls and network routing.
"""

import time
from datetime import datetime
from collections import deque
from typing import Dict, List, Any, Optional
from flask import Blueprint, request, jsonify

from src.core.policy_engine import PolicyEngine
from src.config.policies import AnomalyType, Severity
from src.utils.logger import get_logger

logger = get_logger(__name__)

class CPPMonitorManager:
    """
    Manages state, heartbeat, telemetry aggregation, and alert ingestion
    for connected C++ Network Monitor agents across Linux and Windows.
    """

    def __init__(self, policy_engine: Optional[PolicyEngine] = None):
        self.policy_engine = policy_engine
        self.monitors: Dict[str, Dict[str, Any]] = {}
        self.telemetry_history: deque = deque(maxlen=60)
        self.alerts_received: List[Dict[str, Any]] = []
        self.total_packets_ingested: int = 0
        self.total_bytes_ingested: int = 0
        self.total_threats_reported: int = 0
        self.last_heartbeat_time: float = 0.0

    def set_policy_engine(self, engine: PolicyEngine):
        """Set or update the reference to the global policy engine"""
        self.policy_engine = engine

    def register_heartbeat(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Record heartbeat and telemetry sample from a C++ Network Monitor instance.
        """
        now = time.time()
        monitor_id = str(data.get("monitor_id", "cpp-monitor-default"))
        platform_name = str(data.get("platform", "Unknown"))
        active_interface = str(data.get("active_interface", "eth0"))
        packets = int(data.get("packets_captured", 0))
        bytes_captured = int(data.get("bytes_captured", 0))
        threats = int(data.get("threats_detected", 0))
        bandwidth_kbps = float(data.get("bandwidth_kbps", 0.0))
        uptime = float(data.get("uptime_seconds", 0.0))

        self.last_heartbeat_time = now
        self.total_packets_ingested = max(self.total_packets_ingested, packets)
        self.total_bytes_ingested = max(self.total_bytes_ingested, bytes_captured)
        self.total_threats_reported = max(self.total_threats_reported, threats)

        monitor_record = {
            "monitor_id": monitor_id,
            "platform": platform_name,
            "active_interface": active_interface,
            "packets_captured": packets,
            "bytes_captured": bytes_captured,
            "threats_detected": threats,
            "bandwidth_kbps": bandwidth_kbps,
            "uptime_seconds": uptime,
            "last_seen_epoch": now,
            "last_seen_iso": datetime.now().isoformat(),
            "status": "online"
        }
        self.monitors[monitor_id] = monitor_record

        sample = {
            "timestamp": now,
            "time_iso": datetime.now().strftime("%H:%M:%S"),
            "monitor_id": monitor_id,
            "bandwidth_kbps": bandwidth_kbps,
            "packets": packets,
            "bytes": bytes_captured
        }
        self.telemetry_history.append(sample)

        logger.debug(
            f"[CPPMonitorManager] Heartbeat from {monitor_id} ({platform_name}): "
            f"{packets} pkts, {threats} threats, {bandwidth_kbps:.2f} KB/s"
        )

        return {
            "success": True,
            "status": "acknowledged",
            "monitor_id": monitor_id,
            "server_time": datetime.now().isoformat()
        }

    def handle_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ingest a threat alert emitted by the C++ Network Monitor and execute
        autonomous self-healing remediation via the AEGIS PolicyEngine.
        """
        if not alert_data:
            return {"success": False, "message": "Empty alert payload"}

        raw_type = alert_data.get("threat_type") or alert_data.get("anomaly_type") or "port_scan"
        source_ip = alert_data.get("source_ip", "unknown")
        target_ip = alert_data.get("target_ip", "unknown")
        severity = alert_data.get("severity", "high")
        description = alert_data.get("description", f"Intrusion detected by C++ Network Monitor: {raw_type}")
        monitor_id = alert_data.get("monitor_id", "cpp-monitor")
        platform_name = alert_data.get("platform", "Unknown")

        # Map to AEGIS AnomalyType
        type_str = str(raw_type).lower().strip().replace(" ", "_").replace("-", "_")
        if "port_scan" in type_str or "scan" in type_str:
            anomaly_type = AnomalyType.PORT_SCAN
        elif "mitm" in type_str or "arp" in type_str:
            anomaly_type = AnomalyType.MITM_ATTACK
        elif "dns" in type_str:
            anomaly_type = AnomalyType.DNS_ATTACK
        elif "malware" in type_str or "c2" in type_str:
            anomaly_type = AnomalyType.MALWARE
        elif "exfil" in type_str or "bandwidth" in type_str:
            anomaly_type = AnomalyType.DATA_EXFILTRATION
        elif "flood" in type_str or "ddos" in type_str or "syn" in type_str:
            anomaly_type = AnomalyType.DDOS_FLOOD
        elif "blacklist" in type_str:
            anomaly_type = AnomalyType.PORT_SCAN
            description = f"Blacklisted IP Traffic Detected: {source_ip} -> {target_ip}"
        else:
            anomaly_type = AnomalyType.PORT_SCAN

        # Build payload for AEGIS Policy Engine
        engine_payload = {
            "anomaly_type": anomaly_type.value,
            "severity": severity,
            "source_ip": source_ip,
            "target_ip": target_ip,
            "description": f"[C++ Monitor ({platform_name})] {description}",
            "targets": {
                "malicious_ip": source_ip,
                "affected_device": target_ip,
                "gateway_ip": "192.168.1.1"
            },
            "source_sensor": f"cpp_network_monitor ({platform_name})"
        }

        # Trigger self-healing
        remediation_result = {}
        if self.policy_engine:
            remediation_result = self.policy_engine.evaluate_anomaly(engine_payload)
        else:
            logger.warning("[CPPMonitorManager] PolicyEngine not set! Cannot execute automated remediation.")
            remediation_result = {
                "success": False,
                "error": "PolicyEngine not attached"
            }

        # Record alert
        alert_record = {
            "id": f"CPP-{int(time.time() * 1000)}",
            "timestamp": datetime.now().isoformat(),
            "monitor_id": monitor_id,
            "platform": platform_name,
            "threat_type": raw_type,
            "normalized_type": anomaly_type.value,
            "severity": severity,
            "source_ip": source_ip,
            "target_ip": target_ip,
            "description": description,
            "self_healed": remediation_result.get("healed", False) or remediation_result.get("success", False),
            "remediation_actions": remediation_result.get("actions", []),
            "incident_id": remediation_result.get("incident_id")
        }
        self.alerts_received.insert(0, alert_record)
        if len(self.alerts_received) > 100:
            self.alerts_received.pop()

        self.total_threats_reported += 1

        logger.info(
            f"[CPPMonitorManager] Processed alert from {monitor_id} ({platform_name}): "
            f"{raw_type} from {source_ip} -> Auto-Healed: {alert_record['self_healed']}"
        )

        return {
            "success": True,
            "alert_id": alert_record["id"],
            "incident_id": remediation_result.get("incident_id"),
            "self_healed": alert_record["self_healed"],
            "actions_executed": remediation_result.get("actions", []),
            "health_score": remediation_result.get("health", {}).get("score", 100),
            "message": f"Threat {raw_type} neutralized and self-healed by AEGIS"
        }

    def get_status(self) -> Dict[str, Any]:
        """
        Return the real-time operational status of connected C++ Network Monitors.
        """
        now = time.time()
        # Active if heartbeat within last 12 seconds
        is_online = (now - self.last_heartbeat_time) <= 12.0 and bool(self.monitors)

        # Update per-monitor online status
        active_monitors = []
        for mid, mdata in self.monitors.items():
            mon_online = (now - mdata["last_seen_epoch"]) <= 12.0
            mdata_copy = dict(mdata)
            mdata_copy["status"] = "online" if mon_online else "offline"
            mdata_copy["seconds_since_heartbeat"] = round(now - mdata["last_seen_epoch"], 1)
            active_monitors.append(mdata_copy)

        primary_monitor = active_monitors[0] if active_monitors else None

        return {
            "is_connected": is_online,
            "connected_count": len([m for m in active_monitors if m["status"] == "online"]),
            "monitors": active_monitors,
            "primary_monitor": primary_monitor,
            "total_packets_ingested": self.total_packets_ingested,
            "total_bytes_ingested": self.total_bytes_ingested,
            "total_threats_reported": self.total_threats_reported,
            "last_heartbeat_time": datetime.fromtimestamp(self.last_heartbeat_time).isoformat() if self.last_heartbeat_time else None,
            "recent_alerts": self.alerts_received[:10],
            "telemetry_recent": list(self.telemetry_history)[-10:]
        }

    def get_sync_rules(self) -> Dict[str, Any]:
        """
        Provide live firewall blocked IPs and policies to the C++ Monitor
        so its in-memory blacklists stay continuously synchronized with AEGIS.
        """
        blocked_ips = []
        isolated_devices = []
        auto_remediate = True

        if self.policy_engine:
            blocked_ips = list(self.policy_engine.action_dispatcher.firewall.blocked_ips)
            isolated_devices = list(self.policy_engine.action_dispatcher.network.isolated_devices)
            auto_remediate = self.policy_engine.auto_remediate

        return {
            "success": True,
            "timestamp": datetime.now().isoformat(),
            "blocked_ips": blocked_ips,
            "blocked_count": len(blocked_ips),
            "isolated_devices": isolated_devices,
            "auto_remediate": auto_remediate,
            "suggested_thresholds": {
                "port_scan_packets": 10,
                "port_scan_window_seconds": 5,
                "bandwidth_limit_bytes": 10485760,  # 10MB
                "mitm_packet_threshold": 50
            }
        }


# Global singleton instance of CPPMonitorManager
cpp_monitor_manager = CPPMonitorManager()

# Flask Blueprint
cpp_monitor_bp = Blueprint("cpp_monitor", __name__)

@cpp_monitor_bp.route("/status", methods=["GET"])
def get_cpp_monitor_status():
    """Get the current connection status and telemetry of C++ Network Monitor"""
    try:
        status = cpp_monitor_manager.get_status()
        return jsonify({"success": True, "data": status})
    except Exception as e:
        logger.error(f"Error getting C++ monitor status: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@cpp_monitor_bp.route("/heartbeat", methods=["POST"])
@cpp_monitor_bp.route("/telemetry", methods=["POST"])
def post_cpp_telemetry():
    """Ingest heartbeat and packet telemetry from C++ Monitor"""
    try:
        data = request.get_json(silent=True) or {}
        result = cpp_monitor_manager.register_heartbeat(data)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error recording C++ telemetry: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@cpp_monitor_bp.route("/alert", methods=["POST"])
def post_cpp_alert():
    """
    Ingest a threat alert from C++ Monitor and trigger autonomous self-healing.
    """
    try:
        data = request.get_json(silent=True) or {}
        result = cpp_monitor_manager.handle_alert(data)
        status_code = 200 if result.get("success") else 400
        return jsonify(result), status_code
    except Exception as e:
        logger.error(f"Error handling C++ alert: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@cpp_monitor_bp.route("/sync-rules", methods=["GET"])
def get_cpp_sync_rules():
    """
    Endpoint for C++ Monitor to fetch active firewall blocklists and policies.
    """
    try:
        rules = cpp_monitor_manager.get_sync_rules()
        return jsonify(rules)
    except Exception as e:
        logger.error(f"Error serving sync rules: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@cpp_monitor_bp.route("/simulate-alert", methods=["POST"])
def post_simulate_alert():
    """
    Trigger a simulated alert from a virtual C++ Network Monitor to test
    cross-system integration from the web dashboard or CLI.
    """
    try:
        data = request.get_json(silent=True) or {}
        threat_type = data.get("threat_type", "port_scan")
        source_ip = data.get("source_ip", "198.51.100.77")
        target_ip = data.get("target_ip", "192.168.1.55")

        synthetic_alert = {
            "monitor_id": "cpp-monitor-simulated",
            "platform": "Linux/Windows",
            "threat_type": threat_type,
            "severity": "high",
            "source_ip": source_ip,
            "target_ip": target_ip,
            "description": f"Test intrusion alert from C++ Network Monitor ({threat_type})"
        }
        result = cpp_monitor_manager.handle_alert(synthetic_alert)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error simulating C++ alert: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
