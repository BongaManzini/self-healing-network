"""
Monitoring and system control API endpoints for real-time dashboard and telemetry.
"""

from flask import Blueprint, jsonify, request
from src.core.monitor import NetworkMonitor
from src.api.endpoints.anomaly import policy_engine
from src.utils.logger import get_logger

logger = get_logger(__name__)

monitor_bp = Blueprint('monitor', __name__)

# Singleton NetworkMonitor initialized with the shared PolicyEngine
network_monitor = NetworkMonitor(policy_engine=policy_engine, interval=2.0)
network_monitor.start()

@monitor_bp.route('/summary', methods=['GET'])
def get_summary():
    """Retrieve complete aggregated real-time dashboard metrics"""
    try:
        summary = network_monitor.get_dashboard_summary()
        return jsonify({
            "success": True,
            "data": summary
        })
    except Exception as e:
        logger.error(f"Error fetching dashboard summary: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@monitor_bp.route('/interfaces', methods=['GET'])
def get_interfaces():
    """Retrieve active network adapters with IP and MAC bindings"""
    try:
        interfaces = network_monitor.get_interfaces()
        return jsonify({
            "success": True,
            "interfaces": interfaces
        })
    except Exception as e:
        logger.error(f"Error fetching interfaces: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@monitor_bp.route('/connections', methods=['GET'])
def get_connections():
    """Retrieve active TCP/UDP sockets with process mapping"""
    try:
        limit = int(request.args.get('limit', 50))
        connections = network_monitor.get_active_connections(limit=limit)
        return jsonify({
            "success": True,
            "count": len(connections),
            "connections": connections
        })
    except Exception as e:
        logger.error(f"Error fetching connections: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@monitor_bp.route('/toggle-auto-heal', methods=['POST'])
def toggle_auto_heal():
    """Toggle automated self-healing remediation on or off"""
    try:
        data = request.get_json(silent=True) or {}
        if "enabled" in data:
            policy_engine.auto_remediate = bool(data["enabled"])
        else:
            policy_engine.auto_remediate = not policy_engine.auto_remediate

        logger.info(f"Auto-remediation master switch set to: {policy_engine.auto_remediate}")
        return jsonify({
            "success": True,
            "auto_remediate": policy_engine.auto_remediate,
            "message": f"Autonomous Self-Healing is now {'ENABLED' if policy_engine.auto_remediate else 'DISABLED (Manual Approval Required)'}"
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
