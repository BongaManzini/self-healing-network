"""
Action management API endpoints for manual remediation, firewall rules, and self-healing overrides.
"""

from flask import Blueprint, request, jsonify
from src.api.endpoints.anomaly import policy_engine
from src.utils.logger import get_logger

logger = get_logger(__name__)

actions_bp = Blueprint('actions', __name__)
dispatcher = policy_engine.action_dispatcher
firewall_actions = dispatcher.firewall
network_actions = dispatcher.network
device_actions = dispatcher.device

@actions_bp.route('/block-ip', methods=['POST'])
def block_ip():
    """Manually block an IP address across Linux / Windows"""
    try:
        data = request.get_json() or {}
        ip_address = data.get('ip_address') or data.get('ip')
        
        if not ip_address:
            return jsonify({
                "success": False,
                "message": "Field 'ip_address' is required"
            }), 400
        
        result = firewall_actions.block_ip(ip_address, parameters=data)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error blocking IP: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@actions_bp.route('/unblock-ip', methods=['POST'])
def unblock_ip():
    """Manually unblock an IP address"""
    try:
        data = request.get_json() or {}
        ip_address = data.get('ip_address') or data.get('ip')
        
        if not ip_address:
            return jsonify({
                "success": False,
                "message": "Field 'ip_address' is required"
            }), 400
        
        result = firewall_actions.unblock_ip(ip_address)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error unblocking IP: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@actions_bp.route('/isolate-device', methods=['POST'])
def isolate_device():
    """Manually quarantine a device to prevent lateral movement"""
    try:
        data = request.get_json() or {}
        device_ip = data.get('device_ip') or data.get('ip')
        
        if not device_ip:
            return jsonify({
                "success": False, 
                "message": "Field 'device_ip' is required"
            }), 400
        
        result = network_actions.isolate_device(device_ip, parameters=data)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error isolating device: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@actions_bp.route('/restore-network', methods=['POST'])
@actions_bp.route('/restore-device', methods=['POST'])
def restore_network():
    """Lift quarantine and restore network access for device or all devices"""
    try:
        data = request.get_json(silent=True) or {}
        device_ip = data.get('device_ip') or data.get('ip')
        
        if device_ip:
            result = network_actions.remove_isolation(device_ip, parameters=data)
            return jsonify(result)
        else:
            # Restore all currently quarantined devices
            isolated = list(network_actions.isolated_devices)
            restored = []
            for dev in isolated:
                network_actions.remove_isolation(dev)
                restored.append(dev)
            return jsonify({
                "success": True,
                "message": f"Restored all {len(restored)} quarantined devices",
                "restored_devices": restored
            })
            
    except Exception as e:
        logger.error(f"Error restoring network: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@actions_bp.route('/redirect-dns', methods=['POST'])
@actions_bp.route('/flush-dns', methods=['POST'])
def flush_or_redirect_dns():
    """Trigger DNS self-healing and cache purge"""
    try:
        data = request.get_json(silent=True) or {}
        device_ip = data.get('device_ip', 'local_host')
        safe_dns = data.get('safe_dns', '1.1.1.1')
        result = network_actions.redirect_dns(device_ip, {'safe_dns': safe_dns})
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error handling DNS healing: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@actions_bp.route('/heal-arp', methods=['POST'])
def heal_arp():
    """Purge ARP cache to neutralize ARP spoofing / MITM"""
    try:
        data = request.get_json(silent=True) or {}
        gateway_ip = data.get('gateway_ip')
        result = network_actions.heal_arp(gateway_ip=gateway_ip)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error healing ARP: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@actions_bp.route('/terminate-process', methods=['POST'])
def terminate_process():
    """Kill a malicious process by PID"""
    try:
        data = request.get_json() or {}
        pid = int(data.get('pid', 0))
        if pid <= 0:
            return jsonify({"success": False, "message": "Valid 'pid' parameter is required"}), 400
        result = device_actions.terminate_process(pid, parameters=data)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error terminating process: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@actions_bp.route('/status', methods=['GET'])
def get_status():
    """Get active firewall blocks, quarantined devices, and OS details"""
    try:
        platform_info = dispatcher.os_adapter.get_platform_info()
        status = {
            "blocked_ips": list(firewall_actions.blocked_ips),
            "isolated_devices": list(network_actions.isolated_devices),
            "system_status": "operational",
            "platform": platform_info,
            "auto_remediate": policy_engine.auto_remediate
        }
        
        return jsonify({
            "success": True,
            "status": status
        })
        
    except Exception as e:
        logger.error(f"Error getting status: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500