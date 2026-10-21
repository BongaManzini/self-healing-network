from flask import Blueprint, request, jsonify
from src.actions.firewall_actions import FirewallActions
from src.actions.network_actions import NetworkActions
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Create blueprint for action management
actions_bp = Blueprint('actions', __name__)
firewall_actions = FirewallActions()
network_actions = NetworkActions()

@actions_bp.route('/block-ip', methods=['POST'])
def block_ip():
    """Manually block an IP address"""
    try:
        data = request.get_json()
        ip_address = data.get('ip_address')
        
        if not ip_address:
            return jsonify({
                "success": False,
                "message": "IP address is required"
            }), 400
        
        result = firewall_actions.block_ip(ip_address)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error blocking IP: {str(e)}")
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500

@actions_bp.route('/isolate-device', methods=['POST'])
def isolate_device():
    """Manually isolate a device"""
    try:
        data = request.get_json()
        device_ip = data.get('device_ip')
        
        if not device_ip:
            return jsonify({
                "success": False, 
                "message": "Device IP is required"
            }), 400
        
        result = network_actions.isolate_device(device_ip)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error isolating device: {str(e)}")
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500

@actions_bp.route('/redirect-dns', methods=['POST'])
def redirect_dns():
    """Manually redirect DNS for a device"""
    try:
        data = request.get_json()
        device_ip = data.get('device_ip')
        safe_dns = data.get('safe_dns', '8.8.8.8')
        
        if not device_ip:
            return jsonify({
                "success": False,
                "message": "Device IP is required"
            }), 400
        
        result = network_actions.redirect_dns(device_ip, {'safe_dns': safe_dns})
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error redirecting DNS: {str(e)}")
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500

@actions_bp.route('/status', methods=['GET'])
def get_status():
    """Get current action status"""
    try:
        status = {
            "blocked_ips": list(firewall_actions.blocked_ips),
            "isolated_devices": list(network_actions.isolated_devices),
            "system_status": "operational"
        }
        
        return jsonify({
            "success": True,
            "status": status
        })
        
    except Exception as e:
        logger.error(f"Error getting status: {str(e)}")
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500