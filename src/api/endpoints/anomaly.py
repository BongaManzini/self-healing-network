"""
Anomaly detection and simulation API endpoints.
"""

from flask import Blueprint, request, jsonify
from src.core.policy_engine import PolicyEngine
from src.config.policies import AnomalyType, Severity
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Global singleton policy engine instance to be shared across blueprints
policy_engine = PolicyEngine(auto_remediate=True)

anomaly_bp = Blueprint('anomaly', __name__)

@anomaly_bp.route('/detect', methods=['POST'])
def detect_anomaly():
    """Endpoint for anomaly detection and autonomous self-healing remediation"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "message": "No JSON payload provided"
            }), 400
        
        # Check type (supports 'anomaly_type' or 'type')
        anomaly_type = data.get('anomaly_type') or data.get('type')
        if not anomaly_type:
            return jsonify({
                "success": False,
                "message": "Missing required field: anomaly_type (or type)"
            }), 400

        logger.info(f"Incoming anomaly signal: {anomaly_type}")
        
        # Process the anomaly through self-healing policy engine
        results = policy_engine.evaluate_anomaly(data)
        
        return jsonify({
            "success": results.get("success", True),
            "anomaly_processed": True,
            "results": results
        })
        
    except Exception as e:
        logger.error(f"Error processing anomaly: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Internal server error: {str(e)}"
        }), 500

@anomaly_bp.route('/simulate/<anomaly_type>', methods=['POST'])
def simulate_anomaly(anomaly_type):
    """Simulate different threat types to test autonomous self-healing response"""
    try:
        anomaly_templates = {
            "mitm_attack": {
                "anomaly_type": "mitm_attack",
                "severity": "high",
                "source_ip": "192.168.1.188",
                "target_ip": "192.168.1.55",
                "description": "Simulated ARP Poisoning / MITM Attack",
                "targets": {
                    "malicious_ip": "192.168.1.188",
                    "affected_device": "192.168.1.55",
                    "gateway_ip": "192.168.1.1"
                }
            },
            "dns_attack": {
                "anomaly_type": "dns_attack", 
                "severity": "medium",
                "source_ip": "10.0.0.88",
                "description": "Simulated DNS Cache Poisoning",
                "targets": {
                    "affected_device": "192.168.1.55",
                    "malicious_ip": "10.0.0.88",
                    "malicious_domain": "evil-phishing-portal.com"
                }
            },
            "port_scan": {
                "anomaly_type": "port_scan",
                "severity": "high",
                "source_ip": "198.51.100.42",
                "description": "Simulated Reconnaissance Port Sweep (Targeting ports 21, 22, 80, 443, 3389)",
                "targets": {
                    "malicious_ip": "198.51.100.42"
                }
            },
            "malware": {
                "anomaly_type": "malware",
                "severity": "critical",
                "source_ip": "203.0.113.99",
                "description": "Simulated Trojan / C2 Command Beaconing",
                "targets": {
                    "malicious_ip": "203.0.113.99",
                    "affected_device": "192.168.1.55",
                    "pid": 99999
                }
            },
            "data_exfiltration": {
                "anomaly_type": "data_exfiltration",
                "severity": "critical",
                "source_ip": "192.168.1.55",
                "target_ip": "198.51.100.77",
                "description": "Simulated High-Bandwidth Outbound Data Exfiltration",
                "targets": {
                    "malicious_ip": "198.51.100.77",
                    "affected_device": "192.168.1.55"
                }
            },
            "ddos_flood": {
                "anomaly_type": "ddos_flood",
                "severity": "critical",
                "source_ip": "198.51.100.105",
                "description": "Simulated Volumetric SYN Flood Attack",
                "targets": {
                    "malicious_ip": "198.51.100.105"
                }
            }
        }
        
        normalized_key = anomaly_type.lower().replace("-", "_")
        if normalized_key not in anomaly_templates:
            return jsonify({
                "success": False,
                "message": f"Unknown anomaly simulation type: '{anomaly_type}'. Supported: {list(anomaly_templates.keys())}"
            }), 400
        
        # Use template with optional user payload overrides
        anomaly_data = dict(anomaly_templates[normalized_key])
        custom_data = request.get_json(silent=True) or {}
        anomaly_data.update(custom_data)
        
        # Execute self-healing policy
        results = policy_engine.evaluate_anomaly(anomaly_data)
        
        return jsonify({
            "success": True,
            "anomaly_simulated": normalized_key,
            "results": results
        })
        
    except Exception as e:
        logger.error(f"Error simulating anomaly: {str(e)}")
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500

@anomaly_bp.route('/incidents', methods=['GET'])
def get_incidents():
    """Retrieve security incident history"""
    return jsonify({
        "success": True,
        "incidents": policy_engine.get_incidents(50)
    })

@anomaly_bp.route('/audit', methods=['GET'])
def get_audit():
    """Retrieve audit log of executed self-healing policies"""
    return jsonify({
        "success": True,
        "audit": policy_engine.get_audit_log(50)
    })