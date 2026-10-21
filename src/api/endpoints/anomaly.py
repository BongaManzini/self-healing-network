from flask import Blueprint, request, jsonify
from src.core.policy_engine import PolicyEngine
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Create blueprint for anomaly endpoints
anomaly_bp = Blueprint('anomaly', __name__)
policy_engine = PolicyEngine()

@anomaly_bp.route('/detect', methods=['POST'])
def detect_anomaly():
    """Endpoint for anomaly detection and automatic remediation"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "success": False,
                "message": "No data provided"
            }), 400
        
        # Validate required fields
        required_fields = ['anomaly_type', 'severity', 'source_ip']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    "success": False,
                    "message": f"Missing required field: {field}"
                }), 400
        
        logger.info(f"Received anomaly detection request: {data['anomaly_type']}")
        
        # Process the anomaly through policy engine
        results = policy_engine.evaluate_anomaly(data)
        
        return jsonify({
            "success": True,
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
    """Simulate different types of anomalies for testing"""
    try:
        # Sample anomaly data for different types
        anomaly_templates = {
            "mitm_attack": {
                "anomaly_type": "mitm_attack",
                "severity": "high",
                "source_ip": "192.168.1.100",
                "target_ip": "192.168.1.50",
                "description": "Potential MITM attack detected",
                "targets": {
                    "malicious_ip": "192.168.1.100",
                    "affected_device": "192.168.1.50"
                }
            },
            "dns_attack": {
                "anomaly_type": "dns_attack", 
                "severity": "medium",
                "source_ip": "192.168.1.101",
                "description": "DNS poisoning attempt detected",
                "targets": {
                    "affected_device": "192.168.1.101",
                    "malicious_domain": "malicious-site.com"
                }
            },
            "port_scan": {
                "anomaly_type": "port_scan",
                "severity": "medium",
                "source_ip": "192.168.1.102",
                "description": "Port scanning activity detected",
                "targets": {
                    "malicious_ip": "192.168.1.102"
                }
            }
        }
        
        if anomaly_type not in anomaly_templates:
            return jsonify({
                "success": False,
                "message": f"Unknown anomaly type: {anomaly_type}"
            }), 400
        
        # Use the template and allow override via request body
        anomaly_data = anomaly_templates[anomaly_type]
        custom_data = request.get_json() or {}
        anomaly_data.update(custom_data)
        
        # Process the simulated anomaly
        results = policy_engine.evaluate_anomaly(anomaly_data)
        
        return jsonify({
            "success": True,
            "anomaly_simulated": anomaly_type,
            "results": results
        })
        
    except Exception as e:
        logger.error(f"Error simulating anomaly: {str(e)}")
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500