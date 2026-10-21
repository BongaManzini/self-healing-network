"""
Unit tests for PolicyEngine and self-healing orchestration.
"""

import pytest
from src.core.policy_engine import PolicyEngine
from src.config.policies import AnomalyType, Severity

def test_policy_engine_mitm_self_healing():
    engine = PolicyEngine(auto_remediate=True)
    anomaly_data = {
        "anomaly_type": "mitm_attack",
        "severity": "high",
        "source_ip": "192.168.1.188",
        "target_ip": "192.168.1.55",
        "targets": {
            "malicious_ip": "192.168.1.188",
            "gateway_ip": "192.168.1.1"
        }
    }
    
    result = engine.evaluate_anomaly(anomaly_data)
    assert result["success"] is True
    assert result["healed"] is True
    assert len(result["actions"]) > 0
    
    # Check that block_ip and heal_arp were executed
    action_types = [a["action"] for a in result["actions"]]
    assert "block_ip" in action_types
    assert "heal_arp" in action_types
    
    # Check that IP is blocked in firewall
    assert "192.168.1.188" in engine.action_dispatcher.firewall.blocked_ips

def test_policy_engine_dns_attack_self_healing():
    engine = PolicyEngine(auto_remediate=True)
    anomaly_data = {
        "anomaly_type": "dns_attack",
        "severity": "medium",
        "source_ip": "10.0.0.99",
        "targets": {
            "affected_device": "192.168.1.55"
        }
    }
    
    result = engine.evaluate_anomaly(anomaly_data)
    assert result["success"] is True
    assert result["healed"] is True
    action_types = [a["action"] for a in result["actions"]]
    assert "redirect_dns" in action_types

def test_policy_engine_health_score_tracking():
    engine = PolicyEngine(auto_remediate=True)
    initial_health = engine.get_health_score()
    assert initial_health["score"] == 100
    assert initial_health["status"] == "healthy"
    
    # Simulate attack
    engine.evaluate_anomaly({
        "anomaly_type": "port_scan",
        "severity": "high",
        "source_ip": "198.51.100.22"
    })
    
    health_after = engine.get_health_score()
    assert health_after["total_detected"] == 1
    assert health_after["total_healed"] == 1

def test_policy_engine_manual_mode():
    engine = PolicyEngine(auto_remediate=False)
    result = engine.evaluate_anomaly({
        "anomaly_type": "port_scan",
        "severity": "medium",
        "source_ip": "198.51.100.33"
    })
    
    assert result["auto_remediated"] is False
    assert result["status"] == "pending_manual_approval"
    assert len(engine.pending_remediations) == 1
