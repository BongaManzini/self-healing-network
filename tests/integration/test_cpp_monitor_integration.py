"""
Integration tests for C++ Network Monitor and AEGIS Self-Healing integration.
Tests telemetry ingestion, threat alerting, dynamic blacklist sync, and autonomous healing.
"""

import pytest
from src.api.routes import create_app
from src.config.settings import Settings
from src.integrations.cpp_monitor import cpp_monitor_manager

@pytest.fixture
def client():
    settings = Settings(ENVIRONMENT="testing", AUTO_REMEDIATE=True)
    app = create_app(settings)
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_cpp_monitor_status_initial(client):
    """Test C++ monitor status query when initialized"""
    res = client.get("/api/integrations/cpp-monitor/status")
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["success"] is True
    data = json_data["data"]
    assert "is_connected" in data
    assert "total_packets_ingested" in data
    assert "total_threats_reported" in data

def test_cpp_monitor_heartbeat_and_telemetry(client):
    """Test heartbeat registration from Linux and Windows C++ agent"""
    payload = {
        "monitor_id": "cpp-sensor-linux-01",
        "platform": "Linux",
        "active_interface": "eth0",
        "packets_captured": 1250,
        "bytes_captured": 850200,
        "threats_detected": 2,
        "bandwidth_kbps": 34.8,
        "uptime_seconds": 95.0
    }
    res = client.post("/api/integrations/cpp-monitor/telemetry", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["status"] == "acknowledged"

    # Verify status reflects the connected agent
    status_res = client.get("/api/integrations/cpp-monitor/status")
    status_data = status_res.get_json()["data"]
    assert status_data["is_connected"] is True
    assert status_data["connected_count"] >= 1
    assert status_data["total_packets_ingested"] >= 1250
    assert status_data["primary_monitor"]["platform"] == "Linux"

def test_cpp_monitor_alert_triggers_self_healing(client):
    """
    Test that an incoming intrusion alert from C++ monitor triggers
    sub-second automated self-healing in AEGIS (blocking attacker in firewall).
    """
    attacker_ip = "198.51.100.99"
    target_ip = "192.168.1.55"
    alert_payload = {
        "monitor_id": "cpp-sensor-linux-01",
        "platform": "Linux",
        "threat_type": "port_scan",
        "severity": "high",
        "source_ip": attacker_ip,
        "target_ip": target_ip,
        "description": "Rapid TCP SYN probe sweep detected across 24 ports in 2.1s"
    }

    res = client.post("/api/integrations/cpp-monitor/alert", json=alert_payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["self_healed"] is True
    assert "incident_id" in data
    assert len(data["actions_executed"]) > 0

    # Verify attacker IP was actually blocked in AEGIS firewall
    sync_res = client.get("/api/integrations/cpp-monitor/sync-rules")
    sync_data = sync_res.get_json()
    assert sync_data["success"] is True
    assert attacker_ip in sync_data["blocked_ips"]

def test_cpp_monitor_mitm_alert_heals_arp_and_firewall(client):
    """
    Test that a MITM alert from C++ monitor triggers ARP purging and firewall blocking.
    """
    mitm_attacker = "192.168.1.189"
    alert_payload = {
        "monitor_id": "cpp-sensor-win-01",
        "platform": "Windows",
        "threat_type": "mitm_attack",
        "severity": "high",
        "source_ip": mitm_attacker,
        "target_ip": "192.168.1.1",
        "description": "Suspicious ARP spoofing burst claiming gateway IP"
    }

    res = client.post("/api/integrations/cpp-monitor/alert", json=alert_payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["self_healed"] is True
    actions = [a.get("action") for a in data["actions_executed"]]
    assert "block_ip" in actions
    assert "heal_arp" in actions

def test_cpp_monitor_sync_rules_endpoint(client):
    """Test that C++ monitor can retrieve active firewall blocklist for sync"""
    res = client.get("/api/integrations/cpp-monitor/sync-rules")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert isinstance(data["blocked_ips"], list)
    assert "suggested_thresholds" in data
    assert data["suggested_thresholds"]["port_scan_packets"] == 10

def test_cpp_monitor_simulate_endpoint(client):
    """Test simulated alert endpoint used for testing from UI or CLI"""
    res = client.post("/api/integrations/cpp-monitor/simulate-alert", json={
        "threat_type": "port_scan",
        "source_ip": "198.51.100.111"
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["self_healed"] is True
