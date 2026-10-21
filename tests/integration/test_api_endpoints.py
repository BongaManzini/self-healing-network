"""
Integration tests for Flask Web Dashboard and REST API endpoints.
"""

import pytest
from src.api.routes import create_app
from src.config.settings import Settings

@pytest.fixture
def client():
    config = Settings(ENVIRONMENT="testing")
    app = create_app(config)
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_health_endpoint(client):
    res = client.get('/health')
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["status"] == "healthy"
    assert "timestamp" in json_data

def test_web_dashboard_html_rendering(client):
    res = client.get('/')
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "AEGIS" in html
    assert "Self-Healing Network" in html
    assert "Autonomous Self-Healing" in html

def test_api_directory_endpoint(client):
    res = client.get('/api')
    assert res.status_code == 200
    json_data = res.get_json()
    assert "endpoints" in json_data

def test_anomaly_detect_endpoint(client):
    payload = {
        "anomaly_type": "port_scan",
        "severity": "high",
        "source_ip": "198.51.100.80",
        "targets": {"malicious_ip": "198.51.100.80"}
    }
    res = client.post('/api/anomaly/detect', json=payload)
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["success"] is True
    assert json_data["results"]["healed"] is True

def test_anomaly_simulate_endpoint(client):
    for threat in ["mitm_attack", "dns_attack", "port_scan", "malware", "data_exfiltration", "ddos_flood"]:
        res = client.post(f'/api/anomaly/simulate/{threat}', json={})
        assert res.status_code == 200
        json_data = res.get_json()
        assert json_data["success"] is True
        assert json_data["anomaly_simulated"] == threat

def test_monitor_summary_endpoint(client):
    res = client.get('/api/monitor/summary')
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["success"] is True
    assert "health" in json_data["data"]

def test_actions_block_and_unblock(client):
    # Block
    block_res = client.post('/api/actions/block-ip', json={"ip_address": "198.51.100.99"})
    assert block_res.status_code == 200
    assert block_res.get_json()["success"] is True
    
    # Check status
    status_res = client.get('/api/actions/status')
    assert status_res.status_code == 200
    assert "198.51.100.99" in status_res.get_json()["status"]["blocked_ips"]
    
    # Unblock
    unblock_res = client.post('/api/actions/unblock-ip', json={"ip_address": "198.51.100.99"})
    assert unblock_res.status_code == 200
    assert unblock_res.get_json()["success"] is True

def test_actions_isolate_and_restore(client):
    # Isolate
    iso_res = client.post('/api/actions/isolate-device', json={"device_ip": "192.168.1.150"})
    assert iso_res.status_code == 200
    
    # Restore
    rest_res = client.post('/api/actions/restore-device', json={"device_ip": "192.168.1.150"})
    assert rest_res.status_code == 200

def test_actions_flush_dns_and_arp(client):
    dns_res = client.post('/api/actions/flush-dns', json={"safe_dns": "1.1.1.1"})
    assert dns_res.status_code == 200
    
    arp_res = client.post('/api/actions/heal-arp', json={})
    assert arp_res.status_code == 200
