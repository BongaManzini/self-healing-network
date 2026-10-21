"""
Unit tests for NetworkMonitor and real-time telemetry.
"""

import pytest
from src.core.monitor import NetworkMonitor
from src.core.policy_engine import PolicyEngine

def test_network_monitor_sampling():
    engine = PolicyEngine()
    monitor = NetworkMonitor(policy_engine=engine, interval=1.0)
    
    metrics = monitor._sample_metrics()
    assert "timestamp" in metrics
    assert "bytes_sent_rate" in metrics
    assert "bytes_recv_rate" in metrics
    assert "packets_sent_rate" in metrics
    assert "total_connections" in metrics
    assert len(monitor.traffic_history) >= 1

def test_network_monitor_interfaces():
    monitor = NetworkMonitor()
    ifaces = monitor.get_interfaces()
    assert isinstance(ifaces, list)
    if len(ifaces) > 0:
        first = ifaces[0]
        assert "name" in first
        assert "ip" in first

def test_network_monitor_dashboard_summary():
    engine = PolicyEngine()
    monitor = NetworkMonitor(policy_engine=engine)
    summary = monitor.get_dashboard_summary()
    
    assert "health" in summary
    assert "platform" in summary
    assert "current_traffic" in summary
    assert "history" in summary
    assert "blocked_ips" in summary
    assert "isolated_devices" in summary
