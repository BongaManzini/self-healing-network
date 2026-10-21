"""
Unit tests for cross-platform OSAdapter.
Verifies Linux, Windows, and Virtual/Fallback modes.
"""

import pytest
from unittest.mock import patch, MagicMock
from src.core.os_adapter import OSAdapter

def test_os_adapter_initialization():
    adapter = OSAdapter()
    info = adapter.get_platform_info()
    assert "os" in info
    assert "is_windows" in info
    assert "is_linux" in info
    assert "elevated" in info
    assert "mode" in info

def test_os_adapter_virtual_block_and_unblock():
    adapter = OSAdapter()
    adapter.has_admin_privileges = False
    
    test_ip = "203.0.113.10"
    res_block = adapter.block_ip(test_ip)
    assert res_block["success"] is True
    assert test_ip in adapter.virtual_blocked_ips
    
    res_unblock = adapter.unblock_ip(test_ip)
    assert res_unblock["success"] is True
    assert test_ip not in adapter.virtual_blocked_ips

def test_os_adapter_virtual_isolation():
    adapter = OSAdapter()
    adapter.has_admin_privileges = False
    
    test_device = "192.168.1.99"
    res_iso = adapter.isolate_device(test_device)
    assert res_iso["success"] is True
    assert test_device in adapter.virtual_isolated_devices
    
    res_restore = adapter.restore_device(test_device)
    assert res_restore["success"] is True
    assert test_device not in adapter.virtual_isolated_devices

def test_os_adapter_dns_healing():
    adapter = OSAdapter()
    res = adapter.flush_and_heal_dns(safe_dns="1.1.1.1")
    assert res["success"] is True
    assert res["safe_dns"] == "1.1.1.1"

def test_os_adapter_arp_healing():
    adapter = OSAdapter()
    res = adapter.flush_and_heal_arp()
    assert res["success"] is True
    assert "ARP" in res["message"]

@patch("subprocess.run")
def test_windows_firewall_command_generation(mock_subproc):
    """Test Windows-specific netsh advfirewall execution"""
    adapter = OSAdapter()
    adapter.is_windows = True
    adapter.is_linux = False
    adapter.has_admin_privileges = True
    
    test_ip = "198.51.100.5"
    res = adapter.block_ip(test_ip)
    
    assert res["success"] is True
    assert mock_subproc.call_count == 2
    # Verify netsh was invoked
    first_call_args = mock_subproc.call_args_list[0][0][0]
    assert "netsh" in first_call_args
    assert "advfirewall" in first_call_args
    assert f"remoteip={test_ip}" in first_call_args

@patch("subprocess.run")
def test_linux_iptables_command_generation(mock_subproc):
    """Test Linux-specific iptables execution"""
    adapter = OSAdapter()
    adapter.is_windows = False
    adapter.is_linux = True
    adapter.has_admin_privileges = True
    
    test_ip = "198.51.100.6"
    res = adapter.block_ip(test_ip)
    
    assert res["success"] is True
    # Verify iptables was invoked
    calls = [c[0][0] for c in mock_subproc.call_args_list]
    iptables_invoked = any("iptables" in cmd for cmd in calls)
    assert iptables_invoked is True
