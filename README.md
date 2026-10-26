# AEGIS // Self-Healing Network Defense & Real-Time Monitor

> **Cross-Platform Autonomous Intrusion Detection, Self-Healing Remediation, and Web Operations Dashboard for Linux and Windows.**

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Cross-Platform Architecture (Linux & Windows)](#cross-platform-architecture-linux--windows)
- [Web Alternative (Dashboard)](#web-alternative-dashboard)
- [Self-Healing Action Chains](#self-healing-action-chains)
- [Installation & Quickstart](#installation--quickstart)
- [API Reference](#api-reference)
- [Testing](#testing)
- [License](#license)

---

## Overview

**AEGIS Self-Healing Network** is an intelligent, autonomous network security and monitoring system designed to defend enterprise hosts and subnets. When an intrusion is detected (e.g. ARP poisoning/MITM, DNS spoofing, port scans, malware C2 communication, or data exfiltration), the system **automatically self-heals**:

1. **Drops attacker traffic** instantly at the host firewall (`iptables` on Linux, `netsh advfirewall` on Windows).
2. **Purges poisoned network caches** (flushes ARP neighbor tables and resets DNS resolvers to trusted upstreams like `1.1.1.1` or `8.8.8.8`).
3. **Quarantines compromised devices** to stop lateral threat traversal.
4. **Terminates unauthorized processes and rogue listening sockets**.
5. **Restores healthy baseline operations** and computes live dynamic network health scores.

In addition to headless CLI and REST API control, the system features a **built-in Cyber-Defense Web Alternative** providing real-time telemetry, live charts, an interactive attack simulator, and manual remediation tools.

---

## Key Features

- **Cross-Platform Enforcer** — Native, elevated firewall and networking controls for both **Linux** (via `iptables`, `ip neigh`, `resolvectl`) and **Windows** (via `netsh advfirewall`, `ipconfig /flushdns`, `arp -d *`, PowerShell). Includes safe **Virtual Mode** fallback for unprivileged environments.
- **Autonomous Self-Healing** — Sub-second policy-driven remediation chains execute without waiting for human intervention.
- **Real-Time Network Monitoring (IDS)** — Continuous sampling of network interface bandwidth (KB/s in/out), active TCP/UDP connections, process PID mapping, and heuristic anomaly detection.
- **Web Dashboard Alternative** — Futuristic, responsive web operations console with SVG health gauge, Chart.js time-series graphs, and interactive test triggers.
- **One-Click Attack & Healing Simulator** — Directly test defense reactions to MITM attacks, port scans, DNS poisoning, malware beacons, data exfiltration bursts, and volumetric floods.
- **Dynamic Network Health Score** — Live 0–100% health calculation that reacts to threats in real time and verifies recovery once remediated.
- **Emergency Remediation Toolbox** — One-click DNS healing, ARP table purging, mass unblock, and process termination.

---

## Cross-Platform Architecture (Linux & Windows)

The system abstracts OS operations into a unified `OSAdapter` layer:

| Security Action | Linux Implementation | Windows Implementation | Virtual / Safe Fallback |
|---|---|---|---|
| **Block IP** | `iptables -A INPUT/OUTPUT -s <ip> -j DROP` | `netsh advfirewall firewall add rule ... action=block` | In-memory blacklist + virtual packet filter |
| **Quarantine Host** | `iptables -A FORWARD -s <ip> -j DROP` | `netsh advfirewall firewall add rule ...` | Virtual quarantine table |
| **Heal DNS Cache** | `resolvectl flush-caches` / `systemd-resolve` | `ipconfig /flushdns` | Virtual resolver reset |
| **Heal ARP (MITM)** | `ip neigh flush all` / `arp -d` | `arp -d *` | Virtual ARP table purge |
| **Kill Rogue Process** | `psutil` terminate/kill or `kill -9 <pid>` | `psutil` terminate/kill or `taskkill /F /PID` | Process signal dispatch |

---

## Web Alternative (Dashboard)

The web dashboard is served directly by the application at:
```
http://localhost:5000/
```

### Dashboard Capabilities:
1. **Live Network Health Gauge**: Visual SVG radial meter with status badges (`HEALTHY`, `ELEVATED / CONTAINED`, `CRITICAL INTRUSION`).
2. **Throughput Graph**: Real-time Chart.js streaming inbound/outbound transfer rates and packet counters.
3. **Attack & Healing Simulator**: Buttons to trigger simulated intrusions and view automated remediation in real time.
4. **Incidents & Audit Log**: Chronological record of threats, target IPs, policy steps, and remediation timestamps.
5. **Firewall & Quarantine Tables**: Real-time view of currently blocked IPs and quarantined nodes with one-click unblock/restore.
6. **Network Adapters & Active Sockets**: Live inspection of active interfaces and TCP/UDP connections mapped to process PIDs.

---

## Self-Healing Action Chains

| Threat Type | Default Severity | Automated Self-Healing Chain |
|---|---|---|
| **ARP Poisoning / MITM** | High / Critical | `Block Attacker IP` → `Purge & Heal ARP Cache` → `Isolate Affected Node` → `Alert Admin` |
| **DNS Poisoning** | Medium / High | `Flush DNS Cache` → `Assert Safe Upstream (1.1.1.1)` → `Block Rogue Resolver` → `Alert Admin` |
| **Port Scan Sweep** | Medium / High | `Drop Attacker IP in Firewall` → `Apply Port Lockdown Rule` → `Alert Admin` |
| **Malware C2 Beacon** | Critical | `Kill Rogue Process PID` → `Block C2 Destination IP` → `Quarantine Host` → `Alert Admin` |
| **Data Exfiltration** | Critical | `Blackhole Remote Destination IP` → `Throttle & Quarantine Node` → `Alert Admin` |
| **SYN / Connection Flood** | Critical | `Volumetric Firewall Blacklist` → `Drop Inbound Sockets` → `Alert Admin` |

---

## Installation & Quickstart

### 1. Set Up Environment

```bash
cd Self-Healing-Network

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate    # On Windows: .\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Start the Self-Healing System & Web Dashboard

```bash
python src/main.py
```

Console Output:
```
========================================================================
    🛡️  AEGIS: Self-Healing Network Defense & Monitor System
========================================================================
 [•] Operating System : Linux / Windows
 [•] Python Runtime   : 3.12+
 [•] Web Dashboard    : http://localhost:5000/
 [•] REST API Index   : http://localhost:5000/api
 [•] Auto-Remediation : ENABLED (Sub-second Self-Healing)
========================================================================
```

Open your browser to `http://localhost:5000` to access the Cyber-Defense Web Operations Dashboard.

---

## API Reference

### Real-Time Monitoring & Telemetry
- `GET /api/monitor/summary` — Full aggregated metrics, health score, platform info, and history.
- `GET /api/monitor/interfaces` — Enumerate active network adapters (IP, Netmask, MAC, Link State).
- `GET /api/monitor/connections` — List active sockets with process PID and blocked status.
- `POST /api/monitor/toggle-auto-heal` — Toggle autonomous remediation master switch (ON/OFF).

### Threat Detection & Simulation
- `POST /api/anomaly/detect` — Ingest anomaly signal and trigger autonomous self-healing.
- `POST /api/anomaly/simulate/<type>` — Simulate attack (`mitm_attack`, `dns_attack`, `port_scan`, `malware`, `data_exfiltration`, `ddos_flood`).
- `GET /api/anomaly/incidents` — Retrieve incident history and remediation results.
- `GET /api/anomaly/audit` — Retrieve complete remediation audit logs.

### Remediation & Firewall Overrides
- `POST /api/actions/block-ip` — Drop IP address across Linux (`iptables`) / Windows (`netsh`).
- `POST /api/actions/unblock-ip` — Remove firewall block rule.
- `POST /api/actions/isolate-device` — Quarantine a compromised device from local subnets.
- `POST /api/actions/restore-device` — Lift quarantine for a device.
- `POST /api/actions/restore-network` — Restore all quarantined nodes.
- `POST /api/actions/flush-dns` — Flush DNS cache and force verified safe DNS resolvers.
- `POST /api/actions/heal-arp` — Clear poisoned ARP entries to neutralize MITM.
- `POST /api/actions/terminate-process` — Terminate malicious process by PID.
- `GET /api/actions/status` — Current firewall and quarantine status.

### C++ Network Monitor Sensor Integration
- `POST /api/integrations/cpp-monitor/alert` — Ingest threat alert from C++ Network Monitor sensor (Linux/Windows) and trigger autonomous self-healing.
- `POST /api/integrations/cpp-monitor/telemetry` — Ingest heartbeat, packet count, and bandwidth metrics from C++ sensor.
- `GET /api/integrations/cpp-monitor/status` — Query connection health, active C++ agents, and recent alerts.
- `GET /api/integrations/cpp-monitor/sync-rules` — Provide active firewall blocked IPs and policies to synchronize C++ monitor in-memory blacklists.
- `POST /api/integrations/cpp-monitor/simulate-alert` — Trigger synthetic alert to test C++ integration pipeline from web UI or scripts.

---

## Testing

Run the full automated test suite covering unit operations and API integration:

```bash
./venv/bin/pytest tests/ -v
```

Output:
```
tests/integration/test_api_endpoints.py::test_health_endpoint PASSED
tests/integration/test_api_endpoints.py::test_web_dashboard_html_rendering PASSED
tests/integration/test_api_endpoints.py::test_api_directory_endpoint PASSED
tests/integration/test_api_endpoints.py::test_anomaly_detect_endpoint PASSED
tests/integration/test_api_endpoints.py::test_anomaly_simulate_endpoint PASSED
tests/integration/test_api_endpoints.py::test_monitor_summary_endpoint PASSED
tests/integration/test_api_endpoints.py::test_actions_block_and_unblock PASSED
tests/integration/test_api_endpoints.py::test_actions_isolate_and_restore PASSED
tests/integration/test_api_endpoints.py::test_actions_flush_dns_and_arp PASSED
tests/unit/test_monitor.py::test_network_monitor_sampling PASSED
tests/unit/test_monitor.py::test_network_monitor_interfaces PASSED
tests/unit/test_monitor.py::test_network_monitor_dashboard_summary PASSED
tests/unit/test_os_adapter.py::test_os_adapter_initialization PASSED
tests/unit/test_os_adapter.py::test_os_adapter_virtual_block_and_unblock PASSED
tests/unit/test_os_adapter.py::test_os_adapter_virtual_isolation PASSED
tests/unit/test_os_adapter.py::test_os_adapter_dns_healing PASSED
tests/unit/test_os_adapter.py::test_os_adapter_arp_healing PASSED
tests/unit/test_os_adapter.py::test_windows_firewall_command_generation PASSED
tests/unit/test_os_adapter.py::test_linux_iptables_command_generation PASSED
tests/unit/test_policy_engine.py::test_policy_engine_mitm_self_healing PASSED
tests/unit/test_policy_engine.py::test_policy_engine_dns_attack_self_healing PASSED
tests/unit/test_policy_engine.py::test_policy_engine_health_score_tracking PASSED
tests/unit/test_policy_engine.py::test_policy_engine_manual_mode PASSED

============================== 23 passed in 0.88s ==============================
```

---

## License

MIT License. Copyright (c) 2024–2026 Self-Healing Network Contributors.