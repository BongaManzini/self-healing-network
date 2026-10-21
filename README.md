# Self-Healing Network – AI-Powered Network Security & Auto-Remediation

> An intelligent, policy-driven network security system that automatically detects, classifies, and remediates network anomalies in real time — with no manual intervention required.

---

## Table of Contents

- [Description](#description)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Architecture Overview](#architecture-overview)
- [API Reference](#api-reference)
- [Policy System](#policy-system)
- [AI Integration](#ai-integration)
- [Security Considerations](#security-considerations)
- [License](#license)

---

## Description

**Self-Healing Network** is a Python-based, AI-ready network security platform built on Flask. It continuously monitors network activity and, upon detecting a threat, automatically executes a policy-defined remediation sequence — blocking malicious IPs, isolating compromised devices, redirecting DNS traffic, and updating firewall rules — all without waiting for human input.

The system is designed to be modular: plug in any AI/ML model for anomaly detection (TensorFlow, PyTorch, scikit-learn), configure your network devices, and deploy to any Linux environment with administrative network access.

---

## Features

### Core Capabilities

- **Real-Time Anomaly Detection** — Policy-driven classification of network threats including MITM attacks, DNS poisoning, port scanning, malware activity, and data exfiltration
- **Automated Remediation** — Instant, multi-step response sequences executed the moment a threat is confirmed
- **Policy Engine** — Flexible, severity-aware remediation policies that map each threat type to a targeted action chain
- **Audit Trail** — Full execution history logged per incident for compliance and post-incident review
- **Self-Learning Ready** — Architecture designed to integrate online learning and feedback loops for continuous model improvement
- **Flask-Native** — Exposes a clean REST API; can run standalone or be embedded into any existing Flask application as a Blueprint or extension

### Security Actions

| Action | Description |
|---|---|
| **Block IP** | Drops traffic from a malicious IP via `iptables` |
| **Isolate Device** | Quarantines a compromised device at the network layer using `iptables FORWARD` rules |
| **Redirect DNS** | NAT-redirects DNS queries from a device to a safe resolver (e.g. `8.8.8.8`) |
| **Update Firewall** | Applies dynamic rule changes on managed firewall devices via SSH (Paramiko/Netmiko) |
| **Device Reboot** | Remotely reboots a compromised device via SSH |
| **Clear Cache** | Clears device ARP/DNS cache to neutralise poisoning attacks |
| **Alert Admin** | Notifies the security team of detected and actioned incidents |

### Threat Coverage

| Anomaly Type | Default Severity | Actions Triggered |
|---|---|---|
| MITM Attack | High | Block IP → Isolate Device → Update Firewall → Alert Admin |
| DNS Attack | Medium | Redirect DNS → Block Domain → Alert Admin |
| Port Scan | Medium | Block IP → Update Firewall Rules |
| Malware | Critical | Isolate Device → Block IP → Reboot Device |
| Data Exfiltration | High | Isolate Device → Block IP → Alert Admin |

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Language** | Python 3.8+ |
| **Web Framework** | Flask 2.3 · Werkzeug 2.3 |
| **Production Server** | Waitress (Windows/Linux) · Gunicorn (Linux) |
| **Network Operations** | Scapy 2.5 · Paramiko 3.2 · Netmiko 4.1 |
| **Data Processing** | NumPy 1.24 · Pandas 2.0 |
| **Configuration** | python-dotenv |
| **Testing** | pytest 7.4 · pytest-flask |
| **AI/ML** | Pluggable — TensorFlow, PyTorch, or scikit-learn (not bundled) |

---

## Prerequisites

### System Requirements

- **OS:** Linux (Ubuntu 18.04+) or macOS
- **Python:** 3.8 or higher
- **RAM:** 4 GB minimum (8 GB recommended)
- **Disk:** 2 GB free space
- **Privileges:** Root / `sudo` access required for `iptables` and network device operations

### Network Requirements

- Administrative access to managed firewalls and switches
- Permission to modify `iptables` / `nftables` rules on the host
- DNS server access for query redirection
- SSH connectivity to managed network devices (for Netmiko/Paramiko actions)

---

## Installation

### Option A — Automated Setup

```bash
# 1. Clone the repository
git clone <repository-url>
cd self-healing-network

# 2. Run the setup script
chmod +x scripts/setup_environment.sh
./scripts/setup_environment.sh

# 3. Activate the virtual environment
source venv/bin/activate

# 4. Start the application
python src/main.py
```

### Option B — Manual Setup

```bash
# 1. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Create required runtime directories
mkdir -p data/{logs,backups,pcap_storage,models}

# 4. Copy and configure environment variables
cp .env.example .env   # then edit .env with your values

# 5. Start the application
python src/main.py
```

---

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Application
ENVIRONMENT=development       # development | production
HOST=0.0.0.0
PORT=5000
SECRET_KEY=your-secret-key-here

# Network Device Credentials
FIREWALL_USER=admin
FIREWALL_PASS=your-firewall-password
SWITCH_USER=admin
SWITCH_PASS=your-switch-password

# DNS
DEFAULT_DNS=8.8.8.8
BACKUP_DNS=1.1.1.1

# Behaviour
AUTO_REMEDIATE=true           # Execute actions automatically
REQUIRE_APPROVAL=false        # Require human approval before acting
LOG_LEVEL=INFO
```

### Network Device Configuration

Edit [`src/config/settings.py`](src/config/settings.py) to describe your network topology:

```python
NETWORK_DEVICES = {
    "firewall": {
        "ip": "192.168.1.1",
        "type": "cisco_asa",          # generic | cisco_asa | cisco_catalyst | …
        "credentials": {
            "username": os.getenv("FIREWALL_USER"),
            "password": os.getenv("FIREWALL_PASS")
        }
    },
    "switch": {
        "ip": "192.168.1.2",
        "type": "cisco_catalyst",
        "credentials": {
            "username": os.getenv("SWITCH_USER"),
            "password": os.getenv("SWITCH_PASS")
        }
    }
}
```

---

## Usage

### Starting the Application

```bash
# Development mode (Flask dev server, auto-reload)
python src/main.py

# Production mode (Waitress — set in .env)
ENVIRONMENT=production python src/main.py

# Production mode (Gunicorn — Linux only)
gunicorn -w 4 -b 0.0.0.0:5000 "src.main:create_app()"
```

The API will be available at `http://localhost:5000`.

### Quick Smoke Test

```bash
# Health check
curl http://localhost:5000/health

# API index (lists all endpoints)
curl http://localhost:5000/
```

---

## Architecture Overview

```
self-healing-network/
├── src/
│   ├── main.py                  # Application entry point
│   ├── api/
│   │   ├── routes.py            # Flask app factory & blueprint registration
│   │   └── endpoints/
│   │       ├── anomaly.py       # POST /api/anomaly/detect, /simulate/*
│   │       └── actions.py       # POST /api/actions/*, GET /api/actions/status
│   ├── core/
│   │   └── policy_engine.py     # Anomaly evaluation & policy execution loop
│   ├── config/
│   │   ├── settings.py          # Application & device configuration (dataclass)
│   │   └── policies.py          # Remediation policies, AnomalyType & Severity enums
│   ├── actions/
│   │   ├── network_actions.py   # iptables isolation, DNS redirection
│   │   ├── firewall_actions.py  # SSH-based firewall rule management
│   │   └── device_actions.py    # Remote device reboot & cache clearing
│   └── utils/
│       └── logger.py            # Structured logging setup
├── scripts/
│   └── setup_environment.sh     # Automated environment bootstrap
├── data/                        # Runtime data (excluded from version control)
│   ├── logs/
│   ├── models/
│   ├── pcap_storage/
│   └── backups/
├── requirements.txt
└── .env                         # Local secrets (excluded from version control)
```

### Request Flow

```
Incoming Threat Signal
        │
        ▼
  POST /api/anomaly/detect
        │
        ▼
  PolicyEngine.evaluate_anomaly()
   ├── Parse anomaly_type + severity
   ├── Look up RemediationPolicy
   └── Execute action chain via ActionDispatcher
            ├── NetworkActions  (iptables, DNS NAT)
            ├── FirewallActions (SSH → firewall device)
            └── DeviceActions   (SSH → endpoint device)
        │
        ▼
  Audit log + JSON response
```

---

## API Reference

### Anomaly Endpoints — `/api/anomaly`

```bash
# Detect and remediate an anomaly
POST /api/anomaly/detect
Content-Type: application/json

{
  "type": "mitm_attack",          # mitm_attack | dns_attack | port_scan | malware | data_exfiltration
  "severity": "high",             # low | medium | high | critical
  "targets": {
    "malicious_ip": "192.168.1.100",
    "affected_device": "192.168.1.50"
  }
}

# Simulate attacks (for testing)
POST /api/anomaly/simulate/mitm_attack
POST /api/anomaly/simulate/dns_attack
POST /api/anomaly/simulate/port_scan
```

### Action Endpoints — `/api/actions`

```bash
# Block a specific IP
POST /api/actions/block-ip
{ "ip_address": "192.168.1.100" }

# Isolate a device
POST /api/actions/isolate-device
{ "device_ip": "192.168.1.50" }

# Redirect DNS
POST /api/actions/redirect-dns
{ "device_ip": "192.168.1.75", "safe_dns": "8.8.8.8" }

# Remove device isolation (rollback)
POST /api/actions/restore-network

# System status
GET /api/actions/status
```

### System Endpoints

```bash
GET  /health                    # Liveness check
GET  /                          # API index

POST /api/system/pause          # Suspend automated remediation
POST /api/system/resume         # Resume automated remediation
```

---

## Policy System

Remediation policies live in [`src/config/policies.py`](src/config/policies.py). Each policy maps an `AnomalyType` + `Severity` pair to an ordered list of `RemediationAction` objects.

### Adding a Custom Policy

```python
from src.config.policies import (
    REMEDIATION_POLICIES, AnomalyType, Severity,
    RemediationPolicy, RemediationAction
)

REMEDIATION_POLICIES[AnomalyType.PORT_SCAN] = {
    Severity.MEDIUM: RemediationPolicy(
        anomaly_type=AnomalyType.PORT_SCAN,
        severity=Severity.MEDIUM,
        description="Port scan detected — block source and update firewall",
        actions=[
            RemediationAction("block_ip", "malicious_ip"),
            RemediationAction("update_firewall", "block_traffic"),
            RemediationAction("alert_admin", "security_team"),
        ]
    )
}
```

---

## AI Integration

The system is AI-model agnostic. To plug in your own model, implement a class with a `predict_anomaly(network_data: dict) -> dict` interface and wire it into the policy engine.

### Expected Prediction Schema

```python
{
    "is_anomaly": True,
    "anomaly_type": "mitm_attack",   # Must match an AnomalyType enum value
    "confidence": 0.92,              # 0.0 – 1.0
    "severity": "high",              # Must match a Severity enum value
    "malicious_ips": ["192.168.1.100"],
    "affected_devices": ["192.168.1.50"],
    "description": "Potential MITM attack detected"
}
```

### Framework Examples

<details>
<summary>scikit-learn (Isolation Forest)</summary>

```python
import joblib

class SklearnDetector:
    def __init__(self, model_path: str):
        self.model = joblib.load(model_path)

    def predict_anomaly(self, network_data: dict) -> dict:
        features = self._extract_features(network_data)
        prediction = self.model.predict([features])
        return {
            "is_anomaly": prediction[0] == -1,
            "anomaly_type": "network_anomaly",
            "severity": "medium",
            "confidence": abs(self.model.decision_function([features])[0])
        }
```
</details>

<details>
<summary>TensorFlow / Keras</summary>

```python
import tensorflow as tf
import numpy as np

class TFDetector:
    def __init__(self, model_path: str):
        self.model = tf.keras.models.load_model(model_path)

    def predict_anomaly(self, network_data: dict) -> dict:
        features = np.array([self._preprocess(network_data)])
        score = float(self.model.predict(features)[0])
        return {
            "is_anomaly": score > 0.5,
            "anomaly_type": self._classify(score),
            "severity": "high" if score > 0.85 else "medium",
            "confidence": score
        }
```
</details>

<details>
<summary>PyTorch</summary>

```python
import torch

class TorchDetector:
    def __init__(self, model_path: str):
        self.model = torch.load(model_path)
        self.model.eval()

    def predict_anomaly(self, network_data: dict) -> dict:
        with torch.no_grad():
            features = torch.tensor(self._preprocess(network_data), dtype=torch.float32)
            score = self.model(features).item()
        return {
            "is_anomaly": score > 0.7,
            "anomaly_type": "security_threat",
            "severity": "high",
            "confidence": score
        }
```
</details>

---

## Security Considerations

- **Run as a dedicated service account** with only the minimum `iptables` and SSH privileges needed — avoid running as root in production.
- **Use HTTPS** (`gunicorn` with an nginx TLS reverse proxy) — never expose the API over plain HTTP in production.
- **Restrict API access** to internal/management networks via firewall rules.
- **Rotate secrets** stored in `.env` regularly; never commit `.env` to version control.
- **Review all automated actions** in the audit log periodically; maintain a tested rollback procedure.
- **Test in a staging environment** before enabling `AUTO_REMEDIATE=true` in production.

---

## Testing

```bash
# Run the full test suite
pytest tests/

# Unit tests only
pytest tests/unit/ -v

# Integration tests only
pytest tests/integration/ -v

# With coverage report
pytest --cov=src tests/

# Simulate a specific attack via the API
curl -X POST http://localhost:5000/api/anomaly/simulate/mitm_attack
curl -X POST http://localhost:5000/api/anomaly/simulate/dns_attack
```

---

## License

This project is licensed under the **MIT License**.

```
MIT License

Copyright (c) 2024 Self-Healing Network Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

> **Warning:** This is a security-critical system. Always validate automated remediation actions in a controlled lab environment before production deployment. Maintain manual override capabilities and a tested rollback procedure at all times.