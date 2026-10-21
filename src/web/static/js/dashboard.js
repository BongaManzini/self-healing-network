// AEGIS Self-Healing Network Defense & Monitor Dashboard Controller

let trafficChart = null;
let currentSummary = null;

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  initChart();
  fetchSummary();
  fetchInterfaces();
  fetchActiveSockets();
  
  // Set up 2-second real-time polling
  setInterval(fetchSummary, 2000);
});

// Toast Notification Manager
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerText = message;
  container.appendChild(toast);
  
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 400);
  }, 4000);
}

// Chart.js Initialization
function initChart() {
  const ctx = document.getElementById('trafficChart').getContext('2d');
  
  trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Inbound (KB/s)',
          data: [],
          borderColor: '#06b6d4',
          backgroundColor: 'rgba(6, 182, 212, 0.1)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 2
        },
        {
          label: 'Outbound (KB/s)',
          data: [],
          borderColor: '#3b82f6',
          backgroundColor: 'rgba(59, 130, 246, 0.05)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 2
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 11 } }
        }
      },
      scales: {
        x: {
          grid: { color: '#1e293b' },
          ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
        },
        y: {
          beginAtZero: true,
          grid: { color: '#1e293b' },
          ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
        }
      }
    }
  });
}

// Fetch Aggregated Telemetry Summary
async function fetchSummary() {
  try {
    const res = await fetch('/api/monitor/summary');
    const json = await res.json();
    if (!json.success) return;
    
    currentSummary = json.data;
    updateDashboardUI(currentSummary);
  } catch (err) {
    console.warn('Telemetry polling error:', err);
  }
}

// Update UI with incoming data
function updateDashboardUI(data) {
  // 1. Host OS / Platform Badge
  if (data.platform) {
    const pText = `${data.platform.os} ${data.platform.release} (${data.platform.mode})`;
    document.getElementById('platform-text').innerText = pText;
  }

  // 2. Health Score & Status
  const health = data.health || { score: 100, status: 'healthy', auto_remediate: true };
  const score = health.score;
  document.getElementById('health-score-val').innerText = score;
  
  // Radial Gauge animation
  const circle = document.getElementById('health-circle');
  const circumference = 2 * Math.PI * 42; // ~264
  const offset = circumference - (score / 100) * circumference;
  circle.style.strokeDashoffset = offset;
  
  const statusTag = document.getElementById('health-status-tag');
  const threatLevel = document.getElementById('threat-level-val');
  
  if (score >= 90) {
    circle.style.stroke = 'var(--accent-green)';
    statusTag.className = 'status-pill status-healthy';
    statusTag.innerText = 'HEALTHY';
    threatLevel.className = 'meta-val normal';
    threatLevel.innerText = 'LOW / NORMAL';
  } else if (score >= 60) {
    circle.style.stroke = 'var(--accent-amber)';
    statusTag.className = 'status-pill';
    statusTag.style.background = 'rgba(245, 158, 11, 0.2)';
    statusTag.style.color = 'var(--accent-amber)';
    statusTag.style.border = '1px solid var(--accent-amber)';
    statusTag.innerText = 'THREAT MITIGATED';
    threatLevel.className = 'meta-val';
    threatLevel.style.color = 'var(--accent-amber)';
    threatLevel.innerText = 'ELEVATED / CONTAINED';
  } else {
    circle.style.stroke = 'var(--accent-red)';
    statusTag.className = 'status-pill status-threat';
    statusTag.innerText = 'UNDER ATTACK';
    threatLevel.className = 'meta-val';
    threatLevel.style.color = 'var(--accent-red)';
    threatLevel.innerText = 'CRITICAL INTRUSION';
  }

  // 3. Auto-Heal Switch State
  const autoToggle = document.getElementById('auto-heal-toggle');
  const autoBadge = document.getElementById('auto-heal-status-badge');
  autoToggle.checked = health.auto_remediate;
  if (health.auto_remediate) {
    autoBadge.className = 'status-badge active';
    autoBadge.innerText = 'ONLINE';
  } else {
    autoBadge.className = 'status-badge paused';
    autoBadge.innerText = 'PAUSED';
  }

  // 4. Intrusions Neutralized KPI
  const detected = health.total_detected || 0;
  const healed = health.total_healed || 0;
  document.getElementById('total-healed-val').innerText = healed;
  document.getElementById('total-detected-val').innerText = detected;
  
  const rate = detected > 0 ? Math.round((healed / detected) * 100) : 100;
  document.getElementById('healing-rate-val').innerText = `${rate}%`;
  document.getElementById('healed-progress-bar').style.width = `${rate}%`;

  // 5. Blocked / Contained Hosts KPI
  document.getElementById('blocked-count-val').innerText = data.blocked_count || 0;
  document.getElementById('isolated-count-val').innerText = data.isolated_count || 0;
  document.getElementById('active-sockets-val').innerText = data.active_connections_count || 0;

  // 6. Traffic Rates KPI
  const traffic = data.current_traffic || {};
  const recvKB = ((traffic.bytes_recv_rate || 0) / 1024).toFixed(1);
  const sentKB = ((traffic.bytes_sent_rate || 0) / 1024).toFixed(1);
  document.getElementById('bytes-recv-val').innerText = `${recvKB} KB/s`;
  document.getElementById('bytes-sent-val').innerText = `${sentKB} KB/s`;

  // 7. Update Chart Data
  if (trafficChart && data.history && data.history.length > 0) {
    const labels = data.history.map(h => h.timestamp);
    const recvData = data.history.map(h => (h.bytes_recv_rate / 1024).toFixed(1));
    const sentData = data.history.map(h => (h.bytes_sent_rate / 1024).toFixed(1));

    trafficChart.data.labels = labels;
    trafficChart.data.datasets[0].data = recvData;
    trafficChart.data.datasets[1].data = sentData;
    trafficChart.update('none'); // Update without full redraw glitch
  }

  // 8. Update Incidents Table
  renderIncidentsTable(data.recent_incidents || []);

  // 9. Update Blocked IPs & Isolated Devices Tables
  renderBlockedIPsTable(data.blocked_ips || []);
  renderIsolatedDevicesTable(data.isolated_devices || []);
}

// Render Incidents Table
function renderIncidentsTable(incidents) {
  const tbody = document.getElementById('incidents-tbody');
  if (incidents.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="text-center empty-state">No intrusions detected yet. System secure.</td></tr>';
    return;
  }

  tbody.innerHTML = incidents.map(inc => {
    const actionsHtml = (inc.actions_executed || []).map(a => 
      `<span class="action-pill">${a.action}: ${a.target || 'target'}</span>`
    ).join('') || '<span class="text-dim">Autonomous Policy Enacted</span>';

    const sevClass = inc.severity === 'critical' ? 'status-threat' : 
                     inc.severity === 'high' ? 'status-threat' : 'status-sim';

    const statusBadge = inc.healed ? 
      '<span class="status-pill status-healthy">✓ REMEDIATED</span>' : 
      '<span class="status-pill status-threat">⚡ ACTIVE</span>';

    const timeFormatted = inc.timestamp ? inc.timestamp.substring(11, 19) : 'Now';

    return `
      <tr>
        <td><code>${inc.id || 'INC'}</code></td>
        <td>${timeFormatted}</td>
        <td><strong>${inc.anomaly_type.toUpperCase()}</strong></td>
        <td><span class="status-pill ${sevClass}">${inc.severity}</span></td>
        <td><code>${inc.source_ip}</code></td>
        <td><code>${inc.target_ip}</code></td>
        <td>${actionsHtml}</td>
        <td>${statusBadge}</td>
      </tr>
    `;
  }).join('');
}

// Render Blocked IPs Table
function renderBlockedIPsTable(blockedIps) {
  const tbody = document.getElementById('blocked-ips-tbody');
  if (blockedIps.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" class="text-center empty-state">No blocked IPs</td></tr>';
    return;
  }

  tbody.innerHTML = blockedIps.map(ip => `
    <tr>
      <td><code>${ip}</code></td>
      <td><span class="action-pill">DROP IN/OUT</span></td>
      <td>
        <button class="cyber-btn btn-secondary" onclick="unblockIP('${ip}')">Unblock</button>
      </td>
    </tr>
  `).join('');
}

// Render Isolated Devices Table
function renderIsolatedDevicesTable(devices) {
  const tbody = document.getElementById('isolated-devices-tbody');
  if (devices.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" class="text-center empty-state">No quarantined devices</td></tr>';
    return;
  }

  tbody.innerHTML = devices.map(ip => `
    <tr>
      <td><code>${ip}</code></td>
      <td><span class="status-pill status-threat">QUARANTINED</span></td>
      <td>
        <button class="cyber-btn btn-primary" onclick="restoreDevice('${ip}')">Restore</button>
      </td>
    </tr>
  `).join('');
}

// Attack Simulator Trigger
async function simulateAttack(type) {
  const feedback = document.getElementById('simulation-feedback');
  const text = document.getElementById('sim-feedback-text');
  
  feedback.className = 'sim-feedback';
  text.innerText = `Simulating ${type.toUpperCase()}... Triggering autonomous self-healing...`;

  try {
    const res = await fetch(`/api/anomaly/simulate/${type}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    const json = await res.json();
    
    if (json.success) {
      const actionsCount = (json.results?.actions || []).length;
      text.innerText = `Threat [${type.toUpperCase()}] detected & neutralized! Executed ${actionsCount} self-healing actions.`;
      showToast(`⚡ Threat ${type.toUpperCase()} neutralized! Network self-healed.`, 'healed');
      fetchSummary();
    } else {
      text.innerText = `Simulation failed: ${json.message}`;
      showToast(`Error: ${json.message}`, 'threat');
    }
  } catch (err) {
    text.innerText = `Network error during simulation: ${err.message}`;
    showToast(`Simulation error: ${err.message}`, 'threat');
  }

  setTimeout(() => {
    feedback.className = 'sim-feedback hidden';
  }, 5000);
}

// Master Toggle for Autonomous Healing
async function toggleAutoHeal() {
  try {
    const res = await fetch('/api/monitor/toggle-auto-heal', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    const json = await res.json();
    if (json.success) {
      showToast(json.message, json.auto_remediate ? 'healed' : 'threat');
      fetchSummary();
    }
  } catch (err) {
    showToast(`Failed to toggle auto-heal: ${err.message}`, 'threat');
  }
}

// Manual IP Block
async function manualBlockIP() {
  const input = document.getElementById('manual-block-ip');
  const ip = input.value.trim();
  if (!ip) return;

  try {
    const res = await fetch('/api/actions/block-ip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip_address: ip, reason: 'manual_operator_block' })
    });
    const json = await res.json();
    if (json.success) {
      showToast(`Blocked IP: ${ip}`, 'healed');
      input.value = '';
      fetchSummary();
    } else {
      showToast(`Failed to block: ${json.message}`, 'threat');
    }
  } catch (err) {
    showToast(err.message, 'threat');
  }
}

// Manual IP Unblock
async function unblockIP(ip) {
  try {
    const res = await fetch('/api/actions/unblock-ip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip_address: ip })
    });
    const json = await res.json();
    if (json.success) {
      showToast(`Unblocked IP: ${ip}`, 'info');
      fetchSummary();
    }
  } catch (err) {
    showToast(err.message, 'threat');
  }
}

// Restore Device Quarantine
async function restoreDevice(ip) {
  try {
    const res = await fetch('/api/actions/restore-device', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_ip: ip })
    });
    const json = await res.json();
    if (json.success) {
      showToast(`Restored device: ${ip}`, 'healed');
      fetchSummary();
    }
  } catch (err) {
    showToast(err.message, 'threat');
  }
}

// Restore All Devices
async function restoreAllDevices() {
  try {
    const res = await fetch('/api/actions/restore-network', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    const json = await res.json();
    if (json.success) {
      showToast(json.message, 'healed');
      fetchSummary();
    }
  } catch (err) {
    showToast(err.message, 'threat');
  }
}

// Unblock all IPs
async function unblockAllIPs() {
  if (!currentSummary || !currentSummary.blocked_ips) return;
  for (const ip of currentSummary.blocked_ips) {
    await unblockIP(ip);
  }
  showToast('All firewall blocks cleared', 'healed');
  fetchSummary();
}

// Manual DNS Healing
async function triggerManualDNSHealing() {
  try {
    const res = await fetch('/api/actions/flush-dns', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ safe_dns: '1.1.1.1' })
    });
    const json = await res.json();
    if (json.success) {
      showToast('DNS cache flushed & healed to 1.1.1.1', 'healed');
    } else {
      showToast(`DNS flush failed: ${json.message}`, 'threat');
    }
  } catch (err) {
    showToast(err.message, 'threat');
  }
}

// Manual ARP Healing
async function triggerManualARPHealing() {
  try {
    const res = await fetch('/api/actions/heal-arp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    const json = await res.json();
    if (json.success) {
      showToast('ARP neighbor table purged. MITM neutralized.', 'healed');
    } else {
      showToast(`ARP flush failed: ${json.message}`, 'threat');
    }
  } catch (err) {
    showToast(err.message, 'threat');
  }
}

// Manual Kill Process PID
async function manualKillProcess() {
  const input = document.getElementById('manual-kill-pid');
  const pid = parseInt(input.value);
  if (!pid) return;

  try {
    const res = await fetch('/api/actions/terminate-process', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pid: pid })
    });
    const json = await res.json();
    if (json.success) {
      showToast(`Process PID ${pid} terminated`, 'healed');
      input.value = '';
      fetchActiveSockets();
    } else {
      showToast(`Failed: ${json.message}`, 'threat');
    }
  } catch (err) {
    showToast(err.message, 'threat');
  }
}

// Fetch Active Adapters
async function fetchInterfaces() {
  try {
    const res = await fetch('/api/monitor/interfaces');
    const json = await res.json();
    if (!json.success) return;

    const container = document.getElementById('adapters-summary-cards');
    container.innerHTML = json.interfaces.map(iface => `
      <div class="adapter-badge-card">
        <div class="adapter-name">${iface.name}</div>
        <div class="adapter-details">
          <div>IPv4: <code>${iface.ip}</code></div>
          <div>MAC: <code>${iface.mac}</code></div>
          <div>Status: <span class="action-pill">${iface.is_up ? 'UP' : 'DOWN'}</span></div>
        </div>
      </div>
    `).join('');
  } catch (err) {
    console.debug('Failed to fetch interfaces:', err);
  }
}

// Fetch Active Sockets Table
async function fetchActiveSockets() {
  const tbody = document.getElementById('connections-tbody');
  try {
    const res = await fetch('/api/monitor/connections?limit=40');
    const json = await res.json();
    if (!json.success || json.connections.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center empty-state">No external active connections</td></tr>';
      return;
    }

    tbody.innerHTML = json.connections.map(c => `
      <tr>
        <td><span class="action-pill">${c.type}</span></td>
        <td><code>${c.local_address}</code></td>
        <td><code>${c.remote_address}</code></td>
        <td>${c.status}</td>
        <td><code>${c.process_name} (${c.pid})</code></td>
        <td>${c.is_blocked ? '<span class="status-pill status-threat">BLOCKED</span>' : '<span class="status-pill status-healthy">ALLOWED</span>'}</td>
        <td>
          ${c.remote_ip ? `<button class="cyber-btn btn-danger" onclick="unblockOrBlock('${c.remote_ip}', ${c.is_blocked})">${c.is_blocked ? 'Unblock' : 'Block'}</button>` : '-'}
        </td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center empty-state">Error loading sockets: ${err.message}</td></tr>`;
  }
}

function unblockOrBlock(ip, isBlocked) {
  if (isBlocked) {
    unblockIP(ip);
  } else {
    fetch('/api/actions/block-ip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip_address: ip })
    }).then(() => {
      showToast(`Blocked ${ip}`, 'healed');
      fetchSummary();
      fetchActiveSockets();
    });
  }
}

// Tab Switching
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  
  const targetBtn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick').includes(tabId));
  if (targetBtn) targetBtn.classList.add('active');
  
  const targetContent = document.getElementById(tabId);
  if (targetContent) targetContent.classList.add('active');

  if (tabId === 'sockets-tab') {
    fetchInterfaces();
    fetchActiveSockets();
  }
}
