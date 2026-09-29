// SOC Sentinel - Main Web UI Controller

let map = null;
let mapMarkersGroup = null;
let currentAlerts = [];
let selectedAlertForModal = null;

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  initMap();
  initTabs();
  initEventListeners();
  loadAllData();
  loadRulesConfig();

  // Periodic poll every 5 seconds for live telemetry
  setInterval(() => {
    loadStats();
    loadAlerts(false);
  }, 5000);
});

// Toast notification helper
function showToast(message, type = 'success') {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  const icon = type === 'success' ? 'fa-circle-check' : (type === 'error' ? 'fa-triangle-exclamation' : 'fa-circle-info');
  toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// ---------------- Leaflet Threat Map ---------------- //
function initMap() {
  const mapElem = document.getElementById('mapContainer');
  if (!mapElem) return;

  // Center map globally
  map = L.map('mapContainer', {
    center: [25, 0],
    zoom: 2,
    minZoom: 1.5,
    maxZoom: 9,
    zoomControl: true,
    attributionControl: false
  });

  // Base Dark Tile Layer: Esri World Dark Gray Canvas (No API key required, dedicated dark cybersecurity theme)
  L.tileLayer('https://services.arcgisonline.com/arcgis/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
    minZoom: 1.5,
    maxZoom: 16,
    subdomains: ['server', 'services'],
    attribution: '&copy; Esri &mdash; Esri, DeLorme, NAVTEQ'
  }).addTo(map);

  // Subtle labels overlay (country and major city borders)
  L.tileLayer('https://services.arcgisonline.com/arcgis/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}', {
    minZoom: 1.5,
    maxZoom: 16,
    opacity: 0.8
  }).addTo(map);

  mapMarkersGroup = L.layerGroup().addTo(map);

  // Invalidate size once rendered in DOM
  setTimeout(() => {
    if (map) map.invalidateSize();
  }, 250);
}

function updateThreatMap(markersData) {
  if (!map || !mapMarkersGroup) return;
  mapMarkersGroup.clearLayers();

  const indicator = document.getElementById('mapIndicator');
  const validMarkers = (markersData || []).filter(m => m.geo_lat != null && m.geo_lon != null && !isNaN(parseFloat(m.geo_lat)) && !isNaN(parseFloat(m.geo_lon)));

  if (indicator) {
    indicator.textContent = `${validMarkers.length} Threat Origins Plotted`;
  }

  validMarkers.forEach(m => {
    const lat = parseFloat(m.geo_lat);
    const lon = parseFloat(m.geo_lon);

    const sev = (m.severity || 'HIGH').toUpperCase();
    const sevClass = sev === 'CRITICAL' ? 'severity-critical' : (sev === 'HIGH' ? 'severity-high' : (sev === 'MEDIUM' ? 'severity-medium' : 'severity-low'));

    // Animated Radar Ping Marker
    const iconHtml = `
      <div class="radar-marker-pulse ${sevClass}" title="${m.source_ip} - ${m.geo_city || ''}, ${m.geo_country || ''}">
        <div class="radar-ping"></div>
        <div class="radar-center"></div>
      </div>
    `;

    const radarIcon = L.divIcon({
      className: 'radar-marker-container',
      html: iconHtml,
      iconSize: [28, 28],
      iconAnchor: [14, 14],
      popupAnchor: [0, -14]
    });

    const marker = L.marker([lat, lon], { icon: radarIcon });

    const popupHtml = `
      <div class="soc-map-popup">
        <div class="popup-header">
          <strong style="color: var(--accent-cyan);"><i class="fa-solid fa-crosshairs"></i> ${m.source_ip}</strong>
          <span class="badge ${sev === 'CRITICAL' ? 'badge-critical' : (sev === 'HIGH' ? 'badge-high' : 'badge-low')}">${sev}</span>
        </div>
        <div class="popup-body">
          <div><i class="fa-solid fa-location-dot" style="color: var(--accent-cyan);"></i> <span><strong>Location:</strong> ${m.geo_city || 'Unknown'}, ${m.geo_country || 'Unknown'}</span></div>
          <div><i class="fa-solid fa-tower-broadcast" style="color: var(--accent-amber);"></i> <span><strong>Total Alerts:</strong> ${m.alert_count}</span></div>
          <div><i class="fa-solid fa-shield-halved" style="color: var(--accent-red);"></i> <span><strong>MITRE Tactic:</strong> ${m.mitre_id || 'T1110'}</span></div>
        </div>
        <button class="btn btn-danger btn-sm mt-2 w-100" onclick="blockAttackerIp('${m.source_ip}', 'Malicious Origin')">
          <i class="fa-solid fa-ban"></i> Enforce Drop Rule
        </button>
      </div>
    `;
    marker.bindPopup(popupHtml);
    mapMarkersGroup.addLayer(marker);
  });

  // Ensure map size is fresh
  map.invalidateSize();
}

function focusThreatOnMap(lat, lon, ip) {
  if (!map || lat == null || lon == null) return;
  const targetLat = parseFloat(lat);
  const targetLon = parseFloat(lon);
  if (isNaN(targetLat) || isNaN(targetLon)) return;

  const overviewTab = document.querySelector('.nav-tab[data-tab="tab-overview"]');
  if (overviewTab && !overviewTab.classList.contains('active')) {
    overviewTab.click();
  }

  map.flyTo([targetLat, targetLon], 5, {
    animate: true,
    duration: 1.2
  });

  if (mapMarkersGroup) {
    mapMarkersGroup.eachLayer(layer => {
      if (layer.getLatLng && Math.abs(layer.getLatLng().lat - targetLat) < 0.01 && Math.abs(layer.getLatLng().lng - targetLon) < 0.01) {
        layer.openPopup();
      }
    });
  }
}

// ---------------- Tabs Navigation ---------------- //
function initTabs() {
  const tabs = document.querySelectorAll('.nav-tab');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetId = tab.getAttribute('data-tab');
      tabs.forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      const pane = document.getElementById(targetId);
      if (pane) pane.classList.add('active');

      if (targetId === 'tab-overview' && map) {
        setTimeout(() => map.invalidateSize(), 200);
      }
      if (targetId === 'tab-alerts') loadAlerts(true);
      if (targetId === 'tab-explorer') loadEvents();
      if (targetId === 'tab-firewall') loadBlocklist();
      if (targetId === 'tab-rules') loadRulesConfig();
    });
  });
}

// ---------------- Event Listeners ---------------- //
function initEventListeners() {
  // Quick header actions
  document.getElementById('btnQuickSim')?.addEventListener('click', () => runSimulation('ssh_brute'));
  document.getElementById('btnQuickSample')?.addEventListener('click', () => loadAndIngestSampleData('ssh'));
  document.getElementById('btnClearData')?.addEventListener('click', clearAllData);

  // Simulator scenario buttons
  document.querySelectorAll('.btn-sim').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const scenario = btn.getAttribute('data-scenario');
      runSimulation(scenario, btn);
    });
  });

  // Alert Filters
  document.getElementById('filterAlertSeverity')?.addEventListener('change', () => loadAlerts(true));
  document.getElementById('filterAlertStatus')?.addEventListener('change', () => loadAlerts(true));

  // Log Explorer Filters
  document.getElementById('btnRefreshEvents')?.addEventListener('click', loadEvents);
  document.getElementById('filterEventSource')?.addEventListener('change', loadEvents);
  document.getElementById('filterEventStatus')?.addEventListener('change', loadEvents);
  document.getElementById('filterEventIp')?.addEventListener('keyup', (e) => {
    if (e.key === 'Enter') loadEvents();
  });

  // Manual IP block form
  document.getElementById('formManualBlock')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const ip = document.getElementById('manualIp').value.trim();
    const reason = document.getElementById('manualReason').value.trim();
    const severity = document.getElementById('manualSeverity').value;

    try {
      const res = await fetch('/api/blocklist/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, reason, severity })
      });
      const data = await res.json();
      showToast(`IP ${ip} blocked via iptables!`, 'success');
      document.getElementById('formManualBlock').reset();
      loadBlocklist();
      loadStats();
    } catch (err) {
      showToast(`Failed to block IP: ${err}`, 'error');
    }
  });

  // Ingest Text Form
  document.getElementById('formIngestText')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = document.getElementById('rawLogInput').value.trim();
    const source = document.getElementById('ingestSourceSelect').value || null;

    if (!text) {
      showToast('Please paste log lines first', 'warning');
      return;
    }

    const btn = document.getElementById('btnSubmitIngest');
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Correlating...';

    try {
      const res = await fetch('/api/ingest/text', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ log_text: text, source: source })
      });
      const data = await res.json();
      showToast(`Processed ${data.events_parsed} events. ${data.alerts_fired} alerts triggered!`, 'success');
      document.getElementById('rawLogInput').value = '';
      loadAllData();
    } catch (err) {
      showToast(`Ingestion error: ${err}`, 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<i class="fa-solid fa-radar"></i> Ingest & Correlate Logs';
    }
  });

  // File Upload
  const fileInput = document.getElementById('fileUploadInput');
  fileInput?.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      document.getElementById('selectedFileName').textContent = fileInput.files[0].name;
    }
  });

  document.getElementById('formUploadFile')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!fileInput.files || fileInput.files.length === 0) {
      showToast('Please select a log file to upload', 'warning');
      return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('source', document.getElementById('uploadSourceSelect').value);

    const btn = document.getElementById('btnSubmitUpload');
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Uploading & Parsing...';

    try {
      const res = await fetch('/api/ingest/file', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      showToast(`Analyzed ${data.filename}: ${data.events_parsed} events, ${data.alerts_fired} alerts!`, 'success');
      loadAllData();
    } catch (err) {
      showToast(`File upload failed: ${err}`, 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<i class="fa-solid fa-upload"></i> Process Uploaded File';
    }
  });

  // Ingest Sample Buttons
  document.getElementById('btnLoadAuthSample')?.addEventListener('click', () => loadSampleIntoInput('ssh'));
  document.getElementById('btnLoadWebSample')?.addEventListener('click', () => loadSampleIntoInput('web'));
  document.getElementById('btnLoadWinSample')?.addEventListener('click', () => loadSampleIntoInput('windows'));
  document.getElementById('btnLoadAttackSample')?.addEventListener('click', () => loadSampleIntoInput('attack'));

  // Rules save
  document.getElementById('btnSaveRules')?.addEventListener('click', saveRulesConfig);
  document.getElementById('btnTestDiscord')?.addEventListener('click', testDiscordWebhook);

  // Evidence Modal actions
  document.getElementById('btnCloseModal')?.addEventListener('click', closeModal);
  document.getElementById('btnModalResolve')?.addEventListener('click', () => {
    if (selectedAlertForModal) {
      updateAlertStatus(selectedAlertForModal.id, 'RESOLVED');
      closeModal();
    }
  });
  document.getElementById('btnModalBlockIp')?.addEventListener('click', async () => {
    if (selectedAlertForModal) {
      await blockAttackerIp(selectedAlertForModal.source_ip, `Blocked from Alert ${selectedAlertForModal.id}`);
      closeModal();
    }
  });
}

// ---------------- Data Loading ---------------- //
async function loadAllData() {
  await Promise.all([loadStats(), loadAlerts(false), loadBlocklist()]);
}

async function loadStats() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();

    // KPIs
    document.getElementById('kpiTotalEvents').textContent = data.total_events.toLocaleString();
    document.getElementById('kpiTotalAlerts').textContent = data.total_alerts.toLocaleString();
    document.getElementById('kpiCriticalAlerts').textContent = data.critical_alerts.toLocaleString();
    document.getElementById('kpiBlockedIps').textContent = data.blocked_ips_count.toLocaleString();
    document.getElementById('navAlertCount').textContent = data.total_alerts;

    // Charts
    initOrUpdateTacticsChart(data.mitre_tactics);
    initOrUpdateTimelineChart(data.timeline);

    // Map
    updateThreatMap(data.map_markers);

    // Top Attackers Table (augment with map marker coordinates if available)
    const geoByIp = {};
    (data.map_markers || []).forEach(m => {
      geoByIp[m.source_ip] = { lat: m.geo_lat, lon: m.geo_lon };
    });
    const attackersWithGeo = (data.top_attacking_ips || []).map(a => ({
      ...a,
      geo_lat: a.geo_lat ?? geoByIp[a.source_ip]?.lat,
      geo_lon: a.geo_lon ?? geoByIp[a.source_ip]?.lon
    }));
    renderTopAttackers(attackersWithGeo);
  } catch (err) {
    console.error('Error loading stats:', err);
  }
}

function renderTopAttackers(attackers) {
  const tbody = document.getElementById('topAttackersTableBody');
  if (!tbody) return;

  if (!attackers || attackers.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-dim);">No alerts detected yet</td></tr>';
    return;
  }

  tbody.innerHTML = attackers.map(a => {
    const hasGeo = a.geo_lat != null && a.geo_lon != null && !isNaN(parseFloat(a.geo_lat)) && !isNaN(parseFloat(a.geo_lon));
    const clickHandler = hasGeo ? `onclick="focusThreatOnMap(${a.geo_lat}, ${a.geo_lon}, '${a.source_ip}')" style="cursor: pointer;" title="Center on Geolocation Map"` : '';
    return `
    <tr>
      <td>
        <span class="ip-chip" ${clickHandler}>
          ${a.source_ip}
          ${hasGeo ? '<i class="fa-solid fa-crosshairs" style="font-size: 10px; margin-left: 6px; color: var(--accent-cyan);"></i>' : ''}
        </span>
      </td>
      <td>${a.geo_city || 'Unknown'}, ${a.geo_country || 'Unknown'}</td>
      <td><span class="badge ${a.max_severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'}">${a.alert_count} alerts</span></td>
      <td>
        <button class="btn btn-danger btn-sm" onclick="blockAttackerIp('${a.source_ip}', 'Frequent Threat Actor')">
          <i class="fa-solid fa-ban"></i> Block
        </button>
      </td>
    </tr>
  `;
  }).join('');
}

async function loadAlerts(showLoading = false) {
  const tbody = document.getElementById('alertsTableBody');
  if (!tbody) return;

  const severity = document.getElementById('filterAlertSeverity')?.value || 'ALL';
  const status = document.getElementById('filterAlertStatus')?.value || 'ALL';

  if (showLoading) {
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; padding: 20px;"><i class="fa-solid fa-spinner fa-spin"></i> Loading alerts...</td></tr>';
  }

  try {
    const res = await fetch(`/api/alerts?severity=${severity}&status=${status}&limit=100`);
    const alerts = await res.json();
    currentAlerts = alerts;

    if (alerts.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; color: var(--text-dim); padding: 30px;">No alerts match filter criteria</td></tr>';
      return;
    }

    tbody.innerHTML = alerts.map(a => {
      const sevClass = a.severity === 'CRITICAL' ? 'badge-critical' : (a.severity === 'HIGH' ? 'badge-high' : (a.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low'));
      const statusClass = a.status === 'RESOLVED' ? 'badge-low' : (a.status === 'NEW' ? 'badge-critical' : 'badge-medium');

      return `
        <tr>
          <td><span class="badge ${sevClass}">${a.severity}</span></td>
          <td><span class="ip-chip">${a.id}</span></td>
          <td style="font-size: 0.75rem; color: var(--text-muted);">${a.timestamp.substring(11, 19)}</td>
          <td><span class="badge badge-mitre">${a.mitre_attack_id}</span></td>
          <td style="font-weight: 500;">${a.rule_name}</td>
          <td>
            <span class="ip-chip">${a.source_ip}</span>
            <div style="font-size: 0.7rem; color: var(--text-dim);">${a.geo_city || 'Unknown'}, ${a.geo_country || ''}</div>
          </td>
          <td><span style="font-size: 0.8rem; color: #cbd5e1;">${a.targeted_user || 'N/A'}</span></td>
          <td><span class="badge ${statusClass}">${a.status}</span></td>
          <td>
            <div style="display: flex; gap: 6px;">
              <button class="btn btn-secondary btn-sm" onclick="openEvidenceModal('${a.id}')" title="Inspect Evidence">
                <i class="fa-solid fa-magnifying-glass"></i>
              </button>
              <button class="btn btn-danger btn-sm" onclick="blockAttackerIp('${a.source_ip}', '${a.rule_name}')" title="Block Attacker IP">
                <i class="fa-solid fa-ban"></i>
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error('Error fetching alerts:', err);
  }
}

async function loadEvents() {
  const tbody = document.getElementById('eventsTableBody');
  if (!tbody) return;

  const source = document.getElementById('filterEventSource')?.value || 'ALL';
  const status = document.getElementById('filterEventStatus')?.value || 'ALL';
  const ip = document.getElementById('filterEventIp')?.value.trim() || '';

  tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding: 20px;"><i class="fa-solid fa-spinner fa-spin"></i> Retrieving normalized events...</td></tr>';

  try {
    let url = `/api/events?limit=80&log_source=${source}&status=${status}`;
    if (ip) url += `&source_ip=${encodeURIComponent(ip)}`;

    const res = await fetch(url);
    const events = await res.json();

    if (events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-dim); padding: 30px;">No events found</td></tr>';
      return;
    }

    tbody.innerHTML = events.map(e => `
      <tr>
        <td style="font-size: 0.75rem; color: var(--text-muted);">${e.timestamp.substring(11, 19)}</td>
        <td><span class="badge badge-source">${e.log_source}</span></td>
        <td><span class="ip-chip">${e.source_ip}</span></td>
        <td style="font-size: 0.8rem;">${e.geo_city || 'Unknown'}, ${e.geo_country || ''}</td>
        <td><span style="font-size: 0.8rem; color: #cbd5e1;">${e.user || (e.details?.path ? e.details.path.substring(0, 24) : 'N/A')}</span></td>
        <td><span style="font-size: 0.8rem; font-family: var(--font-mono);">${e.action}</span></td>
        <td><span class="badge ${e.status === 'success' ? 'badge-low' : 'badge-critical'}">${e.status}</span></td>
        <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-dim);">
          ${e.raw_log}
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Error fetching events:', err);
  }
}

async function loadBlocklist() {
  const tbody = document.getElementById('blocklistTableBody');
  if (!tbody) return;

  try {
    const res = await fetch('/api/blocklist');
    const blocked = await res.json();

    if (blocked.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-dim); padding: 30px;">No IPs actively blocked</td></tr>';
      return;
    }

    tbody.innerHTML = blocked.map(b => `
      <tr>
        <td><span class="ip-chip" style="color: var(--accent-red);">${b.ip}</span></td>
        <td style="font-size: 0.8rem;">${b.reason}</td>
        <td><span class="badge ${b.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'}">${b.severity}</span></td>
        <td style="font-size: 0.75rem; color: var(--text-muted);">${b.blocked_at.substring(0, 19).replace('T', ' ')}</td>
        <td><code style="font-size: 0.75rem; color: #4ade80;">${b.firewall_command}</code></td>
        <td>
          ${b.active ? `
            <button class="btn btn-secondary btn-sm" onclick="unblockAttackerIp('${b.ip}')">
              <i class="fa-solid fa-unlock"></i> Unblock
            </button>
          ` : '<span style="color: var(--text-dim); font-size: 0.75rem;">Inactive</span>'}
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Error loading blocklist:', err);
  }
}

// ---------------- Simulations & Quick Actions ---------------- //
async function runSimulation(scenario, btnElement = null) {
  if (btnElement) {
    btnElement.disabled = true;
    btnElement.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Injecting...';
  }

  try {
    const res = await fetch(`/api/simulate/${scenario}`, { method: 'POST' });
    const data = await res.json();

    showToast(`Simulation [${scenario}] complete! Triggered ${data.alerts_triggered} alert(s).`, 'success');
    await loadAllData();
  } catch (err) {
    showToast(`Simulation failed: ${err}`, 'error');
  } finally {
    if (btnElement) {
      btnElement.disabled = false;
      btnElement.innerHTML = '<i class="fa-solid fa-play"></i> Run Simulation';
    }
  }
}

async function blockAttackerIp(ip, reason) {
  try {
    const res = await fetch('/api/blocklist/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, reason, severity: 'CRITICAL' })
    });
    showToast(`Firewall DROP rule applied for IP ${ip}`, 'success');
    loadBlocklist();
    loadStats();
  } catch (err) {
    showToast(`Failed to block IP: ${err}`, 'error');
  }
}

async function unblockAttackerIp(ip) {
  try {
    const res = await fetch('/api/blocklist/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });
    showToast(`IP ${ip} removed from firewall blocklist`, 'success');
    loadBlocklist();
    loadStats();
  } catch (err) {
    showToast(`Failed to unblock: ${err}`, 'error');
  }
}

async function updateAlertStatus(alertId, newStatus) {
  try {
    await fetch(`/api/alerts/${alertId}/status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus })
    });
    showToast(`Alert marked as ${newStatus}`, 'success');
    loadAlerts(false);
  } catch (err) {
    showToast(`Failed to update status: ${err}`, 'error');
  }
}

async function clearAllData() {
  if (!confirm('Are you sure you want to reset all stored events, alerts, and firewall rules?')) return;
  try {
    await fetch('/api/clear', { method: 'POST' });
    showToast('Database and threat telemetry cleared!', 'success');
    loadAllData();
  } catch (err) {
    showToast(`Clear failed: ${err}`, 'error');
  }
}

// ---------------- Sample Ingest Helpers ---------------- //
const SAMPLES = {
  ssh: `Sep 29 02:14:01 prod-web sshd[10201]: Failed password for invalid user admin from 194.26.29.112 port 38291 ssh2
Sep 29 02:14:05 prod-web sshd[10205]: Failed password for invalid user admin from 194.26.29.112 port 38292 ssh2
Sep 29 02:14:09 prod-web sshd[10209]: Failed password for invalid user admin from 194.26.29.112 port 38293 ssh2
Sep 29 02:14:14 prod-web sshd[10214]: Failed password for invalid user admin from 194.26.29.112 port 38294 ssh2
Sep 29 02:14:19 prod-web sshd[10219]: Failed password for invalid user admin from 194.26.29.112 port 38295 ssh2
Sep 29 02:14:24 prod-web sshd[10224]: Failed password for invalid user admin from 194.26.29.112 port 38296 ssh2
Sep 29 02:16:30 prod-web sshd[11050]: Failed password for invalid user root from 185.220.101.5 port 49101 ssh2
Sep 29 02:16:35 prod-web sshd[11054]: Failed password for invalid user root from 185.220.101.5 port 49102 ssh2
Sep 29 02:16:40 prod-web sshd[11058]: Failed password for invalid user root from 185.220.101.5 port 49103 ssh2
Sep 29 02:16:45 prod-web sshd[11062]: Failed password for invalid user root from 185.220.101.5 port 49104 ssh2
Sep 29 02:16:50 prod-web sshd[11066]: Accepted password for root from 185.220.101.5 port 49105 ssh2`,
  web: `118.25.6.39 - - [29/Sep/2026:03:01:10 +0000] "GET /index.php HTTP/1.1" 200 4521 "-" "Mozilla/5.0"
118.25.6.39 - - [29/Sep/2026:03:01:15 +0000] "GET /item.php?id=10%20UNION%20SELECT%201,username,password%20FROM%20users-- HTTP/1.1" 200 3912 "-" "sqlmap/1.5.2"
118.25.6.39 - - [29/Sep/2026:03:01:20 +0000] "GET /search.php?query=%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1" 200 1520 "-" "Mozilla/5.0"
118.25.6.39 - - [29/Sep/2026:03:01:25 +0000] "GET /download.php?file=../../../../etc/passwd HTTP/1.1" 200 852 "-" "curl/7.68.0"
118.25.6.39 - - [29/Sep/2026:03:01:30 +0000] "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.0"`,
  windows: `2026-09-29 04:10:01 WIN-DC01 Security-Auditing[4625]: An account failed to log on. Target User: Administrator Source Network Address: 203.0.113.195
2026-09-29 04:10:05 WIN-DC01 Security-Auditing[4625]: An account failed to log on. Target User: Administrator Source Network Address: 203.0.113.195
2026-09-29 04:10:09 WIN-DC01 Security-Auditing[4625]: An account failed to log on. Target User: Administrator Source Network Address: 203.0.113.195
2026-09-29 04:10:14 WIN-DC01 Security-Auditing[4625]: An account failed to log on. Target User: Administrator Source Network Address: 203.0.113.195
2026-09-29 04:10:18 WIN-DC01 Security-Auditing[4625]: An account failed to log on. Target User: Administrator Source Network Address: 203.0.113.195
2026-09-29 04:10:22 WIN-DC01 Security-Auditing[4625]: An account failed to log on. Target User: Administrator Source Network Address: 203.0.113.195`,
  attack: `Sep 29 03:10:01 gateway-server sshd[21010]: Failed password for invalid user admin from 194.26.29.112 port 41201 ssh2
Sep 29 03:10:05 gateway-server sshd[21014]: Failed password for invalid user admin from 194.26.29.112 port 41202 ssh2
Sep 29 03:10:09 gateway-server sshd[21018]: Failed password for invalid user admin from 194.26.29.112 port 41203 ssh2
Sep 29 03:10:14 gateway-server sshd[21022]: Failed password for invalid user admin from 194.26.29.112 port 41204 ssh2
Sep 29 03:10:18 gateway-server sshd[21026]: Failed password for invalid user admin from 194.26.29.112 port 41205 ssh2
Sep 29 03:10:24 gateway-server sshd[21030]: Accepted password for root from 194.26.29.112 port 41206 ssh2
Sep 29 03:12:00 gateway-server sshd[22100]: Failed password for invalid user oracle from 103.203.57.18 port 51101 ssh2
Sep 29 03:12:08 gateway-server sshd[22105]: Failed password for invalid user postgres from 103.203.57.18 port 51102 ssh2
Sep 29 03:12:15 gateway-server sshd[22110]: Failed password for invalid user gitlab from 103.203.57.18 port 51103 ssh2
Sep 29 03:12:22 gateway-server sshd[22115]: Failed password for invalid user deploy from 103.203.57.18 port 51104 ssh2
Sep 29 03:12:30 gateway-server sshd[22120]: Failed password for invalid user jenkins from 103.203.57.18 port 51105 ssh2
118.25.6.39 - - [29/Sep/2026:03:15:10 +0000] "GET /catalog.php?id=10%20UNION%20SELECT%201,username,password%20FROM%20users-- HTTP/1.1" 200 4812 "-" "sqlmap/1.6.0"
118.25.6.39 - - [29/Sep/2026:03:15:20 +0000] "GET /view.php?page=../../../../etc/passwd HTTP/1.1" 200 1250 "-" "curl/7.88.1"
118.25.6.39 - - [29/Sep/2026:03:15:30 +0000] "GET /search.php?query=%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1" 200 2340 "-" "Mozilla/5.0"
45.148.10.88 - - [29/Sep/2026:03:18:01 +0000] "GET /.env HTTP/1.1" 404 162 "-" "gobuster/3.5"
45.148.10.88 - - [29/Sep/2026:03:18:03 +0000] "GET /.git/config HTTP/1.1" 404 162 "-" "gobuster/3.5"
45.148.10.88 - - [29/Sep/2026:03:18:05 +0000] "GET /wp-config.php HTTP/1.1" 404 162 "-" "gobuster/3.5"
45.148.10.88 - - [29/Sep/2026:03:18:07 +0000] "GET /phpmyadmin/index.php HTTP/1.1" 404 162 "-" "gobuster/3.5"
45.148.10.88 - - [29/Sep/2026:03:18:09 +0000] "GET /backup.sql HTTP/1.1" 404 162 "-" "gobuster/3.5"
45.148.10.88 - - [29/Sep/2026:03:18:11 +0000] "GET /server-status HTTP/1.1" 404 162 "-" "gobuster/3.5"
45.148.10.88 - - [29/Sep/2026:03:18:13 +0000] "GET /api/v1/internal HTTP/1.1" 404 162 "-" "gobuster/3.5"
45.148.10.88 - - [29/Sep/2026:03:18:15 +0000] "GET /admin.php HTTP/1.1" 404 162 "-" "gobuster/3.5"
45.148.10.88 - - [29/Sep/2026:03:18:17 +0000] "GET /debug HTTP/1.1" 404 162 "-" "gobuster/3.5"
Sep 29 03:22:15 gateway-server sudo: devuser : TTY=pts/0 ; PWD=/var/tmp ; USER=root ; COMMAND=/bin/bash
Sep 29 03:30:00 gateway-server sshd[25100]: Accepted publickey for alice from 198.51.100.42 port 49120 ssh2
Sep 29 03:38:00 gateway-server sshd[25890]: Accepted password for alice from 185.220.101.5 port 52890 ssh2`
};

function loadSampleIntoInput(type) {
  document.getElementById('rawLogInput').value = SAMPLES[type] || '';
  document.getElementById('ingestSourceSelect').value = type === 'attack' ? '' : type;
  showToast(`Sample ${type === 'attack' ? 'Full Attack Suite' : type.toUpperCase()} logs loaded into input`, 'info');
}

async function loadAndIngestSampleData(type) {
  const text = SAMPLES[type];
  try {
    const res = await fetch('/api/ingest/text', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ log_text: text, source: type })
    });
    const data = await res.json();
    showToast(`Loaded ${data.events_parsed} sample events and generated ${data.alerts_fired} alerts!`, 'success');
    loadAllData();
  } catch (err) {
    showToast(`Sample load failed: ${err}`, 'error');
  }
}

// ---------------- Rules & Settings ---------------- //
async function loadRulesConfig() {
  try {
    const res = await fetch('/api/rules');
    const data = await res.json();
    const editor = document.getElementById('rulesYamlEditor');
    if (editor && data.yaml_content) {
      editor.value = data.yaml_content;
    }
  } catch (err) {
    console.error('Failed to load rules:', err);
  }
}

async function saveRulesConfig() {
  const content = document.getElementById('rulesYamlEditor')?.value;
  if (!content) return;

  try {
    const res = await fetch('/api/rules/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ yaml_content: content })
    });
    const data = await res.json();
    if (res.ok) {
      showToast('Rules YAML validated and reloaded into engine!', 'success');
    } else {
      showToast(`Rule error: ${data.detail}`, 'error');
    }
  } catch (err) {
    showToast(`Failed to save rules: ${err}`, 'error');
  }
}

async function testDiscordWebhook() {
  const url = document.getElementById('discordWebhookUrl')?.value.trim();
  if (!url) {
    showToast('Please provide a Discord Webhook URL first', 'warning');
    return;
  }

  const btn = document.getElementById('btnTestDiscord');
  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Dispatching...';

  try {
    const res = await fetch('/api/alerter/test-discord', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ webhook_url: url })
    });
    const data = await res.json();
    if (res.ok) {
      showToast('Test embed delivered to Discord channel!', 'success');
    } else {
      showToast(`Discord delivery failed: ${data.detail}`, 'error');
    }
  } catch (err) {
    showToast(`Error connecting to webhook: ${err}`, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Send Test Alert to Discord';
  }
}

// ---------------- Modal Handling ---------------- //
function openEvidenceModal(alertId) {
  const alert = currentAlerts.find(a => a.id === alertId);
  if (!alert) return;

  selectedAlertForModal = alert;

  document.getElementById('modalAlertId').textContent = alert.id;
  document.getElementById('modalSeverity').textContent = alert.severity;
  document.getElementById('modalSeverity').className = `badge ${alert.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'}`;
  document.getElementById('modalAttackerIp').textContent = alert.source_ip;
  document.getElementById('modalLocation').textContent = `${alert.geo_city || 'Unknown'}, ${alert.geo_country || 'Unknown'}`;
  document.getElementById('modalMitre').textContent = `${alert.mitre_attack_id} - ${alert.mitre_attack_technique}`;
  document.getElementById('modalTarget').textContent = alert.targeted_user || 'Server';
  document.getElementById('modalDescription').textContent = alert.description;

  const evidenceBox = document.getElementById('modalEvidenceLogs');
  evidenceBox.textContent = JSON.stringify(alert.evidence, null, 2);

  const cmdBox = document.getElementById('modalMitigationCmd');
  cmdBox.textContent = `sudo iptables -A INPUT -s ${alert.source_ip} -j DROP\n# Or via UFW:\nsudo ufw deny from ${alert.source_ip} to any`;

  document.getElementById('evidenceModal').classList.add('open');
}

function closeModal() {
  document.getElementById('evidenceModal').classList.remove('open');
  selectedAlertForModal = null;
}
