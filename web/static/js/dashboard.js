/* Optisec WiFi Monitor - Dashboard JavaScript */

// ---- Shared Utilities ----

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const colors = {success: '#22c55e', danger: '#ef4444', warning: '#eab308', info: '#06b6d4'};
    const id = 'toast_' + Date.now();
    const html = `
        <div id="${id}" class="toast align-items-center border-0 show"
             style="background:#111827;border-left:3px solid ${colors[type] || colors.info}!important;min-width:260px">
            <div class="d-flex">
                <div class="toast-body text-white small">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto"
                        onclick="document.getElementById('${id}').remove()"></button>
            </div>
        </div>`;
    container.insertAdjacentHTML('beforeend', html);
    setTimeout(() => { const el = document.getElementById(id); if (el) el.remove(); }, 4000);
}

function formatTime(ts) {
    if (!ts) return '—';
    return ts.substring(0, 16).replace('T', ' ');
}

function sevBadge(sev) {
    const map = {
        CRITICAL: 'bg-danger',
        HIGH: 'bg-danger',
        MEDIUM: 'bg-warning text-dark',
        LOW: 'bg-info text-dark',
        INFO: 'bg-secondary',
    };
    const icon = {CRITICAL: '🚨', HIGH: '⛔', MEDIUM: '⚠', LOW: 'ℹ', INFO: '•'};
    const cls = map[sev] || 'bg-secondary';
    return `<span class="badge ${cls}">${(icon[sev] || '')} ${sev}</span>`;
}

// ---- Clock ----
function startClock() {
    const el = document.getElementById('currentTime');
    if (!el) return;
    function tick() {
        el.textContent = new Date().toLocaleTimeString();
    }
    tick();
    setInterval(tick, 1000);
}

// ---- Alert Badge ----
async function refreshAlertBadge() {
    try {
        const resp = await fetch('/api/stats');
        const data = await resp.json();
        const count = data.stats?.active_alerts || 0;
        const badge = document.getElementById('alertCount');
        if (badge) badge.textContent = count;
    } catch (_) {}
}

// ---- Dashboard Page ----
let alertsLineChart = null;
let attacksPieChart = null;

async function initDashboard() {
    await loadDashboardStats();
    await loadRecentAlerts();
    await loadRecentAttacks();
    setInterval(loadDashboardStats, 10000);
    setInterval(loadRecentAlerts, 8000);
    setInterval(loadRecentAttacks, 12000);
}

async function loadDashboardStats() {
    try {
        const resp = await fetch('/api/stats');
        const data = await resp.json();
        const stats = data.stats || {};

        const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
        setEl('stat-devices', stats.total_devices || 0);
        setEl('stat-alerts', stats.active_alerts || 0);
        setEl('stat-attacks', stats.total_attacks || 0);
        setEl('stat-audits', stats.audits || 0);

        const badge = document.getElementById('alertCount');
        if (badge) badge.textContent = stats.active_alerts || 0;

        buildAlertsChart(data.alerts_by_hour || []);
        buildAttacksChart(data.attacks_by_type || []);
        updateAlertChartBadge(data.alerts_by_hour || []);
    } catch (e) {
        console.error('Stats load error:', e);
    }
}

function buildAlertsChart(alertsByHour) {
    const ctx = document.getElementById('alertsChart');
    if (!ctx) return;

    const labels = Array.from({length: 24}, (_, i) => String(i).padStart(2, '0') + ':00');
    const counts = Array(24).fill(0);
    alertsByHour.forEach(r => { counts[parseInt(r.hour)] = r.count; });

    if (alertsLineChart) {
        alertsLineChart.data.datasets[0].data = counts;
        alertsLineChart.update('none');
        return;
    }

    alertsLineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [{
                label: 'Alerts',
                data: counts,
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239,68,68,0.08)',
                fill: true,
                tension: 0.4,
                pointRadius: 2,
                pointHoverRadius: 4,
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#64748b', maxTicksLimit: 8 }, grid: { color: '#1e293b' } },
                y: { ticks: { color: '#64748b' }, grid: { color: '#1e293b' }, beginAtZero: true }
            }
        }
    });
}

function updateAlertChartBadge(alertsByHour) {
    const total = alertsByHour.reduce((s, r) => s + r.count, 0);
    const badge = document.getElementById('alertChartBadge');
    if (badge) badge.textContent = total + ' total';
}

function buildAttacksChart(attacksByType) {
    const ctx = document.getElementById('attacksChart');
    if (!ctx) return;

    const labels = attacksByType.map(r => r.attack_type);
    const values = attacksByType.map(r => r.count);
    const colors = ['#ef4444', '#eab308', '#06b6d4', '#8b5cf6', '#22c55e'];

    if (attacksPieChart) {
        attacksPieChart.data.labels = labels;
        attacksPieChart.data.datasets[0].data = values;
        attacksPieChart.update('none');
        return;
    }

    if (!labels.length) {
        const empty = document.getElementById('attacksChart');
        if (empty) empty.style.display = 'none';
        const parent = empty?.parentElement;
        if (parent && !parent.querySelector('.no-data-msg')) {
            const msg = document.createElement('p');
            msg.className = 'text-muted text-center no-data-msg';
            msg.textContent = 'No attacks detected';
            parent.appendChild(msg);
        }
        return;
    }

    attacksPieChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels,
            datasets: [{
                data: values,
                backgroundColor: colors.slice(0, labels.length),
                borderWidth: 0,
            }]
        },
        options: {
            cutout: '60%',
            plugins: {
                legend: { position: 'bottom', labels: { color: '#94a3b8', font: {size: 11} } }
            }
        }
    });
}

async function loadRecentAlerts() {
    const tbody = document.getElementById('recentAlertsBody');
    if (!tbody) return;
    try {
        const resp = await fetch('/api/alerts?limit=8');
        const data = await resp.json();
        const alerts = data.alerts || [];
        tbody.innerHTML = alerts.map(a =>
            `<tr>
                <td>${sevBadge(a.severity)}</td>
                <td><code class="text-cyan small">${a.alert_type || ''}</code></td>
                <td class="small">${(a.message || '').substring(0, 50)}</td>
                <td class="text-muted small">${formatTime(a.timestamp)}</td>
            </tr>`
        ).join('') || '<tr><td colspan="4" class="text-center text-muted py-3">No alerts</td></tr>';
    } catch (_) {}
}

async function loadRecentAttacks() {
    const tbody = document.getElementById('recentAttacksBody');
    if (!tbody) return;
    try {
        const resp = await fetch('/api/attacks?limit=8');
        const data = await resp.json();
        const attacks = data.attacks || [];
        tbody.innerHTML = attacks.map(a =>
            `<tr>
                <td><span class="badge bg-danger">${a.attack_type || ''}</span></td>
                <td>${sevBadge(a.severity)}</td>
                <td><code class="text-red small">${(a.source_mac || 'N/A').substring(0, 17)}</code></td>
                <td class="text-muted small">${formatTime(a.timestamp)}</td>
            </tr>`
        ).join('') || '<tr><td colspan="4" class="text-center text-muted py-3">No attacks</td></tr>';
    } catch (_) {}
}

// ---- Sidebar Toggle ----
function initSidebar() {
    const btn = document.getElementById('sidebarToggle');
    if (btn) {
        btn.addEventListener('click', () => {
            const sidebar = document.getElementById('sidebar');
            if (sidebar) sidebar.style.width = sidebar.style.width === '60px' ? '' : '60px';
        });
    }
}

// ---- Init ----
document.addEventListener('DOMContentLoaded', () => {
    startClock();
    initSidebar();
    refreshAlertBadge();
    setInterval(refreshAlertBadge, 15000);
});
