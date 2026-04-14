const tbody      = document.querySelector('#riskTable tbody');
const empty      = document.getElementById('emptyMessage');
const modal      = document.getElementById('modal');
const modalTitle = document.getElementById('modalTitle');
const modalBody  = document.getElementById('modalBody');

document.getElementById('closeModal').addEventListener('click', closeModal);
window.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });

/* ── FETCH DATA ─────────────────────────────────────────────────────── */
async function analyzeLogs() {
    try {
        const res = await fetch('./dashboard-data.json');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();

        if (!data || !Array.isArray(data.ipData) || data.ipData.length === 0) {
            empty.style.display = 'block';
            empty.textContent = 'No log data found.';
            updateStats(0, 0, 0, 0);
            return;
        }

        empty.style.display = 'none';
        updateStats(data.totalLogs, data.uniqueIps, data.highRiskIps, data.suspiciousLogs);
        renderTable(data.ipData);
        renderCharts(data.ipData);

    } catch (err) {
        console.error('analyzeLogs error:', err);
        empty.style.display = 'block';
        empty.textContent = 'Could not load dashboard-data.json — run the analyzer first.';
        updateStats(0, 0, 0, 0);
    }
}

/* ── STATS ──────────────────────────────────────────────────────────── */
function updateStats(total, unique, high, suspicious) {
    document.getElementById('totalLogs').textContent      = Number(total).toLocaleString();
    document.getElementById('uniqueIps').textContent      = unique      || 0;
    document.getElementById('highRiskIps').textContent    = high        || 0;
    document.getElementById('suspiciousLogs').textContent = suspicious  || 0;
}

/* ── TABLE ──────────────────────────────────────────────────────────── */
function renderTable(ipData) {
    tbody.innerHTML = '';
    const flagged = ipData.filter(ip => ip.risk > 0);

    if (flagged.length === 0) {
        empty.style.display = 'block';
        empty.textContent = 'No suspicious IPs detected.';
        return;
    }

    flagged.forEach(item => {
        const tr = document.createElement('tr');
        tr.style.cursor = 'pointer';
        tr.title = 'Click for full details';
        tr.setAttribute('data-threat', item.status);
        tr.setAttribute('data-ip', item.ip);
        tr.innerHTML = `
            <td>${item.ip}</td>
            <td>${item.requests}</td>
            <td>${item.risk}</td>
            <td><span class="badge ${item.status}">${item.status}</span></td>
        `;
        tr.addEventListener('click', () => showDetails(item));
        tbody.appendChild(tr);
    });
}

/* ── CHARTS ─────────────────────────────────────────────────────────── */
let pieChart = null;
let barChart = null;

function renderCharts(ipData) {
    if (typeof Chart === 'undefined') {
        console.error('Chart.js not loaded');
        return;
    }

    const pieCanvas = document.getElementById('chartPie');
    const barCanvas = document.getElementById('chartBar');
    if (!pieCanvas || !barCanvas) {
        console.error('Chart canvases not found in DOM');
        return;
    }

    const high   = ipData.filter(d => d.status === 'HIGH').length;
    const medium = ipData.filter(d => d.status === 'MEDIUM').length;
    const low    = ipData.filter(d => d.status === 'LOW').length;

    const isDark     = document.documentElement.getAttribute('data-theme') === 'dark';
    const gridColor  = isDark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.08)';
    const labelColor = isDark ? '#8b8a88' : '#6b6a68';
    const bgColor    = isDark ? '#1a1917' : '#ffffff';

    const tooltip = {
        backgroundColor: bgColor,
        borderColor: isDark ? 'rgba(255,255,255,0.12)' : 'rgba(0,0,0,0.12)',
        borderWidth: 1,
        titleColor: isDark ? '#d4d3d1' : '#1a1916',
        bodyColor: labelColor,
        padding: 10,
        cornerRadius: 8
    };

    /* PIE / DOUGHNUT */
    if (pieChart) { pieChart.destroy(); pieChart = null; }
    pieChart = new Chart(pieCanvas, {
        type: 'doughnut',
        data: {
            labels: ['High Risk', 'Medium Risk', 'Low Risk'],
            datasets: [{
                data: [high, medium, low],
                backgroundColor: ['#e05c4a', '#e8924a', '#5aaa38'],
                borderColor: bgColor,
                borderWidth: 3,
                hoverOffset: 10
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '60%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: labelColor,
                        font: { size: 12 },
                        padding: 16,
                        usePointStyle: true,
                        pointStyleWidth: 10
                    }
                },
                tooltip: tooltip
            }
        }
    });

    /* BAR — Top 10 by Risk */
    const top10 = [...ipData]
        .sort((a, b) => b.risk - a.risk)
        .slice(0, 10);

    const colors = top10.map(d =>
        d.status === 'HIGH' ? '#e05c4a' : d.status === 'MEDIUM' ? '#e8924a' : '#5aaa38'
    );

    if (barChart) { barChart.destroy(); barChart = null; }
    barChart = new Chart(barCanvas, {
        type: 'bar',
        data: {
            labels: top10.map(d => d.ip),
            datasets: [{
                label: 'Risk Score',
                data: top10.map(d => d.risk),
                backgroundColor: colors.map(c => c + 'bb'),
                borderColor: colors,
                borderWidth: 1.5,
                borderRadius: 6,
                borderSkipped: false
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    ...tooltip,
                    callbacks: { label: item => ' Risk Score: ' + item.raw }
                }
            },
            scales: {
                x: {
                    ticks: { color: labelColor, font: { size: 10 }, maxRotation: 40 },
                    grid: { color: gridColor }
                },
                y: {
                    min: 0,
                    max: 100,
                    ticks: { color: labelColor, font: { size: 11 }, stepSize: 25 },
                    grid: { color: gridColor }
                }
            }
        }
    });
}

/* ── MODAL ──────────────────────────────────────────────────────────── */
function showDetails(item) {
    modalTitle.textContent = '📍 ' + item.ip;
    modalBody.innerHTML = `
        <table class="detail-table">
            <tr><td>🌐 IP Address</td>      <td>${item.ip}</td></tr>
            <tr><td>📨 Total Requests</td>  <td>${item.requests}</td></tr>
            <tr><td>⚠️ Risk Score</td>       <td>${item.risk}</td></tr>
            <tr><td>🚦 Status</td>           <td><span class="badge ${item.status}">${item.status}</span></td></tr>
            <tr><td>🔐 Auth Errors</td>     <td>${item.authErrors}</td></tr>
            <tr><td>🔍 404 Errors</td>      <td>${item.notFoundErrors}</td></tr>
            <tr><td>❌ Failed Logins</td>    <td>${item.failedLogins}</td></tr>
            <tr><td>🔗 Unique URLs</td>     <td>${item.uniqueURLs}</td></tr>
            <tr><td>🎯 Threats Detected</td><td>${item.threats || 'None'}</td></tr>
        </table>
    `;
    modal.style.display = 'flex';
}

function closeModal() {
    modal.style.display = 'none';
}

/* ── FILTER & SEARCH ────────────────────────────────────────────────── */
let activeFilter = 'ALL';

function setFilter(f, btn) {
    activeFilter = f;
    document.querySelectorAll('.pill').forEach(p => {
        p.classList.remove('active');
        p.setAttribute('aria-pressed', 'false');
    });
    if (btn) { btn.classList.add('active'); btn.setAttribute('aria-pressed', 'true'); }
    filterTable();
}

function filterTable() {
    const searchEl = document.getElementById('searchInput');
    const q = searchEl ? searchEl.value.toLowerCase().trim() : '';
    const rows = document.querySelectorAll('#riskTable tbody tr[data-threat]');
    let visible = 0;
    rows.forEach(r => {
        const ip     = (r.getAttribute('data-ip') || '').toLowerCase();
        const threat =  r.getAttribute('data-threat') || '';
        const show   = ip.includes(q) && (activeFilter === 'ALL' || threat === activeFilter);
        r.style.display = show ? '' : 'none';
        if (show) visible++;
    });
    empty.style.display = visible === 0 ? 'block' : 'none';
    if (visible === 0) empty.textContent = 'No results match your filter.';
}

/* ── INIT ───────────────────────────────────────────────────────────── */
analyzeLogs();