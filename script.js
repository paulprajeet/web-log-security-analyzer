const tbody   = document.querySelector('#riskTable tbody');
const empty   = document.getElementById('emptyMessage');
const modal   = document.getElementById('modal');
const modalTitle = document.getElementById('modalTitle');
const modalBody  = document.getElementById('modalBody');


document.getElementById('closeModal').addEventListener('click', closeModal);
window.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });

async function analyzeLogs() {
    try {
        const res = await fetch('./dashboard-data.json');
        if (!res.ok) throw new Error('Not found');

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

    } catch (err) {
        console.error(err);
        empty.style.display = 'block';
        empty.textContent = '❌ Could not load dashboard-data.json — run the analyzer first.';
        updateStats(0, 0, 0, 0);
    }
}

function updateStats(total, unique, high, suspicious) {
    document.getElementById('totalLogs').textContent      = Number(total).toLocaleString();
    document.getElementById('uniqueIps').textContent      = unique      || 0;
    document.getElementById('highRiskIps').textContent    = high        || 0;
    document.getElementById('suspiciousLogs').textContent = suspicious  || 0;
}

// TABLE — shows only basic columns, only flagged IPs
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

// MODAL — shows full details on click
function showDetails(item) {
    modalTitle.textContent = `📍 ${item.ip}`;
    modalBody.innerHTML = `
        <table class="detail-table">
            <tr>
                <td>🌐 IP Address</td>
                <td>${item.ip}</td>
            </tr>
            <tr>
                <td>📨 Total Requests</td>
                <td>${item.requests}</td>
            </tr>
            <tr>
                <td>⚠️ Risk Score</td>
                <td>${item.risk}</td>
            </tr>
            <tr>
                <td>🚦 Status</td>
                <td><span class="badge ${item.status}">${item.status}</span></td>
            </tr>
            <tr>
                <td>🔐 Auth Errors</td>
                <td>${item.authErrors}</td>
            </tr>
            <tr>
                <td>🔍 404 Errors</td>
                <td>${item.notFoundErrors}</td>
            </tr>
            <tr>
                <td>❌ Failed Logins</td>
                <td>${item.failedLogins}</td>
            </tr>
            <tr>
                <td>🔗 Unique URLs</td>
                <td>${item.uniqueURLs}</td>
            </tr>
            <tr>
                <td>🎯 Threats Detected</td>
                <td>${item.threats || 'None'}</td>
            </tr>
        </table>
    `;
    modal.style.display = 'flex';
}

function closeModal() {
    modal.style.display = 'none';
}

analyzeLogs();