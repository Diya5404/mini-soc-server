// Global chart instances
let eventsChart, alertsChart, attackersChart;

// Setup Charts
function initCharts() {
    Chart.defaults.color = '#8b949e';
    Chart.defaults.font.family = "'Inter', sans-serif";

    // Events Timeline Chart
    const ctx1 = document.getElementById('eventsChart').getContext('2d');
    eventsChart = new Chart(ctx1, {
        type: 'line',
        data: { labels: [], datasets: [{ label: 'Events / Min', data: [], borderColor: '#58a6ff', backgroundColor: 'rgba(88, 166, 255, 0.15)', fill: true, tension: 0.4, pointRadius: 3, pointHoverRadius: 6 }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { title: { display: true, text: 'Events Timeline (Requests/Min)' }, legend: { display: false } }, scales: { y: { beginAtZero: true, grid: { color: 'rgba(48, 54, 61, 0.5)' } }, x: { grid: { display: false } } } }
    });

    // Alerts by Severity Chart
    const ctx2 = document.getElementById('alertsSeverityChart').getContext('2d');
    alertsChart = new Chart(ctx2, {
        type: 'doughnut',
        data: { labels: ['High', 'Medium', 'Low'], datasets: [{ data: [0, 0, 0], backgroundColor: ['#f85149', '#d29922', '#2ea043'], borderWidth: 0, hoverOffset: 4 }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { title: { display: true, text: 'Alerts by Severity' }, legend: { position: 'bottom' } }, cutout: '75%' }
    });

    // Top Attackers Chart
    const ctx3 = document.getElementById('topAttackersChart').getContext('2d');
    attackersChart = new Chart(ctx3, {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Alerts trigger count', data: [], backgroundColor: '#a371f7', borderRadius: 4, hoverBackgroundColor: '#b388ff' }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { title: { display: true, text: 'Top Attacker IPs (Port Scans)' }, legend: { display: false } }, scales: { y: { beginAtZero: true, grid: { color: 'rgba(48, 54, 61, 0.5)' } }, x: { grid: { display: false } } } }
    });
}

function updateDashboard() {
    fetch('/api/data')
        .then(response => response.json())
        .then(data => {
            updatePanels(data);
            updateTables(data);
            if (document.getElementById('eventsChart')) {
                updateChartsData(data);
            }
        })
        .catch(error => console.error('Error fetching data:', error));
}

function updatePanels(data) {
    if (document.getElementById('total-events')) animateValue('total-events', data.events.length);
    if (document.getElementById('total-alerts')) animateValue('total-alerts', data.alerts.length);

    if (document.getElementById('high-alerts')) {
        const highAlerts = data.alerts.filter(a => a.severity === 'HIGH').length;
        animateValue('high-alerts', highAlerts);
    }

    if (document.getElementById('avg-threat') && data.alerts.length > 0) {
        const totalScore = data.alerts.reduce((sum, a) => sum + (a.threat_score || 0), 0);
        document.getElementById('avg-threat').innerText = (totalScore / data.alerts.length).toFixed(1);
    }

    if (document.getElementById('incident-count')) document.getElementById('incident-count').innerText = data.incidents.length;
    if (document.getElementById('response-count') && data.responses) document.getElementById('response-count').innerText = data.responses.length;
    if (document.getElementById('event-count')) document.getElementById('event-count').innerText = data.events.length;
    if (document.getElementById('alert-count')) document.getElementById('alert-count').innerText = data.alerts.length;
}

function animateValue(id, value) {
    const el = document.getElementById(id);
    if (el && parseInt(el.innerText) !== value) {
        el.innerText = value;
        el.style.transform = "scale(1.2)";
        setTimeout(() => el.style.transform = "scale(1)", 200);
    }
}

function getSeverityClass(severity) {
    if (severity === 'HIGH') return 'severity-high';
    if (severity === 'MEDIUM') return 'severity-medium';
    return 'severity-low';
}

function formatTime(isoStr) {
    if (!isoStr) return 'N/A';
    const d = new Date(isoStr);
    return d.toLocaleTimeString([], { hour12: false });
}

function createRow(contentHtml, isNew = false) {
    return `<tr ${isNew ? 'style="animation: fadeIn 0.5s ease"' : ''}>${contentHtml}</tr>`;
}

function updateTables(data) {
    // Responses Table
    const respBody = document.querySelector('#responses-table tbody');
    if (data.responses && respBody) {
        respBody.innerHTML = '';
        [...data.responses].reverse().slice(0, 10).forEach(resp => {
            const html = `
                <td><strong>${formatTime(resp.timestamp)}</strong></td>
                <td>${resp.agent_id}</td>
                <td><span class="tag" style="background: rgba(88, 166, 255, 0.15); color: var(--highlight); border: 1px solid rgba(88,166,255,0.3);">${resp.action_type}</span></td>
                <td><strong>${resp.target}</strong></td>
                <td><span class="tag ${resp.status === 'success' ? 'severity-low' : 'severity-high'}">${resp.status}</span></td>
                <td>${resp.details || ''}</td>
            `;
            respBody.innerHTML += createRow(html);
        });
    }

    // Incidents Table
    const incBody = document.querySelector('#incidents-table tbody');
    if (incBody) {
        incBody.innerHTML = '';
        [...data.incidents].reverse().slice(0, 10).forEach(inc => {
            const html = `
                <td><strong>${formatTime(inc.timestamp)}</strong></td>
                <td><span class="tag ${getSeverityClass(inc.severity)}">${inc.severity}</span></td>
                <td><strong>${inc.threat_score}</strong></td>
                <td><span class="highlight">${inc.mitre_technique || 'N/A'}</span></td>
                <td>${inc.message || ''}</td>
            `;
            incBody.innerHTML += createRow(html);
        });
    }

    // Alerts Table
    const altBody = document.querySelector('#alerts-table tbody');
    if (altBody) {
        altBody.innerHTML = '';
        [...data.alerts].reverse().slice(0, 10).forEach(alt => {
            const sevClass = getSeverityClass(alt.severity) || 'severity-low';
            const html = `
                <td>${formatTime(alt.timestamp)}</td>
                <td><strong>${alt.alert_type}</strong></td>
                <td><span class="tag ${sevClass}">${alt.severity || 'UNKNOWN'}</span></td>
                <td>${alt.source || 'Unknown'}</td>
                <td>${alt.message}</td>
            `;
            altBody.innerHTML += createRow(html);
        });
    }

    // Events Table
    const evtBody = document.querySelector('#events-table tbody');
    if (evtBody) {
        evtBody.innerHTML = '';
        [...data.events].reverse().slice(0, 15).forEach(evt => {
            let msg = typeof evt.message === 'string' ? evt.message : JSON.stringify(evt.message);
            if (msg.length > 70) msg = msg.substring(0, 70) + '...';
            const html = `
                <td>${formatTime(evt.timestamp)}</td>
                <td>${evt.event_type}</td>
                <td>${evt.source}</td>
                <td style="font-family: monospace; font-size: 0.85rem; color: #8b949e;">${msg}</td>
            `;
            evtBody.innerHTML += createRow(html);
        });
    }
}

function updateChartsData(data) {
    if (!alertsChart || !eventsChart || !attackersChart) return;

    // Alerts Severity Doughnut
    let high = 0, med = 0, low = 0;
    data.alerts.forEach(a => {
        if (a.severity === 'HIGH') high++;
        else if (a.severity === 'MEDIUM') med++;
        else low++;
    });
    alertsChart.data.datasets[0].data = [high, med, low];
    alertsChart.update();

    // Events Timeline
    const eventsByMin = {};
    data.events.forEach(e => {
        if (e.timestamp) {
            const minStr = e.timestamp.substring(11, 16);
            eventsByMin[minStr] = (eventsByMin[minStr] || 0) + 1;
        }
    });

    let sortedMins = Object.keys(eventsByMin).sort();
    if (sortedMins.length > 10) {
        sortedMins = sortedMins.slice(-10);
    }

    eventsChart.data.labels = sortedMins;
    eventsChart.data.datasets[0].data = sortedMins.map(m => eventsByMin[m]);
    eventsChart.update();

    // Top Attackers
    const attackers = {};
    data.alerts.forEach(a => {
        if (a.alert_type === 'port_scan_detected') {
            const match = a.message.match(/from ([\d\.]+)/);
            if (match && match[1]) {
                const ip = match[1];
                attackers[ip] = (attackers[ip] || 0) + 1;
            }
        }
    });

    const sortedIp = Object.keys(attackers).sort((a, b) => attackers[b] - attackers[a]).slice(0, 5);
    attackersChart.data.labels = sortedIp;
    attackersChart.data.datasets[0].data = sortedIp.map(ip => attackers[ip]);
    attackersChart.update();
}

// Add CSS keyframe for table rows dynamically
const style = document.createElement('style');
style.innerHTML = `@keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }`;
document.head.appendChild(style);

window.onload = () => {
    if (document.getElementById('eventsChart')) {
        initCharts();
    }
    updateDashboard();
    setInterval(updateDashboard, 5000);
};
