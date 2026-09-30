document.addEventListener("DOMContentLoaded", () => {
    fetchDashboardStats();
    fetchRecentThreats();
});

async function fetchDashboardStats() {
    try {
        const res = await fetch("/api/dashboard/stats");
        const data = await res.json();

        document.getElementById("totalThreats").innerText = data.total_threats;
        document.getElementById("critThreats").innerText = data.critical_threats;
        document.getElementById("highThreats").innerText = data.high_threats;
        document.getElementById("uniqueIocs").innerText = data.unique_indicators;
        document.getElementById("avgConf").innerText = `${data.avg_confidence}%`;

        renderCharts(data);
    } catch (err) {
        console.error("Failed to load statistics:", err);
    }
}

async function fetchRecentThreats() {
    try {
        const res = await fetch("/api/threats?limit=15");
        const json = await res.json();
        const tbody = document.getElementById("threatTableBody");
        tbody.innerHTML = "";

        json.data.forEach(t => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><code>${t.threat_id}</code></td>
                <td>${t.threat_category}</td>
                <td><span class="badge">${t.indicator_type}</span></td>
                <td><code>${t.indicator_value}</code></td>
                <td style="color:${t.severity === 'CRITICAL' ? '#ef4444' : '#38bdf8'}">${t.severity}</td>
                <td>${t.risk_score}/100</td>
                <td>${t.confidence_score}%</td>
                <td>${t.status}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error("Failed to render threat feed:", err);
    }
}

function renderCharts(stats) {
    const sevCtx = document.getElementById("sevChart").getContext("2d");
    new Chart(sevCtx, {
        type: "doughnut",
        data: {
            labels: Object.keys(stats.severity_distribution),
            datasets: [{
                data: Object.values(stats.severity_distribution),
                backgroundColor: ["#38bdf8", "#34d399", "#fbbf24", "#f97316", "#ef4444"]
            }]
        },
        options: { plugins: { title: { display: true, text: "Threats by Severity", color: "#fff" } } }
    });

    const catCtx = document.getElementById("catChart").getContext("2d");
    new Chart(catCtx, {
        type: "bar",
        data: {
            labels: Object.keys(stats.category_distribution),
            datasets: [{
                label: "Sightings",
                data: Object.values(stats.category_distribution),
                backgroundColor: "#38bdf8"
            }]
        },
        options: {
            plugins: { title: { display: true, text: "Threat Distribution by Category", color: "#fff" } },
            scales: { x: { ticks: { color: "#94a3b8" } }, y: { ticks: { color: "#94a3b8" } } }
        }
    });
}

async function performSearch() {
    const query = document.getElementById("iocSearchInput").value;
    if (!query) return;

    const resBox = document.getElementById("searchResults");
    resBox.classList.remove("hidden");
    resBox.innerHTML = "Querying local threat intel...";

    try {
        const res = await fetch(`/api/indicators/search?query=${encodeURIComponent(query)}`);
        const data = await res.json();

        if (!data.known_in_dataset) {
            resBox.innerHTML = `<strong>Result:</strong> Syntactically Valid: <code>${data.validation.valid}</code> | Type: <code>${data.indicator_type}</code> | No malicious sightings logged in demo database.`;
            return;
        }

        resBox.innerHTML = `
            <h3>Analysis for: <code>${data.indicator}</code></h3>
            <p><strong>Indicator Type:</strong> ${data.indicator_type} | <strong>Risk:</strong> ${data.risk_score}/100 | <strong>Confidence:</strong> ${data.confidence_score}%</p>
            <p><strong>Associated Category:</strong> ${data.category} | <strong>Severity:</strong> ${data.severity}</p>
            <p><strong>MITRE ATT&CK:</strong> ${data.mitre_mapping.tactic} (${data.mitre_mapping.technique_id})</p>
            <p><strong>Defensive Recommendation:</strong> ${data.defensive_guidance}</p>
        `;
    } catch (err) {
        resBox.innerHTML = "Query evaluation encountered an error.";
    }
}