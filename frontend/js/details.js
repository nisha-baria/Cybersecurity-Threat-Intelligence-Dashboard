document.addEventListener("DOMContentLoaded", async () => {
    const params = new URLSearchParams(window.location.search);
    const threatId = params.get("id");
    const container = document.getElementById("content");

    if (!threatId) {
        container.innerHTML = "<p>No Threat Identifier provided in request query.</p>";
        return;
    }

    try {
        const res = await fetch(`/api/threats/${threatId}`);
        if (!res.ok) throw new Error("Threat record unavailable");
        const t = await res.json();

        container.innerHTML = `
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:1.5rem; margin-top:1rem;">
                <div>
                    <p><strong>Threat ID:</strong> <code>${t.threat_id}</code></p>
                    <p><strong>Indicator Value:</strong> <code>${t.indicator_value}</code></p>
                    <p><strong>Indicator Type:</strong> ${t.indicator_type}</p>
                    <p><strong>Category:</strong> ${t.threat_category}</p>
                    <p><strong>Severity:</strong> <span style="color:#ef4444; font-weight:bold;">${t.severity}</span></p>
                </div>
                <div>
                    <p><strong>Risk Score:</strong> ${t.risk_score} / 100</p>
                    <p><strong>Confidence:</strong> ${t.confidence_score}%</p>
                    <p><strong>Feed Source:</strong> ${t.source_name} (Reliability: ${t.source_reliability})</p>
                    <p><strong>First Seen:</strong> ${t.first_seen}</p>
                    <p><strong>Last Telemetry:</strong> ${t.last_seen}</p>
                </div>
            </div>
            <hr style="border:0; border-top:1px solid #1e293b; margin:1.5rem 0;">
            <h3>MITRE ATT&CK Behavioral Mapping</h3>
            <p><strong>Tactic:</strong> ${t.mitre_tactic} | <strong>Technique:</strong> ${t.mitre_technique} (<code>${t.mitre_technique_id}</code>)</p>
            <p><strong>Analyst Guidance:</strong> Passive defense logging only. Do not trigger outbound socket queries or execute payloads associated with this record.</p>
        `;
    } catch (err) {
        container.innerHTML = `<p style="color:#ef4444;">Failed to fetch record ${threatId}: ${err.message}</p>`;
    }
});