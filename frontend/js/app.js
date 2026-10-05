/**
 * AEGIS-SOC Master Frontend Application Controller
 * Handles WebSockets, UI state, DEFCON levels, and real-time feeds.
 */

document.addEventListener('DOMContentLoaded', () => {
    // Initialize Lucide icons
    if (window.lucide) window.lucide.createIcons();

    // Components
    const attackGraph = new AttackGraphVisualizer('attackGraphCanvas');
    const mitreHeatmap = new MitreHeatmap('mitreMatrixGrid');
    const aiConsole = new AIConsoleManager();

    // State
    let totalEvents = 0;
    let criticalAlerts = 0;
    let highAlerts = 0;
    let soarActionsCount = 0;
    let eventCountWindow = 0;
    let currentDefcon = 5;

    // Elements
    const kpiTotalEvents = document.getElementById('kpiTotalEvents');
    const kpiEps = document.getElementById('kpiEps');
    const kpiCriticalAlerts = document.getElementById('kpiCriticalAlerts');
    const kpiHighAlerts = document.getElementById('kpiHighAlerts');
    const kpiMitreTactics = document.getElementById('kpiMitreTactics');
    const kpiSoarActions = document.getElementById('kpiSoarActions');
    const eventTableBody = document.getElementById('eventTableBody');
    const alertListContainer = document.getElementById('alertListContainer');
    const soarTableBody = document.getElementById('soarTableBody');
    const defconLevel = document.getElementById('defconLevel');
    const defconText = document.getElementById('defconText');
    const defconGlow = document.getElementById('defconGlow');
    const defconContainer = document.getElementById('defconGauge');
    const clockDisplay = document.getElementById('clockDisplay');
    const activeAlertCount = document.getElementById('activeAlertCount');

    // Modals
    const dossierModal = document.getElementById('dossierModal');
    const dossierBody = document.getElementById('dossierModalBody');
    const eventModal = document.getElementById('eventModal');
    const rawEventJsonContent = document.getElementById('rawEventJsonContent');

    // 1. Clock Ticker
    setInterval(() => {
        const now = new Date();
        clockDisplay.textContent = now.toUTCString().split(' ')[4] + ' UTC';
    }, 1000);

    // 1b. Real Windows Host Telemetry Poller
    async function updateHostTelemetry() {
        try {
            const resp = await fetch('/api/host-info');
            const info = await resp.json();
            if (info && info.hostname) {
                const liveHostName = document.getElementById('liveHostName');
                const liveHostStats = document.getElementById('liveHostStats');
                if (liveHostName) liveHostName.textContent = info.hostname;
                if (liveHostStats) {
                    const osShort = info.os ? info.os.split('-')[0] : 'Windows';
                    liveHostStats.textContent = `${osShort} • ${info.total_processes} Procs • ${info.cpu_percent}% CPU • ${info.ram_percent}% RAM`;
                }
            }
        } catch (e) {
            console.debug('Host info error:', e);
        }
    }
    updateHostTelemetry();
    setInterval(updateHostTelemetry, 3000);

    // 1c. Autonomous Auto-Kill Mode Toggle
    const btnToggleAutoSoar = document.getElementById('btnToggleAutoSoar');
    const autoSoarStatusText = document.getElementById('autoSoarStatusText');

    async function checkAutoSoarMode() {
        try {
            const resp = await fetch('/api/soar/mode');
            const data = await resp.json();
            updateAutoSoarUI(data.auto_soar_enabled);
        } catch (e) {}
    }

    function updateAutoSoarUI(enabled) {
        if (enabled) {
            btnToggleAutoSoar.classList.remove('disabled');
            autoSoarStatusText.textContent = 'AUTO-KILL: ON';
        } else {
            btnToggleAutoSoar.classList.add('disabled');
            autoSoarStatusText.textContent = 'AUTO-KILL: OFF';
        }
    }

    btnToggleAutoSoar?.addEventListener('click', async () => {
        try {
            const resp = await fetch('/api/soar/toggle-auto', { method: 'POST' });
            const data = await resp.json();
            updateAutoSoarUI(data.auto_soar_enabled);
            aiConsole.addThought(
                'Containment Mode Changed',
                `Autonomous SOAR is now ${data.auto_soar_enabled ? 'ENABLED (Auto-Kill & Auto-Isolate active)' : 'DISABLED (Manual approval required)'}`,
                data.auto_soar_enabled ? 'green' : 'amber'
            );
        } catch (e) {
            console.error('Toggle error:', e);
        }
    });

    checkAutoSoarMode();

    // 2. EPS Calculation
    setInterval(() => {
        const eps = (eventCountWindow / 2).toFixed(1);
        if (kpiEps) kpiEps.textContent = `${eps} EPS`;
        eventCountWindow = 0;
    }, 2000);

    // 3. Tab Switching
    document.querySelectorAll('.tab-btn[data-tab]').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            const targetId = btn.getAttribute('data-tab');
            document.getElementById(targetId)?.classList.add('active');
            if (targetId === 'tab-war-room') {
                attackGraph.initCanvasSize();
            }
        });
    });

    // 4. DEFCON Update Logic
    function setDefcon(level, reason = '') {
        currentDefcon = level;
        const defconConfig = {
            1: { name: 'DEFCON 1', text: 'MAXIMUM ALERT // CRITICAL INTRUSION', color: '#ef4444', bg: 'rgba(239, 68, 68, 0.15)' },
            2: { name: 'DEFCON 2', text: 'CREDENTIAL BREACH DETECTED', color: '#f97316', bg: 'rgba(249, 115, 22, 0.15)' },
            3: { name: 'DEFCON 3', text: 'SUSPICIOUS EXECUTION OBSERVED', color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.15)' },
            4: { name: 'DEFCON 4', text: 'ANOMALOUS TELEMETRY', color: '#3b82f6', bg: 'rgba(59, 130, 246, 0.15)' },
            5: { name: 'DEFCON 5', text: 'NORMAL BASELINE // SECURE', color: '#10b981', bg: 'rgba(16, 185, 129, 0.1)' }
        };
        const cfg = defconConfig[level] || defconConfig[5];
        defconLevel.textContent = cfg.name;
        defconText.textContent = cfg.text;
        defconLevel.style.color = cfg.color;
        defconContainer.style.borderColor = cfg.color;
        defconContainer.style.background = cfg.bg;
        defconGlow.style.background = cfg.color;

        if (reason) {
            aiConsole.addThought('DEFCON Escalation', `${cfg.name}: ${reason}`, level <= 2 ? 'red' : 'cyan');
        }
    }

    // 5. WebSocket Telemetry Connection
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;
    const socket = new WebSocket(wsUrl);

    socket.onopen = () => {
        document.getElementById('wsStatusText').textContent = 'WEBSOCKET ACTIVE';
        document.getElementById('wsPulse').classList.remove('crimson');
        document.getElementById('wsPulse').classList.add('green');
        aiConsole.addThought('Stream Link', 'Real-time WebSocket connection established with sensor pipeline.', 'green');
    };

    socket.onclose = () => {
        document.getElementById('wsStatusText').textContent = 'RECONNECTING...';
        document.getElementById('wsPulse').classList.remove('green');
        document.getElementById('wsPulse').classList.add('crimson');
    };

    socket.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            handleIncomingMessage(msg);
        } catch (e) {
            console.error('Error parsing WS message:', e);
        }
    };

    function handleIncomingMessage(msg) {
        if (msg.type === 'INIT') {
            if (msg.graph) attackGraph.setData(msg.graph);
            if (msg.dossier) setDefcon(msg.dossier.defcon_level);
        } else if (msg.type === 'EVENT') {
            renderEventRow(msg.data);
        } else if (msg.type === 'ALERT') {
            renderAlert(msg.data);
        } else if (msg.type === 'SOAR_ACTION') {
            renderSoarAction(msg.data);
        }
    }

    // 6. Render Event in Telemetry Table
    function renderEventRow(ev) {
        totalEvents++;
        eventCountWindow++;
        if (kpiTotalEvents) kpiTotalEvents.textContent = totalEvents.toLocaleString();

        const tr = document.createElement('tr');
        if (ev.severity === 'CRITICAL') tr.className = 'row-crit';

        const timeStr = ev.timestamp ? ev.timestamp.split('T')[1].replace('Z', '').split('.')[0] : '--:--:--';
        const cmd = ev.command_line || (ev.raw_data ? JSON.stringify(ev.raw_data).slice(0, 50) : '');

        tr.innerHTML = `
            <td>${timeStr}</td>
            <td><span class="badge-sev ${ev.severity}">${ev.severity}</span></td>
            <td>${ev.channel.replace('Microsoft-Windows-', '')}</td>
            <td><strong>${ev.event_id}</strong></td>
            <td>${ev.computer}</td>
            <td>${ev.process_name ? ev.process_name.split('\\').pop() : '-'}</td>
            <td class="cmd-cell" title="${cmd}">${cmd}</td>
            <td>${ev.mitre_tactic || '-'}</td>
            <td><button class="btn-inspect" data-raw='${JSON.stringify(ev)}'>View</button></td>
        `;

        eventTableBody.insertBefore(tr, eventTableBody.firstChild);

        // Keep table size reasonable
        if (eventTableBody.children.length > 80) {
            eventTableBody.removeChild(eventTableBody.lastChild);
        }

        // Attach modal trigger
        tr.querySelector('.btn-inspect').addEventListener('click', () => {
            rawEventJsonContent.textContent = JSON.stringify(ev, null, 2);
            eventModal.classList.add('active');
        });
    }

    // 7. Render Alert
    const activeAlertsSet = new Set();

    function renderAlert(alert) {
        if (alert.severity === 'CRITICAL') {
            criticalAlerts++;
            setDefcon(1, alert.title);
        } else if (alert.severity === 'HIGH') {
            highAlerts++;
            if (currentDefcon > 2) setDefcon(2, alert.title);
        }

        kpiCriticalAlerts.textContent = criticalAlerts;
        kpiHighAlerts.textContent = highAlerts;
        activeAlertsSet.add(alert.id || alert.title);
        activeAlertCount.textContent = `${activeAlertsSet.size} Alerts`;

        // Highlight in MITRE Heatmap
        if (alert.mitre_technique || alert.mitre_tactic) {
            mitreHeatmap.registerHit(alert.mitre_technique || alert.mitre_tactic);
            kpiMitreTactics.textContent = mitreHeatmap.hitMap.size;
        }

        // Clear empty state
        const emptyState = alertListContainer.querySelector('.empty-state');
        if (emptyState) emptyState.remove();

        const card = document.createElement('div');
        card.className = `alert-item-card ${alert.severity}`;
        card.innerHTML = `
            <div class="alert-card-header">
                <span class="alert-card-title">${alert.title}</span>
                <span class="badge-sev ${alert.severity}">${alert.severity}</span>
            </div>
            <div class="alert-card-meta">
                <span><i data-lucide="monitor"></i> ${alert.host}</span>
                <span><i data-lucide="user"></i> ${alert.user || 'SYSTEM'}</span>
                <span><i data-lucide="target"></i> ${alert.mitre_technique || alert.mitre_tactic}</span>
            </div>
            <p class="alert-card-desc">${alert.description}</p>
        `;

        alertListContainer.insertBefore(card, alertListContainer.firstChild);
        if (window.lucide) window.lucide.createIcons();

        // Feed to AI Console
        aiConsole.addThought(
            `Detection Rule Hit [${alert.severity}]`,
            `${alert.title} on host ${alert.host}. Technique: ${alert.mitre_technique}`,
            alert.severity === 'CRITICAL' ? 'red' : 'cyan'
        );

        // Fetch updated attack graph
        fetch('/api/attack-graph')
            .then(res => res.json())
            .then(data => attackGraph.setData(data));
    }

    // 8. Render SOAR action
    function renderSoarAction(action) {
        soarActionsCount++;
        kpiSoarActions.textContent = soarActionsCount;

        const tr = document.createElement('tr');
        const now = new Date().toTimeString().split(' ')[0];
        tr.innerHTML = `
            <td>${now}</td>
            <td><strong style="color: var(--cyan);">${action.action || action.action_type}</strong></td>
            <td>${action.target || action.host}</td>
            <td>${action.details || action.message}</td>
            <td><span class="badge-tag ai-badge">${action.executed_by || 'VALKYRIE-AI'}</span></td>
            <td><span style="color: var(--emerald);">COMPLETED</span></td>
        `;
        soarTableBody.insertBefore(tr, soarTableBody.firstChild);
    }

    // 9. Real Endpoint Sensor Controls
    document.getElementById('btnAuditNow')?.addEventListener('click', async () => {
        const btn = document.getElementById('btnAuditNow');
        const origContent = btn ? btn.innerHTML : '';
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<i data-lucide="loader-2" class="spin-icon"></i> Auditing Host...';
            if (window.lucide) lucide.createIcons();
        }
        aiConsole.addThought('LIVE AUDIT', 'Initiating instant live Windows kernel sweep (processes, TCP/UDP sockets, event logs)...', 'cyan');
        try {
            const resp = await fetch('/api/sensor/audit-now', { method: 'POST' });
            const data = await resp.json();
            aiConsole.addThought('AUDIT COMPLETE', `Swept real Windows host: ${data.telemetry?.total_processes || 0} active processes, ${data.telemetry?.active_connections || 0} sockets.`, 'green');
            
            // Immediate pill update with exact returned Windows telemetry
            if (data.telemetry) {
                const liveHostName = document.getElementById('liveHostName');
                const liveHostStats = document.getElementById('liveHostStats');
                if (liveHostName && data.telemetry.hostname) liveHostName.textContent = data.telemetry.hostname;
                if (liveHostStats) {
                    const osShort = data.telemetry.os ? data.telemetry.os.split('-')[0] : 'Windows';
                    liveHostStats.textContent = `${osShort} • ${data.telemetry.total_processes} Procs • ${data.telemetry.cpu_percent}% CPU • ${data.telemetry.ram_percent}% RAM`;
                }
            }
            await updateHostTelemetry();

            if (btn) {
                btn.innerHTML = '<i data-lucide="check" style="color: var(--emerald);"></i> Audit Complete!';
                if (window.lucide) lucide.createIcons();
                setTimeout(() => {
                    btn.innerHTML = origContent;
                    btn.disabled = false;
                    if (window.lucide) lucide.createIcons();
                }, 1800);
            }
        } catch (e) {
            console.error('Audit failed:', e);
            if (btn) {
                btn.innerHTML = origContent;
                btn.disabled = false;
                if (window.lucide) lucide.createIcons();
            }
        }
    });

    document.getElementById('btnTestDetection')?.addEventListener('click', async () => {
        const btn = document.getElementById('btnTestDetection');
        const origContent = btn ? btn.innerHTML : '';
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<i data-lucide="loader-2" class="spin-icon"></i> Executing...';
            if (window.lucide) lucide.createIcons();
        }
        aiConsole.addThought('REAL TEST', 'Executing real Windows reconnaissance command (whoami.exe /priv) on active OS...', 'purple');
        try {
            const resp = await fetch('/api/sensor/test-detection', { method: 'POST' });
            const data = await resp.json();
            aiConsole.addThought('PIPELINE VERIFIED', `Real OS command executed: ${data.command}. Event captured by live sensor.`, 'green');
            if (btn) {
                btn.innerHTML = '<i data-lucide="check" style="color: var(--emerald);"></i> Fired & Captured!';
                if (window.lucide) lucide.createIcons();
                setTimeout(() => {
                    btn.innerHTML = origContent;
                    btn.disabled = false;
                    if (window.lucide) lucide.createIcons();
                }, 1800);
            }
        } catch (e) {
            console.error('Detection test failed:', e);
            if (btn) {
                btn.innerHTML = origContent;
                btn.disabled = false;
                if (window.lucide) lucide.createIcons();
            }
        }
    });

    // 10. Dossier Modal
    document.getElementById('btnOpenDossier')?.addEventListener('click', async () => {
        const resp = await fetch('/api/dossier');
        const data = await resp.json();

        dossierBody.innerHTML = `
            <div style="display: flex; justify-content: space-between; margin-bottom: 16px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 12px;">
                <div>
                    <h3 style="font-family: var(--font-heading); font-size: 1.1rem; color: var(--cyan);">${data.dossier_id}</h3>
                    <p style="color: var(--text-muted); font-size: 0.75rem;">Generated by: ${data.generated_by} // Timestamp: ${data.generated_at}</p>
                </div>
                <div>
                    <span class="badge-sev ${data.defcon_level <= 2 ? 'CRITICAL' : 'LOW'}">DEFCON ${data.defcon_level}</span>
                </div>
            </div>
            
            <h4 style="color: var(--amber); margin-bottom: 6px; font-size: 0.85rem;">EXECUTIVE SUMMARY:</h4>
            <p style="margin-bottom: 16px; color: var(--text-secondary);">${data.executive_summary}</p>
            
            <h4 style="color: var(--cyan); margin-bottom: 6px; font-size: 0.85rem;">ROOT CAUSE ANALYSIS:</h4>
            <p style="margin-bottom: 16px; color: var(--text-secondary);">${data.root_cause}</p>

            <h4 style="color: var(--crimson); margin-bottom: 6px; font-size: 0.85rem;">MANDATED CONTAINMENT STEPS:</h4>
            <ul style="padding-left: 20px; color: var(--text-secondary); font-size: 0.8rem; line-height: 1.8;">
                ${data.recommended_steps.map(s => `<li>${s}</li>`).join('')}
            </ul>
        `;
        dossierModal.classList.add('active');
        if (window.lucide) lucide.createIcons();
    });

    document.getElementById('btnCloseDossier')?.addEventListener('click', () => dossierModal.classList.remove('active'));
    document.getElementById('btnModalClose2')?.addEventListener('click', () => dossierModal.classList.remove('active'));
    
    // Backdrop click dismiss
    dossierModal?.addEventListener('click', (e) => {
        if (e.target === dossierModal) dossierModal.classList.remove('active');
    });

    // Print / Export
    document.getElementById('btnPrintDossier')?.addEventListener('click', () => {
        window.print();
    });

    // Copy to clipboard
    document.getElementById('btnCopyDossier')?.addEventListener('click', () => {
        const text = dossierBody ? dossierBody.innerText : '';
        navigator.clipboard.writeText(text).then(() => {
            const btn = document.getElementById('btnCopyDossier');
            if (btn) {
                const oldHtml = btn.innerHTML;
                btn.innerHTML = '<i data-lucide="check"></i> Copied!';
                if (window.lucide) lucide.createIcons();
                setTimeout(() => {
                    btn.innerHTML = oldHtml;
                    if (window.lucide) lucide.createIcons();
                }, 2000);
            }
        });
    });

    // Global ESC key to close any active modal
    window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            dossierModal?.classList.remove('active');
            eventModal?.classList.remove('active');
        }
    });

    document.getElementById('btnCloseEventModal')?.addEventListener('click', () => eventModal.classList.remove('active'));

    // Reset graph button
    document.getElementById('btnResetGraph')?.addEventListener('click', () => {
        fetch('/api/attack-graph')
            .then(res => res.json())
            .then(data => attackGraph.setData(data));
    });

    // 11. Initial State Load
    fetch('/api/events?limit=30')
        .then(res => res.json())
        .then(events => events.reverse().forEach(ev => renderEventRow(ev)));

    fetch('/api/alerts?limit=15')
        .then(res => res.json())
        .then(alerts => alerts.reverse().forEach(al => renderAlert(al)));

    fetch('/api/attack-graph')
        .then(res => res.json())
        .then(data => attackGraph.setData(data));

    fetch('/api/soar/actions')
        .then(res => res.json())
        .then(actions => actions.forEach(act => renderSoarAction(act)));
});
