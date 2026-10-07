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

    // 3. Tab Switching & Horizontal Scroll Controls
    const viewTabsNav = document.getElementById('viewTabsNav');
    const btnScrollLeft = document.getElementById('btnScrollTabsLeft');
    const btnScrollRight = document.getElementById('btnScrollTabsRight');
    const tabsOverflowHint = document.getElementById('tabsOverflowHint');

    function updateTabScrollState() {
        if (!viewTabsNav) return;
        const maxScroll = viewTabsNav.scrollWidth - viewTabsNav.clientWidth;
        const currentScroll = viewTabsNav.scrollLeft;

        if (btnScrollLeft) {
            btnScrollLeft.classList.toggle('disabled', currentScroll <= 4);
        }
        if (btnScrollRight) {
            btnScrollRight.classList.toggle('disabled', currentScroll >= maxScroll - 4);
        }
        if (tabsOverflowHint) {
            // Show hint if there is more than 30px of hidden tab content on the right
            tabsOverflowHint.classList.toggle('hidden', currentScroll >= maxScroll - 30);
        }
    }

    if (viewTabsNav) {
        viewTabsNav.addEventListener('scroll', updateTabScrollState);
        window.addEventListener('resize', updateTabScrollState);
        setTimeout(updateTabScrollState, 200);

        // Convert mouse vertical wheel to smooth horizontal scroll
        viewTabsNav.addEventListener('wheel', (e) => {
            if (e.deltaY !== 0) {
                e.preventDefault();
                viewTabsNav.scrollBy({ left: e.deltaY * 1.5, behavior: 'smooth' });
            }
        }, { passive: false });
    }

    if (btnScrollLeft && viewTabsNav) {
        btnScrollLeft.addEventListener('click', () => {
            viewTabsNav.scrollBy({ left: -260, behavior: 'smooth' });
        });
    }

    if (btnScrollRight && viewTabsNav) {
        btnScrollRight.addEventListener('click', () => {
            viewTabsNav.scrollBy({ left: 260, behavior: 'smooth' });
        });
    }

    if (tabsOverflowHint && viewTabsNav) {
        tabsOverflowHint.addEventListener('click', () => {
            viewTabsNav.scrollBy({ left: 280, behavior: 'smooth' });
        });
    }

    document.querySelectorAll('.tab-btn[data-tab]').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            btn.scrollIntoView({ behavior: 'smooth', inline: 'nearest', block: 'nearest' });
            const targetId = btn.getAttribute('data-tab');
            document.getElementById(targetId)?.classList.add('active');
            if (targetId === 'tab-war-room') {
                attackGraph.initCanvasSize();
            }
            if (targetId === 'tab-defense') {
                if (typeof loadIsolationStatus === 'function') loadIsolationStatus();
                if (typeof loadShieldsStatus === 'function') loadShieldsStatus();
            }
            if (window.lucide) {
                window.lucide.createIcons();
            }
            setTimeout(updateTabScrollState, 150);
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
        } else if (msg.type === 'ISOLATION_UPDATE') {
            if (typeof updateIsolationUI === 'function') updateIsolationUI(msg.data);
        } else if (msg.type === 'BAS_INTERCEPTION') {
            if (typeof appendBasInterceptionToFeed === 'function') appendBasInterceptionToFeed(msg.data);
        } else if (msg.type === 'GRAPH_UPDATE') {
            if (msg.data && attackGraph) attackGraph.setData(msg.data);
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

    // 12. Cognitive Multi-Agent Squadron
    async function loadCognitiveAgents() {
        const grid = document.getElementById('cognitiveAgentsGrid');
        if (!grid) return;
        try {
            const resp = await fetch('/api/ai/agents');
            const agents = await resp.json();
            grid.innerHTML = agents.map(ag => `
                <div class="agent-card">
                    <div class="agent-card-header">
                        <span class="agent-card-title ${ag.badge_color}">${ag.agent_id}</span>
                        <span class="badge-tag ai-badge">${ag.certainty}</span>
                    </div>
                    <div class="agent-card-role">${ag.role}</div>
                    <div class="agent-card-desc">${ag.specialization}</div>
                    <div class="agent-card-footer">
                        <span class="agent-status-tag">${ag.status}</span>
                        <span style="color: var(--text-muted);">${ag.current_task.substring(0, 32)}...</span>
                    </div>
                </div>
            `).join('');
            if (window.lucide) lucide.createIcons();
        } catch (e) {
            console.error('Failed to load cognitive agents:', e);
        }
    }
    loadCognitiveAgents();

    // 13. Threat Hunting & KQL Engine
    async function loadHuntPrebuilts() {
        const container = document.getElementById('huntPrebuiltChips');
        if (!container) return;
        try {
            const resp = await fetch('/api/hunting/prebuilt');
            const prebuilts = await resp.json();
            container.innerHTML = prebuilts.map(p => `
                <span class="prebuilt-chip" title="${p.description}" data-query="${p.query}">
                    ${p.name}
                </span>
            `).join('');
            
            container.querySelectorAll('.prebuilt-chip').forEach(chip => {
                chip.addEventListener('click', () => {
                    const qInput = document.getElementById('huntQueryInput');
                    if (qInput) {
                        qInput.value = chip.getAttribute('data-query');
                        executeHunt();
                    }
                });
            });
        } catch (e) {}
    }
    loadHuntPrebuilts();

    async function executeHunt() {
        const input = document.getElementById('huntQueryInput');
        const query = input ? input.value.trim() : '';
        const tbody = document.getElementById('huntTableBody');
        const matchCount = document.getElementById('huntMatchCount');
        const latency = document.getElementById('huntLatency');
        const procChips = document.getElementById('huntProcChips');

        if (!query) return;

        try {
            const resp = await fetch('/api/hunting/query', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: query, limit: 100 })
            });
            const data = await resp.json();

            if (matchCount) matchCount.textContent = data.count || 0;
            if (latency) latency.textContent = `${data.execution_ms || 0} ms`;

            if (procChips && data.process_breakdown) {
                const procs = Object.entries(data.process_breakdown);
                procChips.innerHTML = procs.length ? procs.map(([p, c]) => `
                    <span class="proc-chip">${p} (${c})</span>
                `).join('') : '<span class="empty-proc-chip">No matching process breakdown</span>';
            }

            if (tbody) {
                if (!data.results || !data.results.length) {
                    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 30px;">No events matched criteria: "${query}"</td></tr>`;
                } else {
                    tbody.innerHTML = data.results.map(ev => {
                        const sevClass = (ev.severity || 'INFO').toLowerCase();
                        return `
                            <tr>
                                <td>${ev.timestamp ? ev.timestamp.split('T')[1].replace('Z','') : ''}</td>
                                <td><span class="badge-sev badge-${sevClass}">${ev.severity || 'INFO'}</span></td>
                                <td>${ev.event_id || '-'}</td>
                                <td>${ev.computer || '-'}</td>
                                <td><strong style="color: var(--cyan);">${ev.process_name || '-'}</strong></td>
                                <td style="max-width: 380px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${ev.command_line || '-'}</td>
                                <td>${ev.mitre_tactic || '-'}</td>
                                <td><button class="btn-micro btn-inspect-event" data-raw='${JSON.stringify(ev).replace(/'/g, "&apos;")}'>View</button></td>
                            </tr>
                        `;
                    }).join('');

                    tbody.querySelectorAll('.btn-inspect-event').forEach(b => {
                        b.addEventListener('click', () => {
                            try {
                                const raw = JSON.parse(b.getAttribute('data-raw'));
                                rawEventJsonContent.textContent = JSON.stringify(raw, null, 2);
                                eventModal.classList.add('active');
                            } catch (e) {}
                        });
                    });
                }
            }
        } catch (e) {
            console.error('Hunt failed:', e);
        }
    }

    document.getElementById('btnExecuteHunt')?.addEventListener('click', executeHunt);
    document.getElementById('huntQueryInput')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') executeHunt();
    });

    // 14. Active Deception Engine Controls
    async function loadDeceptionStatus() {
        const canariesGrid = document.getElementById('canariesListGrid');
        const armedCount = document.getElementById('armedCanaryCount');
        const trippedCount = document.getElementById('trippedCanaryCount');
        const auditBody = document.getElementById('deceptionAuditBody');

        try {
            const resp = await fetch('/api/deception/status');
            const data = await resp.json();

            if (armedCount) armedCount.textContent = data.armed_count || 0;
            if (trippedCount) trippedCount.textContent = data.tripped_count || 0;

            if (canariesGrid && data.canaries) {
                canariesGrid.innerHTML = data.canaries.map(c => `
                    <div class="canary-card ${c.status.toLowerCase()}">
                        <div class="canary-header">
                            <span class="canary-name">${c.filename}</span>
                            <span class="badge-tag ${c.status === 'ARMED' ? 'badge-green' : 'badge-crit'}">${c.status}</span>
                        </div>
                        <div class="canary-desc">${c.description}</div>
                        <div class="canary-meta">Category: ${c.category} • Size: ${c.size_bytes}B • SHA256: ${c.baseline_hash.substring(0,16)}...</div>
                    </div>
                `).join('');
            }

            if (auditBody && data.recent_trips && data.recent_trips.length) {
                auditBody.innerHTML = data.recent_trips.map(t => `
                    <tr>
                        <td>${t.timestamp}</td>
                        <td><strong>${t.filename}</strong></td>
                        <td>${t.category}</td>
                        <td><span class="badge-tag badge-crit">${t.trip_type}</span></td>
                        <td>${t.reason}</td>
                        <td><span style="color: var(--crimson); font-weight: 700;">ALARM RAISED</span></td>
                    </tr>
                `).join('');
            }
        } catch (e) {
            console.error('Failed to load deception status:', e);
        }
    }
    loadDeceptionStatus();

    document.getElementById('btnResetCanaries')?.addEventListener('click', async () => {
        await fetch('/api/deception/reset', { method: 'POST' });
        aiConsole.addThought('DECEPTION', 'All Canary Honey-Files re-armed with fresh SHA256 baselines.', 'green');
        loadDeceptionStatus();
    });

    document.getElementById('btnTestTripwire')?.addEventListener('click', async () => {
        aiConsole.addThought('DECEPTION TEST', 'Tampering with decoy honeypot file to test real-time tripwire detection...', 'amber');
        try {
            const resp = await fetch('/api/deception/trip-test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filename: 'passwords_backup_2026.docx' })
            });
            const data = await resp.json();
            aiConsole.addThought('CANARY TRIPPED', `Tripwire caught tamper event: ${data.canary}. Defcon 1 alert triggered.`, 'red');
            loadDeceptionStatus();
        } catch (e) {
            console.error(e);
        }
    });

    // 15. DFIR Forensic Evidence Vault
    async function loadDfirVault() {
        const tbody = document.getElementById('dfirTableBody');
        if (!tbody) return;
        try {
            const resp = await fetch('/api/dfir/vault');
            const artifacts = await resp.json();
            if (!artifacts.length) {
                tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 25px;">Evidence vault empty. Capture on-demand process forensics above.</td></tr>`;
            } else {
                tbody.innerHTML = artifacts.map(a => `
                    <tr>
                        <td><strong style="color: var(--emerald);">${a.artifact_id}</strong></td>
                        <td>${a.timestamp ? a.timestamp.split('T')[1].replace('Z','') : '-'}</td>
                        <td>${a.pid || '-'}</td>
                        <td>${a.process_name || '-'}</td>
                        <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${a.cmdline || '-'}</td>
                        <td>${a.memory_info?.rss_mb ? a.memory_info.rss_mb + ' MB' : '-'}</td>
                        <td>${a.open_connections ? a.open_connections.length : 0}</td>
                        <td>${a.loaded_modules ? a.loaded_modules.length : 0}</td>
                        <td><button class="btn-micro btn-inspect-dfir" data-raw='${JSON.stringify(a).replace(/'/g, "&apos;")}'>Inspect</button></td>
                    </tr>
                `).join('');

                tbody.querySelectorAll('.btn-inspect-dfir').forEach(b => {
                    b.addEventListener('click', () => {
                        try {
                            const raw = JSON.parse(b.getAttribute('data-raw'));
                            rawEventJsonContent.textContent = JSON.stringify(raw, null, 2);
                            eventModal.classList.add('active');
                        } catch (e) {}
                    });
                });
            }
        } catch (e) {
            console.error('Failed to load DFIR vault:', e);
        }
    }
    loadDfirVault();

    document.getElementById('btnCaptureDfir')?.addEventListener('click', async () => {
        const pidInput = document.getElementById('dfirPidInput');
        const nameInput = document.getElementById('dfirProcessNameInput');
        const pid = parseInt(pidInput?.value, 10);
        if (!pid) {
            alert('Please enter a valid active PID.');
            return;
        }

        aiConsole.addThought('DFIR VAULT', `Capturing live memory, handles, and DLL modules for PID ${pid}...`, 'emerald');
        try {
            const resp = await fetch('/api/dfir/dump-pid', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pid: pid, process_name: nameInput?.value || '', reason: 'MANUAL_OPERATOR_DUMP' })
            });
            const data = await resp.json();
            aiConsole.addThought('DFIR SUCCESS', `Secured forensic artifact ${data.artifact?.artifact_id} for PID ${pid}.`, 'green');
            loadDfirVault();
        } catch (e) {
            console.error('DFIR dump failed:', e);
        }
    });

    // 16. Autonomous Defense, Host Isolation, and BAS Battle Arena
    window.updateIsolationUI = function(data) {
        const isIsolated = data.is_isolated;
        const panel = document.getElementById('isolationPanel');
        const dot = document.getElementById('isolationDot');
        const title = document.getElementById('isolationTitle');
        const desc = document.getElementById('isolationDesc');

        if (isIsolated) {
            panel?.classList.add('isolated-active');
            dot?.classList.remove('online');
            dot?.classList.add('isolated');
            if (title) title.textContent = '🚨 HOST ISOLATION ACTIVE // PERIMETER SEVERED';
            if (desc) desc.textContent = `All external network packets dropped via Windows Firewall. Management port preserved. Reason: ${data.isolation_reason || data.reason || 'BREACH CONTAINMENT'}`;
        } else {
            panel?.classList.remove('isolated-active');
            dot?.classList.remove('isolated');
            dot?.classList.add('online');
            if (title) title.textContent = 'HOST PERIMETER: UNRESTRICTED / ONLINE';
            if (desc) desc.textContent = 'Windows Firewall active. No emergency perimeter containment active.';
        }
    };

    async function loadIsolationStatus() {
        try {
            const resp = await fetch('/api/defense/isolation/status');
            const data = await resp.json();
            window.updateIsolationUI(data);
        } catch (e) {
            console.error('Failed to load isolation status:', e);
        }
    }
    loadIsolationStatus();

    document.getElementById('btnEngageIsolation')?.addEventListener('click', async () => {
        aiConsole.addThought('HOST ISOLATION', 'Executing emergency perimeter drop policies via netsh advfirewall...', 'red');
        try {
            const resp = await fetch('/api/defense/isolation/engage', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ host: 'LOCAL', reason: 'MANUAL_OPERATOR_ENGAGE' })
            });
            const data = await resp.json();
            window.updateIsolationUI(data);
            aiConsole.addThought('PERIMETER SEVERED', 'Host network severed from external LAN/WAN. Port 8000 whitelisted.', 'red');
        } catch (e) {
            console.error('Isolation engage failed:', e);
        }
    });

    document.getElementById('btnRestoreIsolation')?.addEventListener('click', async () => {
        aiConsole.addThought('RESTORE NETWORK', 'Lifting emergency isolation firewall policies...', 'emerald');
        try {
            const resp = await fetch('/api/defense/isolation/restore', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ host: 'LOCAL', reason: 'OPERATOR_REMEDIATION_CONFIRMED' })
            });
            const data = await resp.json();
            window.updateIsolationUI(data);
            aiConsole.addThought('NETWORK RESTORED', 'Host firewall rules purged. Full network connectivity restored.', 'green');
        } catch (e) {
            console.error('Isolation restore failed:', e);
        }
    });

    async function loadShieldsStatus() {
        try {
            // 1. Ransomware shield
            const rResp = await fetch('/api/defense/ransomware/status');
            const rData = await rResp.json();
            const badge = document.getElementById('ransomwareShieldBadge');
            if (badge) badge.textContent = rData.shield_status || 'ONLINE';

            // 2. Anti-tamper
            const tResp = await fetch('/api/defense/antitamper/status');
            const tData = await tResp.json();
            const tCount = document.getElementById('tamperCount');
            if (tCount) tCount.textContent = `${tData.total_tamper_attacks_intercepted || 0} ATTEMPTS`;

            // 3. BAS metrics
            const bResp = await fetch('/api/defense/bas/metrics');
            const bData = await bResp.json();
            const rate = document.getElementById('basBlockRate');
            const latency = document.getElementById('basAvgLatency');
            const tests = document.getElementById('basTotalTests');
            if (rate) rate.textContent = `${bData.block_rate_percent}%`;
            if (latency) latency.textContent = `${bData.avg_response_latency_ms}ms`;
            if (tests) tests.textContent = `${bData.total_tests_executed} RUNS`;

            // 4. Quarantine catalog
            const qResp = await fetch('/api/defense/quarantine/catalog');
            const qCatalog = await qResp.json();
            const qCount = document.getElementById('quarantineCount');
            if (qCount) qCount.textContent = `${qCatalog.length} ITEMS`;
            const qBody = document.getElementById('quarantineTableBody');
            if (qBody && qCatalog.length) {
                qBody.innerHTML = qCatalog.map(item => `
                    <tr>
                        <td><strong style="color: var(--purple);">${item.id}</strong></td>
                        <td>${item.filename}</td>
                        <td style="font-family: monospace; color: var(--cyan);">${item.sha256 ? item.sha256.substring(0, 16) + '...' : '-'}</td>
                        <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${item.original_path}</td>
                        <td>${item.reason}</td>
                        <td>${item.quarantined_at ? item.quarantined_at.split('T')[1].replace('Z','') : '-'}</td>
                        <td><span class="badge-tag badge-purple">${item.status}</span></td>
                    </tr>
                `).join('');
            }
        } catch (e) {
            console.error('Failed to load defense shields status:', e);
        }
    }
    loadShieldsStatus();

    // BAS Live Battle Feed handler
    window.appendBasInterceptionToFeed = function(result) {
        const consoleEl = document.getElementById('basFeedConsole');
        if (!consoleEl) return;

        const timeStr = result.timestamp ? result.timestamp.split('T')[1].replace('Z', '').split('.')[0] : new Date().toLocaleTimeString();
        const entry = document.createElement('div');
        entry.className = 'feed-entry intercepted';
        entry.innerHTML = `
            <div class="feed-entry-header">
                <span class="feed-ts">[${timeStr}]</span>
                <span class="feed-scenario">${result.scenario_name}</span>
                <span class="feed-latency">⚡ ${result.latency_ms}ms TTR</span>
                <span class="badge-tag badge-green">${result.verdict}</span>
            </div>
            <div class="feed-details">
                <em>Simulated Adversary Vector:</em> <code>${result.simulated_cmd}</code>
            </div>
            <div class="feed-actions">
                ${(result.countermeasures || []).map(c => `<div class="feed-action-item">✔ ${c}</div>`).join('')}
            </div>
        `;
        consoleEl.insertBefore(entry, consoleEl.firstChild);
    };

    // Attach BAS Launch Attack Buttons
    document.querySelectorAll('.btn-launch-bas[data-scenario]').forEach(btn => {
        btn.addEventListener('click', async () => {
            const scenario = btn.getAttribute('data-scenario');
            btn.classList.add('running');
            btn.textContent = 'Engaging...';

            aiConsole.addThought('BAS EMULATION', `Simulating atomic attack: ${scenario}...`, 'amber');
            try {
                const resp = await fetch('/api/defense/bas/run-test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ scenario: scenario, host: 'DESKTOP-SEC-HOST' })
                });
                const data = await resp.json();
                if (data.result) {
                    window.appendBasInterceptionToFeed(data.result);
                    aiConsole.addThought('THREAT BLOCKED', `${data.result.scenario_name} intercepted in ${data.result.latency_ms}ms with active countermeasure execution.`, 'green');
                }
                loadShieldsStatus();
            } catch (e) {
                console.error('BAS test failed:', e);
            } finally {
                btn.classList.remove('running');
                btn.textContent = 'Launch Attack';
            }
        });
    });

    // =========================================================================
    // OPERATOR GUIDE INTERACTIVE ENHANCEMENTS (SEARCH, COPY, SMOOTH JUMP)
    // =========================================================================
    // 1. Copy snippet button handler
    document.addEventListener('click', (e) => {
        const copyBtn = e.target.closest('.btn-copy-code');
        if (copyBtn) {
            const codeEl = copyBtn.closest('.copy-snippet-box')?.querySelector('.copy-snippet-code') 
                        || copyBtn.previousElementSibling;
            const textToCopy = copyBtn.getAttribute('data-copy') || codeEl?.textContent?.trim() || '';
            if (textToCopy) {
                navigator.clipboard.writeText(textToCopy).then(() => {
                    const originalText = copyBtn.innerHTML;
                    copyBtn.innerHTML = '✔ COPIED!';
                    copyBtn.classList.add('copied');
                    setTimeout(() => {
                        copyBtn.innerHTML = originalText;
                        copyBtn.classList.remove('copied');
                    }, 2000);
                }).catch(err => {
                    console.error('Copy failed:', err);
                });
            }
        }
    });

    // 2. Smooth jump & highlight for guide pills
    document.querySelectorAll('.guide-pill[href^="#"]').forEach(pill => {
        pill.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = pill.getAttribute('href').substring(1);
            const targetCard = document.getElementById(targetId);
            if (targetCard) {
                targetCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
                targetCard.classList.remove('card-targeted');
                void targetCard.offsetWidth; // trigger reflow
                targetCard.classList.add('card-targeted');
            }
        });
    });

    // 3. Live search filter for guide
    const guideSearchInput = document.getElementById('guideSearchInput');
    const guideSearchCounter = document.getElementById('guideSearchCounter');
    if (guideSearchInput) {
        guideSearchInput.addEventListener('input', () => {
            const query = guideSearchInput.value.toLowerCase().trim();
            const cards = document.querySelectorAll('.guide-scroll-content .guide-card');
            let matchCount = 0;

            cards.forEach(card => {
                if (!query) {
                    card.style.display = '';
                    matchCount++;
                } else {
                    const text = card.textContent.toLowerCase();
                    if (text.includes(query)) {
                        card.style.display = '';
                        matchCount++;
                    } else {
                        card.style.display = 'none';
                    }
                }
            });

            if (guideSearchCounter) {
                if (!query) {
                    guideSearchCounter.textContent = `${cards.length} SECTIONS`;
                } else {
                    guideSearchCounter.textContent = `${matchCount} MATCH${matchCount === 1 ? '' : 'ES'}`;
                }
            }
        });
    }
});

