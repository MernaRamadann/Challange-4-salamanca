/**
 * Autonomous Forensic Orchestrator - Enhanced Dashboard JavaScript
 * Features: Network Graph, MITRE Matrix, Real-time Charts, LLM Chat, PDF Export
 */

// API Base - use server URL, detect if running from file:// protocol
const API_BASE = window.location.protocol === 'file:'
    ? 'http://localhost:8000'
    : window.location.origin;
const WS_BASE = API_BASE.replace("http", "ws");

console.log('API Base:', API_BASE);
console.log('WebSocket Base:', WS_BASE);

// Get session ID from URL
const urlParams = new URLSearchParams(window.location.search);
const sessionId = urlParams.get("session");

if (!sessionId) {
    window.location.href = "index.html";
}

// ============================================================================
// DOM Elements
// ============================================================================

const sessionIdEl = document.getElementById("session-id");
const connectionStatus = document.getElementById("connection-status");
const progressPhase = document.getElementById("progress-phase");
const progressPercent = document.getElementById("progress-percent");
const progressFill = document.getElementById("progress-fill");
const stepsFeed = document.getElementById("steps-feed");
const stepsCount = document.getElementById("steps-count");
const evidenceGrid = document.getElementById("evidence-grid");
const evidenceCount = document.getElementById("evidence-count");
const timelineFeed = document.getElementById("timeline-feed");
const mitreGrid = document.getElementById("mitre-grid");
const mitreCount = document.getElementById("mitre-count");
const hypothesesList = document.getElementById("hypotheses-list");
const chatMessages = document.getElementById("chat-messages");
const chatInput = document.getElementById("chat-input");
const chatSend = document.getElementById("chat-send");

// Modals
const summaryModal = document.getElementById("summary-modal");
const closeSummaryModal = document.getElementById("close-summary-modal");
const summaryContent = document.getElementById("summary-content");
const stepModal = document.getElementById("step-modal");
const closeStepModal = document.getElementById("close-step-modal");
const stepDetailContent = document.getElementById("step-detail-content");
const mitreModal = document.getElementById("mitre-modal");
const closeMitreModal = document.getElementById("close-mitre-modal");

// Report download buttons
const downloadJson = document.getElementById("download-json");
const downloadHtml = document.getElementById("download-html");
const downloadStix = document.getElementById("download-stix");
const downloadPdf = document.getElementById("download-pdf");
const btnExport = document.getElementById("btn-export");

// ============================================================================
// State
// ============================================================================

let ws = null;
let steps = [];
let evidence = [];
let timeline = [];
let mitreTechniques = {};
let hypotheses = [];
let networkGraph = null;
let networkNodes = null;
let networkEdges = null;
let charts = {};
let physicsEnabled = true;

// MITRE ATT&CK Tactics (ordered)
const MITRE_TACTICS = [
    { id: 'reconnaissance', name: 'Reconnaissance', color: '#6366f1' },
    { id: 'resource-development', name: 'Resource Development', color: '#8b5cf6' },
    { id: 'initial-access', name: 'Initial Access', color: '#ec4899' },
    { id: 'execution', name: 'Execution', color: '#ef4444' },
    { id: 'persistence', name: 'Persistence', color: '#f97316' },
    { id: 'privilege-escalation', name: 'Privilege Escalation', color: '#f59e0b' },
    { id: 'defense-evasion', name: 'Defense Evasion', color: '#eab308' },
    { id: 'credential-access', name: 'Credential Access', color: '#84cc16' },
    { id: 'discovery', name: 'Discovery', color: '#22c55e' },
    { id: 'lateral-movement', name: 'Lateral Movement', color: '#10b981' },
    { id: 'collection', name: 'Collection', color: '#14b8a6' },
    { id: 'command-and-control', name: 'Command & Control', color: '#06b6d4' },
    { id: 'exfiltration', name: 'Exfiltration', color: '#0ea5e9' },
    { id: 'impact', name: 'Impact', color: '#3b82f6' }
];

// Sample MITRE Techniques for demo (subset)
const MITRE_TECHNIQUES_DB = {
    'T1566': { name: 'Phishing', tactic: 'initial-access', description: 'Adversaries may send phishing messages to gain access to victim systems.' },
    'T1566.001': { name: 'Spearphishing Attachment', tactic: 'initial-access', description: 'Adversaries may send spearphishing emails with a malicious attachment.' },
    'T1059': { name: 'Command and Scripting Interpreter', tactic: 'execution', description: 'Adversaries may abuse command and script interpreters to execute commands.' },
    'T1059.001': { name: 'PowerShell', tactic: 'execution', description: 'Adversaries may abuse PowerShell commands and scripts for execution.' },
    'T1059.003': { name: 'Windows Command Shell', tactic: 'execution', description: 'Adversaries may abuse the Windows command shell for execution.' },
    'T1547': { name: 'Boot or Logon Autostart Execution', tactic: 'persistence', description: 'Adversaries may configure system settings to run programs at boot.' },
    'T1547.001': { name: 'Registry Run Keys', tactic: 'persistence', description: 'Adversaries may add entries to the Registry to run programs at boot.' },
    'T1055': { name: 'Process Injection', tactic: 'defense-evasion', description: 'Adversaries may inject code into processes to evade detection.' },
    'T1055.001': { name: 'DLL Injection', tactic: 'defense-evasion', description: 'Adversaries may inject DLLs into running processes.' },
    'T1003': { name: 'OS Credential Dumping', tactic: 'credential-access', description: 'Adversaries may dump credentials from the OS.' },
    'T1003.001': { name: 'LSASS Memory', tactic: 'credential-access', description: 'Adversaries may dump LSASS memory to obtain credentials.' },
    'T1087': { name: 'Account Discovery', tactic: 'discovery', description: 'Adversaries may attempt to discover accounts.' },
    'T1082': { name: 'System Information Discovery', tactic: 'discovery', description: 'Adversaries may gather system information.' },
    'T1021': { name: 'Remote Services', tactic: 'lateral-movement', description: 'Adversaries may use remote services to move laterally.' },
    'T1071': { name: 'Application Layer Protocol', tactic: 'command-and-control', description: 'Adversaries may communicate using application layer protocols.' },
    'T1071.001': { name: 'Web Protocols', tactic: 'command-and-control', description: 'Adversaries may use web protocols for C2.' },
    'T1041': { name: 'Exfiltration Over C2 Channel', tactic: 'exfiltration', description: 'Adversaries may exfiltrate data over the C2 channel.' },
    'T1486': { name: 'Data Encrypted for Impact', tactic: 'impact', description: 'Adversaries may encrypt data to interrupt availability.' }
};

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener("DOMContentLoaded", () => {
    sessionIdEl.textContent = sessionId;
    initWebSocket();
    setupEventListeners();
    initViews();
    initMitreMatrix();
    initCharts();
});

// ============================================================================
// View Management
// ============================================================================

function initViews() {
    const viewBtns = document.querySelectorAll('.view-btn');
    viewBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const viewId = btn.dataset.view;
            switchView(viewId);

            // Update active button
            viewBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
        });
    });
}

function switchView(viewId) {
    // Hide all views
    document.querySelectorAll('.dashboard-view').forEach(view => {
        view.classList.remove('active');
    });

    // Show selected view
    const selectedView = document.getElementById(`view-${viewId}`);
    if (selectedView) {
        selectedView.classList.add('active');
    }

    // Initialize network graph if switching to network view
    if (viewId === 'network' && !networkGraph) {
        initNetworkGraph();
    }

    // Update charts if switching to charts view
    if (viewId === 'charts') {
        updateAllCharts();
    }
}

// ============================================================================
// WebSocket Connection
// ============================================================================

function initWebSocket() {
    updateConnectionStatus("connecting");

    ws = new WebSocket(`${WS_BASE}/ws/agent/${sessionId}`);

    ws.onopen = () => {
        console.log("WebSocket connected");
        updateConnectionStatus("connected");
    };

    ws.onclose = () => {
        console.log("WebSocket disconnected");
        updateConnectionStatus("disconnected");

        // Attempt to reconnect after 3 seconds
        setTimeout(() => {
            if (!ws || ws.readyState === WebSocket.CLOSED) {
                initWebSocket();
            }
        }, 3000);
    };

    ws.onerror = (error) => {
        console.error("WebSocket error:", error);
        updateConnectionStatus("error");
    };

    ws.onmessage = (event) => {
        try {
            const message = JSON.parse(event.data);
            handleMessage(message);
        } catch (error) {
            console.error("Failed to parse message:", error);
        }
    };
}

function updateConnectionStatus(status) {
    const dot = connectionStatus.querySelector(".status-dot");
    const text = connectionStatus.querySelector(".status-text");

    dot.classList.remove("connected", "disconnected");

    switch (status) {
        case "connected":
            dot.classList.add("connected");
            text.textContent = "Connected";
            break;
        case "disconnected":
            dot.classList.add("disconnected");
            text.textContent = "Disconnected";
            break;
        case "connecting":
            dot.classList.add("disconnected");
            text.textContent = "Connecting...";
            break;
        case "error":
            dot.classList.add("disconnected");
            text.textContent = "Error";
            break;
    }
}

// ============================================================================
// Message Handling
// ============================================================================

function handleMessage(message) {
    switch (message.type) {
        case "step":
            handleStep(message.data);
            break;
        case "evidence":
            handleEvidence(message.data);
            break;
        case "progress":
            handleProgress(message.data);
            break;
        case "timeline_event":
            handleTimelineEvent(message.data);
            break;
        case "mitre_mapping":
            handleMitreMapping(message.data);
            break;
        case "hypothesis":
            handleHypothesis(message.data);
            break;
        case "complete":
            handleComplete(message.data);
            break;
        case "error":
            handleError(message.data);
            break;
        case "instruction_ack":
            addChatMessage("agent", `Instruction received: "${message.message}"`);
            break;
        case "llm_response":
            handleLLMResponse(message.data);
            break;
        case "full_state":
            handleFullState(message.data);
            break;
    }
}

function handleStep(step) {
    steps.push(step);
    stepsCount.textContent = steps.length;

    // Remove empty state if present
    const emptyState = stepsFeed.querySelector(".empty-state");
    if (emptyState) emptyState.remove();

    // Create step card
    const stepCard = document.createElement("div");
    stepCard.className = "step-card";
    stepCard.innerHTML = `
        <div class="step-header">
            <span class="step-number">${step.step_number}</span>
            <span class="step-tool">${step.tool}</span>
            <span class="step-phase">${step.phase}</span>
        </div>
        <p class="step-thought">${truncate(step.thought, 150)}</p>
        <p class="step-action">${truncate(step.action, 100)}</p>
        <p class="step-evidence-count">${step.evidence?.length || 0} evidence items extracted</p>
    `;

    stepCard.addEventListener("click", () => showStepDetail(step));
    stepsFeed.appendChild(stepCard);
    stepsFeed.scrollTop = stepsFeed.scrollHeight;

    // Update network graph
    if (step.evidence) {
        step.evidence.forEach(ev => addToNetworkGraph(ev, step));
    }

    // Update charts
    updateToolsChart();
}

function handleEvidence(ev) {
    evidence.push(ev);
    evidenceCount.textContent = evidence.length;

    // Remove empty state if present
    const emptyState = evidenceGrid.querySelector(".empty-state");
    if (emptyState) emptyState.remove();

    // Create evidence card
    const evCard = document.createElement("div");
    evCard.className = `evidence-card type-${ev.type}`;
    const confidence = (ev.confidence * 100).toFixed(0);

    evCard.innerHTML = `
        <div class="evidence-type">${ev.type}</div>
        <div class="evidence-value">${truncate(ev.value, 50)}</div>
        <div class="evidence-confidence">
            <span>Confidence:</span>
            <div class="confidence-bar">
                <div class="confidence-fill" style="width: ${confidence}%"></div>
            </div>
            <span>${confidence}%</span>
        </div>
    `;

    evidenceGrid.appendChild(evCard);

    // Update network graph
    addToNetworkGraph(ev);

    // Update charts
    updateEvidenceChart();
    updateThreatScoreChart(ev);
}

function handleProgress(data) {
    progressPhase.textContent = formatPhase(data.phase);
    progressPercent.textContent = `${data.progress.toFixed(0)}%`;
    progressFill.style.width = `${data.progress}%`;

    // Update timeline chart
    updateTimelineChart(data);
}

function handleTimelineEvent(event) {
    timeline.push(event);

    const emptyState = timelineFeed.querySelector(".empty-state");
    if (emptyState) emptyState.remove();

    const timelineEvent = document.createElement("div");
    timelineEvent.className = `timeline-event severity-${event.severity || "info"}`;
    const time = event.timestamp ? formatTime(event.timestamp) : "--:--";

    timelineEvent.innerHTML = `
        <div class="timeline-time">${time}</div>
        <div class="timeline-content">
            <span class="timeline-severity ${event.severity || "info"}">${(event.severity || "INFO").toUpperCase()}</span>
            <span class="timeline-description">${event.event}</span>
        </div>
    `;

    timelineFeed.appendChild(timelineEvent);

    // Update severity chart
    updateSeverityChart(event);
}

function handleMitreMapping(mapping) {
    const tactic = mapping.tactic;
    const techId = mapping.technique_id;

    if (!mitreTechniques[tactic]) {
        mitreTechniques[tactic] = [];
    }

    if (!mitreTechniques[tactic].includes(techId)) {
        mitreTechniques[tactic].push(techId);
    }

    renderMitreGrid();
    updateMitreMatrix(techId, tactic);
    updateMitreChart();
}

function renderMitreGrid() {
    const totalTechniques = Object.values(mitreTechniques).flat().length;
    mitreCount.textContent = totalTechniques;

    if (totalTechniques === 0) return;

    const emptyState = mitreGrid.querySelector(".empty-state");
    if (emptyState) emptyState.remove();

    mitreGrid.innerHTML = Object.entries(mitreTechniques)
        .map(([tactic, techniques]) => `
            <div class="mitre-tactic">
                <div class="mitre-tactic-name">${tactic}</div>
                <div class="mitre-techniques">
                    ${techniques.map(t => `<span class="technique-badge" onclick="showMitreDetail('${t}')">${t}</span>`).join("")}
                </div>
            </div>
        `).join("");
}

function handleHypothesis(hypothesis) {
    hypotheses.push(hypothesis);

    const emptyState = hypothesesList.querySelector(".empty-state");
    if (emptyState) emptyState.remove();

    const confidence = (hypothesis.confidence * 100).toFixed(0);
    const confClass = confidence >= 80 ? "high" : "medium";

    const hypCard = document.createElement("div");
    hypCard.className = "hypothesis-card";
    hypCard.innerHTML = `
        <div class="hypothesis-title">
            ${hypothesis.title}
            <span class="hypothesis-confidence ${confClass}">${confidence}%</span>
        </div>
        <div class="hypothesis-details">
            <strong>Threat Actor:</strong> ${hypothesis.threat_actor || "Unknown"}<br>
            <strong>Objective:</strong> ${hypothesis.objective || "Unknown"}
        </div>
    `;

    hypothesesList.appendChild(hypCard);
}

function handleComplete(data) {
    progressPhase.textContent = "Investigation Complete";
    progressPercent.textContent = "100%";
    progressFill.style.width = "100%";

    summaryContent.innerHTML = `
        <div class="summary-stats">
            <div class="summary-stat">
                <span class="stat-value">${steps.length}</span>
                <span class="stat-label">Analysis Steps</span>
            </div>
            <div class="summary-stat">
                <span class="stat-value">${evidence.length}</span>
                <span class="stat-label">Evidence Items</span>
            </div>
            <div class="summary-stat">
                <span class="stat-value">${Object.values(mitreTechniques).flat().length}</span>
                <span class="stat-label">MITRE Techniques</span>
            </div>
            <div class="summary-stat">
                <span class="stat-value">${hypotheses.length}</span>
                <span class="stat-label">Hypotheses</span>
            </div>
        </div>
        <h3>Executive Summary</h3>
        <pre class="summary-text">${data.summary}</pre>
        <h3>Conclusion</h3>
        <p class="conclusion-text">${data.conclusion}</p>
    `;

    summaryModal.classList.add("active");
}

function handleError(data) {
    console.error("Investigation error:", data.message);
    addChatMessage("system", `Error: ${data.message}`);
}

function handleLLMResponse(data) {
    addChatMessage("agent", data.response, true);
}

function handleFullState(state) {
    if (state.steps) state.steps.forEach(step => handleStep(step));
    if (state.evidence) state.evidence.forEach(ev => handleEvidence(ev));
    if (state.timeline) state.timeline.forEach(event => handleTimelineEvent(event));
    if (state.mitre_coverage) {
        mitreTechniques = state.mitre_coverage;
        renderMitreGrid();
    }
    if (state.hypotheses) state.hypotheses.forEach(hyp => handleHypothesis(hyp));
    if (state.progress !== undefined) {
        handleProgress({ progress: state.progress, phase: state.current_phase });
    }
}

// ============================================================================
// Network Graph (vis.js)
// ============================================================================

function initNetworkGraph() {
    const container = document.getElementById('network-graph');
    if (!container) return;

    networkNodes = new vis.DataSet([]);
    networkEdges = new vis.DataSet([]);

    const data = { nodes: networkNodes, edges: networkEdges };

    const options = {
        nodes: {
            shape: 'dot',
            size: 20,
            font: { color: '#f3f4f6', size: 12 },
            borderWidth: 2,
            shadow: true
        },
        edges: {
            width: 2,
            color: { color: '#4b5563', highlight: '#00d4ff', hover: '#00d4ff' },
            arrows: { to: { enabled: true, scaleFactor: 0.5 } },
            smooth: { type: 'continuous' }
        },
        physics: {
            enabled: true,
            barnesHut: {
                gravitationalConstant: -2000,
                centralGravity: 0.3,
                springLength: 150,
                springConstant: 0.04
            }
        },
        interaction: {
            hover: true,
            tooltipDelay: 100
        }
    };

    networkGraph = new vis.Network(container, data, options);

    // Add controls
    document.getElementById('network-fit')?.addEventListener('click', () => {
        networkGraph.fit();
    });

    document.getElementById('network-physics')?.addEventListener('click', () => {
        physicsEnabled = !physicsEnabled;
        networkGraph.setOptions({ physics: { enabled: physicsEnabled } });
    });

    // Add existing evidence to graph
    evidence.forEach(ev => addToNetworkGraph(ev));
}

function addToNetworkGraph(ev, step = null) {
    if (!networkNodes || !networkEdges) return;

    const nodeColors = {
        ip: { background: '#ef4444', border: '#dc2626' },
        domain: { background: '#f97316', border: '#ea580c' },
        process: { background: '#3b82f6', border: '#2563eb' },
        file: { background: '#22c55e', border: '#16a34a' },
        hash: { background: '#eab308', border: '#ca8a04' },
        malware: { background: '#dc2626', border: '#b91c1c' },
        command: { background: '#a855f7', border: '#9333ea' },
        registry: { background: '#06b6d4', border: '#0891b2' }
    };

    const nodeId = `${ev.type}-${ev.value}`;
    const color = nodeColors[ev.type] || { background: '#6b7280', border: '#4b5563' };

    // Add node if it doesn't exist
    if (!networkNodes.get(nodeId)) {
        networkNodes.add({
            id: nodeId,
            label: truncate(ev.value, 20),
            title: `${ev.type.toUpperCase()}: ${ev.value}\nConfidence: ${(ev.confidence * 100).toFixed(0)}%`,
            color: color,
            group: ev.type
        });
    }

    // Add edge from step's tool if available
    if (step) {
        const toolNodeId = `tool-${step.tool}`;
        if (!networkNodes.get(toolNodeId)) {
            networkNodes.add({
                id: toolNodeId,
                label: step.tool,
                title: `Tool: ${step.tool}`,
                color: { background: '#8b5cf6', border: '#7c3aed' },
                shape: 'diamond',
                size: 15
            });
        }

        const edgeId = `${toolNodeId}-${nodeId}`;
        if (!networkEdges.get(edgeId)) {
            networkEdges.add({
                id: edgeId,
                from: toolNodeId,
                to: nodeId,
                title: `Discovered by ${step.tool}`
            });
        }
    }

    // Update stats
    document.getElementById('stat-nodes').textContent = networkNodes.length;
    document.getElementById('stat-edges').textContent = networkEdges.length;
}

// ============================================================================
// MITRE ATT&CK Matrix
// ============================================================================

function initMitreMatrix() {
    const matrixContainer = document.getElementById('mitre-matrix');
    if (!matrixContainer) return;

    let html = '<div class="matrix-grid">';

    MITRE_TACTICS.forEach(tactic => {
        html += `
            <div class="matrix-column" data-tactic="${tactic.id}">
                <div class="matrix-tactic-header" style="background-color: ${tactic.color}20; border-color: ${tactic.color}">
                    <span class="tactic-name">${tactic.name}</span>
                    <span class="tactic-count" id="tactic-count-${tactic.id}">0</span>
                </div>
                <div class="matrix-techniques" id="matrix-tech-${tactic.id}">
                    <!-- Techniques will be added here -->
                </div>
            </div>
        `;
    });

    html += '</div>';
    matrixContainer.innerHTML = html;

    // Pre-populate with known techniques (greyed out)
    Object.entries(MITRE_TECHNIQUES_DB).forEach(([techId, tech]) => {
        const container = document.getElementById(`matrix-tech-${tech.tactic}`);
        if (container) {
            const techEl = document.createElement('div');
            techEl.className = 'matrix-technique inactive';
            techEl.id = `tech-${techId}`;
            techEl.innerHTML = `<span class="tech-id">${techId}</span><span class="tech-name">${tech.name}</span>`;
            techEl.onclick = () => showMitreDetail(techId);
            container.appendChild(techEl);
        }
    });
}

function updateMitreMatrix(techId, tactic) {
    const techEl = document.getElementById(`tech-${techId}`);
    if (techEl) {
        techEl.classList.remove('inactive');
        techEl.classList.add('detected');
    }

    // Update coverage percentage
    const totalTechs = Object.keys(MITRE_TECHNIQUES_DB).length;
    const detectedTechs = Object.values(mitreTechniques).flat().length;
    const coverage = ((detectedTechs / totalTechs) * 100).toFixed(1);

    document.getElementById('mitre-coverage-percent').textContent = `${coverage}%`;
    document.getElementById('mitre-detected-count').textContent = detectedTechs;

    // Update tactic counts
    MITRE_TACTICS.forEach(t => {
        const count = mitreTechniques[t.id]?.length || mitreTechniques[t.name]?.length || 0;
        const countEl = document.getElementById(`tactic-count-${t.id}`);
        if (countEl) countEl.textContent = count;
    });
}

function showMitreDetail(techId) {
    const tech = MITRE_TECHNIQUES_DB[techId];
    if (!tech) return;

    const tactic = MITRE_TACTICS.find(t => t.id === tech.tactic);

    document.getElementById('mitre-modal-title').textContent = `${techId} - ${tech.name}`;
    document.getElementById('mitre-modal-content').innerHTML = `
        <div class="mitre-detail">
            <div class="mitre-detail-row">
                <span class="detail-label">Technique ID:</span>
                <span class="detail-value">${techId}</span>
            </div>
            <div class="mitre-detail-row">
                <span class="detail-label">Name:</span>
                <span class="detail-value">${tech.name}</span>
            </div>
            <div class="mitre-detail-row">
                <span class="detail-label">Tactic:</span>
                <span class="detail-value" style="color: ${tactic?.color || '#fff'}">${tactic?.name || tech.tactic}</span>
            </div>
            <div class="mitre-detail-row">
                <span class="detail-label">Description:</span>
                <span class="detail-value">${tech.description}</span>
            </div>
            <div class="mitre-detail-row">
                <span class="detail-label">Status:</span>
                <span class="detail-value ${mitreTechniques[tech.tactic]?.includes(techId) ? 'detected' : 'not-detected'}">
                    ${mitreTechniques[tech.tactic]?.includes(techId) ? '✓ Detected in this investigation' : 'Not detected'}
                </span>
            </div>
            <a href="https://attack.mitre.org/techniques/${techId}/" target="_blank" class="btn btn-secondary btn-sm">
                View on MITRE ATT&CK
            </a>
        </div>
    `;

    mitreModal.classList.add('active');
}

// ============================================================================
// Charts (Chart.js)
// ============================================================================

function initCharts() {
    // Threat Score Over Time
    const threatCtx = document.getElementById('threat-score-chart')?.getContext('2d');
    if (threatCtx) {
        charts.threatScore = new Chart(threatCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Threat Score',
                    data: [],
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, max: 100, grid: { color: '#374151' } },
                    x: { grid: { color: '#374151' } }
                }
            }
        });
    }

    // Evidence Distribution (Doughnut)
    const evidenceCtx = document.getElementById('evidence-chart')?.getContext('2d');
    if (evidenceCtx) {
        charts.evidence = new Chart(evidenceCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6', '#a855f7', '#ec4899', '#06b6d4']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'right', labels: { color: '#9ca3af' } }
                }
            }
        });
    }

    // Tools Usage (Bar)
    const toolsCtx = document.getElementById('tools-chart')?.getContext('2d');
    if (toolsCtx) {
        charts.tools = new Chart(toolsCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Executions',
                    data: [],
                    backgroundColor: '#8b5cf6'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: { legend: { display: false } },
                scales: {
                    x: { beginAtZero: true, grid: { color: '#374151' } },
                    y: { grid: { color: '#374151' } }
                }
            }
        });
    }

    // MITRE Radar
    const mitreCtx = document.getElementById('mitre-chart')?.getContext('2d');
    if (mitreCtx) {
        charts.mitre = new Chart(mitreCtx, {
            type: 'radar',
            data: {
                labels: MITRE_TACTICS.slice(0, 8).map(t => t.name),
                datasets: [{
                    label: 'Techniques Detected',
                    data: [0, 0, 0, 0, 0, 0, 0, 0],
                    backgroundColor: 'rgba(0, 212, 255, 0.2)',
                    borderColor: '#00d4ff',
                    pointBackgroundColor: '#00d4ff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    r: {
                        beginAtZero: true,
                        grid: { color: '#374151' },
                        pointLabels: { color: '#9ca3af', font: { size: 10 } }
                    }
                }
            }
        });
    }

    // Severity Distribution (Polar)
    const severityCtx = document.getElementById('severity-chart')?.getContext('2d');
    if (severityCtx) {
        charts.severity = new Chart(severityCtx, {
            type: 'polarArea',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        'rgba(220, 38, 38, 0.8)',
                        'rgba(249, 115, 22, 0.8)',
                        'rgba(251, 191, 36, 0.8)',
                        'rgba(16, 185, 129, 0.8)',
                        'rgba(59, 130, 246, 0.8)'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'right', labels: { color: '#9ca3af' } } },
                scales: { r: { grid: { color: '#374151' } } }
            }
        });
    }

    // Analysis Timeline
    const timelineCtx = document.getElementById('timeline-chart')?.getContext('2d');
    if (timelineCtx) {
        charts.timeline = new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Progress',
                        data: [],
                        borderColor: '#00d4ff',
                        backgroundColor: 'rgba(0, 212, 255, 0.1)',
                        fill: true,
                        yAxisID: 'y'
                    },
                    {
                        label: 'Evidence Found',
                        data: [],
                        borderColor: '#22c55e',
                        backgroundColor: 'transparent',
                        type: 'bar',
                        yAxisID: 'y1'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { labels: { color: '#9ca3af' } } },
                scales: {
                    y: { type: 'linear', position: 'left', max: 100, grid: { color: '#374151' } },
                    y1: { type: 'linear', position: 'right', grid: { drawOnChartArea: false } },
                    x: { grid: { color: '#374151' } }
                }
            }
        });
    }
}

function updateThreatScoreChart(ev) {
    if (!charts.threatScore) return;

    const score = (ev.threat_score || ev.confidence) * 100;
    const time = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });

    charts.threatScore.data.labels.push(time);
    charts.threatScore.data.datasets[0].data.push(score);

    // Keep last 20 points
    if (charts.threatScore.data.labels.length > 20) {
        charts.threatScore.data.labels.shift();
        charts.threatScore.data.datasets[0].data.shift();
    }

    charts.threatScore.update('none');
}

function updateEvidenceChart() {
    if (!charts.evidence) return;

    const typeCounts = {};
    evidence.forEach(ev => {
        typeCounts[ev.type] = (typeCounts[ev.type] || 0) + 1;
    });

    charts.evidence.data.labels = Object.keys(typeCounts);
    charts.evidence.data.datasets[0].data = Object.values(typeCounts);
    charts.evidence.update('none');
}

function updateToolsChart() {
    if (!charts.tools) return;

    const toolCounts = {};
    steps.forEach(step => {
        toolCounts[step.tool] = (toolCounts[step.tool] || 0) + 1;
    });

    const sorted = Object.entries(toolCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);
    charts.tools.data.labels = sorted.map(([name]) => name);
    charts.tools.data.datasets[0].data = sorted.map(([, count]) => count);
    charts.tools.update('none');
}

function updateMitreChart() {
    if (!charts.mitre) return;

    const tacticCounts = MITRE_TACTICS.slice(0, 8).map(t => {
        return mitreTechniques[t.id]?.length || mitreTechniques[t.name]?.length || 0;
    });

    charts.mitre.data.datasets[0].data = tacticCounts;
    charts.mitre.update('none');
}

function updateSeverityChart(event) {
    if (!charts.severity) return;

    const severityMap = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const idx = severityMap[event.severity?.toLowerCase()] ?? 4;
    charts.severity.data.datasets[0].data[idx]++;
    charts.severity.update('none');
}

function updateTimelineChart(data) {
    if (!charts.timeline) return;

    const time = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });

    charts.timeline.data.labels.push(time);
    charts.timeline.data.datasets[0].data.push(data.progress);
    charts.timeline.data.datasets[1].data.push(evidence.length);

    if (charts.timeline.data.labels.length > 30) {
        charts.timeline.data.labels.shift();
        charts.timeline.data.datasets[0].data.shift();
        charts.timeline.data.datasets[1].data.shift();
    }

    charts.timeline.update('none');
}

function updateAllCharts() {
    updateEvidenceChart();
    updateToolsChart();
    updateMitreChart();
}

// ============================================================================
// LLM Chat
// ============================================================================

function sendChatMessage() {
    const message = chatInput.value.trim();
    if (!message) return;

    addChatMessage("user", message);

    // Send to backend for LLM processing
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: "llm_query",
            message: message,
            context: {
                evidence: evidence.slice(-10),
                steps: steps.slice(-5),
                mitre: mitreTechniques,
                hypotheses: hypotheses
            }
        }));
    } else {
        // Fallback: simulate LLM response for demo
        simulateLLMResponse(message);
    }

    chatInput.value = "";
}

function simulateLLMResponse(query) {
    const lowerQuery = query.toLowerCase();
    let response = "";

    if (lowerQuery.includes("process") && lowerQuery.includes("ip")) {
        const processes = evidence.filter(e => e.type === 'process');
        const ips = evidence.filter(e => e.type === 'ip');
        response = `Based on the analysis, I found ${processes.length} suspicious processes and ${ips.length} external IP connections.\n\n`;
        if (ips.length > 0) {
            response += `External IPs detected:\n${ips.map(ip => `• ${ip.value} (${(ip.confidence * 100).toFixed(0)}% confidence)`).join('\n')}`;
        }
    } else if (lowerQuery.includes("malicious") || lowerQuery.includes("summary")) {
        response = `**Investigation Summary**\n\n`;
        response += `• ${steps.length} analysis steps completed\n`;
        response += `• ${evidence.length} evidence items collected\n`;
        response += `• ${Object.values(mitreTechniques).flat().length} MITRE ATT&CK techniques identified\n`;
        response += `• ${hypotheses.length} attack hypotheses generated\n\n`;
        if (hypotheses.length > 0) {
            response += `Top hypothesis: ${hypotheses[0].title} (${(hypotheses[0].confidence * 100).toFixed(0)}% confidence)`;
        }
    } else if (lowerQuery.includes("persistence")) {
        const persistenceTechs = mitreTechniques['Persistence'] || mitreTechniques['persistence'] || [];
        response = `Found ${persistenceTechs.length} persistence techniques:\n`;
        if (persistenceTechs.length > 0) {
            response += persistenceTechs.map(t => `• ${t}`).join('\n');
        } else {
            response += "No persistence mechanisms detected yet.";
        }
    } else if (lowerQuery.includes("credential")) {
        const credTechs = mitreTechniques['Credential Access'] || mitreTechniques['credential-access'] || [];
        response = `Credential theft indicators:\n`;
        if (credTechs.length > 0) {
            response += credTechs.map(t => `• ${t}`).join('\n');
        } else {
            response += "No credential theft indicators detected.";
        }
    } else {
        response = `I analyzed the investigation data based on your query: "${query}"\n\n`;
        response += `Current status: ${steps.length} steps completed, ${evidence.length} evidence items found.\n`;
        response += `\nYou can ask me specific questions about:\n• Processes and network connections\n• Malicious activity summary\n• Persistence mechanisms\n• Credential theft indicators`;
    }

    setTimeout(() => {
        addChatMessage("agent", response, true);
    }, 500 + Math.random() * 1000);
}

function addChatMessage(type, text, isFormatted = false) {
    const messageEl = document.createElement("div");
    messageEl.className = `chat-message ${type}`;

    if (type === 'agent' || type === 'system') {
        messageEl.innerHTML = `
            <div class="chat-avatar ${type === 'agent' ? 'ai' : ''}">
                <svg viewBox="0 0 24 24" fill="currentColor">
                    ${type === 'agent'
                        ? '<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/>'
                        : '<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/>'}
                </svg>
            </div>
            <div class="chat-content">
                ${isFormatted ? formatMarkdown(text) : `<p>${text}</p>`}
            </div>
        `;
    } else {
        messageEl.innerHTML = `<p>${text}</p>`;
    }

    chatMessages.appendChild(messageEl);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function formatMarkdown(text) {
    return text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\n/g, '<br>')
        .replace(/• /g, '<br>• ');
}

function askQuestion(question) {
    chatInput.value = question;
    sendChatMessage();
}

// ============================================================================
// PDF Report Generation
// ============================================================================

async function generatePDFReport() {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();

    const pageWidth = doc.internal.pageSize.getWidth();
    let y = 20;

    // Title
    doc.setFontSize(24);
    doc.setTextColor(0, 212, 255);
    doc.text('Forensic Investigation Report', pageWidth / 2, y, { align: 'center' });
    y += 15;

    // Session Info
    doc.setFontSize(12);
    doc.setTextColor(150, 150, 150);
    doc.text(`Session ID: ${sessionId}`, pageWidth / 2, y, { align: 'center' });
    y += 5;
    doc.text(`Generated: ${new Date().toLocaleString()}`, pageWidth / 2, y, { align: 'center' });
    y += 20;

    // Executive Summary
    doc.setFontSize(16);
    doc.setTextColor(0, 0, 0);
    doc.text('Executive Summary', 20, y);
    y += 10;

    doc.setFontSize(11);
    const summaryText = [
        `Total Analysis Steps: ${steps.length}`,
        `Evidence Items Collected: ${evidence.length}`,
        `MITRE ATT&CK Techniques: ${Object.values(mitreTechniques).flat().length}`,
        `Attack Hypotheses Generated: ${hypotheses.length}`,
        `Timeline Events: ${timeline.length}`
    ];
    summaryText.forEach(line => {
        doc.text(line, 25, y);
        y += 7;
    });
    y += 10;

    // Evidence Summary
    if (evidence.length > 0) {
        doc.setFontSize(16);
        doc.text('Evidence Summary', 20, y);
        y += 10;

        doc.setFontSize(10);
        const evidenceByType = {};
        evidence.forEach(ev => {
            if (!evidenceByType[ev.type]) evidenceByType[ev.type] = [];
            evidenceByType[ev.type].push(ev);
        });

        Object.entries(evidenceByType).forEach(([type, items]) => {
            if (y > 270) { doc.addPage(); y = 20; }
            doc.setTextColor(100, 100, 100);
            doc.text(`${type.toUpperCase()} (${items.length}):`, 25, y);
            y += 6;
            doc.setTextColor(0, 0, 0);
            items.slice(0, 5).forEach(item => {
                if (y > 270) { doc.addPage(); y = 20; }
                const text = `• ${item.value.substring(0, 60)} (${(item.confidence * 100).toFixed(0)}% confidence)`;
                doc.text(text, 30, y);
                y += 5;
            });
            if (items.length > 5) {
                doc.text(`  ... and ${items.length - 5} more`, 30, y);
                y += 5;
            }
            y += 5;
        });
    }

    // MITRE ATT&CK Coverage
    if (Object.keys(mitreTechniques).length > 0) {
        if (y > 220) { doc.addPage(); y = 20; }
        doc.setFontSize(16);
        doc.text('MITRE ATT&CK Coverage', 20, y);
        y += 10;

        doc.setFontSize(10);
        Object.entries(mitreTechniques).forEach(([tactic, techs]) => {
            if (y > 270) { doc.addPage(); y = 20; }
            doc.setTextColor(100, 100, 100);
            doc.text(`${tactic}:`, 25, y);
            y += 6;
            doc.setTextColor(0, 0, 0);
            doc.text(techs.join(', '), 30, y);
            y += 8;
        });
    }

    // Hypotheses
    if (hypotheses.length > 0) {
        if (y > 220) { doc.addPage(); y = 20; }
        doc.setFontSize(16);
        doc.text('Attack Hypotheses', 20, y);
        y += 10;

        doc.setFontSize(10);
        hypotheses.forEach((hyp, idx) => {
            if (y > 260) { doc.addPage(); y = 20; }
            doc.setTextColor(0, 0, 0);
            doc.text(`${idx + 1}. ${hyp.title} (${(hyp.confidence * 100).toFixed(0)}% confidence)`, 25, y);
            y += 6;
            if (hyp.threat_actor) {
                doc.setTextColor(100, 100, 100);
                doc.text(`   Threat Actor: ${hyp.threat_actor}`, 25, y);
                y += 5;
            }
            if (hyp.objective) {
                doc.text(`   Objective: ${hyp.objective}`, 25, y);
                y += 5;
            }
            y += 5;
        });
    }

    // Footer on last page
    doc.setFontSize(8);
    doc.setTextColor(150, 150, 150);
    doc.text('Generated by Autonomous Forensic Orchestrator', pageWidth / 2, 285, { align: 'center' });

    // Save
    doc.save(`forensic_report_${sessionId}.pdf`);
}

// ============================================================================
// Event Listeners
// ============================================================================

function setupEventListeners() {
    // Chat
    chatSend.addEventListener("click", sendChatMessage);
    chatInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") sendChatMessage();
    });

    // Modals
    closeSummaryModal?.addEventListener("click", () => summaryModal.classList.remove("active"));
    closeStepModal?.addEventListener("click", () => stepModal.classList.remove("active"));
    closeMitreModal?.addEventListener("click", () => mitreModal.classList.remove("active"));

    summaryModal?.addEventListener("click", (e) => {
        if (e.target === summaryModal) summaryModal.classList.remove("active");
    });
    stepModal?.addEventListener("click", (e) => {
        if (e.target === stepModal) stepModal.classList.remove("active");
    });
    mitreModal?.addEventListener("click", (e) => {
        if (e.target === mitreModal) mitreModal.classList.remove("active");
    });

    // Report downloads
    downloadPdf?.addEventListener("click", generatePDFReport);
    downloadJson?.addEventListener("click", () => downloadReport("json"));
    downloadHtml?.addEventListener("click", () => downloadReport("html"));
    downloadStix?.addEventListener("click", () => downloadReport("stix"));
    btnExport?.addEventListener("click", () => summaryModal.classList.add("active"));

    // Keyboard
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            summaryModal.classList.remove("active");
            stepModal.classList.remove("active");
            mitreModal.classList.remove("active");
        }
    });
}

// ============================================================================
// Report Download
// ============================================================================

async function downloadReport(format) {
    try {
        const response = await fetch(`${API_BASE}/report/${sessionId}?format=${format}`);
        if (!response.ok) throw new Error(`Failed to get report: ${response.statusText}`);

        let blob, filename;

        if (format === "html") {
            const data = await response.json();
            blob = new Blob([data.html], { type: "text/html" });
            filename = `report_${sessionId}.html`;
        } else {
            const data = await response.json();
            blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
            filename = format === "stix" ? `stix_bundle_${sessionId}.json` : `report_${sessionId}.json`;
        }

        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (error) {
        console.error("Download error:", error);
        alert(`Failed to download report: ${error.message}`);
    }
}

// ============================================================================
// Step Detail Modal
// ============================================================================

function showStepDetail(step) {
    stepDetailContent.innerHTML = `
        <div class="step-detail-section">
            <h3>Step ${step.step_number} - ${step.tool}</h3>
            <p><strong>Phase:</strong> ${step.phase}</p>
            <p><strong>Category:</strong> ${step.tool_category}</p>
            <p><strong>Duration:</strong> ${step.duration_ms}ms</p>
        </div>

        <div class="step-detail-section">
            <h3>Thought Process</h3>
            <p>${step.thought}</p>
        </div>

        <div class="step-detail-section">
            <h3>Action Taken</h3>
            <p>${step.action}</p>
        </div>

        <div class="step-detail-section">
            <h3>Input</h3>
            <pre>${JSON.stringify(step.input, null, 2)}</pre>
        </div>

        <div class="step-detail-section">
            <h3>Output</h3>
            <pre>${JSON.stringify(step.output, null, 2)}</pre>
        </div>

        <div class="step-detail-section">
            <h3>Evidence Extracted (${step.evidence?.length || 0})</h3>
            ${step.evidence?.length > 0
                ? `<ul>${step.evidence.map(e => `<li><strong>${e.type}:</strong> ${e.value} (${(e.confidence * 100).toFixed(0)}% confidence)</li>`).join("")}</ul>`
                : "<p>No evidence extracted</p>"}
        </div>

        <div class="step-detail-section">
            <h3>Next Step Reasoning</h3>
            <p>${step.next_step_reasoning}</p>
        </div>
    `;

    stepModal.classList.add("active");
}

// ============================================================================
// Utility Functions
// ============================================================================

function truncate(text, maxLength) {
    if (!text) return "";
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + "...";
}

function formatPhase(phase) {
    if (!phase) return "Initializing";
    return phase.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase());
}

function formatTime(timestamp) {

    const date = new Date(timestamp);

    return date.toLocaleString(
        'en-GB',
        {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        }
    );
}

// Global functions for onclick handlers
window.askQuestion = askQuestion;
window.showMitreDetail = showMitreDetail;
