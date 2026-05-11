"""
Autonomous Forensic Orchestrator - FastAPI Backend
Main application entry point
"""
from __future__ import annotations

import os
import sys
import uuid
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv
from openai import AsyncOpenAI

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

load_dotenv(override=True)

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from pydantic import BaseModel

# Import services using relative imports when run as module, absolute when run directly
try:
    from backend.services.session_manager import SessionManager, session_manager
    from backend.services.websocket_manager import WebSocketManager, ws_manager
    from backend.services.real_agent import RealForensicAgent
    from backend.services.report_generator import ReportGenerator
except ImportError:
    from services.session_manager import SessionManager, session_manager
    from services.websocket_manager import WebSocketManager, ws_manager
    from services.real_agent import RealForensicAgent
    from services.report_generator import ReportGenerator

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Autonomous Forensic Orchestrator",
    description="AI-powered DFIR analysis pipeline with real-time investigation tracking",
    version="1.0.0",
)

# CORS middleware - allow all origins for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Determine paths
BACKEND_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = BACKEND_DIR.parent
UI_DIR = PROJECT_ROOT / "ui"
UPLOAD_DIR = PROJECT_ROOT / "uploads"
REPORTS_DIR = PROJECT_ROOT / "reports"

# Create directories
UPLOAD_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

logger.info(f"Backend directory: {BACKEND_DIR}")
logger.info(f"UI directory: {UI_DIR}")
logger.info(f"Upload directory: {UPLOAD_DIR}")


# ============================================================================
# Pydantic Models
# ============================================================================

class UploadResponse(BaseModel):
    session_id: str
    status: str
    message: str
    artifact_name: str
    artifact_size: int


class ChatMessage(BaseModel):
    session_id: str
    message: str


class ChatResponse(BaseModel):
    session_id: str
    response: str
    status: str


class SessionStatus(BaseModel):
    session_id: str
    status: str
    current_phase: str
    steps_completed: int
    total_evidence: int
    progress_percent: float


# ============================================================================
# Static Files - Serve UI
# ============================================================================

# Mount UI static files (CSS, JS)
if UI_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(UI_DIR)), name="static")
    logger.info(f"Mounted UI static files from {UI_DIR}")


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    """Serve the main landing page."""
    index_path = UI_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path), media_type="text/html")
    return HTMLResponse("<h1>Autonomous Forensic Orchestrator API</h1><p>UI not found. Go to <a href='/docs'>/docs</a></p>")


@app.get("/dashboard", response_class=HTMLResponse)
@app.get("/dashboard.html", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the investigation dashboard."""
    dashboard_path = UI_DIR / "dashboard.html"
    if dashboard_path.exists():
        return FileResponse(str(dashboard_path), media_type="text/html")
    raise HTTPException(status_code=404, detail="Dashboard not found")


@app.get("/index.html", response_class=HTMLResponse)
async def serve_index_html():
    """Serve the main landing page (explicit path)."""
    return await serve_index()


# Serve CSS and JS files directly
@app.get("/styles.css")
async def serve_styles():
    """Serve CSS file."""
    css_path = UI_DIR / "styles.css"
    if css_path.exists():
        return FileResponse(str(css_path), media_type="text/css")
    raise HTTPException(status_code=404, detail="styles.css not found")


@app.get("/app.js")
async def serve_app_js():
    """Serve app.js file."""
    js_path = UI_DIR / "app.js"
    if js_path.exists():
        return FileResponse(str(js_path), media_type="application/javascript")
    raise HTTPException(status_code=404, detail="app.js not found")


@app.get("/dashboard.js")
async def serve_dashboard_js():
    """Serve dashboard.js file."""
    js_path = UI_DIR / "dashboard.js"
    if js_path.exists():
        return FileResponse(str(js_path), media_type="application/javascript")
    raise HTTPException(status_code=404, detail="dashboard.js not found")


# ============================================================================
# API Endpoints
# ============================================================================

@app.post("/upload_artefact", response_model=UploadResponse)
async def upload_artefact(
    file: UploadFile = File(...),
    artifact_type: str = Form(default="auto"),
    description: str = Form(default=""),
):
    """
    Upload a forensic artifact to start investigation.

    Supported types:
    - memory_dump: RAM dump files (.raw, .mem, .dmp)
    - disk_image: Disk images (.img, .dd, .E01)
    - evtx: Windows Event Logs (.evtx)
    - pcap: Network captures (.pcap, .pcapng)
    - malware_sample: Suspicious executables
    - auto: Auto-detect based on extension
    """
    try:
        # Generate session ID
        session_id = str(uuid.uuid4())[:8]

        # Save uploaded file
        file_ext = Path(file.filename).suffix.lower() if file.filename else ".bin"
        saved_filename = f"{session_id}_{file.filename}"
        file_path = UPLOAD_DIR / saved_filename

        content = await file.read()
        file_size = len(content)

        with open(file_path, "wb") as f:
            f.write(content)

        # Auto-detect artifact type
        if artifact_type == "auto":
            artifact_type = _detect_artifact_type(file_ext, content[:1024])

        # Create session
        session_manager.create_session(
            session_id=session_id,
            artifact_path=str(file_path),
            artifact_name=file.filename or "unknown",
            artifact_type=artifact_type,
            artifact_size=file_size,
            description=description,
        )

        logger.info(f"Created session {session_id} for artifact: {file.filename}")

        return UploadResponse(
            session_id=session_id,
            status="started",
            message=f"Investigation started for {artifact_type} artifact",
            artifact_name=file.filename or "unknown",
            artifact_size=file_size,
        )

    except Exception as e:
        logger.exception("Failed to upload artifact")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/chat", response_model=ChatResponse)
async def chat(message: ChatMessage):
    """
    Send a message/instruction to the forensic agent.

    Example instructions:
    - "Focus on network connections"
    - "Look for persistence mechanisms"
    - "Check for credential theft"
    """
    session = session_manager.get_session(message.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Add instruction to session
    session_manager.add_instruction(message.session_id, message.message)

    # Broadcast instruction to WebSocket
    await ws_manager.broadcast(message.session_id, {
        "type": "instruction",
        "timestamp": datetime.utcnow().isoformat(),
        "message": message.message,
    })

    return ChatResponse(
        session_id=message.session_id,
        response=f"Instruction received: {message.message}. Agent will incorporate this guidance.",
        status="acknowledged",
    )


@app.get("/status/{session_id}", response_model=SessionStatus)
async def get_status(session_id: str):
    """Get the current status of an investigation."""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return SessionStatus(
        session_id=session_id,
        status=session.get("status", "unknown"),
        current_phase=session.get("current_phase", "initializing"),
        steps_completed=len(session.get("steps", [])),
        total_evidence=len(session.get("evidence", [])),
        progress_percent=session.get("progress", 0),
    )


@app.get("/report/{session_id}")
async def get_report(session_id: str, format: str = "json"):
    """
    Get the final investigation report.

    Formats:
    - json: JSON report with all findings
    - html: Rendered HTML report
    - stix: STIX 2.1 bundle
    """
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    generator = ReportGenerator(session)

    if format == "json":
        return JSONResponse(generator.generate_json_report())
    elif format == "html":
        html_content = generator.generate_html_report()
        return JSONResponse({"html": html_content})
    elif format == "stix":
        return JSONResponse(generator.generate_stix_bundle())
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")


@app.get("/sessions")
async def list_sessions():
    """List all active investigation sessions."""
    return session_manager.list_sessions()


@app.delete("/session/{session_id}")
async def delete_session(session_id: str):
    """Delete/close an investigation session."""
    if session_manager.delete_session(session_id):
        return {"status": "deleted", "session_id": session_id}
    raise HTTPException(status_code=404, detail="Session not found")


@app.get("/tools")
async def list_tools():
    """List all available forensic tools."""
    return {
        "tools": RealForensicAgent.get_available_tools(),
        "total": len(RealForensicAgent.get_available_tools()),
    }


# ============================================================================
# LLM Query Processing
# ============================================================================

async def process_llm_query(query: str, context: dict, session: dict) -> str:
    """
    Process natural language queries about the investigation.
    In production, this calls the configured OpenAI-compatible API (DeepInfra, OpenAI, etc.)
    when available. Otherwise it falls back to the local simulated response.
    """
    query_lower = query.lower()

    # Extract context
    evidence_list = context.get("evidence", []) or session.get("evidence", [])
    steps_list = context.get("steps", []) or session.get("steps", [])
    mitre_data = context.get("mitre", {}) or session.get("mitre_coverage", {})
    hypotheses_list = context.get("hypotheses", []) or session.get("hypotheses", [])

    if os.getenv("REAL_FORENSIC_LLM", "true").lower() in ("1", "true", "yes", "y"):
        try:
            return await _call_real_llm_query(query, evidence_list, steps_list, mitre_data, hypotheses_list)
        except Exception as e:
            logger.exception("Real LLM query failed, falling back to local response")


    # Analyze evidence by type
    evidence_by_type = {}
    for ev in evidence_list:
        ev_type = ev.get("type", "unknown")
        if ev_type not in evidence_by_type:
            evidence_by_type[ev_type] = []
        evidence_by_type[ev_type].append(ev)

    # Generate contextual response based on query
    if "process" in query_lower and ("ip" in query_lower or "network" in query_lower or "connect" in query_lower):
        processes = evidence_by_type.get("process", [])
        ips = evidence_by_type.get("ip", [])
        response = f"**Network Connection Analysis**\n\n"
        response += f"Found {len(processes)} suspicious processes and {len(ips)} external IP connections.\n\n"
        if ips:
            response += "**External IP Addresses:**\n"
            for ip in ips[:5]:
                conf = (ip.get("confidence", 0.5) * 100)
                response += f"• `{ip.get('value', 'N/A')}` - {conf:.0f}% confidence\n"
            if len(ips) > 5:
                response += f"\n... and {len(ips) - 5} more IPs detected.\n"
        if processes:
            response += "\n**Suspicious Processes:**\n"
            for proc in processes[:5]:
                response += f"• `{proc.get('value', 'N/A')}`\n"
        return response

    elif "summary" in query_lower or "malicious" in query_lower or "overview" in query_lower:
        response = f"**Investigation Summary**\n\n"
        response += f"• **Analysis Steps:** {len(steps_list)} completed\n"
        response += f"• **Evidence Items:** {len(evidence_list)} collected\n"
        total_mitre = sum(len(v) if isinstance(v, list) else 1 for v in mitre_data.values())
        response += f"• **MITRE Techniques:** {total_mitre} identified\n"
        response += f"• **Hypotheses:** {len(hypotheses_list)} generated\n\n"

        if hypotheses_list:
            top_hyp = hypotheses_list[0]
            conf = (top_hyp.get("confidence", 0.5) * 100)
            response += f"**Top Hypothesis:** {top_hyp.get('title', 'Unknown')} ({conf:.0f}% confidence)\n"
            if top_hyp.get("threat_actor"):
                response += f"• Suspected Actor: {top_hyp.get('threat_actor')}\n"
            if top_hyp.get("objective"):
                response += f"• Objective: {top_hyp.get('objective')}\n"

        # Evidence breakdown
        if evidence_by_type:
            response += "\n**Evidence Breakdown:**\n"
            for ev_type, items in sorted(evidence_by_type.items(), key=lambda x: -len(x[1])):
                response += f"• {ev_type.upper()}: {len(items)} items\n"

        return response

    elif "persistence" in query_lower:
        persistence_techs = mitre_data.get("Persistence", []) or mitre_data.get("persistence", [])
        registry_evidence = evidence_by_type.get("registry", [])

        response = f"**Persistence Mechanism Analysis**\n\n"

        if persistence_techs:
            response += f"**MITRE Techniques Detected ({len(persistence_techs)}):**\n"
            for tech in persistence_techs:
                response += f"• `{tech}`\n"
        else:
            response += "No persistence techniques detected in MITRE mapping.\n"

        if registry_evidence:
            response += f"\n**Registry Modifications ({len(registry_evidence)}):**\n"
            for reg in registry_evidence[:5]:
                response += f"• `{reg.get('value', 'N/A')}`\n"

        return response

    elif "credential" in query_lower or "password" in query_lower or "theft" in query_lower:
        cred_techs = mitre_data.get("Credential Access", []) or mitre_data.get("credential-access", [])

        response = f"**Credential Theft Analysis**\n\n"

        if cred_techs:
            response += f"**Techniques Detected ({len(cred_techs)}):**\n"
            for tech in cred_techs:
                response += f"• `{tech}`\n"

        # Look for credential-related evidence
        cred_indicators = []
        for ev in evidence_list:
            value = str(ev.get("value", "")).lower()
            if any(kw in value for kw in ["lsass", "mimikatz", "credential", "password", "ntds"]):
                cred_indicators.append(ev)

        if cred_indicators:
            response += f"\n**Credential-Related Evidence ({len(cred_indicators)}):**\n"
            for ev in cred_indicators[:5]:
                response += f"• [{ev.get('type', 'unknown')}] `{ev.get('value', 'N/A')}`\n"

        if not cred_techs and not cred_indicators:
            response += "No credential theft indicators detected yet.\n"

        return response

    elif "c2" in query_lower or "command and control" in query_lower or "c&c" in query_lower:
        c2_techs = mitre_data.get("Command and Control", []) or mitre_data.get("command-and-control", [])
        domains = evidence_by_type.get("domain", [])
        ips = evidence_by_type.get("ip", [])

        response = f"**Command & Control Analysis**\n\n"

        if c2_techs:
            response += f"**MITRE Techniques ({len(c2_techs)}):**\n"
            for tech in c2_techs:
                response += f"• `{tech}`\n"

        if domains:
            response += f"\n**Suspicious Domains ({len(domains)}):**\n"
            for d in domains[:5]:
                response += f"• `{d.get('value', 'N/A')}`\n"

        if ips:
            response += f"\n**External IPs ({len(ips)}):**\n"
            for ip in ips[:5]:
                response += f"• `{ip.get('value', 'N/A')}`\n"

        return response

    elif "ioc" in query_lower or "indicator" in query_lower:
        response = f"**Indicators of Compromise (IOCs)**\n\n"

        ioc_types = ["ip", "domain", "hash", "file", "url"]
        for ioc_type in ioc_types:
            items = evidence_by_type.get(ioc_type, [])
            if items:
                response += f"**{ioc_type.upper()}s ({len(items)}):**\n"
                for item in items[:5]:
                    response += f"• `{item.get('value', 'N/A')}`\n"
                if len(items) > 5:
                    response += f"  ... and {len(items) - 5} more\n"
                response += "\n"

        return response

    else:
        # Generic response
        response = f"**Investigation Query Analysis**\n\n"
        response += f"Query: \"{query}\"\n\n"
        response += f"**Current Status:**\n"
        response += f"• {len(steps_list)} analysis steps completed\n"
        response += f"• {len(evidence_list)} evidence items collected\n"
        total_mitre = sum(len(v) if isinstance(v, list) else 1 for v in mitre_data.values())
        response += f"• {total_mitre} MITRE techniques identified\n\n"

        response += "**Available Query Topics:**\n"
        response += "• Process and network connections\n"
        response += "• Malicious activity summary\n"
        response += "• Persistence mechanisms\n"
        response += "• Credential theft indicators\n"
        response += "• Command & Control analysis\n"
        response += "• IOC extraction\n"

        return response


async def _call_real_llm_query(
    query: str,
    evidence_list: list,
    steps_list: list,
    mitre_data: dict,
    hypotheses_list: list,
) -> str:
    """Call the configured OpenAI-compatible model for investigation responses."""
    api_key = os.getenv("DEEPINFRA_API_KEY") or os.getenv("OPENAI_API_KEY", "")
    base_url = os.getenv("OPENAI_BASE_URL", "https://api.deepinfra.com/v1/openai")
    client = AsyncOpenAI(api_key=api_key, base_url=base_url)
    model = os.getenv("CAI_MODEL", "deepseek-ai/DeepSeek-V3-0324")

    evidence_summary = "\n".join(
        [f"- {ev.get('type', 'unknown')}: {ev.get('value', 'N/A')}" for ev in (evidence_list or [])[:10]]
    ) or "No evidence has been collected yet."
    steps_summary = "\n".join(
        [f"- {step.get('tool', 'step')} ({step.get('phase', 'unknown')}): {step.get('thought', '')[:120]}" for step in (steps_list or [])[:5]]
    ) or "No investigation steps have run yet."
    mitre_summary = "\n".join(
        [f"- {tactic}: {', '.join(values) if isinstance(values, list) else values}" for tactic, values in (mitre_data or {}).items()][:10]
    ) or "No MITRE techniques identified yet."
    hypotheses_summary = "\n".join(
        [f"- {hyp.get('title', 'unknown')} ({hyp.get('confidence', 0.0) * 100:.0f}%): {hyp.get('objective', '')}" for hyp in (hypotheses_list or [])[:5]]
    ) or "No attack hypotheses generated yet."

    messages = [
        {
            "role": "system",
            "content": (
                "You are a highly skilled DFIR analyst and investigation assistant. "
                "Use the context from the current investigation to answer the user query accurately and technically. "
                "Focus on evidence, suspicious behavior, and any MITRE ATT&CK mappings provided. "
                "If evidence is missing, be transparent about what cannot be inferred."
            ),
        },
        {
            "role": "user",
            "content": (
                f"User query: {query}\n\n"
                f"Evidence summary:\n{evidence_summary}\n\n"
                f"Investigation steps summary:\n{steps_summary}\n\n"
                f"MITRE summary:\n{mitre_summary}\n\n"
                f"Hypotheses summary:\n{hypotheses_summary}\n\n"
                "Answer with a concise but technical response that directly addresses the query."
            ),
        },
    ]

    response = await client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=0.2,
        max_tokens=700,
    )

    return response.choices[0].message.content or ""


# ============================================================================
# WebSocket Endpoint
# ============================================================================

@app.websocket("/ws/agent/{session_id}")
async def websocket_agent(websocket: WebSocket, session_id: str):
    """
    WebSocket endpoint for real-time investigation updates.

    Messages sent to client:
    - step: New analysis step with full details
    - evidence: New evidence discovered
    - progress: Progress update
    - complete: Investigation complete
    - error: Error occurred
    """
    # Must accept first, otherwise FastAPI returns 403 Forbidden
    await websocket.accept()

    session = session_manager.get_session(session_id)
    if not session:
        await websocket.send_json({"type": "error", "message": f"Session {session_id} not found. Please upload a new artifact."})
        await websocket.close(code=4004, reason="Session not found")
        return

    async with ws_manager._lock:
        ws_manager._connections[session_id].add(websocket)
    logger.info(f"WebSocket connected for session {session_id}")

    try:
        # Start the forensic agent
        agent = RealForensicAgent(session_id, session_manager, ws_manager)

        # Run analysis in background
        import asyncio
        analysis_task = asyncio.create_task(agent.run_investigation())

        # Listen for client messages
        while True:
            try:
                data = await websocket.receive_json()

                if data.get("type") == "instruction":
                    session_manager.add_instruction(session_id, data.get("message", ""))
                    await ws_manager.send_to_session(session_id, {
                        "type": "instruction_ack",
                        "message": data.get("message"),
                    })
                elif data.get("type") == "llm_query":
                    # Handle LLM query with investigation context
                    response = await process_llm_query(
                        data.get("message", ""),
                        data.get("context", {}),
                        session
                    )
                    await ws_manager.send_to_session(session_id, {
                        "type": "llm_response",
                        "data": {"response": response}
                    })
                elif data.get("type") == "pause":
                    agent.pause()
                elif data.get("type") == "resume":
                    agent.resume()
                elif data.get("type") == "stop":
                    agent.stop()
                    break

            except WebSocketDisconnect:
                logger.info(f"WebSocket disconnected for session {session_id}")
                break

    except Exception as e:
        logger.exception(f"WebSocket error for session {session_id}")
        await ws_manager.send_to_session(session_id, {
            "type": "error",
            "message": str(e),
        })
    finally:
        ws_manager.disconnect(websocket, session_id)


# ============================================================================
# Utility Functions
# ============================================================================

def _detect_artifact_type(extension: str, header_bytes: bytes) -> str:
    """Auto-detect artifact type from extension and file header."""
    ext_mapping = {
        ".raw": "memory_dump",
        ".mem": "memory_dump",
        ".dmp": "memory_dump",
        ".vmem": "memory_dump",
        ".img": "disk_image",
        ".dd": "disk_image",
        ".e01": "disk_image",
        ".evtx": "evtx",
        ".pcap": "pcap",
        ".pcapng": "pcap",
        ".exe": "malware_sample",
        ".dll": "malware_sample",
        ".bin": "binary",
        ".zip": "archive",
        ".tar": "archive",
    }

    # Check magic bytes
    if header_bytes[:4] == b"MZ\x90\x00" or header_bytes[:2] == b"MZ":
        return "malware_sample"
    if header_bytes[:4] == b"\x7fELF":
        return "malware_sample"
    if header_bytes[:8] == b"ElfChnk\x00":
        return "evtx"
    if header_bytes[:4] == b"\xd4\xc3\xb2\xa1" or header_bytes[:4] == b"\xa1\xb2\xc3\xd4":
        return "pcap"

    return ext_mapping.get(extension.lower(), "unknown")


# ============================================================================
# Health Check
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "active_sessions": len(session_manager.list_sessions()),
    }


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("  Autonomous Forensic Orchestrator")
    print("="*60)
    print(f"\n  UI:   http://localhost:8000")
    print(f"  API:  http://localhost:8000/docs")
    print(f"  Health: http://localhost:8000/health")
    print("\n" + "="*60 + "\n")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
    )
