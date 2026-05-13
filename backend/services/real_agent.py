"""
Real Forensic Agent — ReAct loop (Reason → Act → Observe → repeat).

The LLM decides which tool to run at each turn based on accumulated
FINDINGS. Large outputs are summarised before they enter the context
window. At the end an incident timeline is generated — chronological,
MITRE ATT&CK tagged, citing only real tool output.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import uuid
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from dotenv import load_dotenv
from openai import AsyncOpenAI

if TYPE_CHECKING:
    from .session_manager import SessionManager
    from .websocket_manager import WebSocketManager

from .session_manager import InvestigationStep, Evidence
from . import real_tools

logger = logging.getLogger(__name__)

MAX_REACT_TURNS = 20
CONTEXT_BUDGET = 6000          # max chars of tool output sent to LLM
FINDINGS_BUDGET = 4000         # max chars of findings block sent to LLM

# ── Master System Prompt ───────────────────────────────────────────────
SYSTEM_PROMPT = """You are an Autonomous Digital Forensics Analyst (Senior Level).
You receive a forensic artifact (memory dump or disk image) and must analyse it
completely without human guidance.

You operate in a strict ReAct loop:
  THINK → ACT (call one tool) → OBSERVE (read result) → THINK → ACT → ...

You have access to the following tools. Call them one at a time:

┌───────────────────────┬────────────────────────────────────────────────────────┐
│ Tool ID               │ What it does                                           │
├───────────────────────┼────────────────────────────────────────────────────────┤
│ file_identify         │ Identify file type (ELF, PE, raw dump, etc.)           │
│ strings_extract       │ Extract printable strings, grouped: URLs, IPs, paths,  │
│                       │ registry keys, base64 blobs, suspicious commands.      │
│ hexdump               │ Show hex dump of file header (magic bytes).            │
│ yara_scan             │ Scan with built-in YARA rules (malware, crypto, etc.)  │
├───────────────────────┼────────────────────────────────────────────────────────┤
│ vol3_pslist           │ All running processes + parent PIDs + timestamps.      │
│ vol3_pstree           │ Process tree — spot anomalous parent→child chains.     │
│ vol3_netscan          │ Active/recent network connections (IPs, ports).        │
│ vol3_cmdline          │ Command-line arguments for every process.              │
│ vol3_malfind          │ RWX memory regions — injected shellcode detection.     │
│ vol3_dlllist          │ DLLs loaded per process — spot injected DLLs.          │
│ vol3_filescan         │ Scan memory for FILE_OBJECT entries — find hidden      │
│                       │ files, documents, RAR/ZIP archives, executables.       │
│ vol3_consoles         │ Console input/output history — see typed commands,     │
│                       │ passwords, flags, and interactive session content.     │
│ vol3_handles          │ Open handles per process (files, registry, mutexes).   │
│ vol3_envars           │ Environment variables per process.                     │
│ vol3_dumpfiles        │ Extract cached files from memory (by file object).     │
│                       │ MUST USE ARGS: {"pid": 1234} or {"virtaddr": "0x12"}   │
├───────────────────────┼────────────────────────────────────────────────────────┤
│ tsk_fls               │ Sleuth Kit: recursive file listing from disk image.    │
│ tsk_mmls              │ Sleuth Kit: show partition layout of disk image.       │
│ virustotal_hash_lookup│ Query VirusTotal for hash reputation (malicious count).│
│ virustotal_ip_lookup  │ Query VirusTotal for IP reputation and geolocation.    │
│ virustotal_domain_lookup│ Query VirusTotal for Domain reputation and creation. │
└───────────────────────┴────────────────────────────────────────────────────────┘

═══════════════════════════
DECISION STRATEGY (follow this order for a memory dump)
═══════════════════════════

Phase 1 — Triage (automatic, already done before you are asked):
  file_identify → strings_extract → hexdump → yara_scan → virustotal_hash_lookup (on artifact)

Phase 2 — Deep Analysis (YOU decide the order):

Step 1 → vol3_pslist
  Look for: cmd.exe / powershell.exe under unexpected parents.
  Note any suspicious PID. Look for mspaint.exe, WinRAR, DumpIt.

Step 2 → vol3_cmdline
  Look for: base64 strings, -enc flags, suspicious paths, passwords
  typed on command line, paths to archives or tools.

Step 3 → vol3_consoles
  CRITICAL: Shows what the user TYPED in cmd.exe. This is where
  CTF flags, passwords, and secret commands are often found.

Step 4 → vol3_netscan
  Look for: outbound connections on unusual ports from non-browser
  processes. Note remote IPs. Check suspect IPs with virustotal_ip_lookup.

Step 5 → vol3_filescan
  Look for: .rar, .zip, .txt, .flag, .key files. Find documents
  the user had open. Cross-reference with process list. Check hashes
  of interesting extracted files with virustotal_hash_lookup.

Step 6 → vol3_malfind
  Look for: RWX regions in suspect processes from earlier steps.

Step 7 → vol3_handles
  Check what files/registry keys suspect processes had open.

Step 8+ → vol3_dlllist, vol3_envars, vol3_dumpfiles as needed.

For disk images → tsk_mmls first, then tsk_fls.

═══════════════════════════
CRITICAL RULES — NEVER BREAK THESE
═══════════════════════════

1. Never invent timestamps, PIDs, IPs, file paths, or registry keys.
   Only report what appeared in actual tool output.
2. Every hypothesis must cite at least 2 specific tool outputs as evidence.
3. Each tool call must be justified by current findings.
4. If a tool returns an error, note it and choose a different tool.
5. Confidence: HIGH = 3+ evidence items, MEDIUM = 2, LOW = 1.
6. Use ONLY numeric values (0.0-1.0) for confidence and threat_score.
7. Do NOT say DONE until you have run vol3_consoles.
   It often contains the critical evidence (flags, passwords).
"""

# ── Available tools the LLM can pick from ──────────────────────────────
TOOL_CATALOG = {
    "file_identify":   {"name": "File Identification",          "category": "triage"},
    "strings_extract": {"name": "String Extraction",            "category": "triage"},
    "hexdump":         {"name": "Hex Dump Header",              "category": "triage"},
    "yara_scan":       {"name": "YARA Scan",                    "category": "malware_analysis"},
    # ── Volatility3 plugins ──
    "vol3_pslist":     {"name": "Volatility3 – Process List",   "category": "memory_forensics", "plugin": "windows.pslist"},
    "vol3_pstree":     {"name": "Volatility3 – Process Tree",   "category": "memory_forensics", "plugin": "windows.pstree"},
    "vol3_netscan":    {"name": "Volatility3 – Network Scan",   "category": "memory_forensics", "plugin": "windows.netstat"},
    "vol3_cmdline":    {"name": "Volatility3 – Command Lines",  "category": "memory_forensics", "plugin": "windows.cmdline"},
    "vol3_malfind":    {"name": "Volatility3 – Malfind",        "category": "memory_forensics", "plugin": "windows.malfind"},
    "vol3_dlllist":    {"name": "Volatility3 – DLL List",       "category": "memory_forensics", "plugin": "windows.dlllist"},
    "vol3_filescan":   {"name": "Volatility3 – File Scan",      "category": "memory_forensics", "plugin": "windows.filescan"},
    "vol3_consoles":   {"name": "Volatility3 – Consoles",       "category": "memory_forensics", "plugin": "windows.consoles"},
    "vol3_handles":    {"name": "Volatility3 – Handles",        "category": "memory_forensics", "plugin": "windows.handles"},
    "vol3_envars":     {"name": "Volatility3 – Env Vars",       "category": "memory_forensics", "plugin": "windows.envars"},
    "vol3_dumpfiles":  {"name": "Volatility3 – Dump Files",     "category": "memory_forensics", "plugin": "windows.dumpfiles"},
    # ── Sleuth Kit ──
    "tsk_fls":         {"name": "Sleuth Kit – File Listing",    "category": "disk_forensics"},
    "tsk_mmls":        {"name": "Sleuth Kit – Partition Map",   "category": "disk_forensics"},
    "virustotal_hash_lookup": {"name": "VirusTotal Hash Lookup", "category": "threat_intelligence"},
    "virustotal_ip_lookup":   {"name": "VirusTotal IP Lookup",   "category": "threat_intelligence"},
    "virustotal_domain_lookup": {"name": "VirusTotal Domain Lookup", "category": "threat_intelligence"},
}

TOOL_LIST_TEXT = "\n".join(f"  • {tid}" for tid in TOOL_CATALOG)

# ── Findings block ─────────────────────────────────────────────────────

class FindingsBlock:
    """Accumulates structured forensic findings across turns."""

    def __init__(self):
        self.suspect_pids: List[Dict[str, Any]] = []
        self.network_iocs: List[Dict[str, Any]] = []
        self.file_iocs: List[str] = []
        self.yara_hits: List[str] = []
        self.timestamps: List[Dict[str, str]] = []
        self.mitre: List[Dict[str, str]] = []
        self.raw_notes: List[str] = []

    # helpers ──
    def add_pid(self, pid, name, reason, ppid=None):
        entry = {"pid": pid, "name": name, "reason": reason}
        if ppid:
            entry["ppid"] = ppid
        if entry not in self.suspect_pids:
            self.suspect_pids.append(entry)

    def add_network(self, value, direction="unknown", port=None):
        e = {"value": value, "direction": direction}
        if port:
            e["port"] = port
        if e not in self.network_iocs:
            self.network_iocs.append(e)

    def add_file(self, path):
        if path not in self.file_iocs:
            self.file_iocs.append(path)

    def add_yara(self, rule):
        if rule not in self.yara_hits:
            self.yara_hits.append(rule)

    def add_ts(self, ts, event):
        self.timestamps.append({"timestamp": ts, "event": event})

    def add_mitre(self, tactic, tid, name):
        e = {"tactic": tactic, "technique_id": tid, "technique_name": name}
        if e not in self.mitre:
            self.mitre.append(e)

    def add_note(self, note):
        self.raw_notes.append(note)

    def to_text(self, budget=FINDINGS_BUDGET) -> str:
        parts = []
        if self.suspect_pids:
            parts.append("SUSPECT PIDS:\n" + "\n".join(
                f"  PID {p['pid']} ({p['name']}): {p['reason']}" for p in self.suspect_pids[:20]))
        if self.network_iocs:
            parts.append("NETWORK IOCs:\n" + "\n".join(
                f"  {n['value']} dir={n['direction']}" for n in self.network_iocs[:20]))
        if self.file_iocs:
            parts.append("FILE IOCs:\n" + "\n".join(f"  {f}" for f in self.file_iocs[:20]))
        if self.yara_hits:
            parts.append("YARA HITS:\n" + "\n".join(f"  {y}" for y in self.yara_hits))
        if self.timestamps:
            parts.append("KEY TIMESTAMPS:\n" + "\n".join(
                f"  {t['timestamp']}: {t['event']}" for t in self.timestamps[:15]))
        if self.mitre:
            parts.append("MITRE ATT&CK:\n" + "\n".join(
                f"  {m['technique_id']} {m['technique_name']} ({m['tactic']})" for m in self.mitre))
        if self.raw_notes:
            parts.append("NOTES:\n" + "\n".join(f"  {n}" for n in self.raw_notes[-10:]))
        text = "\n\n".join(parts)
        return text[:budget] if text else "(no findings yet)"


# ── Helper: safe confidence ────────────────────────────────────────────

def _safe_conf(val) -> float:
    try:
        return float(val)
    except (ValueError, TypeError):
        return {"high": 0.8, "medium": 0.5, "low": 0.3, "critical": 0.95}.get(
            str(val).lower(), 0.5)


# ── Helper: truncate output for context window ────────────────────────

def _truncate(text: str, budget: int = CONTEXT_BUDGET) -> str:
    if len(text) <= budget:
        return text
    half = budget // 2
    return text[:half] + f"\n\n... [{len(text) - budget} chars truncated] ...\n\n" + text[-half:]


# ══════════════════════════════════════════════════════════════════════
#  ReAct Forensic Agent
# ══════════════════════════════════════════════════════════════════════

class RealForensicAgent:
    """Autonomous DFIR agent using a ReAct loop."""

    def __init__(self, session_id: str, session_manager: "SessionManager",
                 ws_manager: "WebSocketManager"):
        load_dotenv(override=True)
        self.session_id = session_id
        self.sm = session_manager
        self.ws = ws_manager
        self._paused = False
        self._stopped = False
        self._step = 0
        self._tools_run: List[str] = []
        self.findings = FindingsBlock()

        api_key = os.getenv("DEEPINFRA_API_KEY") or os.getenv("OPENAI_API_KEY", "")
        base_url = os.getenv("OPENAI_BASE_URL", "https://api.deepinfra.com/v1/openai")
        self.llm = AsyncOpenAI(api_key=api_key, base_url=base_url)
        self._llm_ok = bool(api_key)
        self._model = os.getenv("CAI_MODEL", "deepseek-ai/DeepSeek-V3-0324")
        logger.info(f"ReActAgent init: llm={self._llm_ok}, model={self._model}")

    # kept for API compat
    @classmethod
    def get_available_tools(cls):
        return real_tools.get_available_tools()
    def pause(self):  self._paused = True
    def resume(self): self._paused = False
    def stop(self):   self._stopped = True

    # ── Main loop ──────────────────────────────────────────────────────

    async def run_investigation(self) -> None:
        session = self.sm.get_session(self.session_id)
        if not session:
            return
        artifact_path = session["artifact_path"]
        if not os.path.exists(artifact_path):
            await self.ws.send_error(self.session_id, f"Artifact not found: {artifact_path}")
            return

        self.sm.update_session(self.session_id, status="running")

        try:
            # ── Phase 1: triage (always) ───────────────────────────
            for tid in ("file_identify", "strings_extract", "hexdump", "yara_scan", "virustotal_hash_lookup"):
                if self._stopped:
                    break
                while self._paused:
                    await asyncio.sleep(0.5)
                await self._execute_and_record(tid, artifact_path)

            # ── Phase 2: ReAct loop — LLM picks the next tool ─────
            for turn in range(MAX_REACT_TURNS):
                if self._stopped:
                    break
                while self._paused:
                    await asyncio.sleep(0.5)

                remaining = [t for t in TOOL_CATALOG if t not in self._tools_run]
                if not remaining:
                    break

                next_tool = await self._reason_next_tool(remaining, artifact_path)
                if next_tool == "DONE" or next_tool is None:
                    break

                await self._execute_and_record(next_tool, artifact_path)

            # ── Phase 3: incident timeline + final summary ────────
            await self._generate_timeline_and_summary()

        except Exception as e:
            logger.exception(f"Investigation error: {e}")
            self.sm.update_session(self.session_id, status="failed")
            await self.ws.send_error(self.session_id, str(e))

    # ── Reason: ask LLM what tool to run next ──────────────────────

    async def _reason_next_tool(self, remaining: List[str], artifact_path: str) -> Optional[str]:
        if not self._llm_ok:
            return remaining[0] if remaining else None

        tools_done = ", ".join(self._tools_run) or "(none)"
        tools_left = ", ".join(remaining)
        tools_called = len(self._tools_run)

        # Enforce mandatory tools before allowing DONE
        mandatory_not_run = [t for t in ("vol3_consoles", "vol3_cmdline",
                                          "vol3_filescan", "vol3_pslist")
                             if t not in self._tools_run and t in remaining]

        prompt = (
            f"TOOLS ALREADY RUN ({tools_called}/{MAX_REACT_TURNS}): {tools_done}\n"
            f"TOOLS AVAILABLE: {tools_left}\n\n"
            f"CURRENT FINDINGS:\n{self.findings.to_text()}\n\n"
            "STOPPING CONDITIONS — only say DONE if ALL are true:\n"
            "  • vol3_consoles has been run (shows typed commands / flags / passwords)\n"
            "  • vol3_filescan has been run (find hidden documents)\n"
            "  • Last 2 tools added zero new findings, OR all tools exhausted\n\n"
            f"MANDATORY TOOLS NOT YET RUN: {', '.join(mandatory_not_run) or 'all done'}\n\n"
            "Pick the NEXT tool. Prioritise mandatory tools first.\n"
            "Respond with ONLY a JSON object:\n"
            '{"reasoning": "<why this tool is needed based on findings>",'
            ' "next_tool": "<tool_id or DONE>",'
            ' "args": {"pid": "1234"}}'
        )
        try:
            resp = await self.llm.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT + "\nRespond with valid JSON only."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1, max_tokens=250,
            )
            text = (resp.choices[0].message.content or "").strip()
            if "{" in text:
                data = json.loads(text[text.find("{"):text.rfind("}") + 1])
                choice = data.get("next_tool", "DONE")
                self._next_tool_args = data.get("args", {})
                logger.info(f"ReAct reasoning: {data.get('reasoning', '?')[:120]} → {choice} with args {self._next_tool_args}")

                # Override DONE if mandatory tools haven't run
                if choice == "DONE" and mandatory_not_run:
                    choice = mandatory_not_run[0]
                    logger.info(f"Overriding DONE → mandatory tool {choice}")

                if choice == "DONE":
                    return "DONE"
                if choice in remaining:
                    return choice
            # Fallback: pick first mandatory, then first remaining
            if mandatory_not_run:
                return mandatory_not_run[0]
            return remaining[0] if remaining else None
        except Exception as e:
            logger.error(f"ReAct reasoning failed: {e}")
            if mandatory_not_run:
                return mandatory_not_run[0]
            return remaining[0] if remaining else None

    # ── Act + Observe: run tool, update findings ───────────────────

    async def _execute_and_record(self, tool_id: str, artifact_path: str) -> None:
        self._step += 1
        step_id = str(uuid.uuid4())[:8]
        meta = TOOL_CATALOG.get(tool_id, {"name": tool_id, "category": "unknown"})
        tool_name = meta["name"]
        category = meta["category"]
        start = datetime.utcnow()

        progress = min(90, (self._step / (MAX_REACT_TURNS + 4)) * 90)
        self.sm.set_progress(self.session_id, progress, category)
        await self.ws.send_progress(self.session_id, progress, category)

        logger.info(f"[Step {self._step}] Running {tool_name}")

        # ── execute ──
        tool_result = await self._dispatch_tool(tool_id, meta, artifact_path)
        duration_ms = int((datetime.utcnow() - start).total_seconds() * 1000)
        self._tools_run.append(tool_id)

        raw_output = self._format_raw(tool_result)
        truncated = _truncate(raw_output)

        # ── observe: LLM interprets + updates findings ──
        interpretation = await self._observe(tool_name, truncated, tool_result)
        self._merge_findings(interpretation)

        thought = interpretation.get("thought", f"Ran {tool_name}.")
        action = interpretation.get("action", f"Executed {tool_name}.")
        evidence_items = interpretation.get("evidence", [])
        mitre_techniques = interpretation.get("mitre_techniques", [])
        timeline_events = interpretation.get("timeline_events", [])
        next_reasoning = interpretation.get("next_step_reasoning", "Continue analysis.")

        step = InvestigationStep(
            step_id=step_id, step_number=self._step,
            timestamp=start.isoformat(), phase=category,
            thought=thought, action=action, tool=tool_name,
            tool_category=category,
            input_data={"artifact": os.path.basename(artifact_path), "tool": tool_id},
            output_data={"raw": raw_output[:5000], "success": tool_result.get("success", False)},
            evidence=evidence_items, next_step_reasoning=next_reasoning,
            duration_ms=duration_ms,
            status="completed" if tool_result.get("success") else "failed",
        )
        self.sm.add_step(self.session_id, step)
        await self.ws.send_step(self.session_id, step.to_dict())

        for ev in evidence_items:
            evidence = Evidence(
                evidence_id=str(uuid.uuid4())[:8],
                type=ev.get("type", "unknown"),
                value=str(ev.get("value", ""))[:500],
                confidence=_safe_conf(ev.get("confidence", 0.5)),
                source_step=step_id, source_tool=tool_name,
                context=str(ev.get("context", ""))[:300],
                mitre_techniques=ev.get("mitre_techniques", []),
                threat_score=_safe_conf(ev.get("threat_score", 0.5)),
                timestamp=start.isoformat(),
            )
            self.sm.add_evidence(self.session_id, evidence)
            await self.ws.send_evidence(self.session_id, evidence.to_dict())

        for tech in mitre_techniques:
            tid = tech.get("technique_id", "")
            tactic = tech.get("tactic", "")
            if tid and tactic:
                self.sm.add_mitre_technique(self.session_id, tactic, tid)
                await self.ws.send_mitre_mapping(self.session_id, tech)

        for event in timeline_events:
            self.sm.add_timeline_event(self.session_id, event)
            await self.ws.send_timeline_event(self.session_id, event)

        await asyncio.sleep(0.3)

    # ── Dispatch to real tools ─────────────────────────────────────

    async def _dispatch_tool(self, tool_id: str, meta: Dict, path: str) -> Dict:
        try:
            if tool_id == "file_identify":
                return await real_tools.tool_file_identify(path)
            elif tool_id == "strings_extract":
                return await real_tools.tool_strings(path)
            elif tool_id == "hexdump":
                return await real_tools.tool_hexdump(path)
            elif tool_id == "yara_scan":
                return await real_tools.tool_yara_scan(path)
            elif tool_id.startswith("vol3_"):
                plugin = meta.get("plugin", "windows.pslist")
                args = getattr(self, "_next_tool_args", {})
                self._next_tool_args = {} # reset
                return await real_tools.tool_volatility3(path, plugin, args)
            elif tool_id == "tsk_fls":
                return await real_tools.tool_tsk_fls(path)
            elif tool_id == "tsk_mmls":
                return await real_tools.tool_tsk_mmls(path)
            elif tool_id == "virustotal_hash_lookup":
                args = getattr(self, "_next_tool_args", {})
                self._next_tool_args = {}
                return await real_tools.tool_virustotal_hash_lookup(path, args.get("hash"))
            elif tool_id == "virustotal_ip_lookup":
                args = getattr(self, "_next_tool_args", {})
                self._next_tool_args = {}
                return await real_tools.tool_virustotal_ip_lookup(args.get("ip"))
            elif tool_id == "virustotal_domain_lookup":
                args = getattr(self, "_next_tool_args", {})
                self._next_tool_args = {}
                return await real_tools.tool_virustotal_domain_lookup(args.get("domain"))
            return {"tool": tool_id, "output": "Unknown tool", "success": False}
        except Exception as e:
            logger.exception(f"Tool {tool_id} failed")
            return {"tool": tool_id, "output": "", "error": str(e), "success": False}

    # ── Observe: interpret tool output ─────────────────────────────

    async def _observe(self, tool_name: str, truncated_output: str, result: Dict) -> Dict:
        if self._llm_ok:
            llm_result = await self._llm_observe(tool_name, truncated_output, result)
            if llm_result:
                return llm_result
        return self._local_observe(tool_name, result)

    async def _llm_observe(self, tool_name: str, output: str, result: Dict) -> Optional[Dict]:
        status = "SUCCESS" if result.get("success") else "FAILED"
        prompt = (
            f"OBSERVE — Tool: {tool_name} | Status: {status}\n\n"
            f"RAW OUTPUT:\n{output}\n\n"
            f"CURRENT FINDINGS SO FAR:\n{self.findings.to_text(2000)}\n\n"
            "Your task: analyse the raw output above like a senior forensic analyst.\n\n"
            "EXTRACTION RULES:\n"
            "1. If the tool FAILED say so. If output is empty (e.g. just headers), it means NO evidence was found, NOT that the tool failed.\n"
            "2. Extract ONLY items that appear verbatim in the output above.\n"
            "3. For processes: note PID, name, parent PID, timestamps, and why suspicious.\n"
            "4. For network: note IP, port, protocol, associated process.\n"
            "5. For files: note full path, associated process, any flags/passwords/hashes.\n"
            "6. For console output: extract EVERY typed command and its output verbatim.\n"
            "   Console output often contains CTF flags, passwords, and secret data.\n"
            "7. For hashdump: extract all username:hash pairs. The hash may BE a flag.\n"
            "8. Map findings to MITRE ATT&CK technique IDs where applicable.\n"
            "9. Include actual timestamps from tool output in timeline_events.\n"
            "10. Look for patterns: flag{...}, FLAG{...}, CTF{...}, base64 strings,\n"
            "    passwords, encryption keys, hidden messages in any output.\n\n"
            "Respond with a JSON object:\n"
            "{\n"
            '  "thought": "<your forensic analysis reasoning>",\n'
            '  "action": "<what was done>",\n'
            '  "evidence": [{"type":"process|ip|domain|file|command|registry|malware|network|hash|credential|flag","value":"...","confidence":0.0-1.0,"context":"...","mitre_techniques":[],"threat_score":0.0-1.0}],\n'
            '  "mitre_techniques": [{"tactic":"...","technique_id":"T####","technique_name":"...","confidence":0.0-1.0}],\n'
            '  "timeline_events": [{"timestamp":"...","event":"...","severity":"info|low|medium|high|critical"}],\n'
            '  "suspect_pids": [{"pid":0,"name":"...","reason":"..."}],\n'
            '  "network_iocs": ["ip:port"],\n'
            '  "file_iocs": ["full/path"],\n'
            '  "next_step_reasoning": "<what to investigate next and why>"\n'
            "}\n"
            "Return ONLY valid JSON. Use numeric values for confidence and threat_score."
        )
        try:
            resp = await self.llm.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT + "\nRespond only with valid JSON. Use numeric values for confidence and threat_score."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1, max_tokens=1200,
            )
            text = (resp.choices[0].message.content or "").strip()
            if "{" in text:
                json_str = text[text.find("{"):text.rfind("}") + 1]
                return json.loads(json_str)
        except Exception as e:
            logger.error(f"LLM observe failed ({type(e).__name__}): {str(e)[:200]}")
        return None

    def _local_observe(self, tool_name: str, result: Dict) -> Dict:
        """Fallback: extract evidence without LLM."""
        evidence, mitre, timeline = [], [], []

        if tool_name == "File Identification":
            evidence.append({"type": "file", "value": f"Artifact: {result.get('output', '?')[:200]}",
                             "confidence": 0.95, "context": "file type ID", "mitre_techniques": [], "threat_score": 0.1})

        elif tool_name == "String Extraction":
            cats = result.get("categorized", {})
            for cat, items in cats.items():
                etype = {"ip": "ip", "url": "url", "path_win": "file", "path_unix": "file",
                         "registry": "registry", "suspicious_cmd": "command", "dll_exe": "file",
                         "email": "domain", "encoding": "command"}.get(cat, "ioc")
                for item in items[:5]:
                    evidence.append({"type": etype, "value": item[:200], "confidence": 0.7,
                                     "context": f"strings ({cat})", "mitre_techniques": [], "threat_score": 0.5})

        elif tool_name == "YARA Scan":
            for m in result.get("matches", [])[:10]:
                evidence.append({"type": "malware", "value": f"YARA: {m.get('rule', '?')}",
                                 "confidence": 0.85, "context": f"{len(m.get('strings', []))} hits",
                                 "mitre_techniques": [], "threat_score": 0.8})

        elif "Volatility3" in tool_name:
            output = result.get("output", "")
            if output and result.get("success"):
                lines = output.strip().splitlines()
                if len(lines) > 1:
                    evidence.append({"type": "process", "value": f"{tool_name}: {len(lines)-1} entries",
                                     "confidence": 0.9, "context": lines[1][:200] if len(lines) > 1 else "",
                                     "mitre_techniques": [], "threat_score": 0.3})
                    for line in lines[1:6]:
                        evidence.append({"type": "process", "value": line.strip()[:150], "confidence": 0.9,
                                         "context": f"From {tool_name}", "mitre_techniques": [], "threat_score": 0.3})

        thought = f"Ran {tool_name} to analyse the artifact."
        if not result.get("success"):
            thought = f"{tool_name} failed or unavailable."

        return {"thought": thought, "action": f"Executed {tool_name}.",
                "evidence": evidence, "mitre_techniques": mitre,
                "timeline_events": timeline, "next_step_reasoning": "Continue."}

    # ── Merge LLM observations into the findings block ─────────────

    def _merge_findings(self, interp: Dict):
        for p in interp.get("suspect_pids", []):
            self.findings.add_pid(p.get("pid"), p.get("name", "?"), p.get("reason", ""))
        for n in interp.get("network_iocs", []):
            if isinstance(n, str):
                self.findings.add_network(n)
            elif isinstance(n, dict):
                self.findings.add_network(n.get("value", str(n)))
        for f in interp.get("file_iocs", []):
            if isinstance(f, str):
                self.findings.add_file(f)
        for ev in interp.get("evidence", []):
            if ev.get("type") == "malware" and "YARA" in str(ev.get("value", "")):
                self.findings.add_yara(ev["value"])
        for m in interp.get("mitre_techniques", []):
            self.findings.add_mitre(m.get("tactic", ""), m.get("technique_id", ""),
                                    m.get("technique_name", ""))
        for t in interp.get("timeline_events", []):
            self.findings.add_ts(t.get("timestamp", "?"), t.get("event", "?"))

    # ── Format raw output ──────────────────────────────────────────

    def _format_raw(self, result: Dict) -> str:
        if "output" in result and isinstance(result["output"], str):
            return result["output"][:8000]
        parts = []
        for key in ("output", "total_strings", "categorized", "matches", "error", "stderr"):
            val = result.get(key)
            if not val:
                continue
            if isinstance(val, dict):
                for k, v in val.items():
                    if v:
                        parts.append(f"[{k}] {', '.join(str(x) for x in (v[:10] if isinstance(v, list) else [v]))}")
            elif isinstance(val, list):
                parts.append(json.dumps(val[:10], indent=2))
            else:
                parts.append(str(val))
        return "\n".join(parts) if parts else "No output"

    # ── Phase 3: timeline + summary ────────────────────────────────

    async def _generate_timeline_and_summary(self) -> None:
        session_obj = self.sm.get_session_object(self.session_id)
        if not session_obj:
            return

        findings_text = self.findings.to_text(4000)

        evidence_text = "\n".join(
            f"- [{ev.type}] {ev.value} (conf={_safe_conf(ev.confidence):.0%})"
            for ev in session_obj.evidence[-30:]
        ) or "No evidence."

        summary = (f"Investigation of {session_obj.artifact_name} complete. "
                    f"{len(session_obj.steps)} tools, {len(session_obj.evidence)} evidence items.")
        conclusion = "Review findings and MITRE mappings."
        hypotheses = []
        timeline_events = []

        if self._llm_ok:
            try:
                prompt = (
                    "You are a senior DFIR investigator. Generate the FINAL report.\n\n"
                    f"ARTIFACT: {session_obj.artifact_name} ({session_obj.artifact_type})\n\n"
                    f"FINDINGS BLOCK:\n{findings_text}\n\n"
                    f"EVIDENCE:\n{evidence_text}\n\n"
                    "Produce a JSON object with:\n"
                    '  "summary": "<2-3 sentence executive summary>",\n'
                    '  "conclusion": "<actionable conclusion>",\n'
                    '  "hypotheses": [{"title":"...","confidence":0.0-1.0,"threat_actor":"...","objective":"..."}],\n'
                    '  "incident_timeline": [\n'
                    '    {"timestamp":"...","event":"...","severity":"...","mitre_id":"T####","source_tool":"...","evidence_cited":"..."}\n'
                    "  ]\n"
                    "Sort incident_timeline chronologically. Only cite REAL evidence.\n"
                    "Use numeric confidence values. Return ONLY valid JSON."
                )
                resp = await self.llm.chat.completions.create(
                    model=self._model,
                    messages=[
                        {"role": "system", "content": "Respond only with valid JSON. Use numeric confidence values."},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.2, max_tokens=1200,
                )
                text = (resp.choices[0].message.content or "").strip()
                if "{" in text:
                    data = json.loads(text[text.find("{"):text.rfind("}") + 1])
                    summary = data.get("summary", summary)
                    conclusion = data.get("conclusion", conclusion)
                    hypotheses = data.get("hypotheses", [])
                    timeline_events = data.get("incident_timeline", [])
            except Exception as e:
                logger.error(f"Final analysis LLM failed: {e}")

        if not hypotheses:
            hypotheses = [{"title": "Potential compromise detected", "confidence": 0.5,
                           "threat_actor": "Unknown", "objective": "Further analysis needed."}]

        # Send timeline events
        for evt in timeline_events:
            self.sm.add_timeline_event(self.session_id, evt)
            await self.ws.send_timeline_event(self.session_id, evt)

        self.sm.complete_session(self.session_id, summary, conclusion)
        self.sm.set_progress(self.session_id, 100, "completed")
        await self.ws.send_progress(self.session_id, 100, "completed")
        await self.ws.send_complete(self.session_id, summary, conclusion)

        for hyp in hypotheses:
            self.sm.add_hypothesis(self.session_id, hyp)
            await self.ws.send_hypothesis(self.session_id, hyp)
