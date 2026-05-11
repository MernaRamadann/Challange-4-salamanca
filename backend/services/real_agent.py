"""
Real Forensic Agent - Actually analyzes artifacts using real tools + LLM orchestration.
Replaces the mock agent with genuine forensic analysis.
"""
from __future__ import annotations

import asyncio
import json
import os
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


# ============================================================================
# Analysis pipeline: ordered tool phases for each artifact type
# ============================================================================

PIPELINES = {
    "memory_dump": [
        {"id": "file_identify", "name": "File Identification", "category": "triage"},
        {"id": "strings_extract", "name": "String Extraction", "category": "triage"},
        {"id": "hexdump", "name": "Hex Dump Header", "category": "triage"},
        {"id": "yara_scan", "name": "YARA Scan", "category": "malware_analysis"},
        {"id": "vol3_pslist", "name": "Volatility3 - Process List", "category": "memory_forensics", "plugin": "windows.pslist"},
        {"id": "vol3_pstree", "name": "Volatility3 - Process Tree", "category": "memory_forensics", "plugin": "windows.pstree"},
        {"id": "vol3_netscan", "name": "Volatility3 - Network Scan", "category": "memory_forensics", "plugin": "windows.netstat"},
        {"id": "vol3_cmdline", "name": "Volatility3 - Command Lines", "category": "memory_forensics", "plugin": "windows.cmdline"},
        {"id": "vol3_malfind", "name": "Volatility3 - Malfind", "category": "memory_forensics", "plugin": "windows.malfind"},
        {"id": "vol3_dlllist", "name": "Volatility3 - DLL List", "category": "memory_forensics", "plugin": "windows.dlllist"},
    ],
    "default": [
        {"id": "file_identify", "name": "File Identification", "category": "triage"},
        {"id": "strings_extract", "name": "String Extraction", "category": "triage"},
        {"id": "hexdump", "name": "Hex Dump Header", "category": "triage"},
        {"id": "yara_scan", "name": "YARA Scan", "category": "malware_analysis"},
    ],
}

# Use memory pipeline for common memory dump types
for t in ("malware_sample", "binary", "unknown", "evtx", "disk_image", "pcap"):
    PIPELINES[t] = PIPELINES["default"]


class RealForensicAgent:
    """Agent that actually runs forensic tools on the uploaded artifact."""

    def __init__(
        self,
        session_id: str,
        session_manager: "SessionManager",
        ws_manager: "WebSocketManager",
    ):
        load_dotenv(override=True)
        self.session_id = session_id
        self.session_manager = session_manager
        self.ws_manager = ws_manager
        self._paused = False
        self._stopped = False
        self._step_counter = 0
        self._all_tool_outputs: List[Dict[str, Any]] = []

        # LLM client
        api_key = os.getenv("DEEPINFRA_API_KEY") or os.getenv("OPENAI_API_KEY", "")
        base_url = os.getenv("OPENAI_BASE_URL", "https://api.deepinfra.com/v1/openai")
        self.openai_client = AsyncOpenAI(api_key=api_key, base_url=base_url)
        self._llm_available = bool(api_key)
        logger.info(f"RealForensicAgent: base_url={base_url}, llm_available={self._llm_available}")

    @classmethod
    def get_available_tools(cls) -> List[Dict[str, Any]]:
        """List tools available on this system."""
        return real_tools.get_available_tools()

    def pause(self): self._paused = True
    def resume(self): self._paused = False
    def stop(self): self._stopped = True

    # ========================================================================
    # Main investigation loop
    # ========================================================================

    async def run_investigation(self) -> None:
        """Run the full autonomous investigation."""
        session = self.session_manager.get_session(self.session_id)
        if not session:
            return

        artifact_path = session["artifact_path"]
        artifact_type = session["artifact_type"]

        if not os.path.exists(artifact_path):
            await self.ws_manager.send_error(self.session_id, f"Artifact not found: {artifact_path}")
            return

        self.session_manager.update_session(self.session_id, status="running")
        pipeline = PIPELINES.get(artifact_type, PIPELINES["default"])

        try:
            for i, tool_config in enumerate(pipeline):
                if self._stopped:
                    break
                while self._paused:
                    await asyncio.sleep(0.5)

                progress = ((i + 1) / len(pipeline)) * 90
                self.session_manager.set_progress(self.session_id, progress, tool_config["category"])
                await self.ws_manager.send_progress(self.session_id, progress, tool_config["category"])

                await self._run_tool(tool_config, artifact_path)
                await asyncio.sleep(0.3)  # small delay for UI streaming

            # Final LLM analysis
            await self._final_analysis()

        except Exception as e:
            logger.exception(f"Investigation error: {e}")
            self.session_manager.update_session(self.session_id, status="failed")
            await self.ws_manager.send_error(self.session_id, str(e))

    # ========================================================================
    # Tool execution
    # ========================================================================

    async def _run_tool(self, tool_config: Dict, artifact_path: str) -> None:
        """Execute one real forensic tool and process results."""
        self._step_counter += 1
        step_id = str(uuid.uuid4())[:8]
        tool_id = tool_config["id"]
        tool_name = tool_config["name"]
        category = tool_config["category"]
        start = datetime.utcnow()

        logger.info(f"[Step {self._step_counter}] Running {tool_name} on {os.path.basename(artifact_path)}")

        # Run the actual tool
        tool_result = await self._execute_real_tool(tool_id, tool_config, artifact_path)
        duration_ms = int((datetime.utcnow() - start).total_seconds() * 1000)

        self._all_tool_outputs.append({"tool": tool_name, "id": tool_id, "result": tool_result})

        # Ask LLM to interpret the results (or use local extraction)
        interpretation = await self._interpret_tool_output(tool_name, tool_result)

        thought = interpretation.get("thought", f"Running {tool_name} to analyze the artifact.")
        action = interpretation.get("action", f"Executed {tool_name}.")
        evidence_items = interpretation.get("evidence", [])
        mitre_techniques = interpretation.get("mitre_techniques", [])
        timeline_events = interpretation.get("timeline_events", [])
        next_reasoning = interpretation.get("next_step_reasoning", "Continue with next tool in pipeline.")

        # Build raw output string for display
        raw_output = self._format_raw_output(tool_result)

        step = InvestigationStep(
            step_id=step_id,
            step_number=self._step_counter,
            timestamp=start.isoformat(),
            phase=category,
            thought=thought,
            action=action,
            tool=tool_name,
            tool_category=category,
            input_data={"artifact": os.path.basename(artifact_path), "tool": tool_id},
            output_data={"raw": raw_output[:5000], "success": tool_result.get("success", False)},
            evidence=evidence_items,
            next_step_reasoning=next_reasoning,
            duration_ms=duration_ms,
            status="completed" if tool_result.get("success") else "failed",
        )

        self.session_manager.add_step(self.session_id, step)
        await self.ws_manager.send_step(self.session_id, step.to_dict())

        # Process evidence
        for ev in evidence_items:
            evidence = Evidence(
                evidence_id=str(uuid.uuid4())[:8],
                type=ev.get("type", "unknown"),
                value=ev.get("value", ""),
                confidence=ev.get("confidence", 0.5),
                source_step=step_id,
                source_tool=tool_name,
                context=ev.get("context", ""),
                mitre_techniques=ev.get("mitre_techniques", []),
                threat_score=ev.get("threat_score", 0.5),
                timestamp=start.isoformat(),
            )
            self.session_manager.add_evidence(self.session_id, evidence)
            await self.ws_manager.send_evidence(self.session_id, evidence.to_dict())

        for tech in mitre_techniques:
            self.session_manager.add_mitre_technique(self.session_id, tech["tactic"], tech["technique_id"])
            await self.ws_manager.send_mitre_mapping(self.session_id, tech)

        for event in timeline_events:
            self.session_manager.add_timeline_event(self.session_id, event)
            await self.ws_manager.send_timeline_event(self.session_id, event)

    async def _execute_real_tool(self, tool_id: str, config: Dict, artifact_path: str) -> Dict:
        """Dispatch to the real tool implementation."""
        try:
            if tool_id == "file_identify":
                return await real_tools.tool_file_identify(artifact_path)
            elif tool_id == "strings_extract":
                return await real_tools.tool_strings(artifact_path)
            elif tool_id == "hexdump":
                return await real_tools.tool_hexdump(artifact_path)
            elif tool_id == "yara_scan":
                return await real_tools.tool_yara_scan(artifact_path)
            elif tool_id.startswith("vol3_"):
                plugin = config.get("plugin", "windows.pslist")
                return await real_tools.tool_volatility3(artifact_path, plugin)
            else:
                return {"tool": tool_id, "output": "Unknown tool", "success": False}
        except Exception as e:
            logger.exception(f"Tool {tool_id} failed")
            return {"tool": tool_id, "output": "", "error": str(e), "success": False}

    def _format_raw_output(self, result: Dict) -> str:
        """Format tool result for display."""
        if "output" in result and isinstance(result["output"], str):
            return result["output"][:5000]
        # For structured results (like strings categorized)
        parts = []
        for key in ("output", "total_strings", "categorized", "matches", "error", "stderr"):
            if key in result and result[key]:
                val = result[key]
                if isinstance(val, dict):
                    for k, v in val.items():
                        if v:
                            parts.append(f"[{k}] {', '.join(str(x) for x in (v[:10] if isinstance(v, list) else [v]))}")
                elif isinstance(val, list):
                    parts.append(json.dumps(val[:10], indent=2))
                else:
                    parts.append(str(val))
        return "\n".join(parts) if parts else "No output"

    # ========================================================================
    # LLM interpretation
    # ========================================================================

    async def _interpret_tool_output(self, tool_name: str, result: Dict) -> Dict:
        """Use LLM to interpret tool output and extract evidence, or fall back to local extraction."""
        # Build a summary of the output
        output_summary = self._format_raw_output(result)[:3000]

        # Try LLM first
        if self._llm_available:
            llm_result = await self._llm_interpret(tool_name, output_summary, result)
            if llm_result:
                return llm_result

        # Local fallback: extract evidence from structured results
        return self._local_interpret(tool_name, result)

    async def _llm_interpret(self, tool_name: str, output_summary: str, result: Dict) -> Optional[Dict]:
        """Ask LLM to interpret the tool output."""
        try:
            model = os.getenv("CAI_MODEL", "deepseek-ai/DeepSeek-V3-0324")
            status_msg = "SUCCESS" if result.get("success") else "FAILED"
            prompt = (
                f"You are a DFIR analyst. Tool '{tool_name}' was executed and its status is {status_msg}.\n\n"
                f"Output/Error details:\n"
                f"{output_summary}\n\n"
                f"If the tool failed or produced no output, do NOT invent evidence. State that the tool failed.\n"
                "Respond with a JSON object containing:\n"
                '- "thought": why this tool was useful (1-2 sentences)\n'
                '- "action": what was done (1 sentence)\n'
                '- "evidence": array of objects with {type, value, confidence, context, mitre_techniques, threat_score}\n'
                '  types: ip, domain, url, hash, process, file, command, registry, malware, network\n'
                '- "mitre_techniques": array of {tactic, technique_id, technique_name, confidence}\n'
                '- "timeline_events": array of {timestamp, event, severity} (severity: info/low/medium/high/critical)\n'
                '- "next_step_reasoning": what to investigate next (1 sentence)\n'
                "Return ONLY valid JSON."
            )
            resp = await self.openai_client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are a DFIR analyst. Respond only with valid JSON."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                max_tokens=800,
            )
            text = (resp.choices[0].message.content or "").strip()
            # Extract JSON from response
            if "{" in text:
                json_str = text[text.find("{"):text.rfind("}") + 1]
                return json.loads(json_str)
        except Exception as e:
            logger.error(f"LLM interpret failed ({type(e).__name__}): {str(e)[:200]}")
        return None

    def _local_interpret(self, tool_name: str, result: Dict) -> Dict:
        """Extract evidence from tool output without LLM."""
        evidence = []
        mitre = []
        timeline = []
        import re

        if tool_name == "File Identification":
            file_type = result.get("output", "unknown")
            evidence.append({
                "type": "file", "value": f"Artifact type: {file_type}",
                "confidence": 0.95, "context": "File type identification",
                "mitre_techniques": [], "threat_score": 0.1,
            })

        elif tool_name == "String Extraction":
            categorized = result.get("categorized", {})
            for cat, items in categorized.items():
                for item in items[:5]:
                    ev_type = {"ip": "ip", "url": "url", "path_win": "file", "path_unix": "file",
                               "registry": "registry", "suspicious_cmd": "command",
                               "dll_exe": "file", "email": "domain", "encoding": "command"}.get(cat, "ioc")
                    score = 0.7 if cat in ("suspicious_cmd", "encoding", "ip") else 0.4
                    evidence.append({
                        "type": ev_type, "value": item[:200],
                        "confidence": 0.7, "context": f"Found via strings ({cat})",
                        "mitre_techniques": [], "threat_score": score,
                    })
            if categorized.get("suspicious_cmd"):
                mitre.append({"tactic": "Execution", "technique_id": "T1059",
                              "technique_name": "Command and Scripting Interpreter", "confidence": 0.7})
            if categorized.get("registry"):
                mitre.append({"tactic": "Persistence", "technique_id": "T1547.001",
                              "technique_name": "Registry Run Keys", "confidence": 0.6})

        elif tool_name == "YARA Scan":
            matches = result.get("matches", [])
            output = result.get("output", "")
            if matches:
                for m in matches[:10]:
                    evidence.append({
                        "type": "malware", "value": f"YARA match: {m.get('rule', 'unknown')}",
                        "confidence": 0.85, "context": f"Matched {len(m.get('strings', []))} strings",
                        "mitre_techniques": [], "threat_score": 0.8,
                    })
            elif output and "Suspicious" in output:
                evidence.append({
                    "type": "malware", "value": "YARA: Suspicious patterns found",
                    "confidence": 0.7, "context": output[:200],
                    "mitre_techniques": [], "threat_score": 0.7,
                })

        elif "Volatility3" in tool_name:
            output = result.get("output", "")
            if output and result.get("success"):
                lines = output.strip().splitlines()
                if len(lines) > 1:
                    evidence.append({
                        "type": "process", "value": f"{tool_name}: {len(lines)-1} entries found",
                        "confidence": 0.9, "context": f"Raw output: {lines[1][:200] if len(lines) > 1 else 'N/A'}",
                        "mitre_techniques": [], "threat_score": 0.3,
                    })
                    # Extract specific data from CSV output
                    for line in lines[1:6]:
                        evidence.append({
                            "type": "process", "value": line.strip()[:150],
                            "confidence": 0.9, "context": f"From {tool_name}",
                            "mitre_techniques": [], "threat_score": 0.3,
                        })
            elif not result.get("success"):
                err = result.get("error") or result.get("stderr", "")
                if "not installed" in str(err).lower():
                    evidence.append({
                        "type": "file", "value": f"{tool_name}: Tool not available",
                        "confidence": 1.0, "context": str(err)[:200],
                        "mitre_techniques": [], "threat_score": 0.0,
                    })

        thought = f"Ran {tool_name} to analyze the forensic artifact."
        if not result.get("success"):
            thought = f"{tool_name} failed or is not available. Continuing with next tool."

        return {
            "thought": thought,
            "action": f"Executed {tool_name} on the uploaded artifact.",
            "evidence": evidence,
            "mitre_techniques": mitre,
            "timeline_events": timeline,
            "next_step_reasoning": "Continue with the next tool in the analysis pipeline.",
        }

    # ========================================================================
    # Final analysis
    # ========================================================================

    async def _final_analysis(self) -> None:
        """Generate final summary and hypotheses."""
        session_obj = self.session_manager.get_session_object(self.session_id)
        if not session_obj:
            return

        # Build evidence summary for LLM
        def _safe_conf(val) -> float:
            try:
                return float(val)
            except (ValueError, TypeError):
                return {"high": 0.8, "medium": 0.5, "low": 0.3}.get(str(val).lower(), 0.5)

        evidence_text = "\n".join(
            f"- [{ev.type}] {ev.value} (confidence={_safe_conf(ev.confidence):.0%})"
            for ev in session_obj.evidence[-20:]
        ) or "No evidence collected."

        steps_text = "\n".join(
            f"- {s.tool}: {s.thought[:120]}"
            for s in session_obj.steps[-10:]
        ) or "No steps executed."

        summary = f"Investigation of {session_obj.artifact_name} completed. {len(session_obj.steps)} tools run, {len(session_obj.evidence)} evidence items found."
        conclusion = "Review collected evidence and MITRE mappings for incident response."
        hypotheses = []

        # Try LLM for better summary
        if self._llm_available:
            try:
                model = os.getenv("CAI_MODEL", "deepseek-ai/DeepSeek-V3-0324")
                prompt = (
                    "You are a senior DFIR investigator. Summarize this investigation.\n\n"
                    f"Artifact: {session_obj.artifact_name} ({session_obj.artifact_type})\n"
                    f"Evidence:\n{evidence_text}\n\nSteps:\n{steps_text}\n\n"
                    "Return JSON with: summary (str), conclusion (str), "
                    "hypotheses (array of {title, confidence, threat_actor, objective})."
                )
                resp = await self.openai_client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": "Respond only with valid JSON."},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.2,
                    max_tokens=600,
                )
                text = (resp.choices[0].message.content or "").strip()
                if "{" in text:
                    data = json.loads(text[text.find("{"):text.rfind("}") + 1])
                    summary = data.get("summary", summary)
                    conclusion = data.get("conclusion", conclusion)
                    hypotheses = data.get("hypotheses", [])
            except Exception as e:
                logger.error(f"Final analysis LLM failed: {e}")

        if not hypotheses:
            hypotheses = [{
                "title": "Potential compromise detected",
                "confidence": 0.5,
                "threat_actor": "Unknown",
                "objective": "Further analysis needed based on collected evidence.",
            }]

        self.session_manager.complete_session(self.session_id, summary, conclusion)
        self.session_manager.set_progress(self.session_id, 100, "completed")
        await self.ws_manager.send_progress(self.session_id, 100, "completed")
        await self.ws_manager.send_complete(self.session_id, summary, conclusion)

        for hyp in hypotheses:
            self.session_manager.add_hypothesis(self.session_id, hyp)
            await self.ws_manager.send_hypothesis(self.session_id, hyp)
