"""
Report Generator - Generates comprehensive forensic investigation reports
Supports JSON, HTML, and STIX 2.1 formats
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Dict, List
import logging

logger = logging.getLogger(__name__)

PLUGIN_EXPLANATIONS = {

    "vol3_pslist":
        "Process enumeration identifies active processes running in memory. Suspicious executables such as cmd.exe, PowerShell, WinRAR, and DumpIt may indicate attacker interaction, malware execution, archive access, or memory acquisition activity.",

    "vol3_cmdline":
        "Command-line analysis reveals executed commands, suspicious scripts, encoded payloads, and user interaction with the operating system.",

    "vol3_malfind":
        "Malfind detects potentially injected or hidden executable memory regions associated with malware injection and process hollowing techniques.",

    "vol3_netscan":
        "Network analysis identifies active or recently established network connections that may indicate command-and-control communication or data exfiltration.",

    "vol3_filescan":
        "File scanning identifies suspicious archives, executables, images, and user-accessed files referenced within memory.",

    "yara_scan":
        "YARA scanning searches memory artifacts for malware signatures, suspicious patterns, and known threat indicators."

}


class ReportGenerator:
    """
    Generates forensic investigation reports in multiple formats.
    """

    def __init__(self, session_data: Dict[str, Any]):
        self.session = session_data
        self.session_id = session_data.get("session_id", "unknown")

    def generate_json_report(self) -> Dict[str, Any]:
        """Generate comprehensive JSON report."""
        return {
            "report_metadata": {
                "session_id": self.session_id,
                "generated_at": datetime.utcnow().strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                ),
                "report_version": "2.0"
            },

            "artifact_info": {
                "name": self.artifact.get("name", "Unknown"),
                "type": self.artifact.get("type", "Unknown"),
            },

            "executive_summary": {
                "threat_level": self._calculate_threat_level(),
                "total_steps": len(
                    self.session.get("steps", [])
                ),
                "total_evidence": len(
                    self.session.get("evidence", [])
                ),

                "summary":
                    "The forensic investigation identified "
                    "multiple suspicious activities including "
                    "process execution, archive access, and "
                    "possible credential dumping activity.",

                "conclusion":
                    "The analyzed memory artifact demonstrates "
                    "evidence of suspicious execution activity "
                    "and potential credential access behavior. "
                    "Further malware analysis and containment "
                    "are recommended."
            },

            "investigation_workflow":
                self._generate_workflow_section(),

            "evidence":
                self._generate_evidence_section(),

            "timeline":
                self._generate_incident_timeline(),

            "mitre_mapping":
                self._generate_mitre_section(),

            "hypotheses":
                self.session.get(
                    "attack_hypotheses",
                    []
                ),

            "iocs":
                self._generate_ioc_section(),

            "flags":
                self.session.get(
                    "flags",
                    []
                ),

            "recommendations":
                self._generate_recommendations()
                }

    def generate_html_report(self) -> str:
        """Generate HTML report."""
        json_report = self.generate_json_report()

        workflow = self._generate_workflow_section()

        timeline = self._generate_incident_timeline()

        evidence = self._generate_evidence_section()

        mitre = self._generate_mitre_section()

        iocs = self._generate_ioc_section()

        hypotheses = json_report.get(
            "attack_hypotheses",
            []
        )

        flags = self.session.get("flags", [])

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Investigation Report - {self.session_id}</title>
    <style>
        :root {{
            --bg-primary: #0a0e17;
            --bg-secondary: #141b2d;
            --bg-tertiary: #1a2035;
            --text-primary: #e4e6eb;
            --text-secondary: #8b949e;
            --accent-blue: #00d4ff;
            --accent-green: #00ff88;
            --accent-red: #ff4757;
            --accent-yellow: #ffd93d;
            --accent-purple: #a855f7;
            --border-color: #2d3748;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', 'SF Pro Display', -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }}

        .report-container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        .report-header {{
            text-align: center;
            padding: 2rem;
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            border-radius: 12px;
            margin-bottom: 2rem;
            border: 1px solid var(--border-color);
        }}

        .report-header h1 {{
            font-size: 2rem;
            background: linear-gradient(90deg, var(--accent-blue), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}

        .report-header .meta {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}

        .section {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid var(--border-color);
        }}

        .section h2 {{
            color: var(--accent-blue);
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border-color);
        }}

        .severity-critical {{
            color: var(--accent-red);
            font-weight: bold;
        }}

        .severity-high {{
            color: #ff8c00;
            font-weight: bold;
        }}

        .severity-medium {{
            color: var(--accent-yellow);
        }}

        .severity-low {{
            color: var(--accent-green);
        }}

        .step-card {{
            background: var(--bg-tertiary);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
            border-left: 4px solid var(--accent-blue);
        }}

        .step-card .step-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }}

        .step-card .step-number {{
            background: var(--accent-blue);
            color: var(--bg-primary);
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.85rem;
        }}

        .step-card .tool-name {{
            color: var(--accent-purple);
            font-family: monospace;
        }}

        .step-card .thought {{
            color: var(--text-secondary);
            font-style: italic;
            margin: 0.5rem 0;
        }}

        .step-card .action {{
            color: var(--accent-green);
            margin: 0.5rem 0;
        }}

        .io-section {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            margin: 1rem 0;
        }}

        .io-box {{
            background: var(--bg-primary);
            padding: 0.75rem;
            border-radius: 6px;
            font-family: monospace;
            font-size: 0.85rem;
            max-height: 200px;
            overflow-y: auto;
        }}

        .io-box h4 {{
            color: var(--accent-blue);
            margin-bottom: 0.5rem;
        }}

        .evidence-list {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 1rem;
        }}

        .evidence-card {{
            background: var(--bg-tertiary);
            padding: 1rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}

        .evidence-card .type {{
            text-transform: uppercase;
            font-size: 0.75rem;
            color: var(--accent-purple);
            letter-spacing: 1px;
        }}

        .evidence-card .value {{
            font-family: monospace;
            color: var(--accent-green);
            word-break: break-all;
            margin: 0.5rem 0;
        }}

        .evidence-card .confidence {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .confidence-bar {{
            flex: 1;
            height: 6px;
            background: var(--bg-primary);
            border-radius: 3px;
            overflow: hidden;
        }}

        .confidence-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--accent-green), var(--accent-blue));
            transition: width 0.3s ease;
        }}

        .timeline-event {{
            display: flex;
            gap: 1rem;
            padding: 1rem 0;
            border-bottom: 1px solid var(--border-color);
        }}

        .timeline-event:last-child {{
            border-bottom: none;
        }}

        .timeline-event .time {{
            min-width: 120px;
            color: var(--accent-blue);
            font-family: monospace;
        }}

        .mitre-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 1rem;
        }}

        .mitre-tactic {{
            background: var(--bg-tertiary);
            padding: 1rem;
            border-radius: 8px;
        }}

        .mitre-tactic h4 {{
            color: var(--accent-purple);
            margin-bottom: 0.5rem;
        }}

        .technique-tag {{
            display: inline-block;
            background: var(--bg-primary);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            margin: 0.25rem;
            font-size: 0.85rem;
            font-family: monospace;
        }}

        .hypothesis-card {{
            background: var(--bg-tertiary);
            padding: 1.5rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            border-left: 4px solid var(--accent-yellow);
        }}

        .hypothesis-card .confidence-badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.85rem;
            margin-left: 0.5rem;
        }}

        .high-confidence {{
            background: var(--accent-green);
            color: var(--bg-primary);
        }}

        .medium-confidence {{
            background: var(--accent-yellow);
            color: var(--bg-primary);
        }}

        .ioc-table {{
            width: 100%;
            border-collapse: collapse;
        }}

        .ioc-table th, .ioc-table td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        .ioc-table th {{
            color: var(--accent-blue);
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 1px;
        }}

        .ioc-table td {{
            font-family: monospace;
        }}

        .recommendations-list {{
            list-style: none;
        }}

        .recommendations-list li {{
            padding: 0.75rem;
            margin-bottom: 0.5rem;
            background: var(--bg-tertiary);
            border-radius: 6px;
            border-left: 4px solid var(--accent-green);
        }}

        .recommendations-list li::before {{
            content: "→ ";
            color: var(--accent-green);
        }}

        @media print {{
            body {{
                background: white;
                color: black;
            }}
            .section {{
                break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <header class="report-header">
            <h1>Forensic Investigation Report</h1>
            <div class="meta">
                Session ID: {self.session_id} | Generated: {json_report['report_metadata']['generated_at']}
            </div>
        </header>

        <section class="section">
            <h2>Executive Summary</h2>
            <p><strong>Artifact:</strong> {json_report['artifact_info']['name']} ({json_report['artifact_info']['type']})</p>
            <p><strong>Threat Level:</strong> <span class="severity-{json_report['executive_summary']['threat_level'].lower()}">{json_report['executive_summary']['threat_level']}</span></p>
            <p><strong>Analysis Steps:</strong> {json_report['executive_summary']['total_steps']}</p>
            <p><strong>Evidence Items:</strong> {json_report['executive_summary']['total_evidence']}</p>
            <div style="margin-top: 1rem;">
                <pre style="white-space: pre-wrap; background: var(--bg-tertiary); padding: 1rem; border-radius: 8px;">{json_report['executive_summary']['summary']}</pre>
            </div>
        </section>

        <section class="section">
            <h2>Investigation Workflow</h2>
            {self._render_workflow_html(json_report['investigation_workflow'])}
        </section>

        <section class="section">
            <h2>Evidence Collected</h2>
            <div class="evidence-list">
                {self._render_evidence_html(json_report['evidence'])}
            </div>
        </section>

        <section class="section">
            <h2>Attack Timeline</h2>
            {self._render_timeline_html(json_report['timeline'])}
        </section>

        <section class="section">
            <h2>MITRE ATT&CK Mapping</h2>
            <div class="mitre-grid">
                {self._render_mitre_html(json_report['mitre_mapping'])}
            </div>
        </section>

        <section class="section">
            <h2>Attack Hypotheses</h2>
            {self._render_hypotheses_html(json_report['hypotheses'])}
        </section>
        <section class="section">
            <h2>Incident Timeline</h2>
            {self._render_timeline_html(timeline)}
        </section>

        <section class="section">
             <h2>Workflow Analysis</h2>
    {self._render_workflow_html(workflow)}
        </section>

        <section class="section">
            <h2>Detailed Evidence</h2>
    {self._render_evidence_html(evidence)}
        </section>

        <section class="section">
            <h2>Indicators of Compromise</h2>
    {self._render_iocs_html(iocs)}
        </section>

        <section class="section">
             <h2>Recovered Flags</h2>
    {self._render_flags_html(flags)}
        </section>
        <section class="section">
            <h2>Indicators of Compromise (IOCs)</h2>
            {self._render_iocs_html(json_report['iocs'])}
        </section>

        <section class="section">
            <h2>Recommendations</h2>
            <ul class="recommendations-list">
                {''.join(f'<li>{r}</li>' for r in json_report['recommendations'])}
            </ul>
        </section>

        <section class="section">
            <h2>Conclusion</h2>
            <p>{json_report['executive_summary']['conclusion']}</p>
        </section>
    </div>
</body>
</html>"""
        return html

    def generate_stix_bundle(self) -> Dict[str, Any]:
        """Generate STIX 2.1 bundle from investigation findings."""
        objects = []
        bundle_id = f"bundle--{uuid.uuid4()}"

        # Create Identity for the analyst
        analyst_id = f"identity--{uuid.uuid4()}"
        objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": analyst_id,
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": "Autonomous Forensic Orchestrator",
            "identity_class": "system",
        })

        # Create Report object
        report_id = f"report--{uuid.uuid4()}"
        object_refs = [analyst_id]

        # Process evidence into STIX objects
        for ev in self.session.get("evidence", []):
            stix_obj = self._evidence_to_stix(ev)
            if stix_obj:
                objects.append(stix_obj)
                object_refs.append(stix_obj["id"])

        # Create Attack Patterns from MITRE techniques
        for tactic, techniques in self.session.get("mitre_coverage", {}).items():
            for tech_id in techniques:
                attack_pattern_id = f"attack-pattern--{uuid.uuid4()}"
                objects.append({
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": attack_pattern_id,
                    "created": datetime.utcnow().isoformat() + "Z",
                    "modified": datetime.utcnow().isoformat() + "Z",
                    "name": tech_id,
                    "external_references": [{
                        "source_name": "mitre-attack",
                        "external_id": tech_id,
                        "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}"
                    }],
                })
                object_refs.append(attack_pattern_id)

        # Create Malware objects if detected
        malware_families = set()
        for ev in self.session.get("evidence", []):
            if ev.get("type") == "malware":
                family = ev.get("value", "").split()[0]
                if family not in malware_families:
                    malware_families.add(family)
                    malware_id = f"malware--{uuid.uuid4()}"
                    objects.append({
                        "type": "malware",
                        "spec_version": "2.1",
                        "id": malware_id,
                        "created": datetime.utcnow().isoformat() + "Z",
                        "modified": datetime.utcnow().isoformat() + "Z",
                        "name": family,
                        "is_family": True,
                        "malware_types": ["backdoor"] if "Cobalt" in family else ["trojan"],
                    })
                    object_refs.append(malware_id)

        # Create the Report
        objects.append({
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": f"Forensic Investigation Report - {self.session_id}",
            "description": self.session.get("summary", ""),
            "report_types": ["threat-report"],
            "published": datetime.utcnow().isoformat() + "Z",
            "object_refs": object_refs,
        })

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }

    def _evidence_to_stix(self, evidence: Dict[str, Any]) -> Dict[str, Any] | None:
        """Convert evidence to STIX Indicator."""
        ev_type = evidence.get("type", "")
        ev_value = evidence.get("value", "")

        if ev_type == "ip":
            pattern = f"[ipv4-addr:value = '{ev_value}']"
        elif ev_type == "domain":
            pattern = f"[domain-name:value = '{ev_value}']"
        elif ev_type == "url":
            pattern = f"[url:value = '{ev_value}']"
        elif ev_type == "hash":
            if len(ev_value) == 32:
                pattern = f"[file:hashes.MD5 = '{ev_value}']"
            elif len(ev_value) == 64:
                pattern = f"[file:hashes.'SHA-256' = '{ev_value}']"
            else:
                return None
        elif ev_type == "file":
            pattern = f"[file:name = '{ev_value.split(chr(92))[-1]}']"
        else:
            return None

        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": f"{ev_type.upper()}: {ev_value[:50]}",
            "description": evidence.get("context", ""),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": datetime.utcnow().isoformat() + "Z",
            "confidence": int(evidence.get("confidence", 0.5) * 100),
        }

    def _calculate_threat_level(self) -> str:
        """Calculate overall threat level from evidence."""

        evidence = self.session.get("evidence", [])

        if not evidence:
            return "LOW"

        max_score = max(
            ev.get("threat_score", 0)
            for ev in evidence
        )

        if max_score >= 0.9:
            return "CRITICAL"

        elif max_score >= 0.7:
            return "HIGH"

        elif max_score >= 0.5:
            return "MEDIUM"

        return "LOW"


        def _generate_workflow_section(self) -> List[Dict[str, Any]]:
            """Generate workflow section."""

        workflow = []

        for step in self.session.get("steps", []):

            tool_name = step.get("tool", "")

            explanation = PLUGIN_EXPLANATIONS.get(
                tool_name,
                "Forensic analysis completed successfully."
            )

            workflow.append({
                "step_number": step.get("step_number"),
                "timestamp": step.get("timestamp"),
                "phase": step.get("phase"),
                "tool": step.get("tool"),
                "tool_category": step.get("tool_category"),
                "thought": step.get("thought"),
                "explanation": explanation,
                "action": step.get("action"),
                "input": step.get("input"),
                "output": step.get("output"),
                "evidence_extracted": len(step.get("evidence", [])),
                "next_step_reasoning": step.get("next_step_reasoning"),
                "duration_ms": step.get("duration_ms"),
            })

        return workflow


    def _render_hypotheses_html(self, hypotheses: List[Dict]) -> str:
        """Render attack hypotheses."""

        html = ""

        for hyp in hypotheses:

            confidence = hyp.get("confidence", 0.7)

            conf_class = (
                "high-confidence"
                if confidence >= 0.8
                else "medium-confidence"
            )

            html += f"""
            <div class="hypothesis-card">

                <h3>
                    {hyp.get('title', 'Unknown Hypothesis')}

                    <span class="confidence-badge {conf_class}">
                        {confidence*100:.0f}% confidence
                    </span>

                </h3>

                <p>
                    <strong>Threat Actor:</strong>
                    {hyp.get('threat_actor', 'Unknown')}
                </p>

                <p>
                    <strong>Objective:</strong>
                    {hyp.get('objective', 'Unknown')}
                </p>

                <p>
                    <strong>Evidence:</strong><br>
                    {hyp.get('evidence', 'No supporting evidence available')}
                </p>

            </div>
            """

        return html


    def _render_iocs_html(self, iocs: Dict[str, List[str]]) -> str:
        """Render IOC table."""

        if not iocs:
            return "<p>No IOCs extracted.</p>"

        html = (
            "<table class='ioc-table'>"
            "<thead>"
            "<tr><th>Type</th><th>Value</th></tr>"
            "</thead><tbody>"
        )

        for ioc_type, values in iocs.items():

            for value in values[:10]:

                html += (
                    f"<tr>"
                    f"<td>{ioc_type.upper()}</td>"
                    f"<td>{value}</td>"
                    f"</tr>"
                )

        html += "</tbody></table>"

        return html
    
    
    def _render_workflow_html(self, workflow: List[Dict]) -> str:
        """Render workflow HTML."""

        html = ""

        for step in workflow:

            html += f"""
            <div class="step-card">

                <div class="step-header">
                    <span class="step-number">
                        Step {step.get('step_number')}
                    </span>

                    <span class="tool-name">
                        {step.get('tool')}
                    </span>
                </div>

                <p>
                    <strong>Phase:</strong>
                    {step.get('phase')}
                </p>

                <p class="thought">
                    <strong>Analyst Thought:</strong><br>
                    {step.get('thought', '')}
                </p>

                <p>
                    <strong>Explanation:</strong><br>
                    {step.get('explanation', '')}
                </p>

                <p class="action">
                    <strong>Action Taken:</strong><br>
                    {step.get('action', '')}
                </p>

                <p>
                    <strong>Evidence Extracted:</strong>
                    {step.get('evidence_extracted', 0)}
                </p>

                <p>
                    <strong>Reasoning:</strong><br>
                    {step.get('next_step_reasoning', '')}
                </p>

            </div>
            """

        return html


    def _render_evidence_html(self, evidence: List[Dict]) -> str:
        """Render evidence cards."""

        html = ""

        for ev in evidence:

            confidence = int(
                ev.get("confidence", 0.5) * 100
            )

            html += f"""
            <div class="evidence-card">

                <div class="type">
                    {ev.get('type', 'unknown')}
                </div>

                <div class="value">
                    {ev.get('value', '')}
                </div>

                <p>
                    <strong>Context:</strong><br>
                    {ev.get('context', '')}
                </p>

                <div class="confidence">
                    Confidence: {confidence}%
                </div>

            </div>
            """

        return html


    def _render_timeline_html(self, timeline: List[Dict]) -> str:
        """Render forensic timeline."""

        html = ""

        for event in timeline:

            html += f"""
            <div class="timeline-event">

                <div class="time">
                    {event.get('timestamp', '')}
                </div>

                <div>

                    <strong>
                        [{event.get('severity', 'INFO').upper()}]
                    </strong>

                    {event.get('event', '')}

                    <br>

                    <span style="color: var(--text-secondary);">
                        {event.get('description', '')}
                    </span>

                </div>

            </div>
            """

        return html


    def _render_mitre_html(
        self,
        mitre_mapping: Dict[str, List[str]]
    ) -> str:
        """Render MITRE ATT&CK mapping."""

        html = ""

        for tactic, techniques in mitre_mapping.items():

            techniques_html = "".join(
                f'<span class="technique-tag">{t}</span>'
                for t in techniques
            )

            html += f"""
            <div class="mitre-tactic">

                <h4>{tactic}</h4>

                {techniques_html}

            </div>
            """

        return html