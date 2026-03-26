#!/usr/bin/env python3
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
import subprocess
import tempfile
from typing import Any, Dict

from cai.sdk.agents import function_tool
from cai.sdk.agents.tracing import custom_span, trace
from openai import OpenAI

client = OpenAI()

# -------------------------
# Helper: Extract strings
# -------------------------
def extract_strings(file_path: str) -> str:
    try:
        return subprocess.getoutput(f"strings {file_path}")
    except Exception as e:
        return ""

# -------------------------
# Step 1: Generate YARA rule using AI
# -------------------------
@function_tool
def generate_yara_rule(file_strings: str) -> str:
    """
    Generate YARA rule from file strings using AI
    """
    with trace(workflow_name="yara_rule_generation"):
        with custom_span(name="generate_rule", span_id="span_gen") as span:
            try:
                prompt = f"""
You are a malware analyst.

Generate a valid YARA rule based on these suspicious strings:

{file_strings[:4000]}

Rules:
- Return ONLY the YARA rule
- Use proper syntax
- Include at least 3 strings
- Add condition section
"""

                response = client.chat.completions.create(
                    model="gpt-4.1",
                    messages=[{"role": "user", "content": prompt}]
                )

                rule = response.choices[0].message.content.strip()

                span.span_data.data = {"generated_rule": rule}

                return rule

            except Exception as e:
                span.set_error({"message": "AI generation failed", "data": str(e)})
                return ""

# -------------------------
# Step 2: Run YARA scan
# -------------------------
@function_tool
def run_yara_scan(rule: str, target_file: str) -> Dict[str, Any]:
    """
    Run YARA scan using generated rule
    """
    with trace(workflow_name="yara_scan"):
        with custom_span(name="scan", span_id="span_scan") as span:
            try:
                # Save rule temporarily
                with tempfile.NamedTemporaryFile(delete=False, suffix=".yar") as f:
                    f.write(rule.encode())
                    rule_path = f.name

                # Run YARA
                completed = subprocess.run(
                    ["yara", "-s", rule_path, target_file],
                    capture_output=True,
                    text=True
                )

                output = completed.stdout.strip()

                span.span_data.data = {"scan_output": output}

                return {
                    "rule": rule,
                    "output": output
                }

            except Exception as e:
                span.set_error({"message": "YARA scan failed", "data": str(e)})
                return {"error": str(e)}

# -------------------------
# Step 3: Full AI Pipeline
# -------------------------
@function_tool
def ai_yara_pipeline(target_file: str) -> Dict[str, Any]:
    """
    Full pipeline:
    Extract → Generate rule → Scan
    """
    with trace(workflow_name="ai_yara_pipeline"):
        with custom_span(name="pipeline", span_id="span_pipeline"):

            # 1. Extract strings
            strings_data = extract_strings(target_file)

            # 2. Generate rule
            rule = generate_yara_rule(strings_data)

            if not rule:
                return {"error": "Failed to generate rule"}

            # 3. Run scan
            result = run_yara_scan(rule, target_file)

            return result

# -------------------------
# CLI usage
# -------------------------
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python ai_yara.py <target_file>")
        exit(1)

    target = sys.argv[1]

    result = ai_yara_pipeline(target)

    print("\n=== GENERATED RULE ===")
    print(result.get("rule", ""))

    print("\n=== SCAN RESULT ===")
    print(result.get("output", result))