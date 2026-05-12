"""
Real Forensic Tools - Actually runs strings, file, volatility3, yara on artifacts.
Falls back gracefully if a tool is not installed.
"""
import asyncio
import subprocess
import os
import re
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


async def run_cmd(cmd: List[str], timeout: int = 120) -> Dict[str, Any]:
    """Run a shell command asynchronously and return stdout/stderr."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {
            "returncode": proc.returncode,
            "stdout": stdout.decode(errors="replace"),
            "stderr": stderr.decode(errors="replace"),
        }
    except asyncio.TimeoutError:
        proc.kill()
        return {"returncode": -1, "stdout": "", "stderr": f"Command timed out after {timeout}s"}
    except FileNotFoundError:
        return {"returncode": -1, "stdout": "", "stderr": f"Command not found: {cmd[0]}"}
    except Exception as e:
        return {"returncode": -1, "stdout": "", "stderr": str(e)}


def _which(name: str) -> Optional[str]:
    """Check if a command exists."""
    import shutil
    return shutil.which(name)


# ============================================================================
# Tool: file (identify artifact type)
# ============================================================================

async def tool_file_identify(artifact_path: str) -> Dict[str, Any]:
    """Identify file type using the `file` command."""
    result = await run_cmd(["file", "-b", artifact_path])
    file_type = result["stdout"].strip() if result["returncode"] == 0 else "unknown"
    return {
        "tool": "file",
        "description": "File type identification",
        "output": file_type,
        "success": result["returncode"] == 0,
        "raw": result,
    }


# ============================================================================
# Tool: strings (extract readable strings)
# ============================================================================

async def tool_strings(artifact_path: str, min_len: int = 6, max_lines: int = 500) -> Dict[str, Any]:
    """Extract readable strings from the artifact."""
    result = await run_cmd(["strings", f"-n{min_len}", artifact_path], timeout=180)
    if result["returncode"] != 0:
        return {"tool": "strings", "output": "", "success": False, "raw": result}

    lines = result["stdout"].splitlines()
    total = len(lines)
    # Filter interesting strings
    interesting = []
    patterns = {
        "ip": re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
        "url": re.compile(r'https?://[^\s"\'<>]+', re.I),
        "email": re.compile(r'[\w.+-]+@[\w-]+\.[\w.]+'),
        "path_win": re.compile(r'[A-Z]:\\[\w\\. -]+', re.I),
        "path_unix": re.compile(r'/(?:usr|etc|bin|tmp|home|var|opt)/[\w/.-]+'),
        "registry": re.compile(r'HKEY_[\w\\]+', re.I),
        "suspicious_cmd": re.compile(r'(?:powershell|cmd\.exe|wget|curl|chmod|nc |ncat|bash -c)', re.I),
        "encoding": re.compile(r'(?:base64|FromBase64|Convert\.)', re.I),
        "dll_exe": re.compile(r'[\w-]+\.(?:dll|exe|sys|bat|ps1|vbs|scr)\b', re.I),
    }
    categorized: Dict[str, List[str]] = {k: [] for k in patterns}

    for line in lines:
        line = line.strip()
        if len(line) < min_len:
            continue
        for cat, pat in patterns.items():
            if pat.search(line):
                if line not in categorized[cat]:
                    categorized[cat].append(line)

    # Also grab some raw sample lines
    sample = lines[:max_lines]

    return {
        "tool": "strings",
        "description": "Readable string extraction",
        "total_strings": total,
        "categorized": {k: v[:50] for k, v in categorized.items() if v},
        "sample": sample[:100],
        "success": True,
    }


# ============================================================================
# Tool: volatility3 (memory forensics)
# ============================================================================

def _find_vol3() -> Optional[str]:
    """Find volatility3 executable."""
    # First check relative to this file's path (cai_env/bin/vol)
    local_bin = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "cai_env", "bin", "vol")
    if os.path.exists(local_bin):
        return local_bin

    # Check common names
    for name in ["vol", "vol3", "volatility3"]:
        path = _which(name)
        if path:
            return path
    return None


async def tool_volatility3(artifact_path: str, plugin: str, args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Run a volatility3 plugin on a memory dump."""
    vol3 = _find_vol3()
    if not vol3:
        return {
            "tool": f"volatility3.{plugin}",
            "output": "",
            "success": False,
            "error": "volatility3 not installed. Install with: pip install volatility3",
        }

    # Dumpfiles MUST have a PID or virtaddr, otherwise it dumps thousands of files and crashes.
    if plugin == "windows.dumpfiles" and not args:
        return {
            "tool": f"volatility3.{plugin}",
            "output": "ERROR: dumpfiles requires an argument like --pid or --virtaddr to avoid extracting the entire filesystem.",
            "success": False,
        }

    cmd = [vol3, "-f", artifact_path, "-r", "csv", plugin]
    if args:
        for k, v in args.items():
            if v:
                cmd.extend([f"--{k}", str(v)])

    result = await run_cmd(cmd, timeout=600)
    return {
        "tool": f"volatility3.{plugin}",
        "description": f"Volatility3 {plugin}",
        "output": result["stdout"][:10000],
        "stderr": result["stderr"][:2000] if result["returncode"] != 0 else "",
        "success": result["returncode"] == 0,
    }


# ============================================================================
# Tool: xxd (hex dump header)
# ============================================================================

async def tool_hexdump(artifact_path: str, length: int = 512) -> Dict[str, Any]:
    """Get hex dump of file header."""
    result = await run_cmd(["xxd", "-l", str(length), artifact_path])
    return {
        "tool": "xxd",
        "description": "Hex dump of file header",
        "output": result["stdout"][:3000],
        "success": result["returncode"] == 0,
    }


# ============================================================================
# Tool: yara (pattern matching)
# ============================================================================

BUILTIN_YARA_RULES = """
rule Suspicious_Strings {
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "-enc " nocase
        $ps3 = "Invoke-Expression" nocase
        $cmd1 = "cmd.exe /c" nocase
        $wmi = "wmic" nocase
        $net1 = "net user" nocase
        $net2 = "net localgroup" nocase
        $reg1 = "reg add" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "URLDownloadToFile" nocase
        $dl4 = "wget" nocase
        $dl5 = "curl" nocase
        $cred1 = "mimikatz" nocase
        $cred2 = "lsass" nocase
        $cred3 = "sekurlsa" nocase
        $shell1 = "/bin/sh" nocase
        $shell2 = "/bin/bash" nocase
        $b64 = "base64" nocase
        $nc = "ncat " nocase
    condition:
        any of them
}

rule PE_Header {
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}

rule ELF_Header {
    strings:
        $elf = { 7F 45 4C 46 }
    condition:
        $elf at 0
}

rule Crypto_Indicators {
    strings:
        $ransom1 = "encrypt" nocase
        $ransom2 = "decrypt" nocase
        $ransom3 = "bitcoin" nocase
        $ransom4 = ".onion" nocase
        $ransom5 = "AES" nocase
        $ransom6 = "RSA" nocase
    condition:
        3 of them
}
"""


async def tool_yara_scan(artifact_path: str) -> Dict[str, Any]:
    """Run built-in YARA rules against artifact."""
    # Try python yara module first
    try:
        import yara
        rules = yara.compile(source=BUILTIN_YARA_RULES)
        matches = rules.match(artifact_path, timeout=120)
        match_data = []
        for m in matches:
            match_strings = []
            for s in m.strings:
                for instance in s.instances:
                    match_strings.append({
                        "offset": instance.offset,
                        "identifier": s.identifier,
                        "data": instance.matched_data.decode(errors="replace")[:100],
                    })
            match_data.append({
                "rule": m.rule,
                "tags": list(m.tags),
                "strings": match_strings[:20],
            })
        return {
            "tool": "yara",
            "description": "YARA pattern matching",
            "matches": match_data,
            "total_matches": len(match_data),
            "success": True,
        }
    except ImportError:
        pass

    # Fallback: try yara CLI
    import tempfile
    rule_file = tempfile.NamedTemporaryFile(mode="w", suffix=".yar", delete=False)
    rule_file.write(BUILTIN_YARA_RULES)
    rule_file.close()
    try:
        result = await run_cmd(["yara", "-s", rule_file.name, artifact_path], timeout=120)
        return {
            "tool": "yara",
            "description": "YARA pattern matching",
            "output": result["stdout"][:5000],
            "success": result["returncode"] == 0,
        }
    finally:
        os.unlink(rule_file.name)


# ============================================================================
# Tool: Sleuth Kit (disk / partition forensics)
# ============================================================================

async def tool_tsk_fls(artifact_path: str, inode: str = "", offset: int = 0) -> Dict[str, Any]:
    """List files and directories using TSK fls."""
    cmd = ["fls", "-r", "-p"]
    if offset:
        cmd += ["-o", str(offset)]
    cmd.append(artifact_path)
    if inode:
        cmd.append(inode)
    result = await run_cmd(cmd, timeout=300)
    return {
        "tool": "tsk_fls",
        "description": "Sleuth Kit file listing (recursive)",
        "output": result["stdout"][:15000],
        "stderr": result["stderr"][:2000] if result["returncode"] != 0 else "",
        "success": result["returncode"] == 0,
    }


async def tool_tsk_icat(artifact_path: str, inode: str, offset: int = 0) -> Dict[str, Any]:
    """Extract a file by inode using TSK icat (returns first 8KB as hex)."""
    cmd = ["icat"]
    if offset:
        cmd += ["-o", str(offset)]
    cmd += [artifact_path, inode]
    result = await run_cmd(cmd, timeout=120)
    raw = result["stdout"]
    # Show printable + hex summary (binary file)
    printable = "".join(c if c.isprintable() or c in "\n\r\t" else "." for c in raw[:4000])
    return {
        "tool": "tsk_icat",
        "description": f"Sleuth Kit file extraction (inode {inode})",
        "output": printable,
        "size_bytes": len(raw),
        "success": result["returncode"] == 0,
    }


async def tool_tsk_mmls(artifact_path: str) -> Dict[str, Any]:
    """List partitions using TSK mmls."""
    result = await run_cmd(["mmls", artifact_path], timeout=60)
    return {
        "tool": "tsk_mmls",
        "description": "Sleuth Kit partition listing",
        "output": result["stdout"][:5000],
        "stderr": result["stderr"][:2000] if result["returncode"] != 0 else "",
        "success": result["returncode"] == 0,
    }


# ============================================================================
# Master: get available tools
# ============================================================================

def get_available_tools() -> List[Dict[str, str]]:
    """Return list of available tools on this system."""
    tools = []
    checks = [
        ("file", "file", "File type identification"),
        ("strings", "strings", "Readable string extraction"),
        ("xxd", "xxd", "Hex dump analysis"),
        ("tsk_fls", "fls", "Sleuth Kit – recursive file listing"),
        ("tsk_mmls", "mmls", "Sleuth Kit – partition map"),
        ("tsk_icat", "icat", "Sleuth Kit – file extraction by inode"),
    ]
    for tool_id, cmd, desc in checks:
        if _which(cmd):
            tools.append({"id": tool_id, "name": cmd, "description": desc, "available": True})
        else:
            tools.append({"id": tool_id, "name": cmd, "description": desc, "available": False})

    # Volatility3
    vol3 = _find_vol3()
    tools.append({
        "id": "volatility3",
        "name": "volatility3",
        "description": "Memory forensics framework",
        "available": vol3 is not None,
        "note": "" if vol3 else "Install with: pip install volatility3",
    })

    # YARA
    yara_available = False
    try:
        import yara  # noqa: F401
        yara_available = True
    except ImportError:
        if _which("yara"):
            yara_available = True
    tools.append({
        "id": "yara",
        "name": "yara",
        "description": "YARA pattern matching for malware identification",
        "available": yara_available,
    })

    return tools
