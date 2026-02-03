"""
Tool implementations for recon and enumeration.
"""

import subprocess
import os
from dataclasses import dataclass
from typing import Optional, Tuple
import sys


@dataclass
class ToolRun:
    """Result of a single tool execution."""
    name: str
    cmd: str
    out_file: str
    err_file: str
    return_code: int = 0
    elapsed_sec: float = 0.0


def ensure_dir(path: str) -> None:
    """Create directory if it doesn't exist."""
    os.makedirs(path, exist_ok=True)


def run_command(cmd: str, out_file: str, err_file: str, timeout_sec: int = 600) -> Tuple[int, float]:
    """
    Execute a shell command and capture stdout/stderr to files.
    
    Returns: (return_code, elapsed_seconds)
    """
    import time
    start = time.time()
    
    try:
        with open(out_file, 'w') as out_fd, open(err_file, 'w') as err_fd:
            result = subprocess.run(
                cmd,
                shell=True,
                stdout=out_fd,
                stderr=err_fd,
                timeout=timeout_sec,
                text=True
            )
        elapsed = time.time() - start
        return result.returncode, elapsed
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        with open(err_file, 'a') as err_fd:
            err_fd.write(f"\n[TIMEOUT] Command exceeded {timeout_sec} seconds\n")
        return -1, elapsed
    except Exception as e:
        elapsed = time.time() - start
        with open(err_file, 'w') as err_fd:
            err_fd.write(f"[ERROR] {str(e)}\n")
        return -1, elapsed


def nmap_top(host_ip: str, out_dir: str, timeout_sec: int = 600) -> ToolRun:
    """
    Run nmap top 200 ports with service detection.
    nmap -T3 --top-ports 200 -sV -Pn <ip>
    """
    ensure_dir(out_dir)
    out_file = os.path.join(out_dir, "nmap_top.txt")
    err_file = os.path.join(out_dir, "nmap_top.err")
    
    cmd = f"nmap -T3 --top-ports 200 -sV -Pn {host_ip}"
    
    rc, elapsed = run_command(cmd, out_file, err_file, timeout_sec)
    
    return ToolRun(
        name="nmap_top",
        cmd=cmd,
        out_file=out_file,
        err_file=err_file,
        return_code=rc,
        elapsed_sec=elapsed
    )


def http_probe(host_ip: str, out_dir: str, timeout_sec: int = 30) -> ToolRun:
    """
    Probe HTTP and HTTPS endpoints with curl HEAD requests.
    """
    ensure_dir(out_dir)
    out_file = os.path.join(out_dir, "http_probe.txt")
    err_file = os.path.join(out_dir, "http_probe.err")
    
    # Probe both http and https, limit output
    cmd = (
        f"("
        f"echo '=== HTTP Probe ===' && "
        f"curl -m 5 -I http://{host_ip} 2>&1 | head -20 && "
        f"echo '\n=== HTTPS Probe ===' && "
        f"curl -m 5 -I -k https://{host_ip} 2>&1 | head -20"
        f")"
    )
    
    rc, elapsed = run_command(cmd, out_file, err_file, timeout_sec)
    
    return ToolRun(
        name="http_probe",
        cmd=cmd,
        out_file=out_file,
        err_file=err_file,
        return_code=rc,
        elapsed_sec=elapsed
    )


def get_tool_function(tool_name: str):
    """Return the function for a given tool name."""
    tools_map = {
        'nmap_top': nmap_top,
        'http_probe': http_probe,
    }
    return tools_map.get(tool_name)