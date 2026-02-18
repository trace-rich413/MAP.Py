import json
import os
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

try:
    import yaml  # type: ignore
except Exception:
    yaml = None


# -----------------------------
# Helpers
# -----------------------------
def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def run_shell(cmd: str, cwd: str, timeout: int, log_path: str) -> Tuple[int, float]:
    """
    Runs a command through bash -lc to support pipes/loops in rule commands.
    Logs stdout+stderr to log_path.
    """
    start = time.time()
    with open(log_path, "w", encoding="utf-8", errors="ignore") as f:
        p = subprocess.run(
            ["bash", "-lc", cmd],
            cwd=cwd,
            stdout=f,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            text=True,
        )
    return p.returncode, time.time() - start

def write_json(path: str, obj) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)

def load_yaml(path: str) -> dict:
    if not yaml:
        raise RuntimeError("pyyaml not installed. Add it to requirements.txt")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def normalize_service(name: str) -> str:
    return (name or "").strip().lower()

def is_ssl_tunnel(service_elem) -> bool:
    # Nmap sets service tunnel="ssl" for TLS-wrapped services
    return (service_elem.get("tunnel") or "").lower() == "ssl"


# -----------------------------
# Nmap XML parsing
# -----------------------------
@dataclass
class PortService:
    ip: str
    proto: str  # tcp/udp
    port: int
    state: str
    service: str
    product: str
    version: str
    extrainfo: str
    tunnel_ssl: bool

def parse_nmap_xml(xml_path: str, ip: str) -> List[PortService]:
    if not os.path.exists(xml_path):
        return []
    out: List[PortService] = []
    tree = ET.parse(xml_path)
    root = tree.getroot()

    for host in root.findall("host"):
        ports = host.find("ports")
        if ports is None:
            continue
        for p in ports.findall("port"):
            proto = p.get("protocol", "")
            portid = int(p.get("portid", "0"))
            state_elem = p.find("state")
            state = state_elem.get("state", "") if state_elem is not None else ""
            if state != "open":
                continue

            svc = p.find("service")
            service_name = normalize_service(svc.get("name", "") if svc is not None else "")
            product = (svc.get("product", "") if svc is not None else "")
            version = (svc.get("version", "") if svc is not None else "")
            extrainfo = (svc.get("extrainfo", "") if svc is not None else "")
            tunnel_ssl = is_ssl_tunnel(svc) if svc is not None else False

            out.append(
                PortService(
                    ip=ip,
                    proto=proto,
                    port=portid,
                    state=state,
                    service=service_name,
                    product=product,
                    version=version,
                    extrainfo=extrainfo,
                    tunnel_ssl=tunnel_ssl,
                )
            )
    return out

def ports_to_csv(ports: List[int]) -> str:
    return ",".join(str(p) for p in sorted(set(ports)))


# -----------------------------
# Rules engine (service-based pivot)
# -----------------------------
def match_rule(rule: dict, ps: PortService) -> bool:
    m = rule.get("match", {}) or {}
    ports = m.get("ports")
    proto = m.get("proto")
    svc_re = m.get("service_regex")
    prod_re = m.get("product_regex")

    if ports and ps.port not in set(ports):
        return False
    if proto and ps.proto != proto:
        return False
    if svc_re and not re.search(svc_re, ps.service or "", re.I):
        return False
    if prod_re and not re.search(prod_re, ps.product or "", re.I):
        return False
    return True

def render_cmd(cmd: str, ps: PortService) -> str:
    scheme = "https" if (ps.tunnel_ssl or ps.service in {"https", "ssl/http"}) else "http"
    # Some services show as "http" even on TLS; tunnel_ssl handles this.
    return cmd.format(
        ip=ps.ip,
        proto=ps.proto,
        port=ps.port,
        service=ps.service,
        product=ps.product,
        version=ps.version,
        scheme=scheme,
    )


# -----------------------------
# Main tool: scan_2stage
# -----------------------------
def tool_scan_2stage(target_ip: str, out_dir: str, timeout_sec: int = 3600) -> str:
    """
    Stage 1: fast discovery (TCP full, UDP top)
    Stage 2: service detect on discovered ports, then run service-based rules
    Returns a short summary string for MAP.Py report.md.
    """
    ensure_dir(out_dir)
    stage1 = os.path.join(out_dir, "00_discovery")
    stage2 = os.path.join(out_dir, "01_services")
    enumdir = os.path.join(out_dir, "02_enum")
    ensure_dir(stage1)
    ensure_dir(stage2)
    ensure_dir(enumdir)

    summary_lines: List[str] = []
    open_tcp: List[int] = []
    open_udp: List[int] = []

    # -----------------------------
    # Stage 1 TCP discovery
    # -----------------------------
    masscan_path = which("masscan")
    nmap_path = which("nmap")
    if not nmap_path:
        raise RuntimeError("nmap not found in PATH")

    if masscan_path:
        ms_out = os.path.join(stage1, "masscan.gnmap")
        rc, dur = run_shell(
            f"sudo masscan -p1-65535 {target_ip} --rate 5000 -oG {ms_out}",
            cwd=stage1,
            timeout=min(timeout_sec, 1800),
            log_path=os.path.join(stage1, "masscan.log"),
        )
        summary_lines.append(f"- Stage1 TCP: masscan rc={rc} ({dur:.1f}s)")

        # Parse masscan grepable
        if os.path.exists(ms_out):
            txt = open(ms_out, "r", encoding="utf-8", errors="ignore").read()
            for m in re.finditer(r"Ports:\s+(\d+)/open/tcp", txt):
                open_tcp.append(int(m.group(1)))

        # Verify via nmap on found ports (or fallback to full if none)
        if open_tcp:
            ports_csv = ports_to_csv(open_tcp)
            rc2, dur2 = run_shell(
                f"sudo nmap -Pn -n -sS -sV --version-light -p{ports_csv} -oA {os.path.join(stage1,'tcp_verify')} {target_ip}",
                cwd=stage1,
                timeout=min(timeout_sec, 1800),
                log_path=os.path.join(stage1, "nmap_tcp_verify.log"),
            )
            summary_lines.append(f"- Stage1 TCP: nmap verify {len(open_tcp)} ports rc={rc2} ({dur2:.1f}s)")
        else:
            rc2, dur2 = run_shell(
                f"sudo nmap -Pn -n -sS -p- --min-rate 1000 -T4 -oA {os.path.join(stage1,'tcp_full')} {target_ip}",
                cwd=stage1,
                timeout=min(timeout_sec, 3600),
                log_path=os.path.join(stage1, "nmap_tcp_full.log"),
            )
            summary_lines.append(f"- Stage1 TCP: nmap full rc={rc2} ({dur2:.1f}s)")
    else:
        # No masscan: go straight nmap full TCP
        rc, dur = run_shell(
            f"sudo nmap -Pn -n -sS -p- --min-rate 1000 -T4 -oA {os.path.join(stage1,'tcp_full')} {target_ip}",
            cwd=stage1,
            timeout=min(timeout_sec, 3600),
            log_path=os.path.join(stage1, "nmap_tcp_full.log"),
        )
        summary_lines.append(f"- Stage1 TCP: nmap full rc={rc} ({dur:.1f}s)")

    # Collect TCP ports from whichever XML exists
    for candidate in ["tcp_verify.xml", "tcp_full.xml"]:
        xmlp = os.path.join(stage1, candidate)
        for ps in parse_nmap_xml(xmlp, target_ip):
            if ps.proto == "tcp":
                open_tcp.append(ps.port)
    open_tcp = sorted(set(open_tcp))

    # -----------------------------
    # Stage 1 UDP discovery (OSCP-sane default)
    # -----------------------------
    rc, dur = run_shell(
        f"sudo nmap -Pn -n -sU --top-ports 200 --max-retries 1 -T4 -oA {os.path.join(stage1,'udp_top')} {target_ip}",
        cwd=stage1,
        timeout=min(timeout_sec, 3600),
        log_path=os.path.join(stage1, "nmap_udp_top.log"),
    )
    summary_lines.append(f"- Stage1 UDP: top-ports 200 rc={rc} ({dur:.1f}s)")

    for ps in parse_nmap_xml(os.path.join(stage1, "udp_top.xml"), target_ip):
        if ps.proto == "udp":
            open_udp.append(ps.port)
    open_udp = sorted(set(open_udp))

    # Persist discovery
    discovery = {
        "target": target_ip,
        "tcp_open_ports": open_tcp,
        "udp_open_ports": open_udp,
    }
    write_json(os.path.join(out_dir, "open_ports.json"), discovery)

    # -----------------------------
    # Stage 2: Service detection on discovered ports
    # -----------------------------
    services: List[PortService] = []

    if open_tcp:
        rc, dur = run_shell(
            f"sudo nmap -Pn -n -sV -sC -p{ports_to_csv(open_tcp)} -oA {os.path.join(stage2,'tcp_services')} {target_ip}",
            cwd=stage2,
            timeout=min(timeout_sec, 3600),
            log_path=os.path.join(stage2, "nmap_tcp_services.log"),
        )
        summary_lines.append(f"- Stage2 TCP: -sV -sC rc={rc} ({dur:.1f}s)")
        services += parse_nmap_xml(os.path.join(stage2, "tcp_services.xml"), target_ip)

    if open_udp:
        rc, dur = run_shell(
            f"sudo nmap -Pn -n -sU -sV -p{ports_to_csv(open_udp)} -oA {os.path.join(stage2,'udp_services')} {target_ip}",
            cwd=stage2,
            timeout=min(timeout_sec, 3600),
            log_path=os.path.join(stage2, "nmap_udp_services.log"),
        )
        summary_lines.append(f"- Stage2 UDP: -sV rc={rc} ({dur:.1f}s)")
        services += parse_nmap_xml(os.path.join(stage2, "udp_services.xml"), target_ip)

    # Save services
    services_json = [
        {
            "proto": s.proto,
            "port": s.port,
            "service": s.service,
            "product": s.product,
            "version": s.version,
            "extrainfo": s.extrainfo,
            "ssl": s.tunnel_ssl,
        }
        for s in sorted(services, key=lambda x: (x.proto, x.port))
    ]
    write_json(os.path.join(out_dir, "services.json"), services_json)

    # -----------------------------
    # Service-based enumeration via rules
    # -----------------------------
    rules_path = os.path.join(os.path.dirname(__file__), "enum_rules.yml")
    rules = []
    if os.path.exists(rules_path):
        y = load_yaml(rules_path)
        rules = y.get("rules", []) or []

    ran = 0
    for s in services:
        svc_bucket = f"{s.proto}_{s.port}_{s.service or 'unknown'}"
        svc_out = os.path.join(enumdir, svc_bucket)
        ensure_dir(svc_out)

        for rule in rules:
            if match_rule(rule, s):
                for i, cmd in enumerate(rule.get("commands", []) or []):
                    rendered = render_cmd(cmd, s)
                    logp = os.path.join(svc_out, f"{rule.get('name','rule')}_{i:02d}.log")
                    run_shell(rendered, cwd=svc_out, timeout=min(timeout_sec, 1800), log_path=logp)
                    ran += 1

    summary_lines.append(f"- Enum rules executed: {ran}")
    summary_path = os.path.join(out_dir, "summary.md")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("# MAP.Py 2-Stage Scan Summary\n\n")
        f.write("\n".join(summary_lines) + "\n")

    return f"2-stage scan complete. TCP open={len(open_tcp)} UDP open={len(open_udp)} rules={ran}. See summary.md"
