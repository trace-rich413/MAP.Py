"""Main orchestration engine for recon and enumeration workflows."""

import os
import json
import time
from typing import List, Dict, Any
import sys

from map_py.config import Scope, Target
from map_py.tools import ToolRun, get_tool_function
from map_py.checklists import write_checklist

def ensure_dir(path: str) -> None:
    """Create directory if it doesn't exist."""
    os.makedirs(path, exist_ok=True)

def run_target(scope: Scope, target: Target) -> Dict[str, Any]:
    """
    Run all enabled tools for a single target IP.
    Creates folder structure and captures all outputs.
    
    Returns a dict with target metadata, tool results, and file paths.
    """
    # Base directory for this IP: outputs/<project>/<ip>/
    base_dir = os.path.join(scope.options.output_root, scope.project, target.ip)
    recon_dir = os.path.join(base_dir, 'recon')
    host_dir = os.path.join(base_dir, 'host')
    loot_dir = os.path.join(host_dir, 'loot')
    
    ensure_dir(recon_dir)
    ensure_dir(host_dir)
    ensure_dir(loot_dir)
    
    target_result = {
        'ip': target.ip,
        'os': target.os,
        'hostname': target.hostname,
        'notes': target.notes,
        'base_dir': base_dir,
        'tools': [],
        'checklist_path': None,
    }
    
    # Generate privilege escalation checklist if enabled
    checklist_enabled = any(t.name == 'privesc_checklist' and t.enabled for t in scope.tools)
    if checklist_enabled:
        checklist_path = write_checklist(target.os, host_dir)
        target_result['checklist_path'] = checklist_path
        print(f"[{target.ip}] Generated checklist: {checklist_path}")
    
    # Run enabled tools
    for tool_cfg in scope.tools:
        if not tool_cfg.enabled or tool_cfg.name == 'privesc_checklist':
            continue
        
        tool_func = get_tool_function(tool_cfg.name)
        if not tool_func:
            print(f"[{target.ip}] WARNING: Unknown tool '{tool_cfg.name}', skipping", file=sys.stderr)
            continue
        
        tool_dir = os.path.join(recon_dir, tool_cfg.name)
        ensure_dir(tool_dir)
        
        print(f"[{target.ip}] Running {tool_cfg.name}...")
        start_time = time.time()
        
        try:
            tool_run = tool_func(target.ip, tool_dir, scope.options.timeout_sec)
            elapsed = time.time() - start_time
            
            target_result['tools'].append({
                'name': tool_run.name,
                'cmd': tool_run.cmd,
                'return_code': tool_run.return_code,
                'elapsed_sec': tool_run.elapsed_sec,
                'out_file': tool_run.out_file,
                'err_file': tool_run.err_file,
            })
            
            status = "OK" if tool_run.return_code == 0 else f"RC={tool_run.return_code}"
            print(f"  └─ {status} ({tool_run.elapsed_sec:.2f}s)")
        
        except Exception as e:
            print(f"  └─ ERROR: {e}", file=sys.stderr)
            target_result['tools'].append({
                'name': tool_cfg.name,
                'cmd': '',
                'return_code': -1,
                'elapsed_sec': time.time() - start_time,
                'out_file': '',
                'err_file': '',
                'error': str(e),
            })
    
    # Generate per-IP report
    report_path = os.path.join(base_dir, 'report.md')
    generate_report(target, target_result, report_path)
    target_result['report_path'] = report_path
    
    return target_result

def generate_report(target: Target, target_result: Dict[str, Any], report_path: str) -> None:
    """Generate a markdown report for a single target IP."""
    report_lines = [
        f"# Recon Report: {target.ip}",
        "",
        "## Target Information",
        f"- **IP Address**: {target.ip}",
        f"- **OS**: {target.os}",
        f"- **Hostname**: {target.hostname if target.hostname else '(not set)'}",
        f"- **Notes**: {target.notes if target.notes else '(none)'}",
        "",
        "## Recon Tools",
    ]
    
    for tool in target_result['tools']:
        report_lines.append(f"### {tool['name']}")
        report_lines.append(f"- **Command**: `{{tool['cmd']}}`")
        report_lines.append(f"- **Return Code**: {{tool['return_code']}}")
        report_lines.append(f"- **Elapsed Time**: {{tool['elapsed_sec']:.2f}}s")
        
        if tool['out_file']:
            rel_out = os.path.relpath(tool['out_file'], os.path.dirname(report_path))
            report_lines.append(f"- **Output**: [{{rel_out}}]({{rel_out}})")
        
        if tool['err_file']:
            rel_err = os.path.relpath(tool['err_file'], os.path.dirname(report_path))
            report_lines.append(f"- **Errors**: [{{rel_err}}]({{rel_err}})")
        
        if 'error' in tool:
            report_lines.append(f"- **Error**: {{tool['error']}}")
        
        report_lines.append("")
    
    # Link to checklist if present
    if target_result['checklist_path']:
        rel_checklist = os.path.relpath(target_result['checklist_path'], os.path.dirname(report_path))
        report_lines.append("## Privilege Escalation Checklist")
        report_lines.append(f"See: [{{rel_checklist}}]({{rel_checklist}})")
        report_lines.append("")
    
    report_lines.append("---")
    report_lines.append(f"*Report generated automatically by MAP.Py*")
    
    with open(report_path, 'w') as f:
        f.write("\n".join(report_lines))

def run_scope(scope: Scope) -> Dict[str, Any]:
    """
    Execute the full reconnaissance workflow for all targets in scope.
    
    Returns a summary dict with per-IP results and overall metadata.
    """
    print(f"\n{'='*70}")
    print(f"MAP.Py v0.2 - Scope: {scope.project}")
    print(f"{'='*70}\n")
    
    project_summary = {
        'project': scope.project,
        'output_root': scope.options.output_root,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'targets': [],
    }
    
    start_time = time.time()
    
    for target in scope.targets:
        print(f"\n>>> Processing target: {target.ip}")
        target_result = run_target(scope, target)
        project_summary['targets'].append(target_result)
    
    elapsed = time.time() - start_time
    project_summary['elapsed_sec'] = elapsed
    
    # Write project-level summary
    summary_path = os.path.join(scope.options.output_root, scope.project, 'summary.json')
    ensure_dir(os.path.dirname(summary_path))
    with open(summary_path, 'w') as f:
        json.dump(project_summary, f, indent=2)
    
    print(f"\n{'='*70}")
    print(f"Recon complete in {{elapsed:.2f}}s")
    print(f"Output root: {{scope.options.output_root}}")
    print(f"Project summary: {{summary_path}}")
    print(f"{'='*70}\n")
    
    return project_summary
