# MAP.Py - Scope-Aware Recon + Enumeration Orchestrator
**Scope in. Map out.**

MapPy (MAP.PY) is a recon + enumeration orchestrator designed for repeatable, scoped engagements. It wraps common CLI tools into a consistent workflow, captures evidence, normalizes outputs, and generates report-ready notes—so you spend less time copy-pasting and more time thinking.

## Features

- **IP-First Targeting**: Define targets by IP address with OS detection hints
- **Evidence-First Approach**: All tool outputs captured and organized per-target
- **Automated Checklists**: Generate Windows/Linux privilege escalation enumeration checklists per target
- **Clean Output Structure**: Organized folder hierarchy with per-IP reports and tool outputs
- **No Auto-Exploitation**: Pure enumeration and evidence capture; no exploit binaries or automated attacks

## Installation

### Prerequisites
- Python 3.7+
- Kali Linux (or compatible Linux distribution)
- Common CLI tools: `nmap`, `curl`

### From Source

```bash
git clone https://github.com/trace-rich413/MAP.Py.git
cd MAP.Py
pip install -r requirements.txt
pip install -e .
```

This installs the `mappy` command globally.

## Quick Start

### 1. Create a Scope File

Create `scopes/my-engagement.yaml`:

```yaml
project: my-project
targets:
  - ip: 10.10.10.10
    os: windows
    hostname: ""
    notes: "Target SME workstation"
  - ip: 10.10.10.20
    os: linux
    hostname: "web-server"
    notes: "Internal web application"

options:
  output_root: outputs
  timeout_sec: 600

tools:
  - name: nmap_top
    enabled: true
  - name: http_probe
    enabled: true
  - name: privesc_checklist
    enabled: true
```

### 2. Run MAP.Py

```bash
mappy scopes/my-engagement.yaml
```

### 3. Review Results

```
outputs/my-project/
├── 10.10.10.10/
│   ├── recon/
│   │   ├── nmap_top/
│   │   │   ├── nmap_top.txt      (command output)
│   │   │   └── nmap_top.err      (stderr if any)
│   │   └── http_probe/
│   │       ├── http_probe.txt
│   │       └── http_probe.err
│   ├── host/
│   │   ├── windows_checklist.md  (privilege escalation enumeration checklist)
│   │   └── loot/                 (reserved for collected evidence)
│   └── report.md                 (per-target summary)
├── 10.10.10.20/
│   ├── recon/
│   ├── host/
│   │   ├── linux_checklist.md
│   │   └── loot/
│   └── report.md
└── summary.json                  (project-level summary)
```

## Configuration

### Scope YAML Format

```yaml
project: <string>           # Project name; used in output folder structure
targets:                    # List of target IPs
  - ip: <string>           # Target IP address (required)
    os: <string>           # OS hint: 'windows' | 'linux' | 'unknown' (required)
    hostname: <string>     # Hostname (optional)
    notes: <string>        # Engagement notes (optional)

options:
  output_root: <string>    # Output directory (default: outputs)
  timeout_sec: <int>       # Timeout per tool execution in seconds (default: 600)

tools:
  - name: <string>         # Tool name (required)
    enabled: <bool>        # Enable/disable (default: true)
```

### Available Tools

| Tool | Description |
|------|-------------|
| `nmap_top` | Scan top 200 ports with service detection (`nmap -T3 --top-ports 200 -sV -Pn`) |
| `http_probe` | Probe HTTP/HTTPS endpoints with curl HEAD requests |
| `privesc_checklist` | Generate privilege escalation enumeration checklist based on target OS |

## Output Structure

### Per-Target Directory: `outputs/<project>/<ip>/`

- **recon/** — Tool execution outputs, organized by tool name
  - `<toolname>/<toolname>.txt` — stdout
  - `<toolname>/<toolname>.err` — stderr
- **host/** — Target-specific data and checklists
  - `windows_checklist.md` or `linux_checklist.md` — Privilege escalation enumeration checklist
  - `loot/` — Reserved for collected evidence (populated manually)
- **report.md** — Markdown summary of all tool runs and checklist location

### Project Summary: `outputs/<project>/summary.json`

JSON file with:
- Project metadata
- List of all targets processed
- Per-target folder locations
- Tool execution status and elapsed times

## Privilege Escalation Checklists

The `privesc_checklist` tool generates **enumeration-only** checklists tailored to the target OS:

- **Windows**: `whoami /priv`, `systeminfo`, services, scheduled tasks, registry, credentials, etc.
- **Linux**: `id`, `sudo -l`, `uname -a`, SUID/SGID binaries, capabilities, cron, secrets, etc.

**Important**: Checklists contain command references only. They do NOT:
- Download or execute exploit binaries (PrintSpoofer, GodPotato, etc.)
- Perform automated privilege escalation
- Modify the target system

Use these checklists to systematically enumerate possible privilege escalation vectors, then research and test exploits in your lab environment only.

## Architecture

MAP.Py is organized as a Python package:

```
map_py/
├── __init__.py       # Package metadata
├── config.py         # Scope YAML parsing and data structures
├── tools.py          # Tool implementations (nmap, curl, etc.)
├── checklists.py     # Privilege escalation enumeration checklists
├── runner.py         # Orchestration engine
└── cli.py            # Command-line interface
```

## Development

### Install in Development Mode

```bash
pip install -e .
```

### Run Tests (Future)

```bash
pytest
```

### Code Style

- Python 3.7+ compatible
- Minimal external dependencies (PyYAML only)
- Clear error messages and logging

## Safety & Scope

- **No auto-exploitation**: This tool is purely for recon and enumeration.
- **Evidence-first**: All outputs are captured and preserved for review.
- **Scoped execution**: Only run tools on authorized targets within defined scope.
- **Lab-tested**: Test all tools in your lab environment before live engagements.

## Example Workflow

1. **Define scope** in YAML with target IPs and OS hints
2. **Run MAP.Py** to orchestrate tools and generate checklists
3. **Review outputs** in organized folder structure
4. **Use checklists** to systematically enumerate privilege escalation vectors
5. **Document findings** in per-target report.md
6. **Manual exploitation** (if authorized) using discovered vectors and your own techniques

## Troubleshooting

### Tools not found
Ensure `nmap` and `curl` are installed:
```bash
sudo apt-get install nmap curl
```

### Permission denied
Run with appropriate privileges if tools require elevated access:
```bash
sudo mappy scopes/my-engagement.yaml
```

### Output files empty
Check the `.err` file in the same directory for error messages.

## License

MIT (See LICENSE file)

## Contributing

Contributions welcome! Please ensure:
- No auto-exploitation or exploit binaries
- Evidence-first design
- Clean, documented code
- Tested on Kali Linux

## Disclaimer

MAP.Py is designed for authorized security assessments only. Users are responsible for:
- Obtaining proper authorization before testing any system
- Complying with all applicable laws and regulations
- Testing in lab environments before live engagements
- Understanding and responsibly using enumeration results

Unauthorized access to computer systems is illegal.
