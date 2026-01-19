# Code Agent Scan

Security audit tooling for Codex/Claude skills. It combines LLM-based script review (local, no upload) with VirusTotal domain reputation checks. The LLM audit focuses on high/medium risk signals and flags suspicious encryption/obfuscation for manual review.

## Project Layout

- `SKILL.md`: skill entry point and workflow
- `config.json`: VT API key config
- `scripts/scan_all.py`: one-click scan (LLM input + VT scan + reports)
- `scripts/vt_domain_scan.py`: VT-only domain scan
- `scripts/vt_utils.py`: shared helpers (domain extraction, cache, VT API)
- `references/llm_scan_prompt.md`: LLM audit prompt
- `references/virustotal_api.md`: VT API notes

## Requirements

- Python 3.8+
- VirusTotal API key

## Configure VT API Key

Option A: config file (recommended)

```
config.json
{
  "VT_API_KEY": "your_key"
}
```

Option B: environment variable

```
VT_API_KEY=your_key
```

## Quick Start (One-Click)

Run from the project root:

```bash
python scripts/scan_all.py
```

Common flags:

```bash
python scripts/scan_all.py --skills-root /path/to/skills --include-bare-domains --max-domains 50 --sleep 0.5
```

## Outputs

Reports are written to the OS user data directory under `codex-risk/reports`.

- `summary.txt`: high-level summary
- `detail.txt`: full VT results
- `llm_input.txt`: file contents for LLM audit
- `llm_report.txt`: write LLM findings (high/medium only)

## LLM Audit Workflow

1. Open `llm_input.txt` and use `references/llm_scan_prompt.md`.
2. Record findings in `llm_report.txt`.
3. Flag any complex encryption/obfuscation for manual review.

## VT Domain Scan Only

```bash
python scripts/vt_domain_scan.py --skills-root /path/to/skills
```

Options:

- `--include-bare-domains`: detect domains without http(s):// or www (more false positives)
- `--max-domains N`: limit scan size
- `--sleep 0.5`: delay between requests
- `--cache-ttl-days 7`: cache TTL in days

## Cache

VT responses are cached at:

- Windows: `%LOCALAPPDATA%\codex-risk\vt_cache.json`
- macOS: `~/Library/Application Support/codex-risk/vt_cache.json`
- Linux: `~/.local/share/codex-risk/vt_cache.json`

## Install As Codex Skill

Copy this folder to:

- `C:\Users\<User>\.codex\skills\code-agent-scan`

