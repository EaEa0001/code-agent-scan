---
name: code-agent-scan
description: VirusTotal domain reputation checks for external domains found during risk scans or audits (AGENTS.md, Skills, MCP configs, or scripts). Use when you need to enrich a risk report by validating outbound domains or URLs against VT.
---

# Risk Scan Virustotal

## Overview

Check external domains for reputation using VirusTotal and summarize results in a compact, human-readable format. Use this to triage outbound domains found in risk scans or code reviews.

## Workflow

### 1) Prepare input

By default, the script scans installed skills and extracts domains from URLs in `SKILL.md` and `scripts/` files. It recognizes `https://`, `http://`, and `www.` links. You can still pass `--input` for ad hoc text.

Examples of inputs:
- Risk scan reports
- MCP configs or logs
- AGENTS.md / SKILL.md notes
- Script outputs

### 2) Configure API key

Use the config file or environment variable. If neither is set, the script will prompt on first run and save to config.json.

```
VT_API_KEY=your_key
```

Config file (recommended):

```
config.json
{
  "VT_API_KEY": "your_key"
}
```

### 3) LLM script scan (no upload)

Use the LLM to scan `SKILL.md` and `scripts/*` content for malicious patterns (backdoor, persistence, hidden exec, credential access, exfiltration, privilege escalation) and suspicious encryption/obfuscation. Do not upload scripts to VirusTotal.

Output should include:
- Risk level (high/medium/low)
- Evidence snippet (short)
- File path

If complex encryption/obfuscation is detected, flag as high priority and require manual review of the logic and data flow.

Focus the report on high/medium risks only. Typical medium risks include:
- shell/subprocess execution
- system-level installs or config changes
- outbound network calls

### 4) Run the domain scan

Use the bundled script:

```bash
python scripts/vt_domain_scan.py
```

Custom skills root:

```bash
python scripts/vt_domain_scan.py --skills-root /path/to/skills
```

Use a custom config path:

```bash
python scripts/vt_domain_scan.py --input report.txt --config /path/to/config.json
```

Limit scan size (useful for large skill sets):

```bash
python scripts/vt_domain_scan.py --max-domains 50
```

Also extract bare domains (more coverage, more false positives):

```bash
python scripts/vt_domain_scan.py --include-bare-domains
```

Read from stdin:

```bash
cat report.txt | python scripts/vt_domain_scan.py --input -
```

Write raw VT JSON responses:

```bash
python scripts/vt_domain_scan.py --input report.txt --json-out vt_raw.json
```

### 5) Interpret output

Each line returns a compact verdict with VT stats:

```
example.com clean m=0 s=0 h=89 u=3 t=0
bad.example suspicious m=2 s=1 h=0 u=12 t=0
```

### 6) Rate limits

If you hit 429s, re-run with a delay:

```
python scripts/vt_domain_scan.py --input report.txt --sleep 1.5
```

## One-click scan (LLM + VT)

Run the end-to-end script to create reports and LLM input:

```bash
python scripts/scan_all.py
```

Optional flags:
- `--skills-root /path/to/skills`
- `--include-bare-domains`
- `--max-domains 50`
- `--sleep 0.5`

Outputs:
- Summary report (high-level)
- Detail report (full VT results)
- LLM input file (for LLM audit)
- LLM report file (write high/medium findings)

Default report location is the OS user data directory (codex-risk/reports).

## References

- references/virustotal_api.md
- references/llm_scan_prompt.md
