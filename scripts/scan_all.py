import argparse
import json
import os
import sys
from pathlib import Path

from vt_utils import (
    extract_domains,
    get_default_base_dir,
    get_default_cache_path,
    get_cached,
    load_cache,
    save_cache,
    set_cached,
    summarize_stats,
    vt_request,
)


def get_skills_root(path_arg):
    if path_arg:
        return Path(path_arg)
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        return Path(codex_home) / "skills"
    return Path.home() / ".codex" / "skills"


def collect_files(skills_root):
    files = []
    for skill_md in skills_root.rglob("SKILL.md"):
        files.append(skill_md)
    for script in skills_root.rglob("scripts/*"):
        if script.is_file():
            files.append(script)
    return files


def read_text(path):
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def main():
    parser = argparse.ArgumentParser(description="LLM audit + VT domain scan.")
    parser.add_argument("--skills-root", help="Root skills directory to scan.")
    parser.add_argument(
        "--include-bare-domains",
        action="store_true",
        help="Also extract bare domains without http(s):// or www.",
    )
    parser.add_argument("--max-domains", type=int, help="Limit number of domains to scan.")
    parser.add_argument("--sleep", type=float, default=0.0, help="Sleep seconds between requests.")
    parser.add_argument("--timeout", type=int, default=20, help="HTTP timeout seconds.")
    parser.add_argument("--config", help="Path to config JSON (default: scripts/../config.json).")
    parser.add_argument("--cache-path", help="Path to VT cache JSON.")
    parser.add_argument("--cache-ttl-days", type=int, default=7, help="Days to keep VT cache entries.")
    parser.add_argument("--output-dir", help="Directory for reports (default: OS user reports path).")
    args = parser.parse_args()

    skills_root = get_skills_root(args.skills_root)
    if not skills_root.is_dir():
        print(f"Skills root not found: {skills_root}", file=sys.stderr)
        return 2

    config_path = args.config
    if not config_path:
        config_path = str(Path(__file__).resolve().parent.parent / "config.json")
    api_key = os.environ.get("VT_API_KEY")
    if not api_key and Path(config_path).is_file():
        try:
            config_data = json.loads(Path(config_path).read_text(encoding="utf-8"))
            api_key = config_data.get("VT_API_KEY") or config_data.get("vt_api_key")
        except (json.JSONDecodeError, OSError):
            api_key = None
    if not api_key and sys.stdin.isatty():
        try:
            api_key = input("Enter VT_API_KEY: ").strip()
        except (EOFError, KeyboardInterrupt):
            api_key = ""
        if api_key:
            try:
                Path(config_path).parent.mkdir(parents=True, exist_ok=True)
                Path(config_path).write_text(
                    json.dumps({"VT_API_KEY": api_key}, ensure_ascii=True, indent=2),
                    encoding="utf-8",
                )
            except OSError:
                pass
    if not api_key:
        print("VT_API_KEY is required (env var, config.json, or interactive prompt).", file=sys.stderr)
        return 2

    output_dir = Path(args.output_dir) if args.output_dir else get_default_base_dir() / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    files = collect_files(skills_root)
    file_entries = []
    for path in files:
        file_entries.append({"path": str(path.relative_to(skills_root)), "content": read_text(path)})

    # LLM audit input
    llm_input_path = output_dir / "llm_input.txt"
    with llm_input_path.open("w", encoding="utf-8") as f:
        f.write("LLM audit input: SKILL.md + scripts/*\n")
        f.write("Use references/llm_scan_prompt.md for rules.\n\n")
        for entry in file_entries:
            f.write(f"FILE: {entry['path']}\n")
            f.write("-----\n")
            f.write(entry["content"])
            f.write("\n-----\n\n")

    # VT scan
    combined_text = "\n".join(entry["content"] for entry in file_entries)
    domains = extract_domains(combined_text, include_bare_domains=args.include_bare_domains)
    if args.max_domains:
        domains = domains[: args.max_domains]

    cache_path = args.cache_path or str(get_default_cache_path())
    cache_ttl = int(args.cache_ttl_days) * 86400
    cache = load_cache(cache_path)

    vt_results = {}
    for domain in domains:
        try:
            data = get_cached(cache, domain, cache_ttl)
            if data is None:
                data = vt_request(domain, api_key, args.timeout)
                set_cached(cache, domain, data)
            vt_results[domain] = data
        except Exception as e:
            vt_results[domain] = {"error": str(e)}
        if args.sleep:
            time.sleep(args.sleep)

    save_cache(cache_path, cache)

    # Reports
    summary_path = output_dir / "summary.txt"
    detail_path = output_dir / "detail.txt"
    llm_report_path = output_dir / "llm_report.txt"

    suspicious_domains = []
    for domain, data in vt_results.items():
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        if stats:
            summary = summarize_stats(stats)
            if summary["label"] == "suspicious":
                suspicious_domains.append((domain, summary))

    with summary_path.open("w", encoding="utf-8") as f:
        f.write("Risk Scan Summary\n")
        f.write(f"Skills root: {skills_root}\n")
        f.write(f"LLM input: {llm_input_path}\n")
        f.write(f"LLM findings: pending (write to {llm_report_path})\n")
        f.write(f"VT domains: {len(domains)}\n")
        f.write(f"VT suspicious: {len(suspicious_domains)}\n")
        for domain, summary in suspicious_domains:
            f.write(
                f"{domain} suspicious m={summary['malicious']} s={summary['suspicious']} "
                f"h={summary['harmless']} u={summary['undetected']} t={summary['timeout']}\n"
            )

    with detail_path.open("w", encoding="utf-8") as f:
        f.write("Risk Scan Details\n")
        f.write(f"Skills root: {skills_root}\n\n")
        f.write("LLM audit input file:\n")
        f.write(str(llm_input_path) + "\n\n")
        f.write("VT results:\n")
        for domain, data in sorted(vt_results.items()):
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if stats:
                summary = summarize_stats(stats)
                f.write(
                    f"{domain} {summary['label']} m={summary['malicious']} s={summary['suspicious']} "
                    f"h={summary['harmless']} u={summary['undetected']} t={summary['timeout']}\n"
                )
            else:
                f.write(f"{domain} error {data.get('error', 'unknown')}\n")

    if not llm_report_path.exists():
        llm_report_path.write_text(
            "LLM Findings (high/medium only)\n"
            "Use references/llm_scan_prompt.md and llm_input.txt to fill this file.\n",
            encoding="utf-8",
        )

    print(f"Summary: {summary_path}")
    print(f"Details: {detail_path}")
    print(f"LLM input: {llm_input_path}")
    print(f"LLM report: {llm_report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
