import argparse
import json
import os
import sys
import time
import urllib.error
from pathlib import Path

from vt_utils import (
    extract_domains,
    get_default_cache_path,
    get_cached,
    load_cache,
    save_cache,
    set_cached,
    summarize_stats,
    vt_request,
)


def main():
    parser = argparse.ArgumentParser(description="Check domain reputation via VirusTotal.")
    parser.add_argument("--input", help="Path to text file; otherwise read stdin.")
    parser.add_argument(
        "--skills-root",
        help="Root skills directory to scan (default: $CODEX_HOME/skills).",
    )
    parser.add_argument(
        "--include-bare-domains",
        action="store_true",
        help="Also extract bare domains without http(s):// or www.",
    )
    parser.add_argument(
        "--config",
        help="Path to config JSON (default: scripts/../config.json).",
    )
    parser.add_argument(
        "--cache-path",
        help="Path to VT cache JSON (default: OS user cache path).",
    )
    parser.add_argument(
        "--cache-ttl-days",
        type=int,
        default=7,
        help="Days to keep VT cache entries.",
    )
    parser.add_argument("--json-out", help="Write raw VT responses to JSON file.")
    parser.add_argument("--timeout", type=int, default=20, help="HTTP timeout seconds.")
    parser.add_argument("--sleep", type=float, default=0.0, help="Sleep seconds between requests.")
    parser.add_argument("--max-domains", type=int, help="Limit number of domains to scan.")
    args = parser.parse_args()

    api_key = os.environ.get("VT_API_KEY")
    config_path = args.config
    if not config_path:
        config_path = str(Path(__file__).resolve().parent.parent / "config.json")
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

    text_parts = []
    if args.input:
        text_parts.append(Path(args.input).read_text(encoding="utf-8", errors="ignore"))
    else:
        codex_home = os.environ.get("CODEX_HOME")
        if codex_home:
            skills_root = Path(codex_home) / "skills"
        else:
            skills_root = Path.home() / ".codex" / "skills"
        if args.skills_root:
            skills_root = Path(args.skills_root)
        if skills_root.is_dir():
            for skill_md in skills_root.rglob("SKILL.md"):
                text_parts.append(skill_md.read_text(encoding="utf-8", errors="ignore"))
            for script in skills_root.rglob("scripts/*"):
                if script.is_file():
                    text_parts.append(script.read_text(encoding="utf-8", errors="ignore"))
        else:
            text_parts.append(sys.stdin.read())
    text = "\n".join(text_parts)

    domains = extract_domains(text, include_bare_domains=args.include_bare_domains)
    if args.max_domains:
        domains = domains[: args.max_domains]
    if not domains:
        print("No domains found.")
        return 0

    results = {}
    cache_path = args.cache_path or str(get_default_cache_path())
    cache_ttl = int(args.cache_ttl_days) * 86400
    cache = load_cache(cache_path)
    for domain in domains:
        try:
            data = get_cached(cache, domain, cache_ttl)
            if data is None:
                data = vt_request(domain, api_key, args.timeout)
                set_cached(cache, domain, data)
            results[domain] = data
            stats = summarize_stats(data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}))
            print(f"{domain} {stats['label']} m={stats['malicious']} s={stats['suspicious']} h={stats['harmless']} u={stats['undetected']} t={stats['timeout']}")
        except urllib.error.HTTPError as e:
            print(f"{domain} error http={e.code}")
        except Exception as e:
            print(f"{domain} error {e}")
        if args.sleep:
            time.sleep(args.sleep)

    save_cache(cache_path, cache)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=True, indent=2)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
