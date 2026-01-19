import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
import re

VT_API_URL = "https://www.virustotal.com/api/v3/domains/{}"

URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s)\]]+")
BARE_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}\b", re.I)

COMMON_FILE_EXTS = {
    ".md",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".py",
    ".js",
    ".json",
    ".csv",
    ".txt",
    ".pdf",
    ".yaml",
    ".yml",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".7z",
    ".mp3",
    ".mp4",
    ".mov",
    ".avi",
    ".webm",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".pptx",
    ".docx",
    ".xlsx",
    ".tex",
    ".sty",
}


def _is_probable_domain(domain):
    if not domain:
        return False
    host = domain.strip(".").lower()
    if host in {"localhost", "127.0.0.1"}:
        return False
    if "_" in host:
        return False
    for ext in COMMON_FILE_EXTS:
        if host.endswith(ext):
            return False
    return True


def extract_domains(text, include_bare_domains=False):
    domains = set()
    for raw in URL_RE.findall(text):
        url = raw if raw.startswith("http") else f"http://{raw}"
        try:
            host = urllib.parse.urlparse(url).hostname
        except ValueError:
            host = None
        if host and _is_probable_domain(host):
            domains.add(host.lower())
    if include_bare_domains:
        for match in BARE_DOMAIN_RE.finditer(text):
            host = match.group(0).lower()
            if _is_probable_domain(host):
                domains.add(host)
    return sorted(domains)


def vt_request(domain, api_key, timeout):
    url = VT_API_URL.format(urllib.parse.quote(domain))
    req = urllib.request.Request(url)
    req.add_header("x-apikey", api_key)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def summarize_stats(stats):
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    timeout = int(stats.get("timeout", 0))
    label = "suspicious" if malicious > 0 or suspicious > 0 else "clean"
    return {
        "label": label,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": timeout,
    }


def get_default_base_dir():
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "codex-risk"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "codex-risk"
    return Path.home() / ".local" / "share" / "codex-risk"


def get_default_cache_path():
    return get_default_base_dir() / "vt_cache.json"


def load_cache(path):
    cache_path = Path(path)
    if not cache_path.is_file():
        return {}
    try:
        return json.loads(cache_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_cache(path, data):
    cache_path = Path(path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(data, ensure_ascii=True, indent=2), encoding="utf-8")


def get_cached(cache, domain, ttl_seconds):
    entry = cache.get(domain)
    if not entry:
        return None
    ts = entry.get("ts")
    data = entry.get("data")
    if not ts or data is None:
        return None
    if time.time() - ts > ttl_seconds:
        return None
    return data


def set_cached(cache, domain, data):
    cache[domain] = {"ts": int(time.time()), "data": data}
