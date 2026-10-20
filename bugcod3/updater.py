"""Fetch official CDN IP ranges and build ``cdn_ranges.json``.

Every provider below publishes its edge ranges. Providers without an
official list keep their curated fallback ranges from the bundled database.
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
import urllib.request
from pathlib import Path
from typing import Callable

USER_AGENT = "BugCod3-IP-CDN-Scanner/2 (+https://github.com/MRvirusIR/BugCod3-IP-CDN-Scanner)"
CIDR_RE = re.compile(r"[0-9a-fA-F:.]+/\d{1,3}")


def _get(url: str, timeout: float = 20.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URLs
        return resp.read().decode("utf-8", "replace")


def _cidrs_from_text(text: str) -> list[str]:
    return CIDR_RE.findall(text)


def _cloudflare() -> list[str]:
    return _cidrs_from_text(_get("https://www.cloudflare.com/ips-v4")) + _cidrs_from_text(
        _get("https://www.cloudflare.com/ips-v6")
    )


def _fastly() -> list[str]:
    data = json.loads(_get("https://api.fastly.com/public-ip-list"))
    return data.get("addresses", []) + data.get("ipv6_addresses", [])


def _cloudfront() -> list[str]:
    data = json.loads(_get("https://ip-ranges.amazonaws.com/ip-ranges.json"))
    out = [p["ip_prefix"] for p in data.get("prefixes", []) if p.get("service") == "CLOUDFRONT"]
    out += [p["ipv6_prefix"] for p in data.get("ipv6_prefixes", []) if p.get("service") == "CLOUDFRONT"]
    return out


def _google() -> list[str]:
    data = json.loads(_get("https://www.gstatic.com/ipranges/goog.json"))
    return [p.get("ipv4Prefix") or p.get("ipv6Prefix") for p in data.get("prefixes", [])]


def _gcore() -> list[str]:
    data = json.loads(_get("https://api.gcore.com/cdn/public-ip-list"))
    return data.get("addresses", []) + data.get("addresses_v6", [])


def _bunny() -> list[str]:
    ips = json.loads(_get("https://bunnycdn.com/api/system/edgeserverlist"))
    ips6 = json.loads(_get("https://bunnycdn.com/api/system/edgeserverlist/IPv6"))
    return [f"{ip}/32" for ip in ips] + [f"{ip}/128" for ip in ips6]


def _arvan() -> list[str]:
    return _cidrs_from_text(_get("https://www.arvancloud.ir/en/ips.txt"))


FETCHERS: dict[str, Callable[[], list[str]]] = {
    "Cloudflare": _cloudflare,
    "Fastly": _fastly,
    "CloudFront": _cloudfront,
    "Google": _google,
    "Gcore": _gcore,
    "BunnyCDN": _bunny,
    "ArvanCloud": _arvan,
}


def _normalise(cidrs: list[str]) -> list[str]:
    nets = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c.strip(), strict=False))
        except ValueError:
            continue
    v4 = ipaddress.collapse_addresses(n for n in nets if n.version == 4)
    v6 = ipaddress.collapse_addresses(n for n in nets if n.version == 6)
    return [str(n) for n in v4] + [str(n) for n in v6]


def update_ranges(path: Path, log: Callable[[str], None] = print) -> dict:
    """Refresh providers in ``path`` from their official sources."""
    from bugcod3.cdn import load_raw_database

    db = load_raw_database(path if path.exists() else None)
    providers = db.setdefault("providers", {})
    for name, fetch in FETCHERS.items():
        try:
            ranges = _normalise(fetch())
        except Exception as exc:  # network errors keep the previous data
            log(f"[!] {name}: update failed ({exc.__class__.__name__}: {exc}) - keeping old ranges")
            continue
        if not ranges:
            log(f"[!] {name}: source returned no ranges - keeping old ranges")
            continue
        entry = providers.setdefault(name, {"color": "#64748b", "asns": []})
        entry["ranges"] = ranges
        entry["source"] = "official"
        log(f"[+] {name}: {len(ranges)} ranges")
    db["updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(db, indent=1) + "\n", encoding="utf-8")
    return db
