"""CDN detection: IP-range database, ASN fallback and HTTP header fingerprints."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Iterable, Mapping

UNKNOWN = "Unknown"
UNKNOWN_COLOR = "#64748b"


def load_raw_database(path: Path | None = None) -> dict:
    """Load a ranges file, falling back to the copy bundled with the package."""
    if path is not None and Path(path).exists():
        return json.loads(Path(path).read_text(encoding="utf-8"))
    text = resources.files("bugcod3.data").joinpath("cdn_ranges.json").read_text(encoding="utf-8")
    return json.loads(text)


@dataclass
class Provider:
    name: str
    color: str = UNKNOWN_COLOR
    asns: set[int] = field(default_factory=set)
    ranges: list[str] = field(default_factory=list)


class CDNDatabase:
    """Longest-prefix-match lookup of IPs against CDN ranges.

    Ranges are stored per prefix length in hash maps, so a lookup costs at most
    one dict access per distinct prefix length (~25 for IPv4) instead of a
    linear scan over thousands of networks.
    """

    def __init__(self, providers: Iterable[Provider]):
        self.providers: dict[str, Provider] = {}
        self._asn_map: dict[int, str] = {}
        # version -> prefixlen -> {network_int >> host_bits: provider}
        self._tables: dict[int, dict[int, dict[int, str]]] = {4: {}, 6: {}}
        for p in providers:
            self.add(p)
        self._plens = {v: sorted(t, reverse=True) for v, t in self._tables.items()}

    @classmethod
    def load(cls, path: Path | None = None) -> "CDNDatabase":
        raw = load_raw_database(path)
        providers = [
            Provider(
                name=name,
                color=info.get("color", UNKNOWN_COLOR),
                asns={int(a) for a in info.get("asns", [])},
                ranges=list(info.get("ranges", [])),
            )
            for name, info in raw.get("providers", {}).items()
        ]
        db = cls(providers)
        db.updated = raw.get("updated", "unknown")
        return db

    def add(self, p: Provider) -> None:
        self.providers[p.name] = p
        for asn in p.asns:
            self._asn_map[asn] = p.name
        for r in p.ranges:
            try:
                net = ipaddress.ip_network(r, strict=False)
            except ValueError:
                continue
            bits = net.max_prefixlen - net.prefixlen
            table = self._tables[net.version].setdefault(net.prefixlen, {})
            # first writer wins for identical prefixes; more specific prefixes win at lookup
            table.setdefault(int(net.network_address) >> bits, p.name)
        self._plens = {v: sorted(t, reverse=True) for v, t in self._tables.items()}

    def lookup(self, ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
        try:
            addr = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
        except ValueError:
            return None
        value = int(addr)
        maxlen = addr.max_prefixlen
        tables = self._tables[addr.version]
        for plen in self._plens[addr.version]:
            hit = tables[plen].get(value >> (maxlen - plen))
            if hit:
                return hit
        return None

    def by_asn(self, asn: int | None) -> str | None:
        return self._asn_map.get(asn) if asn else None

    def color(self, name: str | None) -> str:
        p = self.providers.get(name or "")
        return p.color if p else UNKNOWN_COLOR

    def resolve_names(self, names: Iterable[str]) -> list[str]:
        """Case-insensitive provider-name matching for CLI filters."""
        lookup = {n.lower(): n for n in self.providers}
        out = []
        for n in names:
            key = n.strip().lower()
            if not key:
                continue
            if key not in lookup:
                raise ValueError(f"unknown CDN '{n}'. Known: {', '.join(sorted(self.providers))}")
            out.append(lookup[key])
        return out

    def networks(self, name: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        p = self.providers[name]
        nets = []
        for r in p.ranges:
            try:
                nets.append(ipaddress.ip_network(r, strict=False))
            except ValueError:
                pass
        return nets

    def stats(self) -> dict[str, int]:
        return {name: len(p.ranges) for name, p in self.providers.items()}


# --------------------------------------------------------------------------- headers

# (provider, header name, substring of value or None for "header present")
HEADER_FINGERPRINTS: list[tuple[str, str, str | None]] = [
    ("Cloudflare", "cf-ray", None),
    ("Cloudflare", "server", "cloudflare"),
    ("CloudFront", "x-amz-cf-id", None),
    ("CloudFront", "x-amz-cf-pop", None),
    ("CloudFront", "via", "cloudfront"),
    ("Fastly", "x-fastly-request-id", None),
    ("Fastly", "fastly-debug-digest", None),
    ("Fastly", "x-served-by", "cache-"),
    ("Akamai", "server", "akamaighost"),
    ("Akamai", "x-akamai-transformed", None),
    ("Akamai", "akamai-grn", None),
    ("Google", "server", "gws"),
    ("Google", "via", "google"),
    ("Gcore", "server", "gcore"),
    ("Gcore", "x-id", "gcore"),
    ("BunnyCDN", "server", "bunnycdn"),
    ("BunnyCDN", "cdn-pullzone", None),
    ("ArvanCloud", "server", "arvancloud"),
    ("ArvanCloud", "ar-poweredby", None),
    ("ArvanCloud", "ar-request-id", None),
    ("Vercel", "x-vercel-id", None),
    ("Vercel", "server", "vercel"),
    ("Netlify", "x-nf-request-id", None),
    ("Netlify", "server", "netlify"),
    ("Imperva", "x-iinfo", None),
    ("Imperva", "x-cdn", "imperva"),
    ("Sucuri", "x-sucuri-id", None),
    ("Sucuri", "server", "sucuri"),
    ("Azure Front Door", "x-azure-ref", None),
    ("CDN77", "server", "cdn77"),
]


def fingerprint_headers(headers: Mapping[str, str]) -> str | None:
    """Return the CDN identified by HTTP response headers (keys lower-case)."""
    for name, header, needle in HEADER_FINGERPRINTS:
        value = headers.get(header)
        if value is None:
            continue
        if needle is None or needle in value.lower():
            return name
    return None
