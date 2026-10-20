"""Target parsing and streaming expansion.

Accepted forms (one per line / argument):
    1.1.1.1             single IPv4 / IPv6 address
    104.16.0.0/24       CIDR range
    1.1.1.1-1.1.1.50    explicit address range
    1.1.1.1-50          short last-octet range
    example.com         domain (resolved to all A/AAAA records)
    https://a.com:8443/ URL (scheme, path and port are stripped)
Lines starting with ``#`` and inline ``# comments`` are ignored.
"""

from __future__ import annotations

import ipaddress
import random
import re
from dataclasses import dataclass
from typing import Iterable, Iterator, Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9_-]{1,63}\.)+[a-z][a-z0-9-]{0,62}\.?$", re.I)


@dataclass(frozen=True)
class Target:
    kind: str  # "ip" | "net" | "range" | "domain"
    value: object
    raw: str

    @property
    def size(self) -> int:
        if self.kind == "ip":
            return 1
        if self.kind == "net":
            net: IPNetwork = self.value  # type: ignore[assignment]
            return usable_hosts(net)
        if self.kind == "range":
            a, b = self.value  # type: ignore[misc]
            return int(b) - int(a) + 1
        return 1  # domains: unknown until resolved, count as one


def usable_hosts(net: IPNetwork) -> int:
    if net.version == 4 and net.prefixlen < 31:
        return net.num_addresses - 2
    return net.num_addresses


def clean_line(line: str) -> str:
    line = line.split("#", 1)[0].strip()
    if not line:
        return ""
    if "://" in line:
        line = line.split("://", 1)[1]
    line = line.split("/", 1)[0] if not _looks_like_cidr(line) else line
    # strip :port from host:port (but not from IPv6)
    if line.count(":") == 1 and not line.startswith("["):
        line = line.split(":", 1)[0]
    if line.startswith("[") and "]" in line:
        line = line[1 : line.index("]")]
    return line.strip().strip(",;").lower()


def _looks_like_cidr(line: str) -> bool:
    head, sep, tail = line.partition("/")
    if not sep or not tail.isdigit():
        return False
    try:
        ipaddress.ip_address(head)
        return True
    except ValueError:
        return False


def parse_target(text: str) -> Target | None:
    raw = text
    text = clean_line(text)
    if not text:
        return None
    try:
        return Target("ip", ipaddress.ip_address(text), raw)
    except ValueError:
        pass
    if "/" in text:
        try:
            return Target("net", ipaddress.ip_network(text, strict=False), raw)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR: {raw.strip()}") from exc
    if "-" in text and not DOMAIN_RE.match(text):
        start_s, _, end_s = text.partition("-")
        try:
            start = ipaddress.ip_address(start_s.strip())
            end_s = end_s.strip()
            if end_s.isdigit() and start.version == 4:
                prefix = str(start).rsplit(".", 1)[0]
                end = ipaddress.ip_address(f"{prefix}.{end_s}")
            else:
                end = ipaddress.ip_address(end_s)
        except ValueError as exc:
            raise ValueError(f"invalid range: {raw.strip()}") from exc
        if start.version != end.version or int(end) < int(start):
            raise ValueError(f"invalid range: {raw.strip()}")
        return Target("range", (start, end), raw)
    if DOMAIN_RE.match(text):
        return Target("domain", text.rstrip("."), raw)
    raise ValueError(f"unrecognised target: {raw.strip()}")


def parse_many(lines: Iterable[str], errors: list[str] | None = None) -> list[Target]:
    out: list[Target] = []
    for line in lines:
        try:
            t = parse_target(line)
        except ValueError as exc:
            if errors is not None:
                errors.append(str(exc))
            continue
        if t is not None:
            out.append(t)
    return out


def iter_network(net: IPNetwork, sample: int = 0, rng: random.Random | None = None) -> Iterator[IPAddress]:
    """Yield host addresses of ``net``.

    With ``sample > 0`` only ``sample`` random addresses are taken from each /24
    (IPv4) or /120 (IPv6) block, which is the fast way to map a huge CDN range.
    """
    if net.num_addresses == 1:
        yield net.network_address
        return
    if sample <= 0:
        if net.version == 4 and net.prefixlen < 31:
            first, last = int(net.network_address) + 1, int(net.broadcast_address) - 1
        else:
            first, last = int(net.network_address), int(net.broadcast_address)
        cls = type(net.network_address)
        for v in range(first, last + 1):
            yield cls(v)
        return
    rng = rng or random.Random()
    block = 24 if net.version == 4 else 120
    if net.prefixlen >= block:
        subnets: Iterable[IPNetwork] = [net]
    else:
        subnets = net.subnets(new_prefix=block)
    cls = type(net.network_address)
    for sub in subnets:
        base = int(sub.network_address)
        n = sub.num_addresses
        lo, hi = (1, n - 2) if (sub.version == 4 and n >= 4) else (0, n - 1)
        count = min(sample, hi - lo + 1)
        for off in rng.sample(range(lo, hi + 1), count):
            yield cls(base + off)


def estimate_total(targets: Iterable[Target], sample: int = 0) -> int:
    total = 0
    for t in targets:
        if t.kind == "net" and sample > 0:
            net: IPNetwork = t.value  # type: ignore[assignment]
            block = 24 if net.version == 4 else 120
            if net.prefixlen >= block:
                total += min(sample, usable_hosts(net))
            else:
                total += (2 ** (block - net.prefixlen)) * sample
        else:
            total += t.size
    return total


class Exclusions:
    """Set of networks that must never be scanned."""

    def __init__(self, items: Iterable[str] = ()):
        self.nets: list[IPNetwork] = []
        for item in items:
            item = clean_line(item)
            if not item:
                continue
            try:
                self.nets.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                continue

    def __contains__(self, ip: IPAddress) -> bool:
        return any(ip.version == n.version and ip in n for n in self.nets)

    def __bool__(self) -> bool:
        return bool(self.nets)
