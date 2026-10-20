"""Async DNS helpers: forward lookups, PTR and Team Cymru ASN intelligence."""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass, asdict

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename


@dataclass
class ASNInfo:
    asn: int | None = None
    prefix: str | None = None
    country: str | None = None
    registry: str | None = None
    org: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class Resolver:
    def __init__(self, nameservers: list[str] | None = None, timeout: float = 3.0):
        self._r = dns.asyncresolver.Resolver(configure=not nameservers)
        if nameservers:
            self._r.nameservers = nameservers
        self._r.timeout = timeout
        self._r.lifetime = timeout * 2
        self._r.cache = dns.resolver.LRUCache(50_000)
        self._asn_cache: dict[str, asyncio.Future] = {}
        self._org_cache: dict[int, asyncio.Future] = {}
        self._ptr_cache: dict[str, asyncio.Future] = {}

    async def _query(self, name: str, rtype: str) -> list[str]:
        try:
            ans = await self._r.resolve(name, rtype, raise_on_no_answer=False)
        except (dns.exception.DNSException, OSError):
            return []
        if ans.rrset is None:
            return []
        if rtype == "TXT":
            return [b"".join(r.strings).decode("utf-8", "replace") for r in ans]
        return [r.to_text().rstrip(".") for r in ans]

    async def resolve_host(self, host: str, ipv6: bool = False) -> list[str]:
        tasks = [self._query(host, "A")]
        if ipv6:
            tasks.append(self._query(host, "AAAA"))
        results = await asyncio.gather(*tasks)
        seen: dict[str, None] = {}
        for group in results:
            for ip in group:
                seen.setdefault(ip, None)
        return list(seen)


    async def ptr(self, ip: str) -> str | None:
        fut = self._ptr_cache.get(ip)
        if fut is None:
            fut = asyncio.ensure_future(self._ptr(ip))
            self._ptr_cache[ip] = fut
        return await fut

    async def _ptr(self, ip: str) -> str | None:
        try:
            name = dns.reversename.from_address(ip).to_text()
        except (dns.exception.SyntaxError, ValueError):
            return None
        out = await self._query(name, "PTR")
        return out[0] if out else None

    # ------------------------------------------------------------------ ASN

    async def asn(self, ip: str) -> ASNInfo:
        """ASN lookup through Team Cymru's DNS service, cached per /24 (or /48)."""
        addr = ipaddress.ip_address(ip)
        key = str(ipaddress.ip_network(f"{ip}/{24 if addr.version == 4 else 48}", strict=False))
        fut = self._asn_cache.get(key)
        if fut is None:
            fut = asyncio.ensure_future(self._asn(addr))
            self._asn_cache[key] = fut
        return await fut

    async def _asn(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ASNInfo:
        if addr.version == 4:
            qname = ".".join(reversed(str(addr).split("."))) + ".origin.asn.cymru.com"
        else:
            nibbles = addr.exploded.replace(":", "")
            qname = ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"
        txt = await self._query(qname, "TXT")
        if not txt:
            return ASNInfo()
        # "13335 | 104.16.0.0/13 | US | arin | 2014-03-28"
        parts = [p.strip() for p in txt[0].split("|")]
        try:
            asn = int(parts[0].split()[0])
        except (ValueError, IndexError):
            return ASNInfo()
        info = ASNInfo(
            asn=asn,
            prefix=parts[1] if len(parts) > 1 else None,
            country=parts[2] or None if len(parts) > 2 else None,
            registry=parts[3] if len(parts) > 3 else None,
        )
        info.org = await self.asn_org(asn)
        return info

    async def asn_org(self, asn: int) -> str | None:
        fut = self._org_cache.get(asn)
        if fut is None:
            fut = asyncio.ensure_future(self._asn_org(asn))
            self._org_cache[asn] = fut
        return await fut

    async def _asn_org(self, asn: int) -> str | None:
        txt = await self._query(f"AS{asn}.asn.cymru.com", "TXT")
        if not txt:
            return None
        # "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
        parts = [p.strip() for p in txt[0].split("|")]
        return parts[-1] if parts else None
