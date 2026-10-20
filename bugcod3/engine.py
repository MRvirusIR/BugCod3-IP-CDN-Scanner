"""Streaming async scan engine (producer -> bounded queue -> workers -> sinks)."""

from __future__ import annotations

import asyncio
import ipaddress
import random
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Iterable, Optional, Union

from bugcod3.cdn import UNKNOWN, CDNDatabase, fingerprint_headers
from bugcod3.probe import PortResult, ProbeConfig, Prober, RateLimiter
from bugcod3.resolver import ASNInfo, Resolver
from bugcod3.targets import Exclusions, Target, estimate_total, iter_network


@dataclass
class ScanConfig:
    ports: list[int] = field(default_factory=lambda: [80, 443])
    workers: int = 300
    rate: float = 0.0
    probe: ProbeConfig = field(default_factory=ProbeConfig)
    sample: int = 0
    shuffle: bool = False
    exclude: Exclusions = field(default_factory=Exclusions)
    only_cdn: list[str] = field(default_factory=list)  # pre-filter: scan only IPs in these CDNs
    cdn_only: bool = False  # drop results that are not behind any CDN
    max_latency: float | None = None
    enrich: bool = True
    ptr: bool = True
    ipv6: bool = False
    nameservers: list[str] | None = None
    skip: set[str] = field(default_factory=set)  # already scanned (resume)


@dataclass
class HostResult:
    ip: str
    source: str
    hostname: str | None = None
    ptr: str | None = None
    cdn: str = UNKNOWN
    cdn_color: str = "#64748b"
    cdn_method: str | None = None  # range | header | asn
    asn: ASNInfo = field(default_factory=ASNInfo)
    ports: list[PortResult] = field(default_factory=list)
    scanned_at: float = field(default_factory=time.time)

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.open]

    @property
    def best(self) -> PortResult | None:
        alive = [p for p in self.open_ports if p.latency is not None]
        healthy = [p for p in alive if p.healthy] or alive
        return min(healthy, key=lambda p: p.latency) if healthy else None

    @property
    def latency(self) -> float | None:
        b = self.best
        return b.latency if b else None

    @property
    def colo(self) -> str | None:
        for p in self.ports:
            if p.trace.get("colo"):
                return p.trace["colo"]
            pop = p.headers.get("x-amz-cf-pop")
            if pop:
                return pop[:3]
            served = p.headers.get("x-served-by", "")
            if served.startswith("cache-"):
                # Fastly: "cache-iad-kiad7000071-IAD" -> IAD
                return served.split(",")[-1].strip().rsplit("-", 1)[-1].upper()[:3]
        return None

    @property
    def score(self) -> float | None:
        """Quality score 0-100 (higher is better) for ranking clean IPs."""
        b = self.best
        if b is None or b.latency is None:
            return None
        penalty = b.latency + 2 * (b.jitter or 0) + 400 * (b.loss or 0)
        if not b.healthy:
            penalty += 300
        if b.scheme == "https" and b.tls and b.tls_verified is False and b.tls_error:
            penalty += 25
        return round(max(0.0, 100 - penalty / 10), 1)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "source": self.source,
            "hostname": self.hostname,
            "ptr": self.ptr,
            "cdn": self.cdn,
            "cdn_color": self.cdn_color,
            "cdn_method": self.cdn_method,
            "colo": self.colo,
            "latency": self.latency,
            "score": self.score,
            "asn": self.asn.to_dict(),
            "open_ports": [p.port for p in self.open_ports],
            "ports": [p.to_dict() for p in self.open_ports],
            "scanned_at": round(self.scanned_at, 3),
        }


@dataclass
class Stats:
    total: int = 0
    queued: int = 0
    scanned: int = 0
    alive: int = 0
    filtered: int = 0
    excluded: int = 0
    resolve_failed: int = 0
    errors: int = 0
    started: float = field(default_factory=time.monotonic)
    finished: float | None = None
    cdns: Counter = field(default_factory=Counter)
    ports: Counter = field(default_factory=Counter)
    top: list[HostResult] = field(default_factory=list)

    @property
    def elapsed(self) -> float:
        return (self.finished or time.monotonic()) - self.started

    @property
    def rate(self) -> float:
        e = self.elapsed
        return self.scanned / e if e > 0 else 0.0

    @property
    def eta(self) -> float | None:
        r = self.rate
        if r <= 0 or not self.total:
            return None
        return max(0.0, (self.total - self.scanned) / r)

    def push_top(self, r: HostResult, keep: int = 15) -> None:
        if r.latency is None:
            return
        self.top.append(r)
        self.top.sort(key=lambda h: (-(h.score or 0), h.latency or 1e9))
        del self.top[keep:]


Sink = Callable[[HostResult], Optional[Awaitable[None]]]


class ScanEngine:
    def __init__(self, targets: list[Target], cfg: ScanConfig, cdn_db: CDNDatabase):
        self.targets = targets
        self.cfg = cfg
        self.db = cdn_db
        self.stats = Stats()
        self.results: list[HostResult] = []
        self.sinks: list[Sink] = []
        self.log: Callable[[str], None] = lambda msg: None
        self.resolver = Resolver(cfg.nameservers, timeout=min(3.0, cfg.probe.timeout))
        self._hostnames: dict[str, str] = {}
        self._seen: set[str] = set()

    # ------------------------------------------------------------------ producer

    async def _resolve_domains(self) -> list[tuple[str, str]]:
        domains = [t for t in self.targets if t.kind == "domain"]
        if not domains:
            return []
        sem = asyncio.Semaphore(100)

        async def one(t: Target):
            async with sem:
                return t, await self.resolver.resolve_host(str(t.value), self.cfg.ipv6)

        out: list[tuple[str, str]] = []
        for t, ips in await asyncio.gather(*(one(t) for t in domains)):
            if not ips:
                self.stats.resolve_failed += 1
                self.log(f"[yellow]DNS[/] could not resolve [bold]{t.value}[/]")
                continue
            for ip in ips:
                self._hostnames.setdefault(ip, str(t.value))
                out.append((ip, str(t.value)))
        return out

    def _iter_ips(self, resolved: list[tuple[str, str]]) -> Iterable[tuple[str, str]]:
        rng = random.Random()
        targets = [t for t in self.targets if t.kind != "domain"]
        if self.cfg.shuffle:
            rng.shuffle(targets)
        yield from resolved
        for t in targets:
            if t.kind == "ip":
                yield str(t.value), t.raw.strip()
            elif t.kind == "net":
                for ip in iter_network(t.value, self.cfg.sample, rng):  # type: ignore[arg-type]
                    yield str(ip), str(t.value)
            elif t.kind == "range":
                a, b = t.value  # type: ignore[misc]
                cls = type(a)
                label = f"{a}-{b}"
                for v in range(int(a), int(b) + 1):
                    yield str(cls(v)), label

    def _wanted(self, ip: str) -> bool:
        if ip in self._seen or ip in self.cfg.skip:
            return False
        addr = ipaddress.ip_address(ip)
        if self.cfg.exclude and addr in self.cfg.exclude:
            self.stats.excluded += 1
            return False
        if self.cfg.only_cdn:
            hit = self.db.lookup(addr)
            if hit not in self.cfg.only_cdn:
                self.stats.filtered += 1
                return False
        self._seen.add(ip)
        return True

    async def _producer(self, queue: asyncio.Queue) -> None:
        resolved = await self._resolve_domains()
        self.stats.total = estimate_total([t for t in self.targets if t.kind != "domain"], self.cfg.sample) + len(resolved)
        for n, (ip, source) in enumerate(self._iter_ips(resolved)):
            if not self._wanted(ip):
                self.stats.total = max(self.stats.scanned, self.stats.total - 1)
                if n % 4096 == 0:
                    await asyncio.sleep(0)
                continue
            self.stats.queued += 1
            await queue.put((ip, source))
        self.stats.total = self.stats.queued  # exact once the producer is done

    # ------------------------------------------------------------------ workers

    async def _worker(self, queue: asyncio.Queue, prober: Prober) -> None:
        while True:
            item = await queue.get()
            try:
                if item is None:
                    return
                ip, source = item
                try:
                    result = await self.scan_ip(prober, ip, source)
                except Exception as exc:  # keep the worker alive
                    self.stats.errors += 1
                    self.log(f"[red]error[/] {ip}: {exc.__class__.__name__}: {exc}")
                    result = None
                self.stats.scanned += 1
                if result is not None:
                    await self._emit(result)
            finally:
                queue.task_done()

    async def scan_ip(self, prober: Prober, ip: str, source: str) -> HostResult | None:
        hostname = self._hostnames.get(ip)
        ports = await asyncio.gather(*(prober.probe(ip, port, hostname) for port in self.cfg.ports))
        open_ports = [p for p in ports if p.open]
        if not open_ports:
            return None
        res = HostResult(ip=ip, source=source, hostname=hostname, ports=list(ports))
        if self.cfg.max_latency is not None and (res.latency is None or res.latency > self.cfg.max_latency):
            return None

        # CDN: official ranges -> response headers -> ASN
        cdn = self.db.lookup(ip)
        method = "range" if cdn else None
        if not cdn:
            for p in open_ports:
                cdn = fingerprint_headers(p.headers)
                if cdn:
                    method = "header"
                    break

        if self.cfg.enrich:
            jobs = [self.resolver.asn(ip)]
            if self.cfg.ptr:
                jobs.append(self.resolver.ptr(ip))
            out = await asyncio.gather(*jobs, return_exceptions=True)
            if isinstance(out[0], ASNInfo):
                res.asn = out[0]
            if len(out) > 1 and isinstance(out[1], str):
                res.ptr = out[1]
            if not cdn:
                cdn = self.db.by_asn(res.asn.asn)
                method = "asn" if cdn else None

        res.cdn = cdn or UNKNOWN
        res.cdn_method = method
        res.cdn_color = self.db.color(cdn)
        if self.cfg.cdn_only and not cdn:
            return None
        return res

    async def _emit(self, res: HostResult) -> None:
        self.results.append(res)
        self.stats.alive += 1
        self.stats.cdns[res.cdn] += 1
        for p in res.open_ports:
            self.stats.ports[p.port] += 1
        self.stats.push_top(res)
        for sink in self.sinks:
            try:
                out = sink(res)
                if asyncio.iscoroutine(out):
                    await out
            except (BrokenPipeError, asyncio.CancelledError):
                raise
            except Exception as exc:  # a broken sink must not kill the scan
                self.stats.errors += 1
                self.log(f"[red]sink error[/] {exc.__class__.__name__}: {exc}")

    # ------------------------------------------------------------------ run

    async def run(self) -> list[HostResult]:
        cfg = self.cfg
        workers = max(1, cfg.workers)
        prober = Prober(cfg.probe, RateLimiter(cfg.rate), concurrency=workers * max(1, len(cfg.ports)))
        queue: asyncio.Queue = asyncio.Queue(maxsize=workers * 4)
        tasks = [asyncio.create_task(self._worker(queue, prober)) for _ in range(workers)]
        try:
            await self._producer(queue)
            for _ in tasks:
                await queue.put(None)
            await asyncio.gather(*tasks)
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.stats.finished = time.monotonic()
        return self.results