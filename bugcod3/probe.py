"""Network probes: TCP connect, TLS handshake (with SNI) and HTTP verification."""

from __future__ import annotations

import asyncio
import ssl
import statistics
import time
from dataclasses import asdict, dataclass, field

DEFAULT_TLS_PORTS = {443, 2053, 2083, 2087, 2096, 8443, 9443}
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) BugCod3-Scanner/2.0"
MAX_HEADER_BYTES = 32 * 1024
MAX_BODY_BYTES = 4 * 1024
KEEP_HEADERS = {
    "server", "via", "cf-ray", "cf-cache-status", "x-amz-cf-id", "x-amz-cf-pop", "x-cache",
    "x-served-by", "x-fastly-request-id", "fastly-debug-digest", "x-akamai-transformed",
    "akamai-grn", "x-id", "cdn-pullzone", "cdn-requestcountrycode", "ar-poweredby",
    "ar-request-id", "x-vercel-id", "x-nf-request-id", "x-iinfo", "x-cdn", "x-sucuri-id",
    "x-azure-ref", "location", "content-type", "x-powered-by",
}


class RateLimiter:
    """Token bucket limiting new connections per second (0 = unlimited)."""

    def __init__(self, rate: float):
        self.rate = float(rate)
        self._tokens = max(1.0, self.rate)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self.rate <= 0:
            return
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(max(1.0, self.rate), self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                await asyncio.sleep((1 - self._tokens) / self.rate)


@dataclass
class ProbeConfig:
    mode: str = "http"  # tcp | tls | http
    timeout: float = 3.0
    retries: int = 1
    rounds: int = 1
    sni: str | None = None
    host_header: str | None = None
    path: str = "/"
    method: str = "GET"
    tls_ports: set[int] = field(default_factory=lambda: set(DEFAULT_TLS_PORTS))
    verify_tls: bool = True
    cf_trace: bool = True


@dataclass
class PortResult:
    port: int
    open: bool = False
    scheme: str = "tcp"
    latency: float | None = None  # median TCP connect time (ms)
    latency_min: float | None = None
    jitter: float | None = None
    loss: float | None = None  # 0..1 over rounds
    tls: bool | None = None
    tls_version: str | None = None
    tls_cipher: str | None = None
    tls_verified: bool | None = None
    tls_error: str | None = None
    alpn: str | None = None
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_expires: str | None = None
    tls_ms: float | None = None
    status: int | None = None
    server: str | None = None
    ttfb: float | None = None
    headers: dict[str, str] = field(default_factory=dict)
    trace: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    @property
    def healthy(self) -> bool:
        """Port answered at the deepest layer that was probed."""
        if not self.open:
            return False
        if self.scheme == "https" and self.tls is False:
            return False
        if self.status is None and self.error:
            return False
        return True

    def to_dict(self) -> dict:
        d = asdict(self)
        d["healthy"] = self.healthy
        return {k: v for k, v in d.items() if v not in (None, {}, [])}


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 2)


async def _close(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 1.0)
    except Exception:
        pass


def _cert_name(parts) -> str | None:
    for wanted in ("commonName", "organizationName"):
        for rdn in parts or ():
            for key, value in rdn:
                if key == wanted:
                    return value
    return None


def _tls_context(verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:
        pass
    return ctx


def parse_http_head(raw: bytes) -> tuple[int | None, dict[str, str]]:
    text = raw.decode("iso-8859-1", "replace")
    lines = text.split("\r\n")
    status = None
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower()
        headers[k] = f"{headers[k]}, {v.strip()}" if k in headers else v.strip()
    return status, headers


def parse_cf_trace(body: str) -> dict[str, str]:
    out = {}
    for line in body.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            if k in {"colo", "loc", "http", "tls", "warp", "sni", "fl", "h"}:
                out[k] = v.strip()
    return out


class Prober:
    def __init__(self, cfg: ProbeConfig, limiter: RateLimiter, concurrency: int):
        self.cfg = cfg
        self.limiter = limiter
        self.sem = asyncio.Semaphore(concurrency)
        self._ctx_verify = _tls_context(True)
        self._ctx_noverify = _tls_context(False)

    # ------------------------------------------------------------------ tcp

    async def _connect(self, ip: str, port: int) -> tuple[float | None, str | None]:
        await self.limiter.acquire()
        start = time.perf_counter()
        writer = None
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), self.cfg.timeout)
            return _ms(start), None
        except asyncio.TimeoutError:
            return None, "timeout"
        except ConnectionRefusedError:
            return None, "refused"
        except OSError as exc:
            return None, exc.strerror or exc.__class__.__name__
        finally:
            await _close(writer)

    async def probe(self, ip: str, port: int, hostname: str | None = None) -> PortResult:
        async with self.sem:
            try:
                return await self._probe(ip, port, hostname)
            except Exception as exc:  # never kill a worker on an unexpected probe error
                return PortResult(port=port, error=f"{exc.__class__.__name__}: {exc}")

    async def _probe(self, ip: str, port: int, hostname: str | None) -> PortResult:
        cfg = self.cfg
        res = PortResult(port=port)

        first, err = None, None
        for _ in range(max(1, cfg.retries + 1)):
            first, err = await self._connect(ip, port)
            if first is not None or err != "timeout":
                break
        if first is None:
            res.error = err
            return res

        res.open = True
        samples, failures = [first], 0
        for _ in range(max(0, cfg.rounds - 1)):
            ms, _ = await self._connect(ip, port)
            if ms is None:
                failures += 1
            else:
                samples.append(ms)
        res.latency = round(statistics.median(samples), 2)
        res.latency_min = min(samples)
        res.jitter = round(statistics.pstdev(samples), 2) if len(samples) > 1 else 0.0
        res.loss = round(failures / max(1, cfg.rounds), 3)

        if cfg.mode == "tcp":
            return res

        is_tls = port in cfg.tls_ports
        res.scheme = "https" if is_tls else "http"
        if not is_tls and cfg.mode == "tls":
            return res
        await self._application(ip, port, hostname, res, is_tls)
        return res

    # ------------------------------------------------------------------ tls/http

    async def _application(self, ip: str, port: int, hostname: str | None, res: PortResult, is_tls: bool) -> None:
        cfg = self.cfg
        sni = cfg.sni or hostname
        host_header = cfg.host_header or sni or ip
        writer = None
        await self.limiter.acquire()
        try:
            start = time.perf_counter()
            if is_tls:
                reader, writer, verified = await self._tls_connect(ip, port, sni, res)
                if reader is None:
                    return
                res.tls_ms = _ms(start)
                res.tls_verified = verified
            else:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), cfg.timeout)

            if cfg.mode == "tls":
                return

            use_trace = cfg.cf_trace and cfg.path == "/"
            path = "/cdn-cgi/trace" if use_trace else cfg.path
            status, headers, body, ttfb = await self._http(reader, writer, host_header, path)
            if use_trace and (status is None or status >= 400 or "colo=" not in body):
                # not a Cloudflare-style edge: retry the real path once on a fresh connection
                await _close(writer)
                writer = None
                if is_tls:
                    reader, writer, _ = await self._tls_connect(ip, port, sni, PortResult(port=port))
                    if reader is None:
                        res.status, res.headers, res.ttfb = status, headers, ttfb
                        return
                else:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), cfg.timeout)
                status2, headers2, _, ttfb2 = await self._http(reader, writer, host_header, cfg.path)
                if status2 is not None:
                    status, headers, ttfb = status2, headers2, ttfb2
            elif use_trace:
                res.trace = parse_cf_trace(body)
            res.status = status
            res.ttfb = ttfb
            res.headers = {k: v[:200] for k, v in headers.items() if k in KEEP_HEADERS}
            res.server = headers.get("server")
            if status is None:
                res.error = "no http response"
        except asyncio.TimeoutError:
            res.error = "app timeout"
        except (OSError, ssl.SSLError, asyncio.IncompleteReadError) as exc:
            res.error = exc.__class__.__name__
        finally:
            await _close(writer)

    async def _tls_connect(self, ip: str, port: int, sni: str | None, res: PortResult):
        """Try a verified handshake first (when SNI is known), then an unverified one."""
        attempts = [(self._ctx_verify, True)] if (sni and self.cfg.verify_tls) else []
        attempts.append((self._ctx_noverify, False))
        last_error = None
        for ctx, verified in attempts:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni or None),
                    self.cfg.timeout,
                )
            except ssl.SSLCertVerificationError as exc:
                last_error = f"cert: {exc.verify_message or exc.reason}"
                continue
            except ssl.SSLError as exc:
                last_error = exc.reason or exc.__class__.__name__
                break
            except asyncio.TimeoutError:
                last_error = "tls timeout"
                break
            except OSError as exc:
                last_error = exc.__class__.__name__
                break
            sslobj = writer.get_extra_info("ssl_object")
            res.tls = True
            if sslobj is not None:
                res.tls_version = sslobj.version()
                cipher = sslobj.cipher()
                res.tls_cipher = cipher[0] if cipher else None
                res.alpn = sslobj.selected_alpn_protocol()
                cert = sslobj.getpeercert() if verified else None
                if cert:
                    res.cert_subject = _cert_name(cert.get("subject"))
                    res.cert_issuer = _cert_name(cert.get("issuer"))
                    res.cert_expires = cert.get("notAfter")
            if not verified and last_error:
                res.tls_error = last_error
            return reader, writer, verified
        res.tls = False
        res.tls_error = last_error
        res.error = res.error or "tls failed"
        return None, None, False

    async def _http(self, reader, writer, host: str, path: str):
        req = (
            f"{self.cfg.method} {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        start = time.perf_counter()
        writer.write(req)
        await writer.drain()
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.cfg.timeout)
        except asyncio.LimitOverrunError:
            head = await reader.read(MAX_HEADER_BYTES)
        except asyncio.IncompleteReadError as exc:
            head = exc.partial
        ttfb = _ms(start)
        status, headers = parse_http_head(head[:MAX_HEADER_BYTES])
        body = ""
        if status is not None and self.cfg.method != "HEAD":
            try:
                chunk = await asyncio.wait_for(reader.read(MAX_BODY_BYTES), min(1.5, self.cfg.timeout))
                body = chunk.decode("utf-8", "replace")
            except (asyncio.TimeoutError, OSError, ssl.SSLError):
                pass
        return status, headers, body, ttfb