"""Command-line interface.

    bugcod3 scan  [targets...] [-i file] [options]   scan targets (default command)
    bugcod3 lookup IP [IP...]                         offline CDN + live ASN lookup
    bugcod3 ranges cloudflare [--v6]                  print a provider's CIDRs
    bugcod3 update                                    refresh CDN ranges from official sources
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import signal
import sys
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.table import Table

from bugcod3 import __version__
from bugcod3.cdn import CDNDatabase
from bugcod3.engine import ScanConfig, ScanEngine
from bugcod3.probe import DEFAULT_TLS_PORTS, ProbeConfig
from bugcod3.targets import Exclusions, parse_many

CACHE_DIR = Path(os.environ.get("BUGCOD3_HOME", Path.home() / ".cache" / "bugcod3"))
CACHE_RANGES = CACHE_DIR / "cdn_ranges.json"

PORT_PRESETS = {
    "web": "80,443",
    "cf": "80,443,8080,8443,2052,2053,2082,2083,2086,2087,2095,2096,8880",
    "cf-tls": "443,2053,2083,2087,2096,8443",
    "cf-http": "80,8080,8880,2052,2082,2086,2095",
    "alt": "80,443,8000,8008,8080,8443,8888,9443",
}
ALWAYS_EXCLUDE = ["0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "ff00::/8"]
COMMANDS = {"scan", "lookup", "ranges", "update"}


def parse_ports(spec: str) -> list[int]:
    out: list[int] = []
    for part in spec.split(","):
        part = part.strip().lower()
        if not part:
            continue
        if part in PORT_PRESETS:
            out += parse_ports(PORT_PRESETS[part])
            continue
        if "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
            if a > b:
                a, b = b, a
            out += list(range(a, b + 1))
        else:
            out.append(int(part))
    ports = list(dict.fromkeys(out))
    bad = [p for p in ports if not 0 < p < 65536]
    if bad or not ports:
        raise argparse.ArgumentTypeError(f"invalid port list: {spec}")
    return ports


def csv_list(spec: str) -> list[str]:
    return [x.strip() for x in spec.split(",") if x.strip()]


def read_lines(path: str) -> list[str]:
    if path == "-":
        return sys.stdin.read().splitlines()
    return Path(path).read_text(encoding="utf-8", errors="replace").splitlines()


def ranges_path(arg: str | None) -> Path | None:
    if arg:
        return Path(arg)
    return CACHE_RANGES if CACHE_RANGES.exists() else None


# --------------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bugcod3",
        description="BugCod3 IP CDN Scanner - fast async CDN / edge IP intelligence scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  bugcod3 scan -i data/targets.txt\n"
            "  bugcod3 scan 104.16.0.0/16 --sample 3 -p cf --sni example.com\n"
            "  bugcod3 scan -i ranges.txt --only-cdn cloudflare --max-latency 150 --silent > clean.txt\n"
            "  bugcod3 ranges cloudflare | bugcod3 scan -i - --sample 2\n"
        ),
    )
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--ranges-file", help="custom CDN ranges JSON (default: updated cache or bundled DB)")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="scan targets", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    s.add_argument("targets", nargs="*", help="IPs, CIDRs, ranges (1.1.1.1-50) or domains")
    s.add_argument("-i", "--input", action="append", default=[], help="targets file (repeatable, '-' = stdin)")

    g = s.add_argument_group("probing")
    g.add_argument("-p", "--ports", type=parse_ports, default=parse_ports("web"),
                   help=f"ports, ranges or presets ({', '.join(PORT_PRESETS)})")
    g.add_argument("-m", "--mode", choices=["tcp", "tls", "http"], default="http",
                   help="tcp=connect only, tls=+handshake, http=+real HTTP request & CDN fingerprint")
    g.add_argument("-w", "--workers", type=int, default=300, help="concurrent hosts")
    g.add_argument("-r", "--rate", type=float, default=0, help="max new connections per second (0 = unlimited)")
    g.add_argument("-t", "--timeout", type=float, default=3.0, help="per-connection timeout (s)")
    g.add_argument("--retries", type=int, default=1, help="retries on timeout only")
    g.add_argument("--rounds", type=int, default=1, help="latency samples per open port (jitter / loss)")
    g.add_argument("--sni", help="TLS SNI to send (e.g. your domain behind the CDN)")
    g.add_argument("--host", dest="host_header", help="HTTP Host header (defaults to SNI)")
    g.add_argument("--path", default="/", help="HTTP path to request")
    g.add_argument("--tls-ports", type=parse_ports, default=sorted(DEFAULT_TLS_PORTS), help="ports that speak TLS")
    g.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    g.add_argument("--no-trace", action="store_true", help="skip /cdn-cgi/trace (Cloudflare PoP detection)")

    f = s.add_argument_group("targets & filtering")
    f.add_argument("--sample", type=int, default=0, help="scan only N random IPs per /24 (fast mapping of huge ranges)")
    f.add_argument("--shuffle", action="store_true", help="randomise target order")
    f.add_argument("--exclude", action="append", default=[], help="CIDR/IP or file to never scan (repeatable)")
    f.add_argument("--only-cdn", type=csv_list, default=[], help="scan only IPs inside these CDNs' ranges")
    f.add_argument("--cdn-only", action="store_true", help="drop results not identified as any CDN")
    f.add_argument("--max-latency", type=float, help="drop results slower than this (ms)")
    f.add_argument("--ipv6", action="store_true", help="also resolve AAAA records for domains")
    f.add_argument("--no-enrich", action="store_true", help="skip ASN / PTR lookups (faster)")
    f.add_argument("--no-ptr", action="store_true", help="skip reverse DNS")
    f.add_argument("--resolvers", type=csv_list, help="DNS servers, e.g. 1.1.1.1,8.8.8.8")

    o = s.add_argument_group("output")
    o.add_argument("-o", "--output", default="results", help="output directory")
    o.add_argument("-f", "--format", type=csv_list, default=["json", "csv", "txt", "html"],
                   help="report formats: json,csv,txt,html")
    o.add_argument("--resume", action="store_true", help="append to results.jsonl and skip IPs already found")
    o.add_argument("--no-ui", action="store_true", help="plain log output instead of the live dashboard")
    o.add_argument("--silent", action="store_true", help="print only alive IPs to stdout (pipe friendly)")

    lk = sub.add_parser("lookup", help="identify CDN / ASN of IPs or domains without scanning")
    lk.add_argument("targets", nargs="+")
    lk.add_argument("--no-asn", action="store_true", help="offline only (CDN ranges DB)")

    rg = sub.add_parser("ranges", help="print CIDRs of a CDN provider (pipe into scan)")
    rg.add_argument("provider", nargs="?", help="provider name; omit to list providers")
    rg.add_argument("--v6", action="store_true", help="include IPv6 ranges")

    sub.add_parser("update", help="refresh CDN ranges from official provider lists")
    return p


# --------------------------------------------------------------------------- commands


def cmd_scan(args, console: Console, err: Console) -> int:
    from bugcod3.reports import JsonlSink, build_meta, load_jsonl, sort_results, write_all
    from bugcod3 import ui

    lines = list(args.targets)
    for path in args.input:
        try:
            lines += read_lines(path)
        except OSError as exc:
            err.print(f"[red]✗ cannot read {path}: {exc}[/]")
            return 2
    if not lines and Path("data/targets.txt").exists() and sys.stdin.isatty():
        lines = read_lines("data/targets.txt")
        err.print("[dim]no targets given - using data/targets.txt[/]")
    errors: list[str] = []
    targets = parse_many(lines, errors)
    for e in errors[:10]:
        err.print(f"[yellow]! {e}[/]")
    if len(errors) > 10:
        err.print(f"[yellow]! … {len(errors) - 10} more invalid lines[/]")
    if not targets:
        err.print("[red]✗ no valid targets. Try: bugcod3 scan 1.1.1.1 or -i targets.txt[/]")
        return 2

    excl = list(ALWAYS_EXCLUDE)
    for item in args.exclude:
        excl += read_lines(item) if Path(item).is_file() else [item]

    db = CDNDatabase.load(ranges_path(args.ranges_file))
    try:
        only = db.resolve_names(args.only_cdn)
    except ValueError as exc:
        err.print(f"[red]✗ {exc}[/]")
        return 2

    out_dir = Path(args.output)
    jsonl_path = out_dir / "results.jsonl"
    previous = load_jsonl(jsonl_path) if args.resume else []

    cfg = ScanConfig(
        ports=args.ports,
        workers=args.workers,
        rate=args.rate,
        probe=ProbeConfig(
            mode=args.mode, timeout=args.timeout, retries=max(0, args.retries), rounds=max(1, args.rounds),
            sni=args.sni, host_header=args.host_header, path=args.path, tls_ports=set(args.tls_ports),
            verify_tls=not args.insecure, cf_trace=not args.no_trace,
        ),
        sample=max(0, args.sample),
        shuffle=args.shuffle,
        exclude=Exclusions(excl),
        only_cdn=only,
        cdn_only=args.cdn_only,
        max_latency=args.max_latency,
        enrich=not args.no_enrich,
        ptr=not args.no_ptr,
        ipv6=args.ipv6,
        nameservers=args.resolvers,
        skip={r["ip"] for r in previous if "ip" in r},
    )
    engine = ScanEngine(targets, cfg, db)
    sink = JsonlSink(jsonl_path, append=args.resume)
    engine.sinks.append(sink)
    main_task: list[asyncio.Task] = []
    if args.silent:
        def emit_ip(r):
            try:
                print(r.ip, flush=True)
            except BrokenPipeError:  # e.g. "| head": stop quietly
                devnull = os.open(os.devnull, os.O_WRONLY)
                os.dup2(devnull, sys.stdout.fileno())
                if main_task:
                    main_task[0].cancel()
        engine.sinks.append(emit_ip)

    use_ui = not (args.no_ui or args.silent) and err.is_terminal
    if not args.silent:
        ui.banner(err)
        err.print(
            f"[cyan]»[/] {len(targets)} target entries · ports [bold]{','.join(map(str, cfg.ports))}[/] · "
            f"mode [bold]{cfg.probe.mode}[/] · workers [bold]{cfg.workers}[/]"
            + (f" · rate {cfg.rate:g}/s" if cfg.rate else "")
            + (f" · SNI {cfg.probe.sni}" if cfg.probe.sni else "")
            + (f" · only {','.join(only)}" if only else "")
            + f" · CDN DB {db.updated}"
        )

    interrupted = False

    async def runner():
        nonlocal interrupted
        loop = asyncio.get_running_loop()
        main = asyncio.current_task()
        main_task.append(main)
        try:
            loop.add_signal_handler(signal.SIGINT, main.cancel)
        except (NotImplementedError, RuntimeError):
            pass
        try:
            if use_ui:
                dash = ui.Dashboard(engine)
                engine.log = dash.log
                with Live(dash, console=err, refresh_per_second=4, screen=False, transient=False):
                    await engine.run()
            else:
                if not args.silent:
                    def plain(r):
                        err.print(f"[green]+[/] {r.ip:<16} {r.latency or 0:>7.1f} ms  {r.cdn:<12} "
                                  f"ports={','.join(str(p.port) for p in r.open_ports)} {r.colo or ''}")
                    engine.sinks.append(plain)
                    engine.log = err.print
                await engine.run()
        except asyncio.CancelledError:
            interrupted = True

    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        interrupted = True
    finally:
        sink.close()

    if interrupted and not args.silent:
        err.print("[yellow]⚠ interrupted - saving partial results (resume with --resume)[/]")

    rows = previous + [r.to_dict() for r in sort_results(engine.results)]
    rows.sort(key=lambda d: (-(d.get("score") or 0), d.get("latency") or 1e9))
    meta = build_meta(engine.stats, {
        "ports": cfg.ports, "mode": cfg.probe.mode, "sni": cfg.probe.sni, "sample": cfg.sample,
        "only_cdn": only, "max_latency": cfg.max_latency,
    }, db.updated)
    formats = {f.lower() for f in args.format}
    written = [jsonl_path] + write_all(out_dir, formats, rows, meta)
    if not args.silent:
        ui.summary(err, engine, written)
    return 130 if interrupted else 0


def cmd_lookup(args, console: Console) -> int:
    from bugcod3.resolver import Resolver

    db = CDNDatabase.load(ranges_path(args.ranges_file))

    async def run():
        r = Resolver()
        rows = []
        for t in args.targets:
            try:
                ips = [str(ipaddress.ip_address(t))]
            except ValueError:
                ips = await r.resolve_host(t, ipv6=True)
                if not ips:
                    rows.append((t, "-", "unresolved", "", "", ""))
                    continue
            for ip in ips:
                cdn = db.lookup(ip)
                asn = None if args.no_asn else await r.asn(ip)
                if not cdn and asn:
                    cdn = db.by_asn(asn.asn)
                rows.append((
                    t, ip, cdn or "Unknown",
                    f"AS{asn.asn}" if asn and asn.asn else "",
                    (asn.org or "") if asn else "",
                    (asn.country or "") if asn else "",
                ))
        return rows

    table = Table(title="CDN lookup", header_style="bold cyan")
    for col in ("target", "ip", "cdn", "asn", "org", "cc"):
        table.add_column(col)
    for row in asyncio.run(run()):
        table.add_row(*row, style=None)
    console.print(table)
    return 0


def cmd_ranges(args, console: Console) -> int:
    db = CDNDatabase.load(ranges_path(args.ranges_file))
    if not args.provider:
        table = Table(title=f"CDN providers (DB {db.updated})", header_style="bold cyan")
        table.add_column("provider")
        table.add_column("ranges", justify="right")
        table.add_column("IPv4 addresses", justify="right")
        table.add_column("ASNs")
        for name, p in sorted(db.providers.items()):
            v4 = sum(n.num_addresses for n in db.networks(name) if n.version == 4)
            table.add_row(f"[{p.color}]{name}[/]", str(len(p.ranges)), f"{v4:,}", ", ".join(map(str, sorted(p.asns))))
        console.print(table)
        return 0
    try:
        (name,) = db.resolve_names([args.provider])
    except ValueError as exc:
        Console(stderr=True).print(f"[red]✗ {exc}[/]")
        return 2
    for net in db.networks(name):
        if net.version == 4 or args.v6:
            print(net)
    return 0


def cmd_update(args, console: Console) -> int:
    from bugcod3.updater import update_ranges

    target = Path(args.ranges_file) if args.ranges_file else CACHE_RANGES
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        from bugcod3.cdn import load_raw_database
        import json

        target.write_text(json.dumps(load_raw_database(None)), encoding="utf-8")
    console.print(f"[cyan]»[/] updating CDN ranges → {target}")
    update_ranges(target, log=console.print)
    console.print("[green]✓ done[/]")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # "bugcod3 1.1.1.1 -p 443" is shorthand for "bugcod3 scan 1.1.1.1 -p 443"
    lead = 2 if argv[:1] == ["--ranges-file"] else 0
    head = argv[lead:lead + 1]
    if not head or (head[0] not in COMMANDS and head[0] not in ("-h", "--help", "-V", "--version")):
        argv = argv[:lead] + ["scan"] + argv[lead:]
    args = build_parser().parse_args(argv)
    console = Console()
    err = Console(stderr=True)
    if args.command == "lookup":
        return cmd_lookup(args, console)
    if args.command == "ranges":
        return cmd_ranges(args, console)
    if args.command == "update":
        return cmd_update(args, console)
    return cmd_scan(args, console, err)