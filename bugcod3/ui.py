"""Rich terminal UI: banner, live dashboard and final summary."""

from __future__ import annotations

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text

from bugcod3 import __version__
from bugcod3.engine import ScanEngine, Stats

BANNER = r"""
 ____              ____          _ _____
| __ ) _   _  __ _/ ___|___   __| |___ /
|  _ \| | | |/ _` | |   / _ \ / _` | |_ \
| |_) | |_| | (_| | |__| (_) | (_| |___) |
|____/ \__,_|\__, |\____\___/ \__,_|____/
             |___/   IP · CDN · Edge Scanner
"""


def banner(console: Console) -> None:
    t = Text(BANNER, style="bold cyan")
    t.append(f"\n  v{__version__}  ·  t.me/BugCod3  ·  authorised testing only\n", style="dim")
    console.print(t)


def _fmt_time(sec: float | None) -> str:
    if sec is None:
        return "--:--"
    sec = int(sec)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def _lat_style(v: float | None) -> str:
    if v is None:
        return "dim"
    return "green" if v < 80 else "yellow" if v < 200 else "red"


class Dashboard:
    def __init__(self, engine: ScanEngine):
        self.engine = engine
        self.logs: list[str] = []

    def log(self, msg: str) -> None:
        self.logs.append(msg)
        del self.logs[:-6]

    def __rich__(self):
        s: Stats = self.engine.stats
        total = max(s.total, s.scanned, 1)
        pct = s.scanned / total * 100

        head = Table.grid(expand=True)
        head.add_column(ratio=3)
        head.add_column(justify="right", ratio=2)
        head.add_row(
            ProgressBar(total=total, completed=s.scanned, complete_style="cyan", finished_style="green"),
            Text(f"{pct:5.1f}%  {s.scanned:,}/{total:,}", style="bold"),
        )

        kpi = Table.grid(expand=True, padding=(0, 2))
        for _ in range(6):
            kpi.add_column(justify="center")
        kpi.add_row(*(Text(k, style="dim") for k in ("elapsed", "eta", "speed", "alive", "hit-rate", "errors")))
        hit = (s.alive / s.scanned * 100) if s.scanned else 0
        kpi.add_row(
            Text(_fmt_time(s.elapsed), style="bold"),
            Text(_fmt_time(s.eta), style="bold"),
            Text(f"{s.rate:,.0f} ip/s", style="bold cyan"),
            Text(f"{s.alive:,}", style="bold green"),
            Text(f"{hit:.1f}%", style="bold"),
            Text(str(s.errors), style="bold red" if s.errors else "bold"),
        )

        cdn = Table(box=box.SIMPLE_HEAD, expand=True, show_edge=False)
        cdn.add_column("CDN")
        cdn.add_column("hosts", justify="right")
        cdn.add_column("", ratio=1)
        top = s.cdns.most_common(8)
        peak = max([n for _, n in top] or [1])
        for name, n in top:
            color = self.engine.db.color(name)
            cdn.add_row(Text(name, style=f"bold {color}"), str(n), Text("█" * max(1, int(n / peak * 18)), style=color))
        if not top:
            cdn.add_row(Text("waiting for hits…", style="dim"), "", "")

        best = Table(box=box.SIMPLE_HEAD, expand=True, show_edge=False)
        for col, just in (("IP", "left"), ("ms", "right"), ("score", "right"), ("CDN", "left"), ("PoP", "left"), ("ports", "left")):
            best.add_column(col, justify=just)
        for r in s.top[:10]:
            best.add_row(
                Text(r.ip, style="bold"),
                Text(f"{r.latency:.0f}" if r.latency is not None else "-", style=_lat_style(r.latency)),
                f"{r.score:.0f}" if r.score is not None else "-",
                Text(r.cdn, style=r.cdn_color),
                r.colo or "-",
                ",".join(str(p.port) for p in r.open_ports),
            )
        if not s.top:
            best.add_row(Text("no results yet", style="dim"), "", "", "", "", "")

        layout = Layout()
        layout.split_column(
            Layout(Panel(Group(head, Text(""), kpi), title="[bold cyan]🧠 BugCod3 Scanner", border_style="cyan"), size=7),
            Layout(name="body"),
            Layout(Panel(Text.from_markup("\n".join(self.logs) or "[dim]–[/]"), title="log", border_style="grey30"), size=6),
        )
        layout["body"].split_row(
            Layout(Panel(cdn, title="CDN distribution", border_style="magenta"), ratio=2),
            Layout(Panel(best, title="⚡ Fastest clean IPs", border_style="green"), ratio=3),
        )
        return layout


def summary(console: Console, engine: ScanEngine, written: list) -> None:
    s = engine.stats
    t = Table(box=box.ROUNDED, show_header=False, border_style="cyan")
    t.add_column(style="dim")
    t.add_column(style="bold")
    t.add_row("Scanned", f"{s.scanned:,}")
    t.add_row("Alive", f"[green]{s.alive:,}[/]")
    t.add_row("Duration", _fmt_time(s.elapsed))
    t.add_row("Avg speed", f"{s.rate:,.0f} ip/s")
    if s.excluded:
        t.add_row("Excluded", f"{s.excluded:,}")
    if s.filtered:
        t.add_row("Filtered (CDN)", f"{s.filtered:,}")
    if s.cdns:
        t.add_row("CDNs", ", ".join(f"{k} ({v})" for k, v in s.cdns.most_common()))
    for p in written:
        t.add_row("Saved", str(p))
    console.print(Align.left(Panel(t, title="[bold green]✓ Scan complete", border_style="green", expand=False)))