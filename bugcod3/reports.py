"""Report writers: streaming JSONL plus JSON, CSV, TXT and an interactive HTML report."""

from __future__ import annotations

import csv
import json
import time
from importlib import resources
from pathlib import Path
from typing import Iterable

from jinja2 import Environment, select_autoescape

from bugcod3 import __version__
from bugcod3.engine import HostResult, Stats

CSV_FIELDS = [
    "ip", "score", "latency", "cdn", "cdn_method", "colo", "open_ports", "asn", "asn_org",
    "country", "ptr", "hostname", "status", "server", "tls_version", "source",
]


def sort_results(results: Iterable[HostResult]) -> list[HostResult]:
    return sorted(results, key=lambda r: (-(r.score or 0), r.latency if r.latency is not None else 1e9))


class JsonlSink:
    """Writes every result the moment it is found, so Ctrl+C never loses work."""

    def __init__(self, path: Path, append: bool = False):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._fh = path.open("a" if append else "w", encoding="utf-8")

    def __call__(self, r: HostResult) -> None:
        self._fh.write(json.dumps(r.to_dict(), ensure_ascii=False) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _row(d: dict) -> dict:
    ports = d.get("ports") or [{}]
    answered = [p for p in ports if p.get("status") is not None]
    best = min(answered or ports, key=lambda p: p.get("latency") or 1e9)
    tls = next((p.get("tls_version") for p in ports if p.get("tls_version")), None)
    asn = d.get("asn") or {}
    return {
        "ip": d.get("ip"),
        "score": d.get("score"),
        "latency": d.get("latency"),
        "cdn": d.get("cdn"),
        "cdn_method": d.get("cdn_method"),
        "colo": d.get("colo"),
        "open_ports": " ".join(str(p) for p in d.get("open_ports", [])),
        "asn": asn.get("asn"),
        "asn_org": asn.get("org"),
        "country": asn.get("country"),
        "ptr": d.get("ptr"),
        "hostname": d.get("hostname"),
        "status": best.get("status"),
        "server": best.get("server"),
        "tls_version": tls,
        "source": d.get("source"),
    }


def _csv_safe(v):
    """Neutralise spreadsheet formula injection (PTR / Server values are attacker-controlled)."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def build_meta(stats: Stats, args_summary: dict, cdn_updated: str) -> dict:
    return {
        "tool": "BugCod3 IP CDN Scanner",
        "version": __version__,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed": round(stats.elapsed, 2),
        "scanned": stats.scanned,
        "alive": stats.alive,
        "rate": round(stats.rate, 1),
        "excluded": stats.excluded,
        "filtered": stats.filtered,
        "cdns": dict(stats.cdns.most_common()),
        "ports": {str(k): v for k, v in stats.ports.most_common()},
        "cdn_db_updated": cdn_updated,
        "options": args_summary,
    }


def write_json(path: Path, rows: list[dict], meta: dict) -> None:
    path.write_text(json.dumps({"meta": meta, "results": rows}, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        for d in rows:
            w.writerow({k: _csv_safe(v) for k, v in _row(d).items()})


def write_txt(path: Path, rows: list[dict], with_port: bool = False) -> None:
    lines = []
    for d in rows:
        if with_port:
            lines += [f"{d['ip']}:{p}" for p in d.get("open_ports", [])]
        else:
            lines.append(d["ip"])
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def write_html(path: Path, rows: list[dict], meta: dict) -> None:
    env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
    template = resources.files("bugcod3").joinpath("templates/report.html").read_text(encoding="utf-8")
    html = env.from_string(template).render(
        meta=meta,
        rows=[_row(d) | {"cdn_color": d.get("cdn_color", "#64748b")} for d in rows],
    )
    path.write_text(html, encoding="utf-8")


def write_all(out_dir: Path, formats: set[str], rows: list[dict], meta: dict) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    if "json" in formats:
        p = out_dir / "report.json"
        write_json(p, rows, meta)
        written.append(p)
    if "csv" in formats:
        p = out_dir / "report.csv"
        write_csv(p, rows)
        written.append(p)
    if "txt" in formats:
        p = out_dir / "clean_ips.txt"
        write_txt(p, rows)
        written.append(p)
        p2 = out_dir / "clean_ip_ports.txt"
        write_txt(p2, rows, with_port=True)
        written.append(p2)
    if "html" in formats:
        p = out_dir / "report.html"
        write_html(p, rows, meta)
        written.append(p)
    return written