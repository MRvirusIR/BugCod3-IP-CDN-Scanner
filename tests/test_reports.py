import json

from bugcod3.cli import parse_ports
from bugcod3.engine import HostResult, Stats
from bugcod3.probe import PortResult, parse_cf_trace, parse_http_head
from bugcod3.reports import build_meta, write_all


def _result(ptr):
    return HostResult(ip="1.2.3.4", source="t", ptr=ptr, cdn="Cloudflare",
                      ports=[PortResult(port=443, open=True, latency=12.0, scheme="https", tls=True, status=200)])


def test_html_report_escapes_untrusted_values(tmp_path):
    evil = '</script><img src=x onerror=alert(1)>'
    rows = [_result(evil).to_dict()]
    write_all(tmp_path, {"html", "csv", "json", "txt"}, rows, build_meta(Stats(), {}, "test"))
    html = (tmp_path / "report.html").read_text()
    assert "</script><img" not in html
    assert "onerror=alert(1)>" not in html.split('<script id="data"')[0]
    assert json.loads((tmp_path / "report.json").read_text())["results"][0]["ip"] == "1.2.3.4"
    assert (tmp_path / "clean_ips.txt").read_text() == "1.2.3.4\n"


def test_csv_formula_injection_is_neutralised(tmp_path):
    rows = [_result("=HYPERLINK(\"http://x\")").to_dict()]
    write_all(tmp_path, {"csv"}, rows, build_meta(Stats(), {}, "test"))
    assert "'=HYPERLINK" in (tmp_path / "report.csv").read_text()


def test_score_prefers_fast_healthy_hosts():
    fast = _result(None)
    slow = HostResult(ip="5.6.7.8", source="t", ports=[PortResult(port=443, open=True, latency=400.0, jitter=50)])
    assert fast.score > slow.score


def test_parsers():
    status, headers = parse_http_head(b"HTTP/1.1 301 Moved\r\nServer: cloudflare\r\nCF-RAY: 1-IAD\r\n\r\n")
    assert status == 301 and headers["server"] == "cloudflare" and "cf-ray" in headers
    assert parse_cf_trace("fl=1\ncolo=FRA\nloc=DE\nip=1.2.3.4\n") == {"fl": "1", "colo": "FRA", "loc": "DE"}
    assert parse_ports("80,443,8000-8002") == [80, 443, 8000, 8001, 8002]
    assert 2053 in parse_ports("cf")
