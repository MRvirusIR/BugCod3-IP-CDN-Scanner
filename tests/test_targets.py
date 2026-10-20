import ipaddress
import random

import pytest

from bugcod3.targets import Exclusions, estimate_total, iter_network, parse_many, parse_target


@pytest.mark.parametrize("line,kind", [
    ("1.1.1.1", "ip"),
    ("  1.1.1.1  # comment", "ip"),
    ("2606:4700::1111", "ip"),
    ("104.16.0.0/24", "net"),
    ("1.1.1.1-1.1.1.9", "range"),
    ("1.1.1.1-9", "range"),
    ("Example.COM", "domain"),
    ("https://example.com:8443/path", "domain"),
    ("1.1.1.1:443", "ip"),
    ("[2606:4700::1111]:443", "ip"),
])
def test_parse_kinds(line, kind):
    assert parse_target(line).kind == kind


def test_comments_and_blank_lines_are_skipped():
    assert parse_target("# hello") is None
    assert parse_target("   ") is None


def test_invalid_lines_are_reported_not_raised():
    errors = []
    out = parse_many(["1.1.1.1", "999.1.1.1/8", "not a host!", "1.1.1.9-1.1.1.1"], errors)
    assert [t.raw for t in out] == ["1.1.1.1"]
    assert len(errors) == 3


def test_network_iteration_skips_network_and_broadcast():
    ips = list(iter_network(ipaddress.ip_network("10.0.0.0/30")))
    assert [str(i) for i in ips] == ["10.0.0.1", "10.0.0.2"]


def test_sampling_per_slash24():
    net = ipaddress.ip_network("10.0.0.0/22")
    ips = list(iter_network(net, sample=3, rng=random.Random(1)))
    assert len(ips) == 12
    assert len({str(i).rsplit(".", 1)[0] for i in ips}) == 4
    assert estimate_total(parse_many(["10.0.0.0/22"]), sample=3) == 12


def test_exclusions():
    ex = Exclusions(["10.0.0.0/8", "garbage", "# c"])
    assert ipaddress.ip_address("10.1.2.3") in ex
    assert ipaddress.ip_address("11.1.2.3") not in ex
