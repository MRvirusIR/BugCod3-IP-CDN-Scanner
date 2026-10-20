from bugcod3.cdn import CDNDatabase, Provider, fingerprint_headers


def make_db():
    return CDNDatabase([
        Provider("Big", "#111111", {1}, ["10.0.0.0/8"]),
        Provider("Small", "#222222", {2}, ["10.1.0.0/16", "2001:db8::/32"]),
    ])


def test_longest_prefix_wins():
    db = make_db()
    assert db.lookup("10.1.2.3") == "Small"
    assert db.lookup("10.2.2.3") == "Big"
    assert db.lookup("11.0.0.1") is None
    assert db.lookup("2001:db8::1") == "Small"
    assert db.lookup("not-an-ip") is None


def test_asn_and_names():
    db = make_db()
    assert db.by_asn(2) == "Small"
    assert db.by_asn(None) is None
    assert db.resolve_names(["big", " SMALL "]) == ["Big", "Small"]


def test_bundled_database_is_sane():
    db = CDNDatabase.load()
    assert db.lookup("104.16.0.1") == "Cloudflare"
    assert db.lookup("151.101.1.1") == "Fastly"
    # these used to be mislabelled as Netlify / BunnyCDN in v1
    assert db.lookup("13.32.0.1") == "CloudFront"
    assert db.lookup("147.75.1.1") is None
    # public DNS resolvers are not CDN edges
    assert db.lookup("8.8.8.8") in (None, "Google")


def test_header_fingerprints():
    assert fingerprint_headers({"cf-ray": "abc-IAD"}) == "Cloudflare"
    assert fingerprint_headers({"server": "AkamaiGHost"}) == "Akamai"
    assert fingerprint_headers({"x-amz-cf-id": "x"}) == "CloudFront"
    assert fingerprint_headers({"server": "nginx"}) is None
