import asyncio

import dns.edns
import dns.flags
import dns.message
import dns.rcode
import dns.rrset
import pytest

from shielddns_mcp import check, dns_client, signals


def make_resp(name, rtype="A", rcode="NOERROR", aa=False, ad=False, answers=(), soa=False, ede=None):
    q = dns.message.make_query(name, rtype, want_dnssec=True, use_edns=0)
    r = dns.message.make_response(q)
    r.set_rcode(dns.rcode.from_text(rcode))
    if aa:
        r.flags |= dns.flags.AA
    if ad:
        r.flags |= dns.flags.AD
    for a in answers:
        r.answer.append(dns.rrset.from_text(name, 300, "IN", rtype, a))
    if soa:
        r.authority.append(dns.rrset.from_text("com.", 900, "IN", "SOA",
                                               "a.gtld-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 900"))
    if ede:
        r.use_edns(0, options=[dns.edns.EDEOption(ede[0], ede[1])])
    return r


@pytest.fixture
def fake_dns(monkeypatch):
    table = {}

    def fake_query(name, rtype="A"):
        resp = table.get((name, rtype)) or make_resp(name, rtype, answers=())
        return dns_client.parse_response(name, rtype, resp, "https://test/dns-query")

    monkeypatch.setattr(dns_client, "query", fake_query)
    return table


def test_normalize_url_and_idn():
    assert signals.normalize("https://WWW.Example.com:8443/path?q=1") == "www.example.com"
    assert signals.normalize("user@example.org/x") == "example.org"
    assert signals.normalize("аpple.com").startswith("xn--")
    with pytest.raises(signals.InvalidDomain):
        signals.normalize("not a domain")


@pytest.mark.parametrize("name,code", [
    ("paypa1.com", "brand_lookalike"),
    ("paypal-secure-login.com", "brand_with_lure_words"),
    ("paypal.com.verify-account.net", "brand_in_subdomain"),
    ("xn--pple-43d.com", "mixed_scripts"),
    ("xkqjzvbtrwmpl.com", "random_looking"),
])
def test_name_signals(name, code):
    assert code in [s["code"] for s in signals.analyze(name).signals]


@pytest.mark.parametrize("name", ["www.paypal.com", "sites.google.com", "evil.github.io", "amazon.co.uk", "shielddns.eu"])
def test_no_false_brand_signal(name):
    codes = [s["code"] for s in signals.analyze(name).signals]
    assert not any(c.startswith("brand") for c in codes)


def test_blocked_by_ede(fake_dns):
    fake_dns[("doubleclick.net", "A")] = make_resp("doubleclick.net", rcode="NXDOMAIN", aa=True,
                                                   ede=(15, "ShieldDNS: blocked"))
    r = check.check_domain("https://doubleclick.net/ads")
    assert r["verdict"] == "blocked" and r["advice"] == "do_not_open" and r["risk_score"] >= 90


def test_blocked_without_ede_fallback(fake_dns):
    fake_dns[("tracker.example", "A")] = make_resp("tracker.example", rcode="NXDOMAIN", aa=True)
    assert check.check_domain("tracker.example")["verdict"] == "blocked"


def test_nonexistent_is_not_blocked(fake_dns):
    fake_dns[("nope-12345.com", "A")] = make_resp("nope-12345.com", rcode="NXDOMAIN", soa=True)
    r = check.check_domain("nope-12345.com")
    assert r["verdict"] == "does_not_exist" and r["risk_level"] == "low" and r["advice"] == "caution"


def test_dnssec_bogus(fake_dns):
    fake_dns[("dnssec-failed.org", "A")] = make_resp("dnssec-failed.org", rcode="SERVFAIL", ede=(6, ""))
    r = check.check_domain("dnssec-failed.org")
    assert r["verdict"] == "dnssec_invalid" and r["advice"] == "do_not_open"


def test_good_domain(fake_dns):
    fake_dns[("example.com", "A")] = make_resp("example.com", ad=True, answers=["93.184.216.34"])
    r = check.check_domain("example.com")
    assert r["verdict"] == "resolves" and r["advice"] == "ok_to_open" and r["dnssec"] == "validated"
    assert r["addresses"] == ["93.184.216.34"]


def test_lookalike_that_resolves(fake_dns):
    fake_dns[("paypal-secure-login.com", "A")] = make_resp("paypal-secure-login.com", answers=["203.0.113.7"])
    r = check.check_domain("paypal-secure-login.com")
    assert r["verdict"] == "resolves" and r["advice"] != "ok_to_open"


def test_resolve_rejects_unknown_type():
    from shielddns_mcp import server
    assert server.resolve("example.com", "ANY")["error"] == "invalid_request"


def test_tools_registered():
    from shielddns_mcp import server
    tools = asyncio.run(server.mcp.list_tools())
    names = {t.name for t in tools}
    assert {"check_domain", "resolve", "service_status"} <= names
    assert all(t.annotations and t.annotations.read_only_hint for t in tools)


def test_offline_still_gives_name_signals(monkeypatch):
    def down(name, rtype="A"):
        raise dns_client.ResolverUnavailable("offline")
    monkeypatch.setattr(dns_client, "query", down)
    r = check.check_domain("paypa1.com")
    assert r["verdict"] == "unknown_resolver_unavailable" and r["advice"] != "ok_to_open"


def test_http2_support_installed():
    import h2  # noqa: F401  (httpx[http2]: dnsdist DoH speaks HTTP/2)


def test_real_doh_path_with_mock_transport(monkeypatch):
    import httpx

    def handler(request):
        assert request.method == "POST" and request.headers["content-type"] == "application/dns-message"
        q = dns.message.from_wire(request.content)
        assert q.id == 0
        r = dns.message.make_response(q)
        r.set_rcode(dns.rcode.NXDOMAIN)
        r.flags |= dns.flags.AA
        r.use_edns(0, options=[dns.edns.EDEOption(15, "ShieldDNS: blocked")])
        return httpx.Response(200, content=r.to_wire(), headers={"content-type": "application/dns-message"})

    monkeypatch.setattr(dns_client, "_TRANSPORT", httpx.MockTransport(handler))
    a = dns_client.query("doubleclick.net", "A")
    assert a.blocked and a.ede[0]["code"] == 15 and a.endpoint.startswith("https://secure2.")


def test_failover_to_second_node(monkeypatch):
    import httpx
    calls = []

    def handler(request):
        calls.append(request.url.host)
        if request.url.host.startswith("secure2."):
            raise httpx.ConnectError("down")
        q = dns.message.from_wire(request.content)
        r = dns.message.make_response(q)
        r.answer.append(dns.rrset.from_text("example.com.", 300, "IN", "A", "93.184.216.34"))
        return httpx.Response(200, content=r.to_wire(), headers={"content-type": "application/dns-message"})

    monkeypatch.setattr(dns_client, "_TRANSPORT", httpx.MockTransport(handler))
    a = dns_client.query("example.com", "A")
    assert calls == ["secure2.shielddns.eu", "secure.shielddns.eu"] and a.records
