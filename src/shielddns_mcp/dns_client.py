"""DNS-over-HTTPS client for the ShieldDNS public resolvers.

Only DNS queries are sent, only to ShieldDNS, over HTTPS. Nothing else leaves the machine.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import dns.edns
import httpx
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype

# hel1 first: it adds Extended DNS Error 15 "Blocked" to blocklist answers.
DEFAULT_ENDPOINTS = (
    "https://secure2.shielddns.eu/dns-query",
    "https://secure.shielddns.eu/dns-query",
)

ALLOWED_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "HTTPS", "SVCB", "TLSA", "DS", "DNSKEY", "PTR", "SRV")

EDE_BLOCKED = 15
EDE_FILTERED = 17
EDE_DNSSEC = {1, 2, 5, 6, 7, 8, 9, 10, 11, 12}  # RFC 8914 DNSSEC-related codes


class ResolverUnavailable(RuntimeError):
    pass


@dataclass
class Answer:
    name: str
    rtype: str
    rcode: str
    endpoint: str
    authenticated: bool                    # AD flag: DNSSEC validated by ShieldDNS
    authoritative: bool                    # AA flag (ShieldDNS local zones answer with AA)
    authority_count: int
    records: list[str] = field(default_factory=list)
    ede: list[dict] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        """True if ShieldDNS blocked the name.

        Preferred signal: EDE 15/17. Fallback for nodes without EDE: NXDOMAIN with no record in the
        AUTHORITY section (ShieldDNS block zones carry no SOA, real non-existent names do).
        """
        if any(e["code"] in (EDE_BLOCKED, EDE_FILTERED) for e in self.ede):
            return True
        return self.rcode == "NXDOMAIN" and self.authority_count == 0

    @property
    def dnssec_bogus(self) -> bool:
        return self.rcode == "SERVFAIL" and any(e["code"] in EDE_DNSSEC for e in self.ede)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.rtype,
            "rcode": self.rcode,
            "blocked_by_shielddns": self.blocked,
            "dnssec": "validated" if self.authenticated else ("invalid" if self.dnssec_bogus else "not validated (unsigned or unavailable)"),
            "records": self.records,
            "extended_errors": self.ede,
            "resolver": self.endpoint,
        }


def endpoints() -> tuple[str, ...]:
    env = os.environ.get("SHIELDDNS_DOH", "").strip()
    if env:
        return tuple(e.strip() for e in env.split(",") if e.strip().startswith("https://"))
    return DEFAULT_ENDPOINTS


def _timeout() -> float:
    try:
        return max(1.0, min(30.0, float(os.environ.get("SHIELDDNS_TIMEOUT", "6"))))
    except ValueError:
        return 6.0


def parse_response(name: str, rtype: str, resp: dns.message.Message, endpoint: str) -> Answer:
    ede = []
    for opt in resp.options:
        if isinstance(opt, dns.edns.EDEOption):
            ede.append({"code": int(opt.code), "text": opt.text or ""})
    records = []
    for rrset in resp.answer:
        if rrset.rdtype == dns.rdatatype.RRSIG:
            continue
        for rd in rrset:
            records.append(f"{rrset.name} {rrset.ttl} {dns.rdatatype.to_text(rrset.rdtype)} {rd.to_text()}")
    return Answer(
        name=name,
        rtype=rtype,
        rcode=dns.rcode.to_text(resp.rcode()),
        endpoint=endpoint,
        authenticated=bool(resp.flags & dns.flags.AD),
        authoritative=bool(resp.flags & dns.flags.AA),
        authority_count=sum(len(r) for r in resp.authority),
        records=records,
        ede=ede,
    )


def query(name: str, rtype: str = "A") -> Answer:
    rtype = rtype.upper()
    if rtype not in ALLOWED_TYPES:
        raise ValueError(f"unsupported record type {rtype!r}; allowed: {', '.join(ALLOWED_TYPES)}")
    q = dns.message.make_query(name, rtype, want_dnssec=True, use_edns=0, payload=1232)
    q.id = 0  # RFC 8484: DoH clients should use ID 0
    wire = q.to_wire()
    errors = []
    with _client() as client:
        for ep in endpoints():
            try:
                r = client.post(ep, content=wire, headers=DOH_HEADERS)
                r.raise_for_status()
                if not r.headers.get("content-type", "").startswith("application/dns-message"):
                    raise ValueError(f"unexpected content type {r.headers.get('content-type')!r}")
                return parse_response(name, rtype, dns.message.from_wire(r.content), ep)
            except Exception as exc:  # network, TLS, HTTP or parsing error: try the next node
                errors.append(f"{ep}: {type(exc).__name__}: {str(exc)[:80]}")
    raise ResolverUnavailable("ShieldDNS not reachable (" + "; ".join(errors) + ")")


DOH_HEADERS = {"content-type": "application/dns-message", "accept": "application/dns-message"}
_TRANSPORT = None  # tests can inject an httpx transport


def _client() -> httpx.Client:
    # DNS-over-HTTPS (RFC 8484) over HTTP/2, certificate always verified
    return httpx.Client(http2=True, timeout=_timeout(), transport=_TRANSPORT,
                        headers={"user-agent": "shielddns-mcp"}, follow_redirects=False)
