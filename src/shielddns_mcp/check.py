"""Domain check: ShieldDNS verdict + name-only signals -> risk score 0-100 with reasons."""

from __future__ import annotations

from . import dns_client, signals

LEVELS = ((75, "very_high"), (50, "high"), (25, "medium"), (0, "low"))
ADVICE = {
    "very_high": "do_not_open",
    "high": "do_not_open",
    "medium": "caution",
    "low": "ok_to_open",
}


def _level(score: int) -> str:
    return next(name for limit, name in LEVELS if score >= limit)


def check_domain(value: str) -> dict:
    domain = signals.normalize(value)
    names = signals.analyze(domain)
    reasons: list[dict] = []
    score = 0

    try:
        a = dns_client.query(domain, "A")
    except dns_client.ResolverUnavailable as exc:
        score = min(100, sum(sgn["weight"] for sgn in names.signals))
        level = _level(score)
        return {
            "domain": domain, "display_name": names.unicode, "registrable_domain": names.registrable,
            "verdict": "unknown_resolver_unavailable", "risk_score": score, "risk_level": level,
            "advice": "caution" if level == "low" else ADVICE[level],
            "reasons": names.signals + [{"code": "resolver_unavailable", "weight": 0, "detail": str(exc)}],
            "note": "ShieldDNS could not be reached: only name-based signals were evaluated.",
        }
    addresses = [r.split()[-1] for r in a.records if " A " in r]
    if a.rcode == "NOERROR" and not addresses:
        aaaa = dns_client.query(domain, "AAAA")
        addresses = [r.split()[-1] for r in aaaa.records if " AAAA " in r]

    if a.blocked:
        verdict = "blocked"
        score = max(score, 90)
        text = next((e["text"] for e in a.ede if e["code"] in (15, 17)), "")
        reasons.append({"code": "shielddns_blocklist", "weight": 90,
                        "detail": "ShieldDNS blocks this domain (threat-intelligence, ads or tracking lists)" + (f": {text}" if text else "")})
    elif a.dnssec_bogus:
        verdict = "dnssec_invalid"
        score = max(score, 95)
        codes = ", ".join(f"EDE {e['code']}" + (f" {e['text']}" if e["text"] else "") for e in a.ede)
        reasons.append({"code": "dnssec_invalid", "weight": 95,
                        "detail": f"the DNSSEC signature is invalid: the answer may have been tampered with ({codes})"})
    elif a.rcode == "NXDOMAIN":
        verdict = "does_not_exist"
        reasons.append({"code": "nxdomain", "weight": 0,
                        "detail": "the domain does not exist: it may be a typo or a hallucinated/invented link"})
    elif a.rcode == "SERVFAIL":
        verdict = "resolution_failed"
        reasons.append({"code": "servfail", "weight": 0, "detail": "the domain could not be resolved right now"})
    else:
        verdict = "resolves" if addresses else "exists_no_address"

    for sgn in names.signals:
        reasons.append(sgn)
    if verdict not in ("blocked", "dnssec_invalid"):
        score = min(100, score + sum(sgn["weight"] for sgn in names.signals))
        if a.authenticated and score > 0:
            score = max(0, score - 5)
            reasons.append({"code": "dnssec_signed", "weight": -5, "detail": "the zone is DNSSEC-signed and validated"})

    level = _level(score)
    return {
        "domain": domain,
        "display_name": names.unicode,
        "registrable_domain": names.registrable,
        "verdict": verdict,
        "risk_score": score,
        "risk_level": level,
        "advice": ("do_not_open" if verdict in ("blocked", "dnssec_invalid")
                   else "caution" if verdict in ("does_not_exist", "resolution_failed", "exists_no_address") and level == "low"
                   else ADVICE[level]),
        "reasons": reasons,
        "dnssec": "validated" if a.authenticated else ("invalid" if a.dnssec_bogus else "not validated (unsigned or unavailable)"),
        "addresses": addresses[:6],
        "resolver": a.endpoint,
        "note": "Risk score v1: ShieldDNS blocklist verdict, DNSSEC and signals computed from the name only. "
                "No query is logged by ShieldDNS (zero-log).",
    }
