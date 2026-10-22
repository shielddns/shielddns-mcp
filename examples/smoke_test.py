"""Quick manual test without an MCP client: python examples/smoke_test.py [domain ...]"""
import json
import sys

from shielddns_mcp import check

def main() -> None:
    domains = [a for a in sys.argv[1:] if not a.startswith("-")] or [
        "example.com",                       # resolves, DNSSEC-validated
        "doubleclick.net",                   # blocked by ShieldDNS (ads/tracking)
        "dnssec-failed.org",                 # invalid DNSSEC signature
        "this-domain-does-not-exist-shielddns.com",
        "paypal-secure-login.com",           # look-alike of a known brand
    ]
    for d in domains:
        r = check.check_domain(d)
        print(f"{d:42} verdict={r['verdict']:<28} score={r['risk_score']:>3} advice={r['advice']}")
        for reason in r["reasons"]:
            print(f"{'':44}- {reason['detail']}")
        if "--json" in sys.argv:
            print(json.dumps(r, indent=2))


if __name__ == "__main__":
    main()
