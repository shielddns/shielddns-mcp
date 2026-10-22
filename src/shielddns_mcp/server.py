"""ShieldDNS MCP server: safe domain checks and DNS resolution for AI agents.

Tools
- check_domain: is this domain/link safe to open? (ShieldDNS verdict, DNSSEC, name signals, score)
- resolve:      resolve a name through ShieldDNS (protection + DNSSEC validation)
- service_status: public status of the ShieldDNS nodes
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from . import __version__, check, dns_client, signals

STATUS_URLS = {
    "nbg1": "https://shielddns.eu/assets/fileDNSserver/shielddns-status-nbg1.json",
    "hel1": "https://shielddns.eu/assets/fileDNSserver/shielddns-status-hel1.json",
}

INSTRUCTIONS = (
    "ShieldDNS is a free European public DNS resolver with malware/phishing/tracking protection, DNSSEC "
    "validation and a zero-log policy. Before opening, fetching or recommending a link whose domain you do "
    "not already trust, call check_domain and follow its 'advice' field: do_not_open means do not visit the "
    "site and tell the user why; caution means warn the user and avoid entering credentials or payment data. "
    "A 'does_not_exist' verdict often means the link is mistyped or invented."
)

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=True)

mcp = MCPServer(
    name="shielddns",
    title="ShieldDNS",
    instructions=INSTRUCTIONS,
    website_url="https://www.shielddns.eu",
    version=__version__,
)


@mcp.tool(
    title="Check a domain or link",
    description=(
        "Check whether a domain or URL is safe to open, using the ShieldDNS protective resolver. Returns a verdict "
        "(blocked, dnssec_invalid, does_not_exist, resolves...), a 0-100 risk score with human-readable reasons "
        "(blocklist match, DNSSEC, look-alike of known brands, mixed scripts, random-looking names) and an advice "
        "field (ok_to_open, caution, do_not_open). Accepts a bare domain or a full URL."
    ),
    annotations=READ_ONLY,
)
def check_domain(domain_or_url: str) -> dict:
    try:
        return check.check_domain(domain_or_url)
    except signals.InvalidDomain as exc:
        return {"error": "invalid_domain", "detail": str(exc)}


@mcp.tool(
    title="Resolve a DNS name through ShieldDNS",
    description=(
        "Resolve a DNS name through ShieldDNS (DNS-over-HTTPS, DNSSEC validation, threat blocking). "
        f"record_type is one of: {', '.join(dns_client.ALLOWED_TYPES)}. Returns records, rcode, whether the "
        "answer was DNSSEC-validated, whether ShieldDNS blocked the name, and any Extended DNS Errors (RFC 8914)."
    ),
    annotations=READ_ONLY,
)
def resolve(name: str, record_type: str = "A") -> dict:
    try:
        domain = signals.normalize(name)
        return dns_client.query(domain, record_type).as_dict()
    except (signals.InvalidDomain, ValueError) as exc:
        return {"error": "invalid_request", "detail": str(exc)}
    except dns_client.ResolverUnavailable as exc:
        return {"error": "resolver_unavailable", "detail": str(exc)}


@mcp.tool(
    title="ShieldDNS service status",
    description="Public status of the two ShieldDNS nodes (each node checks the other every 5 minutes).",
    annotations=READ_ONLY,
)
def service_status() -> dict:
    out = {}
    now = time.time()
    with httpx.Client(timeout=8.0, follow_redirects=True) as client:
        for node, url in STATUS_URLS.items():
            try:
                data = client.get(url, params={"t": int(now)}).json()
                gen = datetime.fromisoformat(str(data.get("generated", "")).replace("Z", "+00:00"))
                age_min = int((datetime.now(timezone.utc) - gen).total_seconds() // 60)
                out[node] = {
                    "host": data.get("host"),
                    "self_status": data.get("self", {}).get("status"),
                    "seen_by_other_node": (data.get("peer") or {}).get("status"),
                    "data_age_minutes": age_min,
                    "security_updates": (data.get("security_updates") or {}).get("status"),
                    "blocklist_domains": (data.get("blocklist") or {}).get("domains"),
                }
            except Exception as exc:
                out[node] = {"error": type(exc).__name__}
    # each file describes the OTHER node from the outside: report it under that node
    for node, other in (("nbg1", "hel1"), ("hel1", "nbg1")):
        if "seen_by_other_node" in out.get(other, {}):
            out.setdefault(node, {})["external_check"] = out[other].pop("seen_by_other_node")
    return {"nodes": out, "status_page": "https://www.shielddns.eu/it/stato.html"}


def main() -> None:
    mcp.run("stdio")


if __name__ == "__main__":
    main()
