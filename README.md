# ShieldDNS MCP server

Let AI agents check a link **before** opening it.

`shielddns-mcp` is a small, open-source [Model Context Protocol](https://modelcontextprotocol.io) server that gives AI assistants and agents (Claude, Cursor, any MCP client) safe DNS tools backed by [ShieldDNS](https://www.shielddns.eu), a free European public resolver with malware / phishing / tracking protection, DNSSEC validation and a **zero-log** policy.

*Italiano più sotto.*

## Tools

| Tool | What it does |
|---|---|
| `check_domain(domain_or_url)` | Is this domain or link safe to open? Returns a **verdict** (`blocked`, `dnssec_invalid`, `does_not_exist`, `resolves`…), a **0-100 risk score with human-readable reasons** and an **advice** field: `ok_to_open`, `caution` or `do_not_open`. |
| `resolve(name, record_type)` | Resolve a name through ShieldDNS (DNS-over-HTTPS): records, rcode, DNSSEC validation, whether ShieldDNS blocked it, Extended DNS Errors (RFC 8914). Types: A, AAAA, CNAME, MX, TXT, NS, SOA, CAA, HTTPS, SVCB, TLSA, DS, DNSKEY, PTR, SRV. |
| `service_status()` | Public status of the two ShieldDNS nodes (each node checks the other every 5 minutes). |

The server also gives the agent short instructions: check unfamiliar domains before visiting them and follow the `advice` field.

### What the risk score looks at (v0.1)

- **ShieldDNS blocklist**: about 955,000 domains from 8 threat-intelligence, ads and tracking sources. ShieldDNS marks blocked answers with **Extended DNS Error 15 "Blocked"**; on nodes without EDE the server recognises the block from the answer itself (NXDOMAIN without SOA).
- **DNSSEC**: validated, unsigned, or **invalid signature** (possible tampering, EDE 6-12).
- **Name-only signals**, computed locally:
  - look-alikes of frequently impersonated brands (`paypa1.com`, `arnazon.com`, `paypal-secure-login.com`, `paypal.com.verify-account.net`);
  - mixed scripts and IDN tricks (`аpple.com` with a Cyrillic "а");
  - random-looking names typical of malware domain generation algorithms (DGA);
  - very long or heavily hyphenated names.
- `does_not_exist` is reported separately: for an agent it often means a **mistyped or hallucinated link**.

Example:

```json
{
  "domain": "paypal-secure-login.com",
  "verdict": "resolves",
  "risk_score": 40,
  "risk_level": "medium",
  "advice": "caution",
  "reasons": [
    {"code": "brand_with_lure_words", "weight": 40,
     "detail": "the name evokes the brand \"paypal\" but is not one of its official domains (paypal.com, paypal.me)"}
  ],
  "dnssec": "not validated (unsigned or unavailable)"
}
```

## Privacy

- The server runs **on your machine**. It sends **only DNS queries, only to ShieldDNS**, over HTTPS (`secure2.shielddns.eu`, fallback `secure.shielddns.eu`). `service_status` additionally downloads the public status files from `shielddns.eu`.
- **ShieldDNS does not log queries or client IP addresses.**
- No telemetry, no accounts, no API keys.

## Install

Requires [uv](https://docs.astral.sh/uv/) (`brew install uv` on macOS, or `curl -LsSf https://astral.sh/uv/install.sh | sh`).

From GitHub:

```bash
uvx --from git+https://github.com/shielddns/shielddns-mcp shielddns-mcp
```

From a local copy:

```bash
uvx --from /path/to/shielddns-mcp shielddns-mcp
```

The server speaks MCP over stdio: run it from an MCP client, not by hand.

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "shielddns": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/shielddns/shielddns-mcp", "shielddns-mcp"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add shielddns -- uvx --from git+https://github.com/shielddns/shielddns-mcp shielddns-mcp
```

### Cursor and other clients

Use the same `command` / `args` as above in the client's MCP configuration.

### Test without an MCP client

```bash
cd shielddns-mcp
uv run --with . python examples/smoke_test.py
uv run --with . python examples/smoke_test.py some-domain.example --json
```

Or with the MCP Inspector: `npx @modelcontextprotocol/inspector uvx --from . shielddns-mcp`

### Configuration (optional)

| Variable | Default | Meaning |
|---|---|---|
| `SHIELDDNS_DOH` | `https://secure2.shielddns.eu/dns-query,https://secure.shielddns.eu/dns-query` | DoH endpoints, tried in order |
| `SHIELDDNS_TIMEOUT` | `6` | seconds per query |

## Limits

- The score is a **decision aid**, not a guarantee. A clean result does not mean a site is trustworthy; a `caution` result can be a false positive (e.g. a legitimate site that mentions a brand).
- The brand list is small and curated (`signals.py`); contributions welcome.
- Coming next: a server-side ShieldDNS risk API (domain age, threat source categories, more brands), used automatically by this server when available.

## Development

```bash
uv run --with '.[test]' pytest
```

License: MIT.

---

## Italiano

**ShieldDNS MCP server** permette agli assistenti e agli agenti AI di **controllare un link prima di aprirlo**, usando ShieldDNS, il resolver pubblico europeo gratuito con protezione da malware, phishing e tracciamento, validazione DNSSEC e politica **zero-log**.

- `check_domain`: dice se un dominio o un URL è sicuro, con un **verdetto**, un **punteggio di rischio da 0 a 100 con le motivazioni** e un consiglio: `ok_to_open`, `caution` o `do_not_open`.
- `resolve`: risolve un nome tramite ShieldDNS (DNS-over-HTTPS, DNSSEC, blocco delle minacce).
- `service_status`: stato pubblico dei due nodi.

Il punteggio considera: la blocklist di ShieldDNS (circa 955.000 domini, segnalati con l'errore DNS esteso 15 "Blocked"), la validità della firma DNSSEC, le imitazioni di marchi noti, i nomi con alfabeti mescolati e i nomi generati a caso dal malware. "Il dominio non esiste" viene segnalato a parte: per un agente spesso significa un link sbagliato o inventato.

**Privacy**: il server gira sul tuo computer e invia solo query DNS a ShieldDNS, via HTTPS. ShieldDNS non registra le query né gli indirizzi IP. Nessuna telemetria, nessun account, nessuna chiave.

**Installazione**: vedi sopra (Claude Desktop, Claude Code, Cursor). Serve `uv`.
