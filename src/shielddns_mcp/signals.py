"""Name-only risk signals: computed from the domain name alone (no network access, no user data)."""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import tldextract

# Public Suffix List: use the snapshot bundled with tldextract, never download it.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)

# Brands frequently impersonated in phishing -> official registrable domains.
BRANDS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.me"),
    "apple": ("apple.com", "icloud.com"),
    "icloud": ("icloud.com", "apple.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "microsoftonline.com"),
    "outlook": ("outlook.com", "live.com", "microsoft.com"),
    "office365": ("office.com", "microsoft.com"),
    "google": ("google.com", "google.it", "goo.gl", "gmail.com"),
    "gmail": ("gmail.com", "google.com"),
    "amazon": ("amazon.com", "amazon.it", "amazon.de", "amazon.co.uk", "amazon.fr", "amazon.es"),
    "netflix": ("netflix.com",),
    "facebook": ("facebook.com", "fb.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com", "whatsapp.net"),
    "linkedin": ("linkedin.com",),
    "dropbox": ("dropbox.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "adobe": ("adobe.com",),
    "spotify": ("spotify.com",),
    "steam": ("steampowered.com", "steamcommunity.com"),
    "binance": ("binance.com",),
    "coinbase": ("coinbase.com",),
    "metamask": ("metamask.io",),
    "dhl": ("dhl.com", "dhl.it", "dhl.de"),
    "fedex": ("fedex.com",),
    "ups": ("ups.com",),
    "poste": ("poste.it", "posteitaliane.it"),
    "posteitaliane": ("poste.it", "posteitaliane.it"),
    "bancoposta": ("poste.it",),
    "intesasanpaolo": ("intesasanpaolo.com",),
    "unicredit": ("unicredit.it", "unicredit.eu", "unicreditgroup.eu"),
    "inps": ("inps.it",),
    "agenziaentrate": ("agenziaentrate.gov.it",),
    "satispay": ("satispay.com",),
    "nexi": ("nexi.it", "nexigroup.com"),
    "enel": ("enel.it", "enel.com"),
    "vodafone": ("vodafone.it", "vodafone.com"),
    "telegram": ("telegram.org", "t.me"),
    "github": ("github.com", "github.io"),
    "openai": ("openai.com", "chatgpt.com"),
    "chatgpt": ("chatgpt.com", "openai.com"),
    "anthropic": ("anthropic.com", "claude.ai"),
}

# Characters commonly used to imitate letters.
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_MULTI_HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("cl", "d"))

# Words that often accompany a brand name in phishing domains (EN + IT).
_LURE_WORDS = {
    "login", "signin", "secure", "security", "verify", "verification", "account", "update", "support",
    "help", "service", "billing", "payment", "pay", "wallet", "refund", "invoice", "confirm", "unlock",
    "recovery", "reset", "auth", "id", "online", "web", "app", "tracking", "track", "delivery", "parcel",
    "accesso", "sicurezza", "verifica", "conto", "aggiorna", "aggiornamento", "assistenza", "rimborso",
    "pagamento", "fattura", "conferma", "sblocco", "pacco", "spedizione", "consegna", "area", "clienti", "italiane",
}

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


class InvalidDomain(ValueError):
    pass


def normalize(value: str) -> str:
    """Accept a domain or a URL and return the lowercase ASCII (punycode) host name."""
    v = (value or "").strip()
    if not v:
        raise InvalidDomain("empty input")
    if "://" in v or v.startswith("//"):
        v = urlsplit(v if "://" in v else "http:" + v).hostname or ""
    else:
        v = v.split("/")[0].split("?")[0].split("#")[0]
        v = v.rsplit("@", 1)[-1]
        if v.count(":") == 1:
            v = v.split(":")[0]
    v = v.strip(".").lower()
    try:
        v = v.encode("idna").decode("ascii") if any(ord(c) > 127 for c in v) else v
    except UnicodeError as exc:
        raise InvalidDomain(f"invalid internationalized name: {value!r}") from exc
    if not _DOMAIN_RE.match(v):
        raise InvalidDomain(f"not a valid domain name: {value!r}")
    return v


def _unicode_form(domain: str) -> str:
    try:
        return domain.encode("ascii").decode("idna")
    except UnicodeError:
        return domain


def _scripts(text: str) -> set[str]:
    out = set()
    for ch in text:
        if ch in "-." or ch.isdigit():
            continue
        name = unicodedata.name(ch, "")
        out.add(name.split(" ")[0] if name else "UNKNOWN")
    return out


def _levenshtein(a: str, b: str, limit: int = 3) -> int:
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _randomness(label: str) -> float:
    """0..1: how random a label looks (entropy, vowels, consonant runs, digits)."""
    letters = re.sub(r"[^a-z]", "", label)
    if len(letters) < 8:
        return 0.0
    counts = {c: letters.count(c) for c in set(letters)}
    entropy = -sum(n / len(letters) * math.log2(n / len(letters)) for n in counts.values())
    vowels = sum(letters.count(v) for v in "aeiouy") / len(letters)
    run = max((len(m) for m in re.findall(r"[^aeiouy]+", letters)), default=0)
    digits = sum(c.isdigit() for c in label) / max(len(label), 1)
    score = 0.0
    score += max(0.0, min(1.0, (entropy - 3.0) / 1.2)) * 0.35
    score += (0.35 if vowels < 0.2 else 0.15 if vowels < 0.28 else 0.0)
    score += (0.2 if run >= 5 else 0.1 if run >= 4 else 0.0)
    score += (0.1 if 0.15 <= digits <= 0.6 else 0.0)
    return round(min(score, 1.0), 2)


@dataclass
class NameSignals:
    domain: str
    unicode: str
    registrable: str
    labels_score: float = 0.0
    signals: list[dict] = field(default_factory=list)

    def add(self, code: str, weight: int, detail: str) -> None:
        self.signals.append({"code": code, "weight": weight, "detail": detail})


def analyze(domain: str) -> NameSignals:
    ext = _EXTRACT(domain)
    registrable = ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix") else ext.registered_domain
    registrable = registrable or domain
    label = ext.domain or domain.split(".")[0]
    uni = _unicode_form(domain)
    s = NameSignals(domain=domain, unicode=uni, registrable=registrable)

    # IDN / punycode, mixed scripts (e.g. Latin + Cyrillic)
    if "xn--" in domain:
        scripts = _scripts(uni)
        if len(scripts) > 1:
            s.add("mixed_scripts", 35, f"the name mixes different scripts ({', '.join(sorted(scripts))}), a common trick to imitate a site")
        else:
            s.add("idn", 10, f"internationalized name (displayed as {uni})")

    # impersonation of well-known brands
    official = {d for ds in BRANDS.values() for d in ds}
    if registrable not in official:
        folded = unicodedata.normalize("NFKD", _unicode_form(label)).encode("ascii", "ignore").decode().lower()
        folded = folded.translate(_HOMOGLYPHS)
        for a, b in _MULTI_HOMOGLYPHS:
            folded = folded.replace(a, b)
        tokens = [t for t in re.split(r"[-_.]", folded) if t]
        hit = None
        lure = any(t in _LURE_WORDS for t in tokens)
        for brand in BRANDS:
            if folded == brand:
                hit = ("brand_lookalike", 40, brand)
                break
            if brand in tokens:
                hit = ("brand_with_lure_words", 40, brand) if lure else ("brand_name", 20, brand)
                break
            if len(brand) >= 5 and _levenshtein(folded, brand, 2) <= (1 if len(brand) < 8 else 2):
                hit = ("brand_typo", 40, brand)
                break
            if len(brand) >= 5 and brand in folded and len(folded) <= len(brand) + 12:
                hit = ("brand_inside", 30 if lure else 20, brand)
                break
        if hit:
            code, w, brand = hit
            s.add(code, w, f"the name evokes the brand \"{brand}\" but is not one of its official domains ({', '.join(BRANDS[brand])})")
        sub = ext.subdomain or ""
        for brand, domains in BRANDS.items():
            if any(d in sub for d in domains):
                s.add("brand_in_subdomain", 35, f"the subdomain contains \"{next(d for d in domains if d in sub)}\" but the real site is {registrable}")
                break

    # random-looking name (typical of malware domain generation algorithms, DGA)
    r = _randomness(label)
    s.labels_score = r
    if r >= 0.6:
        s.add("random_looking", 25, f"the name looks randomly generated (index {r})")
    elif r >= 0.45:
        s.add("somewhat_random", 10, f"the name looks somewhat unnatural (index {r})")

    if len(domain) > 50 or _unicode_form(label).count("-") >= 3:
        s.add("long_or_hyphenated", 10, "very long name or many hyphens")
    return s
