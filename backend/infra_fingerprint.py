"""
backend/infra_fingerprint.py
-----------------------------
Layer 2 — Organisation fingerprinting.

Given a reverse-DNS hostname and/or GeoIP org name, identifies whether
a connection belongs to known cloud/CDN/infrastructure providers and
returns a human-readable organisation label.

This is the bridge between a raw IP address and something a user
can actually recognise — without needing to block anything.

Examples:
  "lb-140-82-114-4-iad.github.com"  → OrgInfo("GitHub", "github.com", KNOWN_INFRA)
  "ec2-54-187-100-215.amazonaws.com" → OrgInfo("AWS", "amazonaws.com", CLOUD)
  "1e100.net"                        → OrgInfo("Google", "google.com", KNOWN_INFRA)
  "185.220.101.4"                    → OrgInfo("Tor relay", "", SUSPICIOUS_INFRA)
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional


class InfraTier(Enum):
    KNOWN_INFRA     = auto()   # Recognised CDN / cloud / major service
    CLOUD           = auto()   # Generic cloud provider (AWS, GCP, Azure)
    TRUSTED_SERVICE = auto()   # Explicitly trusted well-known service
    LOCAL           = auto()   # Private / RFC1918
    SUSPICIOUS_INFRA = auto()  # Known-bad infrastructure (Tor exits etc.)
    UNKNOWN         = auto()   # Cannot identify


@dataclass
class OrgInfo:
    org_name: str           # e.g. "GitHub", "Cloudflare", "AWS"
    root_domain: str        # e.g. "github.com", "cloudflare.com"
    tier: InfraTier
    detail: str = ""        # e.g. "CDN", "SSH relay", "EU region"

    @property
    def display(self) -> str:
        if self.detail:
            return f"{self.org_name} ({self.detail})"
        return self.org_name

    @property
    def is_known(self) -> bool:
        return self.tier in (
            InfraTier.KNOWN_INFRA,
            InfraTier.CLOUD,
            InfraTier.TRUSTED_SERVICE,
            InfraTier.LOCAL,
        )

    @property
    def is_suspicious(self) -> bool:
        return self.tier == InfraTier.SUSPICIOUS_INFRA


# ── Domain → org mapping ──────────────────────────────────────────────────────
# Each entry: (domain_suffix, org_name, tier, detail)
# Checked with hostname.endswith(suffix) — more specific entries first.

_DOMAIN_MAP: list[tuple[str, str, InfraTier, str]] = [

    # ── Developer platforms ───────────────────────────────────────────────
    ("github.com",              "GitHub",       InfraTier.TRUSTED_SERVICE, ""),
    ("githubusercontent.com",   "GitHub",       InfraTier.TRUSTED_SERVICE, "content CDN"),
    ("githubassets.com",        "GitHub",       InfraTier.TRUSTED_SERVICE, "assets CDN"),
    ("gitlab.com",              "GitLab",       InfraTier.TRUSTED_SERVICE, ""),
    ("bitbucket.org",           "Bitbucket",    InfraTier.TRUSTED_SERVICE, ""),
    ("npmjs.com",               "npm",          InfraTier.TRUSTED_SERVICE, "registry"),
    ("npmjs.org",               "npm",          InfraTier.TRUSTED_SERVICE, "registry"),
    ("yarnpkg.com",             "Yarn",         InfraTier.TRUSTED_SERVICE, "registry"),
    ("pypi.org",                "PyPI",         InfraTier.TRUSTED_SERVICE, "Python packages"),
    ("pythonhosted.org",        "PyPI",         InfraTier.TRUSTED_SERVICE, "package files"),
    ("crates.io",               "crates.io",    InfraTier.TRUSTED_SERVICE, "Rust packages"),
    ("rubygems.org",            "RubyGems",     InfraTier.TRUSTED_SERVICE, ""),
    ("golang.org",              "Go",           InfraTier.TRUSTED_SERVICE, "module proxy"),
    ("pkg.go.dev",              "Go",           InfraTier.TRUSTED_SERVICE, "packages"),

    # ── Anthropic / Claude ────────────────────────────────────────────────
    ("anthropic.com",           "Anthropic",    InfraTier.TRUSTED_SERVICE, "Claude API"),
    ("claudemcpcontent.com",    "Anthropic",    InfraTier.TRUSTED_SERVICE, "Claude visualizations"),
    ("claude.ai",               "Anthropic",    InfraTier.TRUSTED_SERVICE, "Claude UI"),

    # ── Google ────────────────────────────────────────────────────────────
    ("google.com",              "Google",       InfraTier.KNOWN_INFRA, ""),
    ("googleapis.com",          "Google",       InfraTier.KNOWN_INFRA, "APIs"),
    ("googlevideo.com",         "Google",       InfraTier.KNOWN_INFRA, "video CDN"),
    ("gstatic.com",             "Google",       InfraTier.KNOWN_INFRA, "static CDN"),
    ("ggpht.com",               "Google",       InfraTier.KNOWN_INFRA, "CDN"),
    ("1e100.net",               "Google",       InfraTier.KNOWN_INFRA, "infra"),
    ("googleusercontent.com",   "Google",       InfraTier.KNOWN_INFRA, "user content"),
    ("android.com",             "Google",       InfraTier.KNOWN_INFRA, ""),
    ("doubleclick.net",         "Google Ads",   InfraTier.KNOWN_INFRA, "advertising"),
    ("google-analytics.com",    "Google",       InfraTier.KNOWN_INFRA, "analytics"),

    # ── Cloudflare ────────────────────────────────────────────────────────
    ("cloudflare.com",          "Cloudflare",   InfraTier.KNOWN_INFRA, ""),
    ("cloudflare-dns.com",      "Cloudflare",   InfraTier.KNOWN_INFRA, "DNS"),
    ("cloudflarestorage.com",   "Cloudflare",   InfraTier.KNOWN_INFRA, "storage"),
    ("cloudflareinsights.com",  "Cloudflare",   InfraTier.KNOWN_INFRA, "analytics"),
    ("workers.dev",             "Cloudflare",   InfraTier.KNOWN_INFRA, "Workers"),
    ("pages.dev",               "Cloudflare",   InfraTier.KNOWN_INFRA, "Pages"),
    ("cf-ipv6.com",             "Cloudflare",   InfraTier.KNOWN_INFRA, "IPv6"),

    # ── Amazon / AWS ──────────────────────────────────────────────────────
    ("amazonaws.com",           "AWS",          InfraTier.CLOUD, ""),
    ("amazon.com",              "Amazon",       InfraTier.KNOWN_INFRA, ""),
    ("amazontrust.com",         "Amazon",       InfraTier.KNOWN_INFRA, "PKI"),
    ("awsstatic.com",           "AWS",          InfraTier.CLOUD, "static CDN"),
    ("aws.amazon.com",          "AWS",          InfraTier.CLOUD, "console"),
    ("s3.amazonaws.com",        "AWS",          InfraTier.CLOUD, "S3"),
    ("cloudfront.net",          "AWS CloudFront", InfraTier.CLOUD, "CDN"),

    # ── Microsoft / Azure ─────────────────────────────────────────────────
    ("microsoft.com",           "Microsoft",    InfraTier.KNOWN_INFRA, ""),
    ("microsoftonline.com",     "Microsoft",    InfraTier.KNOWN_INFRA, "auth"),
    ("azure.com",               "Azure",        InfraTier.CLOUD, ""),
    ("azureedge.net",           "Azure",        InfraTier.CLOUD, "CDN"),
    ("windows.net",             "Azure",        InfraTier.CLOUD, "storage"),
    ("live.com",                "Microsoft",    InfraTier.KNOWN_INFRA, ""),
    ("office.com",              "Microsoft",    InfraTier.KNOWN_INFRA, "Office 365"),
    ("visualstudio.com",        "Microsoft",    InfraTier.KNOWN_INFRA, "VS/DevOps"),
    ("vscode-cdn.net",          "Microsoft",    InfraTier.KNOWN_INFRA, "VS Code CDN"),
    ("update.microsoft.com",    "Microsoft",    InfraTier.KNOWN_INFRA, "updates"),

    # ── Ubuntu / Canonical ────────────────────────────────────────────────
    ("ubuntu.com",              "Canonical",    InfraTier.TRUSTED_SERVICE, "Ubuntu"),
    ("canonical.com",           "Canonical",    InfraTier.TRUSTED_SERVICE, ""),
    ("snapcraft.io",            "Canonical",    InfraTier.TRUSTED_SERVICE, "Snap store"),
    ("snapcraftcontent.com",    "Canonical",    InfraTier.TRUSTED_SERVICE, "Snap CDN"),
    ("launchpad.net",           "Canonical",    InfraTier.TRUSTED_SERVICE, "PPA"),

    # ── Debian ────────────────────────────────────────────────────────────
    ("debian.org",              "Debian",       InfraTier.TRUSTED_SERVICE, ""),
    ("debian.net",              "Debian",       InfraTier.TRUSTED_SERVICE, "mirrors"),

    # ── CDNs ──────────────────────────────────────────────────────────────
    ("fastly.net",              "Fastly CDN",   InfraTier.KNOWN_INFRA, "CDN"),
    ("fastlylb.net",            "Fastly CDN",   InfraTier.KNOWN_INFRA, "CDN"),
    ("akamai.net",              "Akamai CDN",   InfraTier.KNOWN_INFRA, "CDN"),
    ("akamaiedge.net",          "Akamai CDN",   InfraTier.KNOWN_INFRA, "CDN"),
    ("akamaitechnologies.com",  "Akamai CDN",   InfraTier.KNOWN_INFRA, "CDN"),
    ("edgesuite.net",           "Akamai CDN",   InfraTier.KNOWN_INFRA, "CDN"),
    ("cdn77.com",               "CDN77",        InfraTier.KNOWN_INFRA, "CDN"),
    ("cdnjs.com",               "Cloudflare CDN", InfraTier.KNOWN_INFRA, "JS CDN"),
    ("jsdelivr.net",            "jsDelivr CDN", InfraTier.KNOWN_INFRA, "CDN"),
    ("unpkg.com",               "unpkg CDN",    InfraTier.KNOWN_INFRA, "CDN"),

    # ── DNS resolvers ─────────────────────────────────────────────────────
    ("dns.google",              "Google DNS",   InfraTier.KNOWN_INFRA, "8.8.8.8"),
    ("one.one.one.one",         "Cloudflare DNS", InfraTier.KNOWN_INFRA, "1.1.1.1"),

    # ── Social / comms ────────────────────────────────────────────────────
    ("slack.com",               "Slack",        InfraTier.KNOWN_INFRA, ""),
    ("slack-edge.com",          "Slack",        InfraTier.KNOWN_INFRA, "CDN"),
    ("discord.com",             "Discord",      InfraTier.KNOWN_INFRA, ""),
    ("discordapp.com",          "Discord",      InfraTier.KNOWN_INFRA, "CDN"),
    ("zoom.us",                 "Zoom",         InfraTier.KNOWN_INFRA, ""),
    ("zoomgov.com",             "Zoom",         InfraTier.KNOWN_INFRA, ""),

    # ── Common SaaS ───────────────────────────────────────────────────────
    ("dropbox.com",             "Dropbox",      InfraTier.KNOWN_INFRA, ""),
    ("dropboxstatic.com",       "Dropbox",      InfraTier.KNOWN_INFRA, "CDN"),
    ("notion.so",               "Notion",       InfraTier.KNOWN_INFRA, ""),
    ("stripe.com",              "Stripe",       InfraTier.KNOWN_INFRA, "payments"),
    ("twilio.com",              "Twilio",       InfraTier.KNOWN_INFRA, ""),
    ("sendgrid.net",            "SendGrid",     InfraTier.KNOWN_INFRA, "email"),
    ("mailchimp.com",           "Mailchimp",    InfraTier.KNOWN_INFRA, ""),

    # ── Browsers ──────────────────────────────────────────────────────────
    ("brave.com",               "Brave",        InfraTier.TRUSTED_SERVICE, "browser"),
    ("bravesoftware.com",       "Brave",        InfraTier.TRUSTED_SERVICE, "browser"),
    ("mozilla.com",             "Mozilla",      InfraTier.TRUSTED_SERVICE, "Firefox"),
    ("mozilla.net",             "Mozilla",      InfraTier.TRUSTED_SERVICE, "Firefox"),
    ("firefox.com",             "Mozilla",      InfraTier.TRUSTED_SERVICE, "Firefox"),
    ("chrome.com",              "Google",       InfraTier.TRUSTED_SERVICE, "Chrome"),

    # ── Suspicious / known-bad ────────────────────────────────────────────
    ("torproject.org",          "Tor Project",  InfraTier.SUSPICIOUS_INFRA, "Tor relay"),

    # ── Local / private ───────────────────────────────────────────────────
    ("local",                   "Local",        InfraTier.LOCAL, "mDNS"),
    ("localhost",               "Localhost",    InfraTier.LOCAL, "loopback"),
    ("internal",                "Internal",     InfraTier.LOCAL, "LAN"),
]

# ── IP prefix → org (for IPs that don't reverse-resolve) ─────────────────────

_IP_PREFIX_MAP: list[tuple[str, str, InfraTier, str]] = [
    # Cloudflare
    ("104.16.",    "Cloudflare",   InfraTier.KNOWN_INFRA, "CDN"),
    ("104.17.",    "Cloudflare",   InfraTier.KNOWN_INFRA, "CDN"),
    ("104.18.",    "Cloudflare",   InfraTier.KNOWN_INFRA, "CDN"),
    ("104.19.",    "Cloudflare",   InfraTier.KNOWN_INFRA, "CDN"),
    ("104.20.",    "Cloudflare",   InfraTier.KNOWN_INFRA, "CDN"),
    ("104.21.",    "Cloudflare",   InfraTier.KNOWN_INFRA, "CDN"),
    ("172.64.",    "Cloudflare",   InfraTier.KNOWN_INFRA, "CDN"),
    ("172.65.",    "Cloudflare",   InfraTier.KNOWN_INFRA, "CDN"),
    ("172.66.",    "Cloudflare",   InfraTier.KNOWN_INFRA, "CDN"),
    ("172.67.",    "Cloudflare",   InfraTier.KNOWN_INFRA, "CDN"),
    ("2606:4700:", "Cloudflare",   InfraTier.KNOWN_INFRA, "CDN IPv6"),
    # GitHub
    ("140.82.",    "GitHub",       InfraTier.TRUSTED_SERVICE, ""),
    ("192.30.",    "GitHub",       InfraTier.TRUSTED_SERVICE, ""),
    ("185.199.",   "GitHub",       InfraTier.TRUSTED_SERVICE, "assets"),
    # Google DNS
    ("8.8.8.",     "Google DNS",   InfraTier.KNOWN_INFRA, ""),
    ("8.8.4.",     "Google DNS",   InfraTier.KNOWN_INFRA, ""),
    # Cloudflare DNS
    ("1.1.1.",     "Cloudflare DNS", InfraTier.KNOWN_INFRA, ""),
    ("1.0.0.",     "Cloudflare DNS", InfraTier.KNOWN_INFRA, ""),
    # AWS broad ranges (common EC2 regions)
    ("54.187.",    "AWS",          InfraTier.CLOUD, "us-west-2"),
    ("54.188.",    "AWS",          InfraTier.CLOUD, "us-west-2"),
    ("35.82.",     "AWS",          InfraTier.CLOUD, "us-west-2"),
    ("52.94.",     "AWS",          InfraTier.CLOUD, ""),
    ("52.95.",     "AWS",          InfraTier.CLOUD, ""),
    # Tor exit nodes (known ranges)
    ("185.220.",   "Tor relay",    InfraTier.SUSPICIOUS_INFRA, "exit node"),
    ("199.87.",    "Tor relay",    InfraTier.SUSPICIOUS_INFRA, "exit node"),
    # Private / RFC1918
    ("192.168.",   "Local network", InfraTier.LOCAL, "LAN"),
    ("10.",        "Local network", InfraTier.LOCAL, "LAN"),
    ("172.16.",    "Local network", InfraTier.LOCAL, "LAN"),
    ("127.",       "Localhost",    InfraTier.LOCAL, "loopback"),
    ("169.254.",   "Link-local",   InfraTier.LOCAL, ""),
]


def _extract_root_domain(hostname: str) -> str:
    """Extract registrable domain from a full hostname."""
    if not hostname or hostname == hostname.split(".")[-1]:
        return hostname
    parts = hostname.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def fingerprint(ip: str, hostname: str, geoip_org: str = "") -> OrgInfo:
    """
    Identify the organisation behind an IP/hostname combination.

    Priority:
      1. Exact hostname suffix match (most specific)
      2. IP prefix match
      3. GeoIP org name fuzzy match
      4. Unknown
    """
    h = (hostname or "").lower().rstrip(".")

    # 1. Domain suffix matching — most specific first
    if h and h not in (ip, ""):
        for suffix, org, tier, detail in _DOMAIN_MAP:
            if h == suffix or h.endswith("." + suffix):
                return OrgInfo(org_name=org, root_domain=suffix,
                               tier=tier, detail=detail)

        # Try root domain extraction as fallback
        root = _extract_root_domain(h)
        for suffix, org, tier, detail in _DOMAIN_MAP:
            if root == suffix:
                return OrgInfo(org_name=org, root_domain=suffix,
                               tier=tier, detail=detail)

    # 2. IP prefix matching
    ip_str = (ip or "").strip()
    for prefix, org, tier, detail in _IP_PREFIX_MAP:
        if ip_str.startswith(prefix):
            return OrgInfo(org_name=org, root_domain="",
                           tier=tier, detail=detail)

    # 3. GeoIP org name fuzzy match
    if geoip_org:
        geo_lower = geoip_org.lower()
        _GEO_MAP = [
            ("cloudflare",  "Cloudflare",  InfraTier.KNOWN_INFRA),
            ("amazon",      "AWS",         InfraTier.CLOUD),
            ("google",      "Google",      InfraTier.KNOWN_INFRA),
            ("microsoft",   "Microsoft",   InfraTier.KNOWN_INFRA),
            ("fastly",      "Fastly CDN",  InfraTier.KNOWN_INFRA),
            ("akamai",      "Akamai CDN",  InfraTier.KNOWN_INFRA),
            ("github",      "GitHub",      InfraTier.TRUSTED_SERVICE),
            ("canonical",   "Canonical",   InfraTier.TRUSTED_SERVICE),
            ("digitalocean","DigitalOcean", InfraTier.CLOUD),
            ("linode",      "Linode/Akamai", InfraTier.CLOUD),
            ("vultr",       "Vultr",       InfraTier.CLOUD),
            ("hetzner",     "Hetzner",     InfraTier.CLOUD),
        ]
        for keyword, org, tier in _GEO_MAP:
            if keyword in geo_lower:
                return OrgInfo(org_name=org, root_domain="",
                               tier=tier, detail=geoip_org)

    return OrgInfo(org_name="", root_domain="",
                   tier=InfraTier.UNKNOWN, detail="")


def org_label(ip: str, hostname: str, geoip_org: str = "") -> str:
    """
    Quick one-line label for display in the connection table.
    Returns org name if known, empty string if unknown.
    """
    info = fingerprint(ip, hostname, geoip_org)
    return info.display if info.is_known else ""
