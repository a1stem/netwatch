"""
pkg_watcher.py
--------------
Identifies package manager network activity and raises alerts when:
  - A package manager connects over plain HTTP (spoofing risk)
  - A package manager contacts an IP that doesn't match known official domains
  - A new/unfamiliar package manager process appears
"""

from __future__ import annotations
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Optional

log = logging.getLogger(__name__)


class PkgRisk(Enum):
    SAFE     = auto()   # HTTPS to a known official domain
    WARN     = auto()   # HTTPS but domain unrecognised
    HIGH     = auto()   # HTTP (plaintext) — spoofing possible
    CRITICAL = auto()   # HTTP + unrecognised domain


# ── Known official domains per package manager ─────────────────────────────

_OFFICIAL_DOMAINS: dict[str, list[str]] = {
    "apt":          ["archive.ubuntu.com", "security.ubuntu.com",
                     "deb.debian.org", "security.debian.org",
                     "packages.debian.org", "ppa.launchpad.net",
                     "ppa.launchpadcontent.net",
                     "dl.google.com", "packages.microsoft.com",
                     "apt.postgresql.org", "download.docker.com",
                     "repo.mysql.com"],
    "apt-get":      ["archive.ubuntu.com", "security.ubuntu.com",
                     "deb.debian.org", "security.debian.org"],
    "snap":         ["api.snapcraft.io", "storage.snapcraftcontent.com"],
    "snapd":        ["api.snapcraft.io", "storage.snapcraftcontent.com",
                     "dashboard.snapcraft.io"],
    "flatpak":      ["dl.flathub.org", "flathub.org"],
    "pip":          ["pypi.org", "files.pythonhosted.org"],
    "pip3":         ["pypi.org", "files.pythonhosted.org"],
    "pipx":         ["pypi.org", "files.pythonhosted.org"],
    "npm":          ["registry.npmjs.org"],
    "yarn":         ["registry.yarnpkg.com", "registry.npmjs.org"],
    "cargo":        ["crates.io", "static.crates.io",
                     "github.com", "raw.githubusercontent.com"],
    "gem":          ["rubygems.org"],
    "go":           ["proxy.golang.org", "sum.golang.org",
                     "pkg.go.dev"],
    "unattended-upgrade": ["archive.ubuntu.com", "security.ubuntu.com",
                           "deb.debian.org"],
}

# Fallback: process names that ARE package managers but lack a specific entry
_GENERIC_PKG_NAMES = frozenset({
    "apt", "apt-get", "apt-cache", "dpkg", "aptd", "unattended-upgrade",
    "snap", "snapd", "flatpak", "pip", "pip3", "pipx",
    "npm", "yarn", "cargo", "gem", "go",
})


def _domain_from_hostname(hostname: str) -> str:
    """Extract registrable domain from a hostname."""
    parts = hostname.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def _matches_official(proc_name: str, hostname: str) -> bool:
    """True if hostname is an official domain for this package manager."""
    domains = _OFFICIAL_DOMAINS.get(proc_name.lower(), [])
    h = hostname.lower()
    return any(h == d or h.endswith("." + d) for d in domains)


# ── Result dataclass ────────────────────────────────────────────────────────

@dataclass
class PkgEvent:
    timestamp: datetime
    proc_name: str
    pid: int
    remote_ip: str
    remote_hostname: str        # may equal remote_ip if DNS failed
    remote_port: int
    is_https: bool
    risk: PkgRisk
    message: str                # human-readable alert text

    @property
    def is_high_risk(self) -> bool:
        return self.risk in (PkgRisk.HIGH, PkgRisk.CRITICAL)

    def badge_text(self) -> str:
        return {
            PkgRisk.SAFE:     "Update — safe",
            PkgRisk.WARN:     "Update — unrecognised host",
            PkgRisk.HIGH:     "Update — HTTP! Risk",
            PkgRisk.CRITICAL: "Update — HTTP + unknown! CRITICAL",
        }[self.risk]

    def badge_color(self) -> str:
        return {
            PkgRisk.SAFE:     "blue",
            PkgRisk.WARN:     "amber",
            PkgRisk.HIGH:     "red",
            PkgRisk.CRITICAL: "red",
        }[self.risk]


# ── Watcher ─────────────────────────────────────────────────────────────────

class PkgWatcher:
    """
    Stateful watcher — call evaluate() for every connection that belongs
    to a package manager process.

    Emits PkgEvent objects; the caller (poller) forwards them to the GUI.
    """

    def __init__(self) -> None:
        # Track seen events to avoid duplicate alerts: (pid, remote_ip) → risk
        self._seen: dict[tuple[int, str], PkgRisk] = {}

    def evaluate(
        self,
        proc_name: str,
        pid: int,
        remote_ip: str,
        remote_hostname: str,
        remote_port: int,
    ) -> Optional[PkgEvent]:
        """
        Returns a PkgEvent if this connection warrants an alert,
        or None if it's routine and already seen.
        """
        is_https = remote_port == 443
        is_http  = remote_port == 80
        is_pkg   = proc_name.lower() in _GENERIC_PKG_NAMES

        if not is_pkg:
            return None

        official = _matches_official(proc_name, remote_hostname)

        # Determine risk level
        if is_https and official:
            risk = PkgRisk.SAFE
        elif is_https and not official:
            risk = PkgRisk.WARN
        elif is_http and official:
            risk = PkgRisk.HIGH
        else:
            risk = PkgRisk.CRITICAL

        key = (pid, remote_ip)
        prev = self._seen.get(key)

        # Always alert on HIGH/CRITICAL even if seen; suppress SAFE repeats
        if prev == risk and risk in (PkgRisk.SAFE, PkgRisk.WARN):
            return None

        self._seen[key] = risk

        msg = _build_message(proc_name, remote_hostname, remote_port,
                             is_https, official, risk)

        return PkgEvent(
            timestamp=datetime.now(),
            proc_name=proc_name,
            pid=pid,
            remote_ip=remote_ip,
            remote_hostname=remote_hostname,
            remote_port=remote_port,
            is_https=is_https,
            risk=risk,
            message=msg,
        )

    def clear_stale(self, active_pids: set[int]) -> None:
        """Remove entries for pids that are no longer running."""
        stale = [k for k in self._seen if k[0] not in active_pids]
        for k in stale:
            del self._seen[k]


def _build_message(
    proc: str,
    hostname: str,
    port: int,
    is_https: bool,
    official: bool,
    risk: PkgRisk,
) -> str:
    proto = "HTTPS" if is_https else "HTTP"
    dom_note = "official domain" if official else "UNRECOGNISED domain"

    if risk == PkgRisk.SAFE:
        return (f"{proc} is fetching updates over {proto} from "
                f"{hostname} ({dom_note}).")
    if risk == PkgRisk.WARN:
        return (f"{proc} connected to {hostname} via {proto}. "
                f"This is not a recognised official repository. "
                f"Verify your sources.list entries.")
    if risk == PkgRisk.HIGH:
        return (f"⚠ {proc} is downloading over plain HTTP from {hostname}. "
                f"This traffic can be intercepted and modified. "
                f"Check your repository configuration.")
    # CRITICAL
    return (f"🚨 {proc} is downloading over plain HTTP from an UNRECOGNISED "
            f"host ({hostname}). This is a strong indicator of repository "
            f"spoofing or misconfiguration. Block this connection.")
