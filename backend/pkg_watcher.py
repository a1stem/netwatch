"""
pkg_watcher.py
--------------
Identifies package manager network activity with three verification levels:

  VERIFIED    — known exe path + known official domain + HTTPS
  UNVERIFIED  — known exe path but unknown domain, OR HTTP from known domain
  SUSPICIOUS  — process name matches a pkg manager but exe path is wrong/unknown
                (possible masquerade — treat as unknown, not as update traffic)

The distinction matters because:
  - A process named 'apt' in /tmp/ or /home/ is NOT apt.
  - A process named 'pip' connecting to a random IP over HTTP is NOT a safe update.
  - Only VERIFIED gets the blue "Update traffic" badge.
  - SUSPICIOUS gets flagged red alongside unknown connections.
"""

from __future__ import annotations
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto
from typing import Optional

log = logging.getLogger(__name__)


class PkgVerification(Enum):
    VERIFIED    = auto()   # trusted path + trusted domain + HTTPS
    UNVERIFIED  = auto()   # trusted path, but domain or protocol is suspect
    SUSPICIOUS  = auto()   # name matches pkg manager but path is wrong
    NOT_PKG     = auto()   # not a package manager at all


class PkgRisk(Enum):
    SAFE     = auto()   # HTTPS + known domain + verified path
    WARN     = auto()   # HTTPS but unrecognised domain, or unverified path
    HIGH     = auto()   # HTTP from known domain
    CRITICAL = auto()   # HTTP + unknown domain
    MASQUERADE = auto() # name looks like pkg manager but path is wrong


# ── Known trusted executable paths ───────────────────────────────────────────
# These are the ONLY locations where a real package manager binary should live.
# A process named 'apt' anywhere else is suspicious.

_TRUSTED_PKG_PATHS: dict[str, list[str]] = {
    "apt":                  ["/usr/bin/apt"],
    "apt-get":              ["/usr/bin/apt-get"],
    "apt-cache":            ["/usr/bin/apt-cache"],
    "dpkg":                 ["/usr/bin/dpkg"],
    "aptd":                 ["/usr/sbin/aptd", "/usr/lib/apt/apt-daemon"],
    "unattended-upgrade":   ["/usr/bin/unattended-upgrade",
                             "/usr/lib/apt/apt.systemd.daily"],
    "snap":                 ["/usr/bin/snap"],
    "snapd":                ["/usr/lib/snapd/snapd"],
    "flatpak":              ["/usr/bin/flatpak"],
    "pip":                  ["/usr/bin/pip", "/usr/bin/pip3",
                             "/usr/local/bin/pip", "/usr/local/bin/pip3"],
    "pip3":                 ["/usr/bin/pip3", "/usr/local/bin/pip3"],
    "pipx":                 ["/usr/bin/pipx", "/usr/local/bin/pipx"],
    "npm":                  ["/usr/bin/npm", "/usr/local/bin/npm"],
    "yarn":                 ["/usr/bin/yarn", "/usr/local/bin/yarn"],
    "cargo":                ["/usr/bin/cargo", "/home"],   # cargo lives in ~/.cargo
    "gem":                  ["/usr/bin/gem"],
    "go":                   ["/usr/local/go/bin/go", "/usr/bin/go"],
}

# Path prefixes that are always suspicious for a pkg manager binary
_SUSPICIOUS_PREFIXES = (
    "/tmp/", "/var/tmp/", "/dev/shm/",
    "/home/", "/root/",     # cargo is the only exception handled above
)

# ── Official domains (inherits from original, expanded) ──────────────────────

_OFFICIAL_DOMAINS: dict[str, list[str]] = {
    "apt":          ["archive.ubuntu.com", "security.ubuntu.com",
                     "deb.debian.org", "security.debian.org",
                     "packages.debian.org", "ppa.launchpad.net",
                     "ppa.launchpadcontent.net",
                     "dl.google.com", "packages.microsoft.com",
                     "apt.postgresql.org", "download.docker.com",
                     "repo.mysql.com", "apt.llvm.org",
                     "packagecloud.io"],
    "apt-get":      ["archive.ubuntu.com", "security.ubuntu.com",
                     "deb.debian.org", "security.debian.org"],
    "snap":         ["api.snapcraft.io", "storage.snapcraftcontent.com"],
    "snapd":        ["api.snapcraft.io", "storage.snapcraftcontent.com",
                     "dashboard.snapcraft.io"],
    "flatpak":      ["dl.flathub.org", "flathub.org"],
    "pip":          ["pypi.org", "files.pythonhosted.org"],
    "pip3":         ["pypi.org", "files.pythonhosted.org"],
    "pipx":         ["pypi.org", "files.pythonhosted.org"],
    "npm":          ["registry.npmjs.org", "registry.npmjs.com"],
    "yarn":         ["registry.yarnpkg.com", "registry.npmjs.org"],
    "cargo":        ["crates.io", "static.crates.io",
                     "github.com", "raw.githubusercontent.com",
                     "index.crates.io"],
    "gem":          ["rubygems.org", "api.rubygems.org"],
    "go":           ["proxy.golang.org", "sum.golang.org",
                     "pkg.go.dev", "storage.googleapis.com"],
    "unattended-upgrade": ["archive.ubuntu.com", "security.ubuntu.com",
                            "deb.debian.org"],
}

# pkg manager names (for quick name-only check before path verification)
_PKG_NAMES = frozenset(_TRUSTED_PKG_PATHS.keys())


# ── Path verification ─────────────────────────────────────────────────────────

def verify_exe_path(proc_name: str, exe_path: str) -> PkgVerification:
    """
    Check whether an executable path is a legitimate location for this
    package manager binary.

    Returns:
      VERIFIED   — path exactly matches or starts with a trusted prefix
      SUSPICIOUS — name matches pkg manager but path is wrong
      NOT_PKG    — process name is not a package manager at all
    """
    name = proc_name.lower()
    if name not in _PKG_NAMES:
        return PkgVerification.NOT_PKG

    if not exe_path:
        # No path available — can't verify, treat conservatively
        log.debug("pkg_watcher: no exe path for %s — treating as unverified", name)
        return PkgVerification.UNVERIFIED

    # Special case: cargo and pip can live in user home dirs legitimately
    # but we still want to flag truly suspicious locations
    if name in ("cargo",):
        if exe_path.startswith(("/home/", "/root/")):
            return PkgVerification.UNVERIFIED   # not ideal but common
        # Fall through to normal check

    # Check against known suspicious prefixes first
    for sus in _SUSPICIOUS_PREFIXES:
        if exe_path.startswith(sus) and name not in ("cargo",):
            log.warning("pkg_watcher: SUSPICIOUS — %s running from %s",
                        name, exe_path)
            return PkgVerification.SUSPICIOUS

    # Check against trusted path list
    trusted = _TRUSTED_PKG_PATHS.get(name, [])
    for t in trusted:
        if exe_path == t or exe_path.startswith(t):
            return PkgVerification.VERIFIED

    # Path not in trusted list but not in suspicious list either
    # (e.g. /opt/ installs, custom builds) — unverified but not flagged red
    log.info("pkg_watcher: %s at unrecognised path %s — unverified",
             name, exe_path)
    return PkgVerification.UNVERIFIED


def _matches_official(proc_name: str, hostname: str) -> bool:
    domains = _OFFICIAL_DOMAINS.get(proc_name.lower(), [])
    h = hostname.lower()
    return any(h == d or h.endswith("." + d) for d in domains)


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class PkgEvent:
    timestamp: datetime
    proc_name: str
    pid: int
    exe_path: str
    remote_ip: str
    remote_hostname: str
    remote_port: int
    is_https: bool
    risk: PkgRisk
    verification: PkgVerification
    message: str

    @property
    def is_high_risk(self) -> bool:
        return self.risk in (PkgRisk.HIGH, PkgRisk.CRITICAL, PkgRisk.MASQUERADE)

    @property
    def is_suspicious_masquerade(self) -> bool:
        return self.verification == PkgVerification.SUSPICIOUS

    def badge_text(self) -> str:
        return {
            PkgRisk.SAFE:       "Update — verified",
            PkgRisk.WARN:       "Update — unverified host",
            PkgRisk.HIGH:       "Update — HTTP risk",
            PkgRisk.CRITICAL:   "Update — HTTP + unknown host",
            PkgRisk.MASQUERADE: "⚠ Masquerade — not a real pkg mgr",
        }[self.risk]

    def badge_color(self) -> str:
        return {
            PkgRisk.SAFE:       "blue",
            PkgRisk.WARN:       "amber",
            PkgRisk.HIGH:       "red",
            PkgRisk.CRITICAL:   "red",
            PkgRisk.MASQUERADE: "red",
        }[self.risk]


# ── Watcher ───────────────────────────────────────────────────────────────────

class PkgWatcher:
    """
    Stateful watcher — call evaluate() for every connection whose process
    name matches a known package manager.

    Now performs both path verification and domain verification before
    deciding how to classify the connection.
    """

    def __init__(self) -> None:
        self._seen: dict[tuple[int, str], PkgRisk] = {}

    def evaluate(
        self,
        proc_name: str,
        pid: int,
        exe_path: str,          # NEW — full executable path for verification
        remote_ip: str,
        remote_hostname: str,
        remote_port: int,
    ) -> Optional[PkgEvent]:
        """
        Returns a PkgEvent describing the risk level, or None if routine/seen.
        """
        name = proc_name.lower()
        if name not in _PKG_NAMES:
            return None

        is_https = remote_port == 443
        is_http  = remote_port == 80

        # ── Step 1: verify the executable path ───────────────────────────
        path_status = verify_exe_path(name, exe_path)

        if path_status == PkgVerification.SUSPICIOUS:
            # Process is masquerading as a package manager
            risk = PkgRisk.MASQUERADE
        elif path_status == PkgVerification.NOT_PKG:
            return None
        else:
            # Path is VERIFIED or UNVERIFIED — now check domain + protocol

            # ── Step 2: cross-reference the domain ───────────────────────
            official = _matches_official(name, remote_hostname)

            if is_https and official and path_status == PkgVerification.VERIFIED:
                risk = PkgRisk.SAFE
            elif is_https and official:
                risk = PkgRisk.WARN      # official domain but unverified path
            elif is_https and not official:
                risk = PkgRisk.WARN      # verified path but unknown domain
            elif is_http and official:
                risk = PkgRisk.HIGH      # HTTP to known domain — spoofable
            else:
                risk = PkgRisk.CRITICAL  # HTTP + unknown domain

        # Suppress duplicate SAFE events; always surface anything worse
        key = (pid, remote_ip)
        prev = self._seen.get(key)
        if prev == risk and risk == PkgRisk.SAFE:
            return None
        self._seen[key] = risk

        msg = _build_message(name, exe_path, remote_hostname,
                             remote_port, is_https, path_status, risk)

        return PkgEvent(
            timestamp=datetime.now(),
            proc_name=name,
            pid=pid,
            exe_path=exe_path,
            remote_ip=remote_ip,
            remote_hostname=remote_hostname,
            remote_port=remote_port,
            is_https=is_https,
            risk=risk,
            verification=path_status,
            message=msg,
        )

    def clear_stale(self, active_pids: set[int]) -> None:
        stale = [k for k in self._seen if k[0] not in active_pids]
        for k in stale:
            del self._seen[k]


def _build_message(
    proc: str,
    exe_path: str,
    hostname: str,
    port: int,
    is_https: bool,
    path_status: PkgVerification,
    risk: PkgRisk,
) -> str:
    proto    = "HTTPS" if is_https else "HTTP"
    path_str = exe_path or "(path unknown)"

    if risk == PkgRisk.MASQUERADE:
        return (
            f"🚨 MASQUERADE DETECTED: A process named '{proc}' is running from "
            f"'{path_str}' — not a system package manager location. "
            f"This process is pretending to be a package manager. "
            f"Block this connection immediately and investigate the file."
        )
    if risk == PkgRisk.SAFE:
        return (
            f"{proc} ({path_str}) is fetching updates over {proto} "
            f"from {hostname} — verified official domain."
        )
    if risk == PkgRisk.WARN:
        path_note = ("path unverified" if path_status == PkgVerification.UNVERIFIED
                     else "path OK")
        return (
            f"{proc} ({path_str}, {path_note}) connected to {hostname} "
            f"via {proto}. Domain is not on the recognised official list. "
            f"Verify your repository configuration."
        )
    if risk == PkgRisk.HIGH:
        return (
            f"⚠ {proc} ({path_str}) is downloading over plain HTTP from "
            f"{hostname}. Traffic can be intercepted and packages replaced. "
            f"Update your repo config to use HTTPS."
        )
    # CRITICAL
    return (
        f"🚨 {proc} ({path_str}) is downloading over plain HTTP from an "
        f"UNRECOGNISED host ({hostname}). This strongly suggests repository "
        f"spoofing or a misconfigured/malicious source. Block immediately."
    )


# ── Module-level helper (used by poller and conn_table) ──────────────────────

def is_pkg_manager_name(proc_name: str) -> bool:
    """Quick name-only check — use verify_exe_path() for full verification."""
    return proc_name.lower() in _PKG_NAMES


def classify_pkg_connection(
    proc_name: str,
    exe_path: str,
    remote_hostname: str,
    remote_port: int,
) -> tuple[bool, PkgVerification, PkgRisk]:
    """
    Stateless one-shot classification for display purposes (conn_table status col).
    Returns (is_pkg_manager, path_verification, risk).
    """
    if not is_pkg_manager_name(proc_name):
        return False, PkgVerification.NOT_PKG, PkgRisk.SAFE

    path_status = verify_exe_path(proc_name, exe_path)
    if path_status == PkgVerification.SUSPICIOUS:
        return True, path_status, PkgRisk.MASQUERADE

    is_https = remote_port == 443
    official = _matches_official(proc_name, remote_hostname)

    if is_https and official and path_status == PkgVerification.VERIFIED:
        risk = PkgRisk.SAFE
    elif is_https:
        risk = PkgRisk.WARN
    elif official:
        risk = PkgRisk.HIGH
    else:
        risk = PkgRisk.CRITICAL

    return True, path_status, risk
