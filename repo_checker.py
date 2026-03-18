"""
repo_checker.py
---------------
Audits configured package repositories for security properties:
  - HTTPS vs HTTP
  - GPG key presence
  - Known official vs third-party vs unknown sources

Reads:
  /etc/apt/sources.list
  /etc/apt/sources.list.d/*.list
  /etc/apt/sources.list.d/*.sources   (deb822 format)
  snap list (subprocess)
  flatpak remotes (subprocess)
"""

from __future__ import annotations
import glob
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

log = logging.getLogger(__name__)


class RepoStatus(Enum):
    SAFE    = auto()    # HTTPS + signed
    INFO    = auto()    # HTTPS + signed, but third-party
    WARN    = auto()    # HTTP or missing key
    DANGER  = auto()    # HTTP AND no key


class RepoKind(Enum):
    APT     = auto()
    SNAP    = auto()
    FLATPAK = auto()


@dataclass
class RepoEntry:
    kind: RepoKind
    name: str               # human label, e.g. "ubuntu — main"
    url: str
    is_https: bool
    has_gpg: bool
    is_official: bool
    is_enabled: bool
    components: list[str] = field(default_factory=list)
    notes: str = ""

    @property
    def status(self) -> RepoStatus:
        if not self.is_enabled:
            return RepoStatus.INFO
        if self.is_https and self.has_gpg:
            return RepoStatus.SAFE if self.is_official else RepoStatus.INFO
        if not self.is_https and not self.has_gpg:
            return RepoStatus.DANGER
        return RepoStatus.WARN

    @property
    def status_label(self) -> str:
        return {
            RepoStatus.SAFE:   "Safe",
            RepoStatus.INFO:   "3rd party",
            RepoStatus.WARN:   "Risk",
            RepoStatus.DANGER: "Danger",
        }[self.status]

    @property
    def https_label(self) -> str:
        return "Yes" if self.is_https else "No — HTTP"

    @property
    def gpg_label(self) -> str:
        return "Signed" if self.has_gpg else "Missing"


# ── Official domain lists ─────────────────────────────────────────────────

_OFFICIAL_APT = [
    "archive.ubuntu.com", "security.ubuntu.com",
    "deb.debian.org", "security.debian.org",
    "packages.debian.org", "extras.ubuntu.com",
]

_OFFICIAL_SNAP = ["api.snapcraft.io"]
_OFFICIAL_FLATPAK = ["dl.flathub.org", "flathub.org"]


def _is_official_apt(url: str) -> bool:
    return any(d in url for d in _OFFICIAL_APT)


# ── GPG key detection ─────────────────────────────────────────────────────

def _gpg_keys_present() -> set[str]:
    """
    Return the set of key fingerprints/filenames known to apt.
    We use this to infer whether a repo has a key — imperfect but workable.
    """
    keys: set[str] = set()
    keydirs = [
        "/etc/apt/trusted.gpg.d/",
        "/usr/share/keyrings/",
    ]
    for kd in keydirs:
        if os.path.isdir(kd):
            for f in os.listdir(kd):
                keys.add(f.lower())
    # Also check legacy keyring
    if os.path.isfile("/etc/apt/trusted.gpg"):
        keys.add("trusted.gpg")
    return keys


def _infer_gpg(url: str, all_keys: set[str]) -> bool:
    """
    Heuristic: if the URL host appears as part of any keyring filename,
    assume it's signed.  Official domains are always assumed signed.
    """
    if _is_official_apt(url) or "launchpad.net" in url:
        return True
    # Check for a keyring file that loosely matches the domain
    host = re.sub(r"https?://", "", url).split("/")[0]
    domain_part = host.replace(".", "-").lower()
    return any(domain_part in k for k in all_keys)


# ── APT parser ────────────────────────────────────────────────────────────

_DEB_LINE = re.compile(
    r"^\s*(?P<disabled>#\s*)?"
    r"deb(?:-src)?\s+"
    r"(?:\[(?P<opts>[^\]]*)\]\s+)?"
    r"(?P<url>https?://\S+)\s+"
    r"(?P<suite>\S+)"
    r"(?P<components>.*)"
)


def _parse_apt_line(line: str, all_keys: set[str]) -> Optional[RepoEntry]:
    m = _DEB_LINE.match(line)
    if not m:
        return None

    disabled = bool(m.group("disabled"))
    url = m.group("url")
    suite = m.group("suite")
    components = m.group("components").split()
    is_https = url.startswith("https://")

    # Check for signed-by option
    opts = m.group("opts") or ""
    signed_by = "signed-by" in opts

    has_gpg = signed_by or _infer_gpg(url, all_keys)
    official = _is_official_apt(url)

    comp_str = ", ".join(components) if components else ""
    name = f"{suite}" + (f" — {comp_str}" if comp_str else "")
    if not official:
        name = f"{url.split('/')[2]} — {name}"

    notes = ""
    if not is_https:
        notes = "Plain HTTP — traffic can be intercepted"
    if not has_gpg:
        notes += (" · " if notes else "") + "No GPG key — packages unverified"

    return RepoEntry(
        kind=RepoKind.APT,
        name=name,
        url=url,
        is_https=is_https,
        has_gpg=has_gpg,
        is_official=official,
        is_enabled=not disabled,
        components=components,
        notes=notes,
    )


def _parse_deb822(path: str, all_keys: set[str]) -> list[RepoEntry]:
    """Parse modern deb822 .sources files."""
    entries: list[RepoEntry] = []
    try:
        with open(path) as f:
            content = f.read()
    except OSError:
        return entries

    blocks = re.split(r"\n\s*\n", content)
    for block in blocks:
        if not block.strip():
            continue
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if ":" in line and not line.startswith(" "):
                k, _, v = line.partition(":")
                fields[k.strip().lower()] = v.strip()

        uris = fields.get("uris", "").split()
        suites = fields.get("suites", "")
        components = fields.get("components", "").split()
        enabled = fields.get("enabled", "yes").lower() != "no"
        signed_by = "signed-by" in fields

        for url in uris:
            is_https = url.startswith("https://")
            has_gpg = signed_by or _infer_gpg(url, all_keys)
            official = _is_official_apt(url)
            entries.append(RepoEntry(
                kind=RepoKind.APT,
                name=f"{url.split('/')[2]} — {suites}",
                url=url,
                is_https=is_https,
                has_gpg=has_gpg,
                is_official=official,
                is_enabled=enabled,
                components=components,
            ))
    return entries


def _collect_apt(all_keys: set[str]) -> list[RepoEntry]:
    entries: list[RepoEntry] = []
    source_files = ["/etc/apt/sources.list"]
    source_files += glob.glob("/etc/apt/sources.list.d/*.list")

    for path in source_files:
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or (line.startswith("#") and "deb" not in line):
                        continue
                    e = _parse_apt_line(line, all_keys)
                    if e:
                        entries.append(e)
        except OSError as exc:
            log.warning("repo_checker: cannot read %s: %s", path, exc)

    for path in glob.glob("/etc/apt/sources.list.d/*.sources"):
        entries.extend(_parse_deb822(path, all_keys))

    return entries


# ── Snap parser ───────────────────────────────────────────────────────────

def _collect_snap() -> list[RepoEntry]:
    entries: list[RepoEntry] = []
    try:
        result = subprocess.run(
            ["snap", "list"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # snap itself is the only "source" we model
            entries.append(RepoEntry(
                kind=RepoKind.SNAP,
                name="Snap store — Canonical",
                url="https://api.snapcraft.io",
                is_https=True,
                has_gpg=True,
                is_official=True,
                is_enabled=True,
                notes="Packages verified by Canonical",
            ))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return entries


# ── Flatpak parser ────────────────────────────────────────────────────────

def _collect_flatpak() -> list[RepoEntry]:
    entries: list[RepoEntry] = []
    try:
        result = subprocess.run(
            ["flatpak", "remotes", "--columns=name,url,gpg-verify"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return entries
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 2:
                continue
            name = parts[0]
            url  = parts[1]
            gpg  = len(parts) > 2 and parts[2].lower() == "true"
            is_https = url.startswith("https://")
            official = any(d in url for d in _OFFICIAL_FLATPAK)
            entries.append(RepoEntry(
                kind=RepoKind.FLATPAK,
                name=f"Flatpak — {name}",
                url=url,
                is_https=is_https,
                has_gpg=gpg,
                is_official=official,
                is_enabled=True,
            ))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return entries


# ── Public API ────────────────────────────────────────────────────────────

def audit_all() -> list[RepoEntry]:
    """
    Collect and audit all configured repositories.
    Safe to call from a worker thread.
    """
    all_keys = _gpg_keys_present()
    entries: list[RepoEntry] = []
    entries.extend(_collect_apt(all_keys))
    entries.extend(_collect_snap())
    entries.extend(_collect_flatpak())
    log.info("repo_checker: audited %d repository entries", len(entries))
    return entries


def danger_count(entries: list[RepoEntry]) -> int:
    return sum(1 for e in entries if e.status == RepoStatus.DANGER)


def warn_count(entries: list[RepoEntry]) -> int:
    return sum(1 for e in entries if e.status == RepoStatus.WARN)
