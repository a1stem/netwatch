"""
data/trust_store.py
-------------------
Persists user trust decisions:
  - Trusted executables (by full path)
  - Blocked IP:port pairs
  - Named trusted applications (for display)

Stored as JSON. Thread-safe via a lock (poller reads, GUI writes).
"""

from __future__ import annotations
import json
import logging
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Optional

log = logging.getLogger(__name__)

_DEFAULT_PATH = os.path.join(
    os.path.dirname(__file__), "trusted_apps.json"
)


@dataclass
class TrustedApp:
    exe: str                # full path, e.g. /usr/bin/firefox
    name: str               # display name
    added: str              # ISO timestamp
    notes: str = ""


@dataclass
class BlockedRule:
    remote_ip: str
    remote_port: int        # 0 = all ports for this IP
    proto: str              # "tcp", "udp", "any"
    reason: str
    added: str
    ufw_applied: bool = False


@dataclass
class _Store:
    trusted_apps: dict[str, TrustedApp] = field(default_factory=dict)   # exe → entry
    blocked_rules: list[BlockedRule]    = field(default_factory=list)
    version: int = 1


class TrustStore:
    """
    Thread-safe trust/block persistence.

    All GUI interactions go through this class; the poller reads via
    is_trusted_exe() and is_blocked_ip() which acquire the lock briefly.
    """

    def __init__(self, path: str = _DEFAULT_PATH) -> None:
        self._path = path
        self._lock = threading.RLock()
        self._store = _Store()
        self._load()

    # ── Persistence ───────────────────────────────────────────────────────

    def _load(self) -> None:
        if not os.path.isfile(self._path):
            log.info("trust_store: no existing store at %s — starting fresh", self._path)
            return
        try:
            if os.path.getsize(self._path) == 0:
                return
            with open(self._path) as f:
                raw = json.load(f)
            with self._lock:
                apps = {
                    k: TrustedApp(**v)
                    for k, v in raw.get("trusted_apps", {}).items()
                }
                rules = [BlockedRule(**r) for r in raw.get("blocked_rules", [])]
                self._store = _Store(
                    trusted_apps=apps,
                    blocked_rules=rules,
                    version=raw.get("version", 1),
                )
            log.info("trust_store: loaded %d trusted, %d blocked",
                     len(apps), len(rules))
        except Exception as exc:
            log.error("trust_store: failed to load %s: %s", self._path, exc)

    def save(self) -> None:
        """Write current state to disk atomically."""
        try:
            os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
            with self._lock:
                data = {
                    "version": self._store.version,
                    "trusted_apps": {
                        k: asdict(v) for k, v in self._store.trusted_apps.items()
                    },
                    "blocked_rules": [asdict(r) for r in self._store.blocked_rules],
                }
            tmp = self._path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, self._path)
            log.debug("trust_store: saved to %s", self._path)
        except Exception as exc:
            log.error("trust_store: save failed: %s", exc)

    # ── Trust operations ──────────────────────────────────────────────────

    def trust_exe(self, exe: str, name: str = "", notes: str = "") -> None:
        with self._lock:
            self._store.trusted_apps[exe] = TrustedApp(
                exe=exe,
                name=name or os.path.basename(exe),
                added=datetime.now().isoformat(timespec="seconds"),
                notes=notes,
            )
        self.save()
        log.info("trust_store: trusted %s", exe)

    def untrust_exe(self, exe: str) -> None:
        with self._lock:
            self._store.trusted_apps.pop(exe, None)
        self.save()
        log.info("trust_store: untrusted %s", exe)

    def is_trusted_exe(self, exe: str) -> bool:
        if not exe:
            return False
        with self._lock:
            return exe in self._store.trusted_apps

    def trusted_apps(self) -> list[TrustedApp]:
        with self._lock:
            return list(self._store.trusted_apps.values())

    # ── Block operations ──────────────────────────────────────────────────

    def block_ip_port(
        self,
        remote_ip: str,
        remote_port: int,
        proto: str = "tcp",
        reason: str = "",
        ufw_applied: bool = False,
    ) -> None:
        rule = BlockedRule(
            remote_ip=remote_ip,
            remote_port=remote_port,
            proto=proto,
            reason=reason,
            added=datetime.now().isoformat(timespec="seconds"),
            ufw_applied=ufw_applied,
        )
        with self._lock:
            # Remove any existing rule for same ip:port
            self._store.blocked_rules = [
                r for r in self._store.blocked_rules
                if not (r.remote_ip == remote_ip and r.remote_port == remote_port)
            ]
            self._store.blocked_rules.append(rule)
        self.save()
        log.info("trust_store: blocked %s:%d", remote_ip, remote_port)

    def unblock_ip_port(self, remote_ip: str, remote_port: int) -> None:
        with self._lock:
            self._store.blocked_rules = [
                r for r in self._store.blocked_rules
                if not (r.remote_ip == remote_ip and r.remote_port == remote_port)
            ]
        self.save()

    def is_blocked_ip(self, remote_ip: str, remote_port: int) -> bool:
        with self._lock:
            for r in self._store.blocked_rules:
                if r.remote_ip == remote_ip:
                    if r.remote_port == 0 or r.remote_port == remote_port:
                        return True
        return False

    def blocked_rules(self) -> list[BlockedRule]:
        with self._lock:
            return list(self._store.blocked_rules)
