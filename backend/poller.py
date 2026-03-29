"""
backend/poller.py
-----------------
Central QThread polling engine — MONITOR-FIRST design.

Key changes from previous version:
  - Auto-deny is REMOVED entirely. UFW rules only applied on explicit user action.
  - Every connection is enriched with OrgInfo from infra_fingerprint.
  - Five trust tiers: TRUSTED / KNOWN_INFRA / UNKNOWN / SUSPICIOUS / BLOCKED
  - ConnectionRecord carries the full OrgInfo for display.
"""

from __future__ import annotations
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import psutil
from PyQt5.QtCore import QThread, pyqtSignal

from backend import resolver, iface_mapper, tls_heuristic, geoip, pkg_watcher
from backend.infra_fingerprint import fingerprint, OrgInfo, InfraTier
from backend.resolver import ProcessNode
from backend.iface_mapper import IfaceInfo
from backend.tls_heuristic import TLSResult
from backend.geoip import GeoResult
from backend.pkg_watcher import PkgEvent, PkgWatcher

log = logging.getLogger(__name__)


class TrustTier(str):
    TRUSTED     = "trusted"
    KNOWN_INFRA = "known_infra"
    UNKNOWN     = "unknown"
    SUSPICIOUS  = "suspicious"
    BLOCKED     = "blocked"


@dataclass
class ConnectionRecord:
    # Raw socket
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    proto: str
    status: str
    pid: int

    # Enriched
    proc_chain: list[ProcessNode] = field(default_factory=list)
    iface: Optional[IfaceInfo] = None
    tls: Optional[TLSResult] = None
    geo: Optional[GeoResult] = None
    org: Optional[OrgInfo] = None          # NEW — organisation fingerprint
    hostname: str = ""
    pkg_event: Optional[PkgEvent] = None

    # Trust state
    is_trusted: bool = False
    is_blocked: bool = False
    is_unidentified: bool = False
    auto_denied: bool = False              # kept for history compat, never set

    first_seen: datetime = field(default_factory=datetime.now)

    # ── Computed properties ───────────────────────────────────────────────

    @property
    def trust_tier(self) -> str:
        """The primary trust tier — drives colour and icon in the table."""
        if self.is_blocked:
            return TrustTier.BLOCKED
        if self.is_trusted:
            return TrustTier.TRUSTED
        if self.org and self.org.is_suspicious:
            return TrustTier.SUSPICIOUS
        if self.org and self.org.is_known:
            return TrustTier.KNOWN_INFRA
        if self.is_pkg_manager:
            # pkg manager connections inherit their risk from pkg_event
            return TrustTier.KNOWN_INFRA
        return TrustTier.UNKNOWN

    @property
    def app_name(self) -> str:
        if self.proc_chain:
            n = self.proc_chain[-1].name
            if n and n not in ("?", ""):
                return n
        if self.pid:
            name = resolver._proc_name(self.pid)
            if name:
                return name
        return "?"

    @property
    def app_exe(self) -> str:
        if self.proc_chain:
            return self.proc_chain[-1].exe
        return ""

    @property
    def root_app_name(self) -> str:
        for node in self.proc_chain:
            if node.pid > 1:
                return node.name
        return self.app_name

    @property
    def org_label(self) -> str:
        """Human-readable org name for display — e.g. 'GitHub', 'Cloudflare CDN'."""
        if self.org and self.org.is_known:
            return self.org.display
        if self.hostname and self.hostname != self.remote_ip:
            # Show root domain as fallback even if org not recognised
            parts = self.hostname.rstrip(".").split(".")
            if len(parts) >= 2:
                return ".".join(parts[-2:])
        return ""

    @property
    def remote_display(self) -> str:
        host = self.hostname if self.hostname and self.hostname != self.remote_ip \
               else self.remote_ip
        return f"{host}:{self.remote_port}"

    @property
    def iface_badge(self) -> str:
        return self.iface.badge if self.iface else "?"

    @property
    def is_wifi(self) -> bool:
        return self.iface is not None and self.iface.is_wireless

    @property
    def is_vpn(self) -> bool:
        return self.iface is not None and self.iface.is_vpn

    @property
    def is_pkg_manager(self) -> bool:
        return resolver.is_pkg_manager_chain(self.proc_chain)

    @property
    def is_plaintext(self) -> bool:
        return self.tls is not None and self.tls.is_plaintext

    @property
    def row_key(self) -> tuple:
        return (self.pid, self.local_ip, self.local_port,
                self.remote_ip, self.remote_port)


class Poller(QThread):
    """
    Monitor-first poller.

    Signals:
        connections_updated(list[ConnectionRecord])
        pkg_alert(PkgEvent)         — high-risk pkg manager event
        dns_resolved(ip, hostname)  — async DNS result
        org_resolved(ip, hostname)  — org fingerprint updated after DNS
        error(str)
    """

    connections_updated: pyqtSignal = pyqtSignal(list)
    pkg_alert:           pyqtSignal = pyqtSignal(object)
    dns_resolved:        pyqtSignal = pyqtSignal(str, str)
    org_resolved:        pyqtSignal = pyqtSignal(str, str)   # ip, org_label
    error:               pyqtSignal = pyqtSignal(str)

    def __init__(self, trust_store, history,
                 interval_sec: int = 5, parent=None):
        super().__init__(parent)
        self._trust_store = trust_store
        self._history = history
        self._interval = interval_sec
        self._running = False
        self._iface_mapper = iface_mapper.IfaceMapper()
        self._pkg_watcher  = PkgWatcher()
        # Cache: ip → OrgInfo (populated async as DNS resolves)
        self._org_cache: dict[str, OrgInfo] = {}

    def run(self) -> None:
        self._running = True
        log.info("poller: started — MONITOR MODE (no auto-deny)")
        while self._running:
            try:
                records = self._poll()
                self.connections_updated.emit(records)
            except Exception as exc:
                log.exception("poller: unhandled error in poll cycle")
                self.error.emit(f"Poll error: {exc}")
            for _ in range(self._interval * 10):
                if not self._running:
                    break
                time.sleep(0.1)
        log.info("poller: stopped")

    def stop(self) -> None:
        self._running = False

    def set_interval(self, seconds: int) -> None:
        self._interval = max(1, seconds)

    def _poll(self) -> list[ConnectionRecord]:
        start = time.monotonic()
        self._iface_mapper.refresh()

        try:
            raw_conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            self.error.emit(
                "Access denied. Run with: sudo python3 main.py"
            )
            return []

        records: list[ConnectionRecord] = []
        active_pids: set[int] = set()

        for conn in raw_conns:
            if not conn.raddr:
                continue
            rip = conn.raddr.ip
            if rip in ("127.0.0.1", "::1"):
                continue
            pid = conn.pid or 0
            active_pids.add(pid)
            records.append(self._build_record(conn))

        self._history.log_batch(records)
        self._pkg_watcher.clear_stale(active_pids)

        log.debug("poller: %d connections in %.2fs",
                  len(records), time.monotonic() - start)
        return records

    def _build_record(self, conn) -> ConnectionRecord:
        lip  = conn.laddr.ip   if conn.laddr else ""
        lp   = conn.laddr.port if conn.laddr else 0
        rip  = conn.raddr.ip   if conn.raddr else ""
        rp   = conn.raddr.port if conn.raddr else 0
        pid  = conn.pid or 0
        proto = "UDP" if conn.type == 2 else "TCP"

        # ── Process chain ─────────────────────────────────────────────────
        chain = []
        is_unidentified = False
        if pid:
            chain = resolver.resolve_process_chain(pid) or []
        if not chain:
            node = resolver.try_resolve_from_socket(rip, rp)
            if node:
                chain = [node]
            else:
                is_unidentified = True

        for node in chain:
            node.is_trusted = self._trust_store.is_trusted_exe(node.exe)

        is_trusted = any(n.is_trusted for n in chain)
        is_blocked = self._trust_store.is_blocked_ip(rip, rp)

        # ── Enrichment ────────────────────────────────────────────────────
        iface = self._iface_mapper.lookup(lip)
        tls   = tls_heuristic.classify(rp)
        geo   = geoip.lookup(rip)

        # Org fingerprint — use cached result if DNS already resolved this IP
        cached_hostname = self._org_cache.get(rip)
        geo_org = geo.country_name if geo else ""
        org = fingerprint(
            ip=rip,
            hostname=cached_hostname.org_name if cached_hostname else rip,
            geoip_org=geo_org,
        )
        # If not yet resolved from hostname, try IP prefix alone
        if org.tier == InfraTier.UNKNOWN:
            org = fingerprint(ip=rip, hostname="", geoip_org=geo_org)

        # ── Package manager ───────────────────────────────────────────────
        pkg_event = None
        if chain and resolver.is_pkg_manager_chain(chain):
            leaf = chain[-1]
            pkg_event = self._pkg_watcher.evaluate(
                proc_name=leaf.name,
                pid=pid,
                exe_path=leaf.exe,
                remote_ip=rip,
                remote_hostname=rip,
                remote_port=rp,
            )
            if pkg_event and pkg_event.is_high_risk:
                self.pkg_alert.emit(pkg_event)

        rec = ConnectionRecord(
            local_ip=lip, local_port=lp,
            remote_ip=rip, remote_port=rp,
            proto=proto, status=conn.status or "",
            pid=pid, proc_chain=chain,
            iface=iface, tls=tls, geo=geo, org=org,
            is_trusted=is_trusted,
            is_blocked=is_blocked,
            is_unidentified=is_unidentified,
            pkg_event=pkg_event,
        )

        # Async DNS — when it resolves, re-fingerprint with the hostname
        import backend.dns_lookup as dns
        dns.lookup_async(rip, self._on_dns)
        return rec

    def _on_dns(self, ip: str, hostname: str) -> None:
        """DNS resolved — update org cache and emit for table update."""
        org = fingerprint(ip=ip, hostname=hostname)
        self._org_cache[ip] = org
        self.dns_resolved.emit(ip, hostname)
        if org.is_known:
            self.org_resolved.emit(ip, org.display)
