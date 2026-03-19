"""
poller.py
---------
The central polling engine.  Runs on a QThread, fires every N seconds,
collects all active internet connections, enriches each one with:
  - process chain (resolver)
  - interface type (iface_mapper)
  - TLS heuristic (tls_heuristic)
  - GeoIP country (geoip)
  - package manager detection (pkg_watcher)
  - trust status (trust_store)

Emits Qt signals that the main window connects to for GUI updates.
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
from backend.resolver import ProcessNode
from backend.iface_mapper import IfaceInfo, IfaceType
from backend.tls_heuristic import TLSResult
from backend.geoip import GeoResult
from backend.pkg_watcher import PkgEvent, PkgWatcher

log = logging.getLogger(__name__)

# ── Connection record ───────────────────────────────────────────────────────

@dataclass
class ConnectionRecord:
    """Everything the GUI needs to know about one active connection."""

    # Raw socket data
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    proto: str          # "TCP" or "UDP"
    status: str         # e.g. "ESTABLISHED", "LISTEN"
    pid: int

    # Enriched data
    proc_chain: list[ProcessNode] = field(default_factory=list)
    iface: Optional[IfaceInfo] = None
    tls: Optional[TLSResult] = None
    geo: Optional[GeoResult] = None
    hostname: str = ""          # reverse-DNS result (filled async)
    pkg_event: Optional[PkgEvent] = None

    # Trust state (set by trust_store lookup)
    is_trusted: bool = False
    is_blocked: bool = False

    # Computed at creation time
    first_seen: datetime = field(default_factory=datetime.now)

    # ── Convenience properties used by the table model ──────────────────

    @property
    def app_name(self) -> str:
        if self.proc_chain:
            # Use the leaf (actual process) name
            return self.proc_chain[-1].name
        return f"PID {self.pid}" if self.pid else "?"

    @property
    def app_exe(self) -> str:
        if self.proc_chain:
            return self.proc_chain[-1].exe
        return ""

    @property
    def root_app_name(self) -> str:
        """The topmost user-space ancestor — usually the user-facing app."""
        for node in self.proc_chain:
            if node.pid > 1:
                return node.name
        return self.app_name

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
    def status_flags(self) -> list[str]:
        """Ordered list of status tags for the GUI status column."""
        flags = []
        if self.is_blocked:
            flags.append("blocked")
        elif self.is_trusted:
            flags.append("trusted")
        elif self.is_pkg_manager:
            if self.pkg_event:
                flags.append(self.pkg_event.badge_text())
            else:
                flags.append("update-traffic")
        else:
            flags.append("unknown")

        if self.is_plaintext:
            flags.append("unencrypted")
        if self.is_wifi:
            flags.append("wifi")
        if self.is_vpn:
            flags.append("vpn")
        return flags

    @property
    def row_key(self) -> tuple:
        """Stable identity key for deduplication across poll cycles."""
        return (self.pid, self.local_ip, self.local_port,
                self.remote_ip, self.remote_port)


# ── Poller thread ───────────────────────────────────────────────────────────

class Poller(QThread):
    """
    Signals emitted to the main thread:

    connections_updated(list[ConnectionRecord])
        Full fresh snapshot on every poll.

    pkg_alert(PkgEvent)
        Fired immediately when a high-risk package manager event is detected.

    dns_resolved(str, str)
        (ip, hostname) — fired from DNS worker threads as lookups complete.
        GUI should update matching table rows.

    error(str)
        Non-fatal error message for the status bar.
    """

    connections_updated: pyqtSignal = pyqtSignal(list)
    pkg_alert:           pyqtSignal = pyqtSignal(object)
    dns_resolved:        pyqtSignal = pyqtSignal(str, str)
    error:               pyqtSignal = pyqtSignal(str)

    def __init__(
        self,
        trust_store,        # data.trust_store.TrustStore instance
        history,            # data.history.History instance
        interval_sec: int = 5,
        parent=None,
    ):
        super().__init__(parent)
        self._trust_store = trust_store
        self._history = history
        self._interval = interval_sec
        self._running = False

        self._iface_mapper = iface_mapper.IfaceMapper()
        self._pkg_watcher  = PkgWatcher()

    # ── Thread lifecycle ────────────────────────────────────────────────

    def run(self) -> None:
        self._running = True
        log.info("poller: started (interval=%ds)", self._interval)
        while self._running:
            try:
                records = self._poll()
                self.connections_updated.emit(records)
            except Exception as exc:
                log.exception("poller: unhandled error in poll cycle")
                self.error.emit(f"Poll error: {exc}")
            # Sleep in short chunks so stop() is responsive
            for _ in range(self._interval * 10):
                if not self._running:
                    break
                time.sleep(0.1)
        log.info("poller: stopped")

    def stop(self) -> None:
        self._running = False

    def set_interval(self, seconds: int) -> None:
        self._interval = max(1, seconds)

    # ── Core poll cycle ─────────────────────────────────────────────────

    def _poll(self) -> list[ConnectionRecord]:
        start = time.monotonic()

        # 1. Refresh interface map once per cycle
        self._iface_mapper.refresh()

        # 2. Get all internet connections
        try:
            raw_conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            self.error.emit(
                "Access denied reading network connections. "
                "Try running with: sudo python3 main.py"
            )
            return []

        records: list[ConnectionRecord] = []
        active_pids: set[int] = set()

        for conn in raw_conns:
            # Skip listen-only and unconnected sockets with no remote address
            if not conn.raddr:
                continue
            # Skip pure loopback
            rip = conn.raddr.ip
            if rip in ("127.0.0.1", "::1"):
                continue

            pid = conn.pid or 0
            active_pids.add(pid)

            rec = self._build_record(conn)
            records.append(rec)

            # High-risk package event → immediate signal
            if rec.pkg_event and rec.pkg_event.is_high_risk:
                self.pkg_alert.emit(rec.pkg_event)

        # 3. Log new connections to history
        self._history.log_batch(records)

        # 4. Clean up stale pkg_watcher state
        self._pkg_watcher.clear_stale(active_pids)

        elapsed = time.monotonic() - start
        log.debug("poller: %d connections in %.2fs", len(records), elapsed)
        return records

    # ── Record construction ─────────────────────────────────────────────

    def _build_record(self, conn) -> ConnectionRecord:
        lip  = conn.laddr.ip   if conn.laddr else ""
        lp   = conn.laddr.port if conn.laddr else 0
        rip  = conn.raddr.ip   if conn.raddr else ""
        rp   = conn.raddr.port if conn.raddr else 0
        pid  = conn.pid or 0
        proto = "UDP" if conn.type == 2 else "TCP"   # SOCK_DGRAM=2

        # Process chain
        chain = resolver.resolve_process_chain(pid) if pid else []
        chain = chain or []

        # Apply trust from store
        if chain:
            exe = chain[-1].exe
            for node in chain:
                node.is_trusted = self._trust_store.is_trusted_exe(node.exe)

        is_trusted = self._trust_store.is_trusted_exe(chain[-1].exe) if chain else False
        is_blocked = self._trust_store.is_blocked_ip(rip, rp)

        # Interface
        iface = self._iface_mapper.lookup(lip)

        # TLS heuristic
        tls = tls_heuristic.classify(rp)

        # GeoIP
        geo = geoip.lookup(rip)

        # Package manager check
        proc_name = chain[-1].name if chain else ""
        pkg_event = None
        if resolver.is_pkg_manager_chain(chain):
            # hostname may not be resolved yet — use IP for now
            pkg_event = self._pkg_watcher.evaluate(
                proc_name=proc_name,
                pid=pid,
                remote_ip=rip,
                remote_hostname=rip,    # updated async via dns_resolved signal
                remote_port=rp,
            )

        rec = ConnectionRecord(
            local_ip=lip, local_port=lp,
            remote_ip=rip, remote_port=rp,
            proto=proto,
            status=conn.status or "",
            pid=pid,
            proc_chain=chain,
            iface=iface,
            tls=tls,
            geo=geo,
            is_trusted=is_trusted,
            is_blocked=is_blocked,
            pkg_event=pkg_event,
        )

        # Kick off async DNS — result fires dns_resolved signal
        import backend.dns_lookup as dns
        dns.lookup_async(rip, self._on_dns)

        return rec

    def _on_dns(self, ip: str, hostname: str) -> None:
        """Called from a DNS worker thread — re-emits as a Qt signal."""
        self.dns_resolved.emit(ip, hostname)
