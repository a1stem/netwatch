"""
poller.py — central QThread polling engine.
Now includes auto-deny for connections with no resolvable process,
and socket-level fallback lookup for zero-PID connections.
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


@dataclass
class ConnectionRecord:
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    proto: str
    status: str
    pid: int

    proc_chain: list[ProcessNode] = field(default_factory=list)
    iface: Optional[IfaceInfo] = None
    tls: Optional[TLSResult] = None
    geo: Optional[GeoResult] = None
    hostname: str = ""
    pkg_event: Optional[PkgEvent] = None

    is_trusted: bool = False
    is_blocked: bool = False
    # New: set True when no process could be identified at all
    is_unidentified: bool = False
    # New: set True when auto-denied due to unidentified process
    auto_denied: bool = False

    first_seen: datetime = field(default_factory=datetime.now)

    @property
    def app_name(self) -> str:
        if self.proc_chain:
            n = self.proc_chain[-1].name
            if n and n != "?":
                return n
        if self.pid:
            # Last-ditch: read comm directly
            name = resolver._proc_name(self.pid)
            if name:
                return name
        if self.is_unidentified:
            return "⚠ unidentified"
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
        flags = []
        if self.auto_denied:
            flags.append("auto-denied")
        elif self.is_blocked:
            flags.append("blocked")
        elif self.is_unidentified:
            flags.append("unidentified")
        elif self.is_trusted:
            flags.append("trusted")
        elif self.is_pkg_manager:
            flags.append(self.pkg_event.badge_text() if self.pkg_event else "update-traffic")
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
        return (self.pid, self.local_ip, self.local_port,
                self.remote_ip, self.remote_port)


class Poller(QThread):
    connections_updated: pyqtSignal = pyqtSignal(list)
    pkg_alert:           pyqtSignal = pyqtSignal(object)
    dns_resolved:        pyqtSignal = pyqtSignal(str, str)
    auto_deny_applied:   pyqtSignal = pyqtSignal(object)   # fires when auto-deny blocks something
    error:               pyqtSignal = pyqtSignal(str)

    def __init__(self, trust_store, history, interval_sec=5,
                 auto_deny_unidentified=True, parent=None):
        super().__init__(parent)
        self._trust_store = trust_store
        self._history = history
        self._interval = interval_sec
        self._auto_deny = auto_deny_unidentified
        self._running = False
        self._iface_mapper = iface_mapper.IfaceMapper()
        self._pkg_watcher  = PkgWatcher()
        # Track auto-denied IPs this session to avoid re-blocking on every poll
        self._auto_denied_keys: set[tuple] = set()

    def run(self) -> None:
        self._running = True
        log.info("poller: started (interval=%ds, auto_deny=%s)",
                 self._interval, self._auto_deny)
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

    def set_auto_deny(self, enabled: bool) -> None:
        self._auto_deny = enabled

    def _poll(self) -> list[ConnectionRecord]:
        start = time.monotonic()
        self._iface_mapper.refresh()

        try:
            raw_conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            self.error.emit(
                "Access denied reading connections. Run with: sudo python3 main.py"
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

            rec = self._build_record(conn)

            # ── Auto-deny unidentified connections ─────────────────────────
            if self._auto_deny and rec.is_unidentified and not rec.is_blocked:
                deny_key = (rec.remote_ip, rec.remote_port)
                if deny_key not in self._auto_denied_keys:
                    self._auto_denied_keys.add(deny_key)
                    self._apply_auto_deny(rec)

            if rec.pkg_event and rec.pkg_event.is_high_risk:
                self.pkg_alert.emit(rec.pkg_event)

            records.append(rec)

        self._history.log_batch(records)
        self._pkg_watcher.clear_stale(active_pids)

        log.debug("poller: %d connections in %.2fs",
                  len(records), time.monotonic() - start)
        return records

    def _apply_auto_deny(self, rec: ConnectionRecord) -> None:
        """Block outbound to this IP:port via UFW and persist to trust store."""
        from backend import ufw as ufw_mod
        result = ufw_mod.block_outbound(rec.remote_ip, rec.remote_port,
                                        rec.proto.lower())
        self._trust_store.block_ip_port(
            remote_ip=rec.remote_ip,
            remote_port=rec.remote_port,
            proto=rec.proto.lower(),
            reason="Auto-denied: no identifiable process",
            ufw_applied=result.success,
        )
        rec.is_blocked = True
        rec.auto_denied = True
        log.warning("poller: auto-denied %s:%d (unidentified process)",
                    rec.remote_ip, rec.remote_port)
        self.auto_deny_applied.emit(rec)

    def _build_record(self, conn) -> ConnectionRecord:
        lip  = conn.laddr.ip   if conn.laddr else ""
        lp   = conn.laddr.port if conn.laddr else 0
        rip  = conn.raddr.ip   if conn.raddr else ""
        rp   = conn.raddr.port if conn.raddr else 0
        pid  = conn.pid or 0
        proto = "UDP" if conn.type == 2 else "TCP"

        # ── Process chain — with socket-level fallback for pid=0 ──────────
        chain = []
        if pid:
            chain = resolver.resolve_process_chain(pid) or []

        # If still empty (pid=0 or psutil failed), try socket scan
        is_unidentified = False
        if not chain:
            node = resolver.try_resolve_from_socket(rip, rp)
            if node:
                chain = [node]
            else:
                is_unidentified = True
                log.debug("poller: unidentified connection %s:%d", rip, rp)

        # Apply trust flags to each node
        for node in chain:
            node.is_trusted = self._trust_store.is_trusted_exe(node.exe)

        is_trusted = any(n.is_trusted for n in chain)
        is_blocked = self._trust_store.is_blocked_ip(rip, rp)

        iface   = self._iface_mapper.lookup(lip)
        tls     = tls_heuristic.classify(rp)
        geo     = geoip.lookup(rip)

        pkg_event = None
        if chain and resolver.is_pkg_manager_chain(chain):
            pkg_event = self._pkg_watcher.evaluate(
                proc_name=chain[-1].name,
                pid=pid,
                remote_ip=rip,
                remote_hostname=rip,
                remote_port=rp,
            )

        rec = ConnectionRecord(
            local_ip=lip, local_port=lp,
            remote_ip=rip, remote_port=rp,
            proto=proto, status=conn.status or "",
            pid=pid,
            proc_chain=chain,
            iface=iface, tls=tls, geo=geo,
            is_trusted=is_trusted,
            is_blocked=is_blocked,
            is_unidentified=is_unidentified,
            pkg_event=pkg_event,
        )

        import backend.dns_lookup as dns
        dns.lookup_async(rip, self._on_dns)
        return rec

    def _on_dns(self, ip: str, hostname: str) -> None:
        self.dns_resolved.emit(ip, hostname)
