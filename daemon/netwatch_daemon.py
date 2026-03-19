#!/usr/bin/env python3
"""
daemon/netwatch_daemon.py
--------------------------
Optional privileged daemon that runs as a systemd service with CAP_NET_ADMIN.
Writes connection snapshots to a Unix socket so the GUI can read them without
needing root itself.

This is the recommended long-term deployment model:
  1. Run this daemon as root (or with cap_net_admin) via systemd.
  2. Run main.py as a normal user — it reads from the socket.

For initial/simple use, just run main.py with sudo instead.

Socket path: /run/netwatch/conn.sock
Protocol:    newline-delimited JSON, one ConnectionSnapshot per line.

Install:
    sudo cp daemon/netwatch.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now netwatch
"""

import json
import logging
import os
import signal
import socket
import sys
import time
import threading
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s — %(message)s",
)
log = logging.getLogger("netwatch.daemon")

_HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_HERE))

SOCKET_PATH = "/run/netwatch/conn.sock"
SOCKET_DIR  = "/run/netwatch"
POLL_INTERVAL = 5   # seconds


def _poll_connections() -> list[dict]:
    """Collect active internet connections. Must run as root / cap_net_admin."""
    import psutil
    results = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr:
                continue
            rip = conn.raddr.ip
            if rip in ("127.0.0.1", "::1"):
                continue
            results.append({
                "local_ip":    conn.laddr.ip   if conn.laddr else "",
                "local_port":  conn.laddr.port if conn.laddr else 0,
                "remote_ip":   rip,
                "remote_port": conn.raddr.port,
                "proto":       "UDP" if conn.type == 2 else "TCP",
                "status":      conn.status or "",
                "pid":         conn.pid or 0,
            })
    except psutil.AccessDenied:
        log.error("Access denied — daemon must run as root or with CAP_NET_ADMIN")
    return results


def _serve(sock_path: str) -> None:
    """Accept client connections and stream snapshots."""
    os.makedirs(SOCKET_DIR, exist_ok=True)
    # Remove stale socket
    try:
        os.unlink(sock_path)
    except FileNotFoundError:
        pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    os.chmod(sock_path, 0o660)      # group-readable for netwatch group
    server.listen(5)
    server.settimeout(1.0)

    log.info("daemon: listening on %s", sock_path)
    clients: list[socket.socket] = []
    clients_lock = threading.Lock()

    def _accept_loop():
        while _running:
            try:
                client, _ = server.accept()
                log.info("daemon: client connected")
                with clients_lock:
                    clients.append(client)
            except socket.timeout:
                pass
            except OSError:
                break

    accept_thread = threading.Thread(target=_accept_loop, daemon=True)
    accept_thread.start()

    while _running:
        snapshot = _poll_connections()
        payload = (json.dumps(snapshot) + "\n").encode()

        with clients_lock:
            dead = []
            for c in clients:
                try:
                    c.sendall(payload)
                except (BrokenPipeError, OSError):
                    dead.append(c)
            for c in dead:
                clients.remove(c)
                try:
                    c.close()
                except OSError:
                    pass

        for _ in range(POLL_INTERVAL * 10):
            if not _running:
                break
            time.sleep(0.1)

    server.close()
    log.info("daemon: stopped")


_running = True


def _handle_signal(sig, _frame):
    global _running
    log.info("daemon: received signal %d — shutting down", sig)
    _running = False


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ERROR: netwatch daemon must run as root.")
        sys.exit(1)

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)

    log.info("daemon: starting (pid=%d)", os.getpid())
    _serve(SOCKET_PATH)
