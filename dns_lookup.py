"""
dns_lookup.py
-------------
Reverse DNS lookups with a bounded in-memory LRU-style cache.
Lookups run on a dedicated thread so they never block the polling loop
or the GUI thread.
"""

from __future__ import annotations
import logging
import socket
import threading
from collections import OrderedDict
from typing import Callable, Optional

log = logging.getLogger(__name__)

# ── Cache ──────────────────────────────────────────────────────────────────

_CACHE_MAX = 2048
_cache: OrderedDict[str, str] = OrderedDict()   # ip → hostname
_cache_lock = threading.Lock()

# IPs that consistently fail reverse lookup — skip them quickly
_FAILED: set[str] = set()


def _cache_get(ip: str) -> Optional[str]:
    with _cache_lock:
        if ip in _cache:
            _cache.move_to_end(ip)
            return _cache[ip]
    return None


def _cache_put(ip: str, hostname: str) -> None:
    with _cache_lock:
        _cache[ip] = hostname
        _cache.move_to_end(ip)
        if len(_cache) > _CACHE_MAX:
            _cache.popitem(last=False)


# ── Well-known IP → org mappings (offline, no lookup needed) ───────────────

_KNOWN_RANGES: list[tuple[str, str]] = [
    # (prefix, label)  — checked with str.startswith so keep specific first
    ("8.8.8.",         "Google DNS"),
    ("8.8.4.",         "Google DNS"),
    ("1.1.1.",         "Cloudflare DNS"),
    ("1.0.0.",         "Cloudflare DNS"),
    ("142.250.",       "Google"),
    ("172.217.",       "Google"),
    ("216.58.",        "Google"),
    ("13.107.",        "Microsoft"),
    ("52.96.",         "Microsoft"),
    ("40.76.",         "Microsoft"),
    ("52.114.",        "Microsoft"),
    ("151.101.",       "Fastly CDN"),
    ("199.232.",       "Fastly CDN"),
    ("104.16.",        "Cloudflare"),
    ("104.17.",        "Cloudflare"),
    ("162.125.",       "Dropbox"),
    ("185.220.",       "Tor relay"),
    ("91.108.",        "Telegram"),
    ("149.154.",       "Telegram"),
]


def _check_known(ip: str) -> Optional[str]:
    for prefix, label in _KNOWN_RANGES:
        if ip.startswith(prefix):
            return label
    return None


# ── Public API ─────────────────────────────────────────────────────────────

def lookup_sync(ip: str, timeout: float = 1.5) -> str:
    """
    Blocking reverse DNS lookup.  Returns hostname or original IP on failure.
    Suitable for calling from a worker thread.
    """
    if not ip or ip in ("0.0.0.0", "::", "::1", "127.0.0.1"):
        return ip

    cached = _cache_get(ip)
    if cached is not None:
        return cached

    if ip in _FAILED:
        return ip

    known = _check_known(ip)
    if known:
        _cache_put(ip, known)
        return known

    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        result = hostname
    except (socket.herror, socket.gaierror, OSError):
        _FAILED.add(ip)
        result = ip
    finally:
        socket.setdefaulttimeout(old_timeout)

    _cache_put(ip, result)
    return result


def lookup_async(
    ip: str,
    callback: Callable[[str, str], None],
    timeout: float = 1.5,
) -> None:
    """
    Non-blocking reverse DNS.  Calls callback(ip, hostname) from a daemon thread.
    The GUI should connect this to a slot that updates the relevant table row.
    """
    if not ip:
        return

    cached = _cache_get(ip)
    if cached is not None:
        callback(ip, cached)
        return

    def _worker():
        result = lookup_sync(ip, timeout)
        callback(ip, result)

    t = threading.Thread(target=_worker, daemon=True, name=f"dns-{ip}")
    t.start()


def cache_size() -> int:
    with _cache_lock:
        return len(_cache)


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()
    _FAILED.clear()
