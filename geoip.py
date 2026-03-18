"""
geoip.py
--------
Offline GeoIP country lookup using the MaxMind GeoLite2-Country database.
Falls back gracefully if the database file is absent (user hasn't downloaded it yet).

To install the database:
    mkdir -p netwatch/data
    # Download GeoLite2-Country.mmdb from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
    # Place it at netwatch/data/GeoLite2-Country.mmdb

The 'maxminddb' package is required:
    pip3 install maxminddb
"""

from __future__ import annotations
import logging
import os
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)

# ── Country data ────────────────────────────────────────────────────────────

# ISO 3166-1 alpha-2 → flag emoji (covers the most common cases)
def _flag(code: str) -> str:
    """Convert ISO country code to flag emoji."""
    if not code or len(code) != 2:
        return "🌐"
    return chr(0x1F1E6 + ord(code[0]) - ord("A")) + \
           chr(0x1F1E6 + ord(code[1]) - ord("A"))


@dataclass
class GeoResult:
    ip: str
    country_code: str       # e.g. "US", "DE", "CN"
    country_name: str       # e.g. "United States"
    flag: str               # emoji flag

    @classmethod
    def unknown(cls, ip: str) -> "GeoResult":
        return cls(ip=ip, country_code="??", country_name="Unknown", flag="🌐")

    @classmethod
    def private(cls, ip: str) -> "GeoResult":
        return cls(ip=ip, country_code="LO", country_name="Private / local", flag="🏠")

    def display(self) -> str:
        return f"{self.flag} {self.country_code}"

    def tooltip(self) -> str:
        return f"{self.flag} {self.country_name} ({self.country_code})"


# ── Private IP detection ────────────────────────────────────────────────────

_PRIVATE_PREFIXES = (
    "10.", "192.168.", "127.", "::1", "fc", "fd",
    "169.254.",     # link-local
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


# ── Loader ──────────────────────────────────────────────────────────────────

class GeoIPLookup:
    """
    Wraps the maxminddb reader.  Safe to instantiate even if the db
    or the library is absent — all lookups return GeoResult.unknown().
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._reader = None
        self._available = False

        if db_path is None:
            # Default: same directory as this file's package (data/)
            here = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(here, "..", "data", "GeoLite2-Country.mmdb")

        db_path = os.path.normpath(db_path)

        if not os.path.isfile(db_path):
            log.info("geoip: database not found at %s — country lookup disabled", db_path)
            return

        try:
            import maxminddb                        # type: ignore
            self._reader = maxminddb.open_database(db_path)
            self._available = True
            log.info("geoip: loaded database from %s", db_path)
        except ImportError:
            log.warning("geoip: 'maxminddb' package not installed — "
                        "run: pip3 install maxminddb")
        except Exception as exc:
            log.warning("geoip: failed to open database: %s", exc)

    @property
    def available(self) -> bool:
        return self._available

    def lookup(self, ip: str) -> GeoResult:
        """Return country info for an IP address."""
        if not ip or ip in ("0.0.0.0", "::", ""):
            return GeoResult.unknown(ip)

        if _is_private(ip):
            return GeoResult.private(ip)

        if not self._available or self._reader is None:
            return GeoResult.unknown(ip)

        try:
            record = self._reader.get(ip)
            if record is None:
                return GeoResult.unknown(ip)

            country = record.get("country", {})
            code = country.get("iso_code", "??")
            name = (country.get("names", {}).get("en", "Unknown"))
            return GeoResult(
                ip=ip,
                country_code=code,
                country_name=name,
                flag=_flag(code),
            )
        except Exception as exc:
            log.debug("geoip: lookup failed for %s: %s", ip, exc)
            return GeoResult.unknown(ip)

    def close(self) -> None:
        if self._reader is not None:
            try:
                self._reader.close()
            except Exception:
                pass
            self._reader = None
            self._available = False


# Module-level singleton — shared across the app
_instance: Optional[GeoIPLookup] = None


def init(db_path: Optional[str] = None) -> GeoIPLookup:
    """Initialize (or re-initialize) the module-level singleton."""
    global _instance
    _instance = GeoIPLookup(db_path)
    return _instance


def lookup(ip: str) -> GeoResult:
    """Convenience function — uses the module singleton."""
    global _instance
    if _instance is None:
        _instance = GeoIPLookup()
    return _instance.lookup(ip)
