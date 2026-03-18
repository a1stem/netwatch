"""
tls_heuristic.py
----------------
Classifies a connection as encrypted, plaintext, or uncertain based on
the remote port and protocol.  No deep-packet inspection — this is a
best-effort heuristic that gives the user a meaningful signal without
requiring root-level traffic analysis.
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum, auto


class TLSStatus(Enum):
    ENCRYPTED    = auto()   # Almost certainly TLS (443, 8443, …)
    PLAINTEXT    = auto()   # Almost certainly cleartext (80, 21, 23, …)
    LIKELY_ENC   = auto()   # Common encrypted alt-ports (8444, 4433, …)
    UNKNOWN      = auto()   # No strong signal either way


_ENCRYPTED_PORTS: frozenset[int] = frozenset({
    443, 8443, 4443, 9443,      # HTTPS / generic TLS
    465, 587, 993, 995,         # SMTPS, IMAPS, POP3S
    636, 3269,                  # LDAPS
    853,                        # DNS over TLS
    5061,                       # SIPS
    6679, 6697,                 # IRCs
})

_LIKELY_ENCRYPTED_PORTS: frozenset[int] = frozenset({
    4433, 8444, 10443, 1443, 2443, 7443,
})

_PLAINTEXT_PORTS: frozenset[int] = frozenset({
    80, 8080, 8008, 3128,       # HTTP / proxies
    21,                         # FTP control
    23,                         # Telnet
    25,                         # SMTP (unencrypted)
    110,                        # POP3
    143,                        # IMAP
    389,                        # LDAP
    3306,                       # MySQL (often unencrypted by default)
    5432,                       # PostgreSQL (often unencrypted by default)
    11211,                      # Memcached
    27017,                      # MongoDB
})

# Ports that are almost always package manager traffic over TLS
_PKG_PORTS: frozenset[int] = frozenset({443, 80})

# Port → service name (for tooltip display)
_PORT_LABELS: dict[int, str] = {
    80:    "HTTP",
    443:   "HTTPS",
    8080:  "HTTP alt",
    8443:  "HTTPS alt",
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    110:   "POP3",
    143:   "IMAP",
    465:   "SMTPS",
    587:   "SMTP/TLS",
    993:   "IMAPS",
    995:   "POP3S",
    3306:  "MySQL",
    5432:  "PostgreSQL",
}


@dataclass
class TLSResult:
    status: TLSStatus
    remote_port: int
    service_name: str       # e.g. "HTTPS", "HTTP", "unknown"
    is_pkg_port: bool       # True if port is typical for package manager traffic

    @property
    def is_plaintext(self) -> bool:
        return self.status == TLSStatus.PLAINTEXT

    @property
    def is_encrypted(self) -> bool:
        return self.status in (TLSStatus.ENCRYPTED, TLSStatus.LIKELY_ENC)

    @property
    def risk_label(self) -> str:
        if self.status == TLSStatus.PLAINTEXT:
            return f"Unencrypted ({self.service_name})"
        if self.status == TLSStatus.ENCRYPTED:
            return f"Encrypted ({self.service_name})"
        if self.status == TLSStatus.LIKELY_ENC:
            return f"Likely encrypted (port {self.remote_port})"
        return f"Unknown encryption (port {self.remote_port})"

    @property
    def color_hint(self) -> str:
        """CSS-style hint for the GUI — 'red', 'green', 'amber', 'gray'."""
        return {
            TLSStatus.PLAINTEXT:  "red",
            TLSStatus.ENCRYPTED:  "green",
            TLSStatus.LIKELY_ENC: "amber",
            TLSStatus.UNKNOWN:    "gray",
        }[self.status]


def classify(remote_port: int) -> TLSResult:
    """Classify encryption status from the remote port number."""
    if remote_port in _ENCRYPTED_PORTS:
        status = TLSStatus.ENCRYPTED
    elif remote_port in _LIKELY_ENCRYPTED_PORTS:
        status = TLSStatus.LIKELY_ENC
    elif remote_port in _PLAINTEXT_PORTS:
        status = TLSStatus.PLAINTEXT
    else:
        status = TLSStatus.UNKNOWN

    return TLSResult(
        status=status,
        remote_port=remote_port,
        service_name=_PORT_LABELS.get(remote_port, f"port {remote_port}"),
        is_pkg_port=remote_port in _PKG_PORTS,
    )


def is_high_risk_update(remote_port: int, is_pkg_manager: bool) -> bool:
    """
    True when a known package manager is connecting over plain HTTP.
    This is the primary spoofed-repo detection signal.
    """
    return is_pkg_manager and remote_port in _PLAINTEXT_PORTS
