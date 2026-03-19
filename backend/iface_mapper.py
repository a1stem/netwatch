"""
iface_mapper.py
---------------
Maps a local IP address to its network interface and classifies the
interface type: WiFi, Ethernet, VPN/tunnel, or loopback.

Refreshed on every poll cycle so interface changes (e.g. connecting to
a VPN mid-session) are reflected immediately.
"""

from __future__ import annotations
import logging
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional
import psutil

log = logging.getLogger(__name__)


class IfaceType(Enum):
    WIFI      = auto()
    ETHERNET  = auto()
    VPN       = auto()
    LOOPBACK  = auto()
    UNKNOWN   = auto()


# Interface name prefixes → type
_PREFIX_MAP: list[tuple[tuple[str, ...], IfaceType]] = [
    (("lo",),                          IfaceType.LOOPBACK),
    (("wlan", "wlp", "wlx", "wifi"),   IfaceType.WIFI),
    (("tun", "wg", "proton", "vpn",
      "nordlynx", "mullvad"),           IfaceType.VPN),
    (("eth", "enp", "ens", "enx",
      "em", "eno"),                     IfaceType.ETHERNET),
]

# Risk blurb shown in the GUI tooltip
_RISK_TEXT: dict[IfaceType, str] = {
    IfaceType.WIFI:     "WiFi — susceptible to man-in-the-middle attacks on untrusted networks",
    IfaceType.ETHERNET: "Ethernet — lower interception risk than WiFi",
    IfaceType.VPN:      "VPN / tunnel — traffic routed through an encrypted tunnel",
    IfaceType.LOOPBACK: "Loopback — local only, no external network exposure",
    IfaceType.UNKNOWN:  "Unknown interface type",
}

# Short badge label shown in the connection table
_BADGE_LABEL: dict[IfaceType, str] = {
    IfaceType.WIFI:     "WiFi",
    IfaceType.ETHERNET: "ETH",
    IfaceType.VPN:      "VPN",
    IfaceType.LOOPBACK: "LO",
    IfaceType.UNKNOWN:  "?",
}


@dataclass
class IfaceInfo:
    name: str           # e.g. "wlan0", "eth0", "tun0"
    iface_type: IfaceType
    is_up: bool
    speed_mbps: int     # 0 if unknown

    @property
    def badge(self) -> str:
        return _BADGE_LABEL[self.iface_type]

    @property
    def risk_text(self) -> str:
        return _RISK_TEXT[self.iface_type]

    @property
    def is_wireless(self) -> bool:
        return self.iface_type == IfaceType.WIFI

    @property
    def is_vpn(self) -> bool:
        return self.iface_type == IfaceType.VPN


def _classify(name: str) -> IfaceType:
    low = name.lower()
    for prefixes, kind in _PREFIX_MAP:
        if any(low.startswith(p) for p in prefixes):
            return kind
    return IfaceType.UNKNOWN


class IfaceMapper:
    """
    Maintains a mapping of local IP → IfaceInfo.

    Call refresh() at the start of each poll cycle.
    Then call lookup(local_ip) for each connection.
    """

    def __init__(self) -> None:
        # ip_str → IfaceInfo
        self._ip_map: dict[str, IfaceInfo] = {}
        # iface name → IfaceInfo (for direct name lookup)
        self._name_map: dict[str, IfaceInfo] = {}
        self.refresh()

    def refresh(self) -> None:
        """Re-read interface addresses and stats from the OS."""
        ip_map: dict[str, IfaceInfo] = {}
        name_map: dict[str, IfaceInfo] = {}

        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
        except Exception as exc:
            log.warning("iface_mapper: failed to read interfaces: %s", exc)
            return

        for iface_name, addr_list in addrs.items():
            stat = stats.get(iface_name)
            info = IfaceInfo(
                name=iface_name,
                iface_type=_classify(iface_name),
                is_up=stat.isup if stat else False,
                speed_mbps=stat.speed if stat else 0,
            )
            name_map[iface_name] = info

            for addr in addr_list:
                if addr.family in (2, 10):      # AF_INET=2, AF_INET6=10
                    ip_str = addr.address.split("%")[0]  # strip IPv6 zone id
                    ip_map[ip_str] = info

        self._ip_map = ip_map
        self._name_map = name_map
        log.debug("iface_mapper: mapped %d addresses across %d interfaces",
                  len(ip_map), len(name_map))

    def lookup(self, local_ip: str) -> IfaceInfo:
        """Return IfaceInfo for a local IP, or UNKNOWN if not found."""
        return self._ip_map.get(
            local_ip,
            IfaceInfo(name="?", iface_type=IfaceType.UNKNOWN, is_up=False, speed_mbps=0),
        )

    def lookup_by_name(self, name: str) -> Optional[IfaceInfo]:
        return self._name_map.get(name)

    def all_interfaces(self) -> list[IfaceInfo]:
        """All known interfaces — used by the status bar summary."""
        return list(self._name_map.values())

    def active_wifi_interfaces(self) -> list[IfaceInfo]:
        return [i for i in self._name_map.values()
                if i.iface_type == IfaceType.WIFI and i.is_up]

    def active_vpn_interfaces(self) -> list[IfaceInfo]:
        return [i for i in self._name_map.values()
                if i.iface_type == IfaceType.VPN and i.is_up]
