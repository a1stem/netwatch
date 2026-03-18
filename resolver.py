"""
resolver.py
-----------
Resolves a PID to a full ProcessNode with its complete parent ancestry chain.
This is the core of the "don't block a child without knowing its parent" safety feature.
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import Optional
import psutil

log = logging.getLogger(__name__)


@dataclass
class ProcessNode:
    """Represents one process in the ancestry chain."""
    pid: int
    name: str
    exe: str                        # full path, e.g. /usr/bin/firefox
    cmdline: str                    # joined command line for display
    ppid: Optional[int]
    username: str
    children: list["ProcessNode"] = field(default_factory=list)

    # Filled in later by trust_store
    is_trusted: bool = False
    is_package_manager: bool = False

    def display_name(self) -> str:
        """Short human-readable label: 'firefox (/usr/bin/firefox)'"""
        if self.exe and self.exe != self.name:
            return f"{self.name}  ({self.exe})"
        return self.name

    def ancestry_path(self) -> str:
        """Used for display in the tree panel, e.g. systemd > gnome-session > firefox"""
        return self.name


# Package manager executable names to auto-flag
_PKG_MANAGERS = frozenset({
    "apt", "apt-get", "apt-cache", "dpkg", "aptd", "unattended-upgrade",
    "snap", "snapd", "flatpak", "pip", "pip3", "pipx",
    "npm", "yarn", "cargo", "gem", "go",
})


def _safe_proc_info(proc: psutil.Process) -> Optional[dict]:
    """Gather process fields tolerantly — process may vanish mid-read."""
    try:
        with proc.oneshot():
            return {
                "pid":      proc.pid,
                "name":     proc.name(),
                "exe":      _safe_exe(proc),
                "cmdline":  " ".join(proc.cmdline()) or proc.name(),
                "ppid":     proc.ppid(),
                "username": _safe_username(proc),
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def _safe_exe(proc: psutil.Process) -> str:
    try:
        return proc.exe()
    except (psutil.AccessDenied, FileNotFoundError, psutil.NoSuchProcess):
        return ""


def _safe_username(proc: psutil.Process) -> str:
    try:
        return proc.username()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return "?"


def _make_node(info: dict) -> ProcessNode:
    is_pm = info["name"].lower() in _PKG_MANAGERS or any(
        pm in info["exe"].lower() for pm in _PKG_MANAGERS
    )
    return ProcessNode(
        pid=info["pid"],
        name=info["name"],
        exe=info["exe"],
        cmdline=info["cmdline"],
        ppid=info["ppid"],
        username=info["username"],
        is_package_manager=is_pm,
    )


def resolve_process_chain(pid: int) -> Optional[list[ProcessNode]]:
    """
    Walk the parent chain for `pid` up to PID 1 (or until psutil gives up).

    Returns a list ordered [root, ..., direct_parent, target_process].
    Returns None if the process no longer exists.

    Example for a Firefox Web Content child:
        [ProcessNode(systemd,1), ProcessNode(gnome-session,2201),
         ProcessNode(firefox,8832), ProcessNode(Web Content,8901)]
    """
    chain: list[ProcessNode] = []
    visited: set[int] = set()

    try:
        proc = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

    # Walk upward: target → parent → grandparent → … → init
    current = proc
    while current is not None:
        if current.pid in visited:
            break                   # cycle guard (shouldn't happen on Linux)
        visited.add(current.pid)

        info = _safe_proc_info(current)
        if info is None:
            break

        chain.append(_make_node(info))

        if current.pid <= 1:
            break

        try:
            parent = current.parent()
            if parent is None or parent.pid in visited:
                break
            current = parent
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            break

    # Reverse so index 0 is the root (systemd/init)
    chain.reverse()
    return chain if chain else None


def root_process(chain: list[ProcessNode]) -> Optional[ProcessNode]:
    """The topmost non-init process — usually the user-facing application."""
    # Skip PID 1 (systemd/init) and return the next meaningful ancestor
    for node in chain:
        if node.pid > 1:
            return node
    return chain[-1] if chain else None


def target_process(chain: list[ProcessNode]) -> Optional[ProcessNode]:
    """The actual process that owns the socket — the last in the chain."""
    return chain[-1] if chain else None


def is_any_trusted(chain: list[ProcessNode]) -> bool:
    """True if any node in the chain has been marked trusted."""
    return any(n.is_trusted for n in chain)


def is_pkg_manager_chain(chain: list[ProcessNode]) -> bool:
    """True if any node in the chain is a known package manager."""
    return any(n.is_package_manager for n in chain)
