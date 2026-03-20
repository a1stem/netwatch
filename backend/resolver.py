"""
resolver.py
-----------
Resolves a PID to a full ProcessNode with its complete parent ancestry chain.
Includes deep fallbacks via /proc for when psutil returns no name (kernel threads,
rapidly-exiting processes, or permission edge cases).
"""

from __future__ import annotations
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Optional
import psutil

log = logging.getLogger(__name__)


@dataclass
class ProcessNode:
    pid: int
    name: str
    exe: str
    cmdline: str
    ppid: Optional[int]
    username: str
    children: list["ProcessNode"] = field(default_factory=list)
    is_trusted: bool = False
    is_package_manager: bool = False
    source: str = "psutil"      # "psutil" | "proc" | "unknown"

    def display_name(self) -> str:
        if self.exe and self.exe != self.name:
            return f"{self.name}  ({self.exe})"
        return self.name

    def ancestry_path(self) -> str:
        return self.name


_PKG_MANAGERS = frozenset({
    "apt", "apt-get", "apt-cache", "dpkg", "aptd", "unattended-upgrade",
    "snap", "snapd", "flatpak", "pip", "pip3", "pipx",
    "npm", "yarn", "cargo", "gem", "go",
})


# ── /proc fallback readers ────────────────────────────────────────────────────

def _proc_read(pid: int, fname: str) -> str:
    """Safely read a /proc/PID/ file, return empty string on any error."""
    try:
        with open(f"/proc/{pid}/{fname}", "rb") as f:
            return f.read(4096).replace(b"\x00", b" ").decode(errors="replace").strip()
    except OSError:
        return ""


def _proc_name(pid: int) -> str:
    """Read process name from /proc/PID/comm (most reliable, always available)."""
    return _proc_read(pid, "comm")


def _proc_exe(pid: int) -> str:
    """Read exe path via /proc/PID/exe symlink."""
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""


def _proc_cmdline(pid: int) -> str:
    return _proc_read(pid, "cmdline")[:200]


def _proc_ppid(pid: int) -> int:
    """Read PPID from /proc/PID/status."""
    status = _proc_read(pid, "status")
    m = re.search(r"PPid:\s*(\d+)", status)
    return int(m.group(1)) if m else 0


def _proc_username(pid: int) -> str:
    """Read UID from /proc/PID/status and resolve to username."""
    status = _proc_read(pid, "status")
    m = re.search(r"Uid:\s*(\d+)", status)
    if not m:
        return "?"
    uid = int(m.group(1))
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError):
        return str(uid)


def _make_node_from_proc(pid: int) -> Optional[ProcessNode]:
    """Build a ProcessNode entirely from /proc without psutil."""
    if not os.path.isdir(f"/proc/{pid}"):
        return None
    name = _proc_name(pid) or f"pid-{pid}"
    exe  = _proc_exe(pid)
    cmdline = _proc_cmdline(pid)
    ppid = _proc_ppid(pid)
    username = _proc_username(pid)
    is_pm = name.lower() in _PKG_MANAGERS
    return ProcessNode(
        pid=pid, name=name, exe=exe, cmdline=cmdline,
        ppid=ppid, username=username,
        is_package_manager=is_pm, source="proc",
    )


# ── psutil helpers ────────────────────────────────────────────────────────────

def _safe_proc_info(proc: psutil.Process) -> Optional[dict]:
    try:
        with proc.oneshot():
            name = proc.name()
            exe  = _safe_exe(proc)
            # If psutil gives empty name, fall back to /proc/comm
            if not name or name == "?":
                name = _proc_name(proc.pid) or f"pid-{proc.pid}"
            if not exe:
                exe = _proc_exe(proc.pid)
            return {
                "pid":      proc.pid,
                "name":     name,
                "exe":      exe,
                "cmdline":  " ".join(proc.cmdline()) or _proc_cmdline(proc.pid) or name,
                "ppid":     proc.ppid(),
                "username": _safe_username(proc),
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        # Full fallback to /proc
        return None


def _safe_exe(proc: psutil.Process) -> str:
    try:
        return proc.exe()
    except (psutil.AccessDenied, FileNotFoundError, psutil.NoSuchProcess):
        return _proc_exe(proc.pid)


def _safe_username(proc: psutil.Process) -> str:
    try:
        return proc.username()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return _proc_username(proc.pid)


def _make_node(info: dict) -> ProcessNode:
    is_pm = info["name"].lower() in _PKG_MANAGERS or any(
        pm in info["exe"].lower() for pm in _PKG_MANAGERS
    )
    return ProcessNode(
        pid=info["pid"], name=info["name"], exe=info["exe"],
        cmdline=info["cmdline"], ppid=info["ppid"], username=info["username"],
        is_package_manager=is_pm, source="psutil",
    )


# ── Public API ────────────────────────────────────────────────────────────────

def resolve_process_chain(pid: int) -> Optional[list[ProcessNode]]:
    """
    Walk the parent chain for pid up to PID 1.
    Uses psutil with /proc fallback at every step.
    Returns list ordered [root … target_process].
    """
    if not pid:
        return None

    chain: list[ProcessNode] = []
    visited: set[int] = set()
    current_pid = pid

    while current_pid and current_pid not in visited:
        visited.add(current_pid)

        # Try psutil first, then /proc
        node: Optional[ProcessNode] = None
        try:
            proc = psutil.Process(current_pid)
            info = _safe_proc_info(proc)
            if info:
                node = _make_node(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        if node is None:
            node = _make_node_from_proc(current_pid)

        if node is None:
            break

        chain.append(node)

        next_ppid = node.ppid or 0
        if next_ppid <= 1:
            # Optionally add init/systemd as root
            if next_ppid == 1 and 1 not in visited:
                init = _make_node_from_proc(1)
                if init:
                    chain.append(init)
            break
        current_pid = next_ppid

    chain.reverse()
    return chain if chain else None


def try_resolve_from_socket(remote_ip: str, remote_port: int) -> Optional[ProcessNode]:
    """
    Last-resort: scan /proc/net/tcp and tcp6 to find the PID owning a socket,
    then resolve it. Used when the poller's pid field is 0 or None.
    """
    hex_port = format(remote_port, "04X")
    # Also try little-endian IP representation for tcp
    for net_file in ("/proc/net/tcp6", "/proc/net/tcp"):
        try:
            with open(net_file) as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    rem_field = parts[2]        # remote address field
                    if hex_port in rem_field.upper():
                        inode = parts[9]
                        pid = _inode_to_pid(inode)
                        if pid:
                            chain = resolve_process_chain(pid)
                            return chain[-1] if chain else None
        except OSError:
            pass
    return None


def _inode_to_pid(inode: str) -> Optional[int]:
    """Scan /proc/*/fd/ symlinks to find which PID owns a socket inode."""
    target = f"socket:[{inode}]"
    try:
        for entry in os.scandir("/proc"):
            if not entry.name.isdigit():
                continue
            try:
                fd_dir = f"/proc/{entry.name}/fd"
                for fd in os.scandir(fd_dir):
                    try:
                        if os.readlink(fd.path) == target:
                            return int(entry.name)
                    except OSError:
                        pass
            except OSError:
                pass
    except OSError:
        pass
    return None


def root_process(chain: list[ProcessNode]) -> Optional[ProcessNode]:
    for node in chain:
        if node.pid > 1:
            return node
    return chain[-1] if chain else None


def target_process(chain: list[ProcessNode]) -> Optional[ProcessNode]:
    return chain[-1] if chain else None


def is_any_trusted(chain: list[ProcessNode]) -> bool:
    return any(n.is_trusted for n in chain)


def is_pkg_manager_chain(chain: list[ProcessNode]) -> bool:
    return any(n.is_package_manager for n in chain)
