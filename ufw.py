"""
ufw.py
------
Wrapper around the 'ufw' command for applying and removing firewall rules.

All commands are run with pkexec (PolicyKit) so the GUI does not need to
run as root.  Each rule applied is persisted to block_rules.json via the
caller (trust_store.py / history.py).

Prerequisite on the host system:
    sudo apt install ufw
    sudo ufw enable

The user running the GUI needs a PolicyKit rule that allows 'ufw':
    /etc/polkit-1/rules.d/50-netwatch.rules
"""

from __future__ import annotations
import logging
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto
from typing import Optional

log = logging.getLogger(__name__)

# Prefer pkexec for privilege escalation; fall back to sudo
_PKEXEC = shutil.which("pkexec")
_SUDO   = shutil.which("sudo")
_UFW    = shutil.which("ufw")


class RuleAction(Enum):
    DENY  = auto()
    ALLOW = auto()
    DELETE = auto()


@dataclass
class UfwResult:
    success: bool
    command: str
    stdout: str
    stderr: str
    timestamp: datetime = None   # filled by apply()

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

    def summary(self) -> str:
        if self.success:
            return f"OK — {self.command}"
        return f"FAILED — {self.command}: {self.stderr.strip()}"


def _run(args: list[str]) -> UfwResult:
    """Run a command via pkexec or sudo and return a UfwResult."""
    if not _UFW:
        return UfwResult(
            success=False,
            command=" ".join(args),
            stdout="",
            stderr="ufw not found on this system",
        )

    # Build privilege escalation prefix
    if _PKEXEC:
        prefix = [_PKEXEC]
    elif _SUDO:
        prefix = [_SUDO, "--non-interactive"]
        log.warning("ufw: pkexec not found, falling back to sudo")
    else:
        return UfwResult(
            success=False,
            command=" ".join(args),
            stdout="",
            stderr="Neither pkexec nor sudo found — cannot run ufw",
        )

    cmd = prefix + [_UFW] + args
    cmd_str = " ".join(cmd)
    log.info("ufw: running: %s", cmd_str)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )
        success = result.returncode == 0
        if not success:
            log.warning("ufw: command failed (rc=%d): %s",
                        result.returncode, result.stderr.strip())
        return UfwResult(
            success=success,
            command=cmd_str,
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip(),
        )
    except subprocess.TimeoutExpired:
        log.error("ufw: command timed out: %s", cmd_str)
        return UfwResult(success=False, command=cmd_str, stdout="",
                         stderr="Command timed out after 15s")
    except Exception as exc:
        log.error("ufw: unexpected error: %s", exc)
        return UfwResult(success=False, command=cmd_str, stdout="",
                         stderr=str(exc))


# ── Public rule operations ─────────────────────────────────────────────────

def block_outbound(remote_ip: str, remote_port: int,
                   proto: str = "tcp") -> UfwResult:
    """
    Deny all outbound traffic to remote_ip:remote_port.
    ufw deny out to <ip> port <port> proto <proto>
    """
    return _run([
        "deny", "out",
        "to", remote_ip,
        "port", str(remote_port),
        "proto", proto.lower(),
    ])


def block_outbound_by_ip(remote_ip: str) -> UfwResult:
    """
    Deny ALL outbound traffic to a remote IP (any port).
    Use with caution — this blocks the entire host.
    """
    return _run(["deny", "out", "to", remote_ip])


def allow_outbound(remote_ip: str, remote_port: int,
                   proto: str = "tcp") -> UfwResult:
    """
    Explicitly allow outbound to remote_ip:remote_port.
    Useful for reinstating a previously blocked connection.
    """
    return _run([
        "allow", "out",
        "to", remote_ip,
        "port", str(remote_port),
        "proto", proto.lower(),
    ])


def delete_rule(remote_ip: str, remote_port: int,
                proto: str = "tcp", action: str = "deny") -> UfwResult:
    """Remove a specific rule added by this tool."""
    return _run([
        "delete", action, "out",
        "to", remote_ip,
        "port", str(remote_port),
        "proto", proto.lower(),
    ])


def ufw_status() -> tuple[bool, str]:
    """
    Returns (is_active, status_text).
    Reads ufw status without privilege escalation.
    """
    if not _UFW:
        return False, "ufw not installed"
    try:
        result = subprocess.run(
            [_UFW, "status"],
            capture_output=True, text=True, timeout=5
        )
        text = result.stdout.strip()
        active = "active" in text.lower() and "inactive" not in text.lower()
        return active, text
    except Exception as exc:
        return False, str(exc)


def list_rules() -> list[str]:
    """Return current UFW rules as a list of text lines."""
    if not _UFW:
        return []
    try:
        result = subprocess.run(
            [_UFW, "status", "numbered"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip().splitlines()
    except Exception:
        return []
