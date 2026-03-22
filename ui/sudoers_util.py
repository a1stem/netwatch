"""
ui/sudoers_util.py
------------------
Utility to resolve the real (non-root) user's home directory when the
app is running under sudo.

When you run:  sudo python3 main.py
  os.getenv("HOME")        → /root        (wrong)
  os.path.expanduser("~")  → /root        (wrong)
  real_user_home()         → /home/cm     (correct)

Linux sets SUDO_USER and SUDO_UID in the environment when sudo is used,
so we can always recover the original user's identity.
"""

from __future__ import annotations
import os
import pwd


def real_user() -> str:
    """
    Return the username of the real (pre-sudo) user.
    Falls back to the current effective user if not running under sudo.
    """
    # SUDO_USER is set by sudo to the original username
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        return sudo_user
    # Not under sudo — return current user
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except (KeyError, AttributeError):
        return os.environ.get("USER", "user")


def real_home() -> str:
    """
    Return the home directory of the real (pre-sudo) user.
    Safe to call whether running as root, sudo, or a normal user.

    Priority order:
      1. SUDO_USER home dir (most reliable under sudo)
      2. SUDO_UID home dir  (fallback if SUDO_USER is absent)
      3. HOME env var       (may be /root under sudo — used as last resort)
      4. /home/<user>       (hardcoded fallback)
    """
    # Best case: SUDO_USER is set
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        try:
            return pwd.getpwnam(sudo_user).pw_dir
        except KeyError:
            pass

    # Second: SUDO_UID is set
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid:
        try:
            return pwd.getpwuid(int(sudo_uid)).pw_dir
        except (KeyError, ValueError):
            pass

    # Third: HOME env var (unreliable under sudo but better than nothing)
    home_env = os.environ.get("HOME", "")
    if home_env and home_env != "/root":
        return home_env

    # Last resort: /home/<username from SUDO_USER>
    if sudo_user:
        candidate = f"/home/{sudo_user}"
        if os.path.isdir(candidate):
            return candidate

    # Give up gracefully — use current HOME even if it's /root
    return home_env or os.path.expanduser("~")


def real_documents() -> str:
    """
    Return the real user's Documents folder.
    Creates it if it doesn't exist.
    """
    docs = os.path.join(real_home(), "Documents")
    os.makedirs(docs, exist_ok=True)
    return docs


def default_export_path(filename: str) -> str:
    """
    Build a safe default export path under the real user's home,
    e.g.  /home/cm/Documents/netwatch_history.csv
    """
    return os.path.join(real_documents(), filename)
