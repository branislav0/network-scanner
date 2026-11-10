"""Where netscan keeps its files, also when it runs through sudo.

Set NETSCAN_HOME to keep everything in one directory (the Docker image uses
/data): devices.toml, the vendor list and the watch state.
"""

import os
from contextlib import contextmanager
from pathlib import Path


def sudo_user():
    """The user who ran sudo, so files land in their home and not root's."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return None
    return os.environ.get("SUDO_USER") or None


def _home_of_sudo_user(user):
    import pwd

    return Path(pwd.getpwnam(user).pw_dir)


def _user_dir(xdg_variable, fallback):
    """$XDG_..._HOME/netscan, or ~/<fallback>/netscan of the real user."""
    if os.environ.get("NETSCAN_HOME"):
        return Path(os.environ["NETSCAN_HOME"])
    user = sudo_user()
    if user:
        return _home_of_sudo_user(user) / fallback / "netscan"
    base = os.environ.get(xdg_variable) or Path.home() / fallback
    return Path(base) / "netscan"


def config_dir():
    return _user_dir("XDG_CONFIG_HOME", ".config")


def cache_dir():
    return _user_dir("XDG_CACHE_HOME", ".cache")


def state_dir():
    return _user_dir("XDG_STATE_HOME", ".local/state")


def _sudo_ids():
    if not sudo_user():
        return None
    try:
        return int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    except (KeyError, ValueError):
        return None


@contextmanager
def as_sudo_user():
    """Touch the user's files with the user's rights, not root's.

    Under sudo, root following a symlink planted in the user's home could
    otherwise overwrite any file on the system. New files also end up owned
    by the user this way.
    """
    ids = _sudo_ids()
    if ids is None:
        yield
        return
    uid, gid = ids
    os.setegid(gid)
    os.seteuid(uid)
    try:
        yield
    finally:
        os.seteuid(0)
        os.setegid(0)
