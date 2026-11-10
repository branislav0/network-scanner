"""Where netscan keeps its files, also when it runs through sudo."""

import os
from pathlib import Path


def sudo_user():
    """The user who ran sudo, so files land in their home and not root's."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return None
    return os.environ.get("SUDO_USER") or None


def _home_of_sudo_user(user):
    import pwd

    return Path(pwd.getpwnam(user).pw_dir)


def config_dir():
    user = sudo_user()
    if user:
        return _home_of_sudo_user(user) / ".config" / "netscan"
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "netscan"


def cache_dir():
    user = sudo_user()
    if user:
        return _home_of_sudo_user(user) / ".cache" / "netscan"
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "netscan"


def hand_to_sudo_user(*paths):
    """Files written under sudo would belong to root; give them to the real user."""
    if not sudo_user():
        return
    try:
        uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    except (KeyError, ValueError):
        return
    for path in paths:
        os.chown(path, uid, gid)
