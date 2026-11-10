"""Known devices: a TOML file that gives your devices names you recognise.

[[device]]
name = "Living room TV"
mac = "a4:5e:60:12:34:56"

[[device]]
name = "Anna's phone"
hostname = "Annas-iPhone"   # for phones whose MAC changes
"""

import json
import tomllib
from dataclasses import dataclass
from pathlib import Path

from netscan import paths

HEADER = """\
# Devices netscan knows. Give them names you recognise - netscan shows the
# name instead of the hostname and highlights every device that is not here.
# A device matches by mac, or by hostname for phones with a changing MAC.
"""


class InventoryError(Exception):
    pass


@dataclass
class KnownDevice:
    name: str
    mac: str | None = None
    hostname: str | None = None


def normalize_mac(mac):
    return mac.strip().lower().replace("-", ":")


def normalize_hostname(hostname):
    """Compare only the first label: "Annas-iPhone.local" == "annas-iphone.lan"."""
    return hostname.strip().rstrip(".").split(".")[0].lower()


def default_path():
    return paths.config_dir() / "devices.toml"


def load(path):
    """Read the known devices from path."""
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as error:
        raise InventoryError(f"{path}: {error}") from None
    except OSError as error:
        raise InventoryError(f"cannot read {path}: {error.strerror}") from None

    entries = data.get("device", [])
    if not isinstance(entries, list):
        raise InventoryError(f"{path}: use [[device]] tables for devices")

    known = []
    for number, entry in enumerate(entries, start=1):
        name = entry.get("name")
        mac = entry.get("mac")
        hostname = entry.get("hostname")
        if not isinstance(name, str) or not name.strip():
            raise InventoryError(f"{path}: device {number} has no name")
        if not mac and not hostname:
            raise InventoryError(f"{path}: device {number} ({name}) needs a mac or a hostname")
        known.append(
            KnownDevice(
                name=name.strip(),
                mac=normalize_mac(mac) if mac else None,
                hostname=hostname.strip() if hostname else None,
            )
        )
    return known


def match(device, known):
    """Return the known device for a scanned one: by MAC first, then by hostname."""
    mac = normalize_mac(device.mac) if device.mac else None
    for entry in known:
        if mac and entry.mac == mac:
            return entry
    if device.hostname:
        hostname = normalize_hostname(device.hostname)
        for entry in known:
            if entry.hostname and normalize_hostname(entry.hostname) == hostname:
                return entry
    return None


def suggested_name(device):
    if device.hostname:
        return device.hostname
    if device.vendor and not device.vendor.startswith("("):
        return f"{device.vendor} device"
    return "Unnamed device"


def _toml(value):
    # JSON string escapes are valid in TOML basic strings
    return json.dumps(value, ensure_ascii=False)


def append(path, devices):
    """Add devices to the file and return what was written for each of them."""
    path = Path(path)
    created_dir = not path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    new_file = not path.exists() or path.stat().st_size == 0

    added = []
    lines = [HEADER.rstrip("\n")] if new_file else []
    for device in devices:
        entry = KnownDevice(
            name=suggested_name(device), mac=device.mac, hostname=device.hostname or None
        )
        lines.append("\n[[device]]")
        lines.append(f"name = {_toml(entry.name)}")
        if entry.mac:
            lines.append(f"mac = {_toml(entry.mac)}")
        if entry.hostname:
            lines.append(f"hostname = {_toml(entry.hostname)}")
        added.append(entry)

    with open(path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    paths.hand_to_sudo_user(path, *([path.parent] if created_dir else []))
    return added
