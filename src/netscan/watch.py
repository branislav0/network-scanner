"""Watch mode: remember who is on the network and report who joined or left."""

import json
import os
import time
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

from netscan import inventory, paths
from netscan.scanner import Device
from netscan.text import clean

# How long a device may stay unseen before it counts as gone. Phones sleep
# and skip ARP replies, so a single missed scan says nothing.
AWAY_AFTER = 30 * 60

PUSH_MESSAGE_LIMIT = 250


@dataclass
class Seen:
    mac: str
    ip: str
    hostname: str | None
    vendor: str | None
    label: str | None
    known: bool | None
    first_seen: float
    last_seen: float
    present: bool = True

    @property
    def name(self):
        return self.label or self.hostname or "?"

    def describe(self):
        """e.g. "192.168.0.20 de:2e:0c:7e:16:c2 Annas-iPhone (random MAC)"."""
        parts = [self.ip, self.mac]
        name = clean(self.label, limit=80) or clean(self.hostname)
        if name:
            parts.append(name)
        vendor = clean(self.vendor, limit=80)
        if vendor:
            parts.append(vendor if vendor.startswith("(") else f"({vendor})")
        return " ".join(parts)


@dataclass
class Event:
    kind: str  # "joined" or "left"
    device: Seen
    first_time: bool = False


def default_state_path():
    return paths.state_dir() / "state.json"


class State:
    def __init__(self, devices=None):
        self.devices = devices or {}  # mac -> Seen

    @classmethod
    def load(cls, path):
        """Read the state; a missing or broken file starts from scratch."""
        try:
            with paths.as_sudo_user():
                text = Path(path).read_text(encoding="utf-8")
            data = json.loads(text)
            return cls({mac: Seen(**record) for mac, record in data["devices"].items()})
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return cls()

    def save(self, path):
        path = Path(path)
        data = {"devices": {mac: asdict(seen) for mac, seen in self.devices.items()}}
        with paths.as_sudo_user():
            path.parent.mkdir(parents=True, exist_ok=True)
            partial = path.with_suffix(".tmp")
            partial.write_text(json.dumps(data, indent=2), encoding="utf-8")
            os.replace(partial, path)

    def present(self):
        return sorted(
            (s for s in self.devices.values() if s.present),
            key=lambda s: tuple(int(part) for part in s.ip.split(".")),
        )

    def unknown_present(self):
        return [s for s in self.present() if s.known is False]

    def update(self, scanned, now, known=None, away_after=AWAY_AFTER):
        """Record a scan and return what changed.

        known is the list from the known devices file (None without a file);
        devices that were not answering this time are matched against it too,
        so renaming a device in the file applies right away.
        """
        events = []
        seen_now = set()
        for device in scanned:
            if device.is_me or not device.mac:
                continue
            seen_now.add(device.mac)
            previous = self.devices.get(device.mac)
            record = Seen(
                mac=device.mac,
                ip=device.ip,
                hostname=device.hostname or (previous.hostname if previous else None),
                vendor=device.vendor,
                label=device.label,
                known=device.known,
                first_seen=previous.first_seen if previous else now,
                last_seen=now,
            )
            self.devices[device.mac] = record
            if previous is None or not previous.present:
                events.append(Event("joined", record, first_time=previous is None))

        for mac, record in self.devices.items():
            if mac in seen_now or not record.present:
                continue
            if known is None:
                record.known, record.label = None, None
            else:
                entry = inventory.match(
                    Device(ip=record.ip, mac=record.mac, hostname=record.hostname), known
                )
                record.known = entry is not None
                record.label = entry.name if entry else None
            if now - record.last_seen >= away_after:
                record.present = False
                events.append(Event("left", record))
        return events


def format_event(event, now):
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
    tags = []
    if event.device.known is False:
        tags.append("unknown")
    if event.first_time:
        tags.append("first time")
    suffix = f"  [{', '.join(tags)}]" if tags else ""
    return f"{stamp}  {event.kind:<6}  {event.device.describe()}{suffix}"


def push_status(url, state, timeout=10):
    """Report to an Uptime Kuma push monitor: down while unknown devices are around.

    Kuma notifies on every change, so you hear when a stranger joins and when
    the network is clean again. Returns False when the push failed.
    """
    unknown = state.unknown_present()
    present = state.present()
    if unknown:
        status = "down"
        message = f"{len(unknown)} unknown device(s): " + "; ".join(s.describe() for s in unknown)
    else:
        status = "up"
        all_known = present and all(s.known for s in present)
        message = f"{len(present)} devices" + (", all known" if all_known else "")
    if len(message) > PUSH_MESSAGE_LIMIT:
        message = message[: PUSH_MESSAGE_LIMIT - 3] + "..."

    parts = urllib.parse.urlsplit(url)
    query = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    query.update(status=status, msg=message, ping="")
    full_url = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))
    request = urllib.request.Request(full_url, headers={"User-Agent": "netscan"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return 200 <= response.status < 300
    except OSError:
        return False
