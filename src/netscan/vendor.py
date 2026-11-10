"""Device maker from the MAC address.

Scapy ships an offline vendor list that misses newer devices (a Raspberry Pi 5
shows up as "?"). `netscan --update-vendors` downloads Wireshark's current list
into the cache, and lookups prefer it when it is there.
"""

import os
import time
import urllib.request
import zlib

from scapy.all import conf

from netscan import paths
from netscan.text import clean

RANDOM_MAC = "(random MAC)"
MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf.gz"
# Today the list is ~0.8 MB compressed and ~3 MB unpacked; refuse anything far
# bigger instead of filling the memory of a small Raspberry Pi.
MAX_DOWNLOAD = 16 * 1024 * 1024
MAX_UNPACKED = 64 * 1024 * 1024

_database = None  # {prefix bits: {prefix value: vendor}}, loaded on first use


class UpdateError(Exception):
    pass


def is_random_mac(mac):
    """Phones use private, randomized MACs per Wi-Fi network (locally administered bit)."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except ValueError:
        return False


def database_path():
    return paths.cache_dir() / "manuf"


def parse_manuf(text):
    """Parse Wireshark's manuf file: "88:A2:9E<TAB>short<TAB>long name".

    Big vendors own a 24-bit prefix, small ones a /28 or /36 block
    ("00:55:DA:10/28").
    """
    database = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = [f.strip() for f in line.split("\t")]
        if len(fields) < 2:
            continue
        prefix, _, bits = fields[0].partition("/")
        digits = prefix.replace(":", "").replace("-", "")
        try:
            value = int(digits, 16) << (48 - 4 * len(digits))
            bits = int(bits) if bits else 24
        except ValueError:
            continue
        name = clean(fields[2] if len(fields) > 2 and fields[2] else fields[1], limit=80)
        if name:
            database.setdefault(bits, {})[value >> (48 - bits)] = name
    return database


def _load_database():
    global _database
    if _database is None:
        try:
            with paths.as_sudo_user():
                text = database_path().read_text(encoding="utf-8")
            _database = parse_manuf(text)
        except OSError:
            _database = {}
    return _database


def database_is_fresh(max_age=7 * 24 * 3600):
    """True when a downloaded vendor list exists and is younger than max_age seconds."""
    try:
        with paths.as_sudo_user():
            modified = database_path().stat().st_mtime
        return time.time() - modified < max_age
    except OSError:
        return False


def has_database():
    return bool(_load_database())


def _lookup_downloaded(mac):
    try:
        value = int(mac.replace(":", "").replace("-", ""), 16)
    except ValueError:
        return None
    database = _load_database()
    for bits in sorted(database, reverse=True):  # most specific block first
        vendor = database[bits].get(value >> (48 - bits))
        if vendor:
            return vendor
    return None


def _lookup_scapy(mac):
    try:
        vendor = conf.manufdb._get_manuf(mac)
    except Exception:
        return None
    if not vendor or vendor.lower() == mac.lower():
        return None
    return vendor


def lookup_vendor(mac):
    """Return the vendor of a MAC, or None when nobody knows it."""
    if is_random_mac(mac):
        return RANDOM_MAC
    return _lookup_downloaded(mac) or _lookup_scapy(mac)


def _gunzip(packed):
    """Unpack gzip data with size limits on both sides."""
    if len(packed) > MAX_DOWNLOAD:
        raise UpdateError("the downloaded vendor list is suspiciously big, keeping the old one")
    unpacker = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16)
    data = unpacker.decompress(packed, MAX_UNPACKED + 1)
    if len(data) > MAX_UNPACKED or unpacker.unconsumed_tail:
        raise UpdateError("the downloaded vendor list is suspiciously big, keeping the old one")
    if not unpacker.eof:
        raise UpdateError("the downloaded vendor list is cut off, keeping the old one")
    return data


def update_database(url=MANUF_URL, timeout=30):
    """Download the vendor list into the cache and return how many vendors it has."""
    global _database
    request = urllib.request.Request(url, headers={"User-Agent": "netscan"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            packed = response.read(MAX_DOWNLOAD + 1)
        text = _gunzip(packed).decode("utf-8")
    except (OSError, EOFError, zlib.error, UnicodeDecodeError) as error:
        raise UpdateError(f"could not download the vendor list: {error}") from None

    database = parse_manuf(text)
    count = sum(len(block) for block in database.values())
    if count < 1000:
        raise UpdateError("the downloaded vendor list looks broken, keeping the old one")

    path = database_path()
    with paths.as_sudo_user():
        path.parent.mkdir(parents=True, exist_ok=True)
        partial = path.with_suffix(".tmp")
        partial.write_text(text, encoding="utf-8")
        os.replace(partial, path)
    _database = database
    return count
