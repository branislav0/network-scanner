"""Finding out what devices call themselves."""

import ipaddress
import socket
import struct
from concurrent.futures import ThreadPoolExecutor

from scapy.all import DNS, DNSQR

TIMEOUT = 1.0

# NetBIOS node status request for the name "*" ("CK" followed by 30 x "A")
NETBIOS_QUERY = (
    struct.pack(">HHHHHH", 0x1337, 0, 1, 0, 0, 0)
    + b"\x20CK"
    + b"A" * 30
    + b"\x00"
    + struct.pack(">HH", 0x21, 1)
)


def _ask(ip, port, query, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(query, (ip, port))
        data, _ = s.recvfrom(4096)
    return data


def mdns_query(ip):
    reverse = ipaddress.ip_address(ip).reverse_pointer
    return bytes(DNS(id=0, rd=0, qd=DNSQR(qname=reverse, qtype="PTR")))


def parse_mdns_response(data):
    """Return the host name from an mDNS PTR answer, or None."""
    try:
        answers = DNS(data).an
    except Exception:
        return None
    if not answers:
        return None
    # Newer scapy returns a list of records, older a single record
    first = answers[0] if isinstance(answers, list) else answers
    name = getattr(first, "rdata", None)
    if isinstance(name, bytes):
        name = name.decode(errors="ignore")
    if not isinstance(name, str):
        return None
    return name.rstrip(".") or None


def parse_netbios_response(data):
    """Return the computer name from a NetBIOS node status answer, or None."""
    try:
        count = data[56]
        for i in range(count):
            entry = data[57 + i * 18 : 57 + (i + 1) * 18]
            name, suffix = entry[:15], entry[15]
            flags = struct.unpack(">H", entry[16:18])[0]
            if suffix == 0x00 and not flags & 0x8000:  # a computer, not a group
                return name.decode(errors="ignore").strip() or None
    except (IndexError, struct.error):
        pass
    return None


def name_from_mdns(ip, timeout=TIMEOUT):
    """mDNS/Bonjour: ask the device itself (Apple, Linux, printers)."""
    try:
        return parse_mdns_response(_ask(ip, 5353, mdns_query(ip), timeout))
    except OSError:
        return None


def name_from_netbios(ip, timeout=TIMEOUT):
    """NetBIOS: the computer name of Windows machines."""
    try:
        return parse_netbios_response(_ask(ip, 137, NETBIOS_QUERY, timeout))
    except OSError:
        return None


def name_from_dns(ip, timeout=TIMEOUT):
    """Reverse DNS: the name your router or DNS server (e.g. Pi-hole) knows."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


METHODS = (name_from_mdns, name_from_netbios, name_from_dns)


def resolve_name(ip, methods=METHODS):
    """Prefer the name a device gave itself, then the one from DNS."""
    for method in methods:
        name = method(ip)
        if name:
            return name
    return None


def resolve_names(ips):
    """Resolve many names in parallel, so a busy network stays quick."""
    ips = list(ips)
    if not ips:
        return {}
    with ThreadPoolExecutor(max_workers=min(32, len(ips))) as pool:
        return dict(zip(ips, pool.map(resolve_name, ips), strict=True))
