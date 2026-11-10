"""ARP sweep of a local network."""

import ipaddress
from dataclasses import dataclass

from scapy.all import ARP, Ether, srp

# Pause between ARP requests. Many home routers drop a burst of broadcasts
# on the way to Wi-Fi clients, so laptops and phones would go unseen.
PACING = 0.005


@dataclass
class Device:
    ip: str
    mac: str
    hostname: str | None = None
    vendor: str | None = None
    is_me: bool = False


def sort_key(device):
    return ipaddress.ip_address(device.ip)


def arp_scan(network, iface, timeout=2.0, retry=1, pacing=PACING):
    """Ask every address in network for its MAC and return who answered.

    Unanswered addresses are asked once more (retry), because sleeping
    phones often miss the first request.
    """
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    answered, _ = srp(
        packet, iface=iface, inter=pacing, timeout=timeout, retry=retry, verbose=False
    )
    devices = {}
    for _sent, reply in answered:
        devices[reply.psrc] = Device(ip=reply.psrc, mac=reply.hwsrc.lower())
    return sorted(devices.values(), key=sort_key)
