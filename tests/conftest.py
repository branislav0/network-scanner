import ipaddress

import pytest

from netscan import cli, names, network, scanner
from netscan.scanner import Device


def ip(text):
    return int(ipaddress.IPv4Address(text))


# Scapy routing table of a laptop on Wi-Fi with Tailscale running
ROUTES = [
    (ip("100.110.80.26"), 0xFFFFFFFF, "0.0.0.0", "tailscale0", "100.110.80.26", 0),
    (ip("127.0.0.0"), ip("255.0.0.0"), "0.0.0.0", "lo", "127.0.0.1", 0),
    (0, 0, "192.168.0.1", "wlan0", "192.168.0.5", 600),
    (ip("192.168.0.0"), ip("255.255.255.0"), "0.0.0.0", "wlan0", "192.168.0.5", 600),
    (ip("192.168.0.5"), 0xFFFFFFFF, "0.0.0.0", "wlan0", "192.168.0.5", 0),
    (ip("224.0.0.0"), ip("240.0.0.0"), "0.0.0.0", "wlan0", "192.168.0.5", 250),
]


@pytest.fixture(autouse=True)
def config_home(tmp_path, monkeypatch):
    """Keep tests away from the real ~/.config/netscan."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.delenv("SUDO_USER", raising=False)
    return tmp_path / "config"


@pytest.fixture
def home_network(monkeypatch):
    """Fake a home network: no root, no packets, two devices answering."""
    calls = {}

    def fake_scan(target, iface, timeout):
        calls.update(target=target, iface=iface, timeout=timeout)
        return [
            Device(ip="192.168.0.1", mac="94:8f:cf:9a:25:89"),
            Device(ip="192.168.0.20", mac="de:2e:0c:7e:16:c2"),
        ]

    monkeypatch.setattr(cli, "ensure_root", lambda argv: None)
    monkeypatch.setattr(network, "route_for", lambda ip: ("wlan0", "192.168.0.5"))
    monkeypatch.setattr(network, "routing_table", lambda: ROUTES)
    monkeypatch.setattr(network, "get_mac", lambda iface: "8c:8b:5b:76:f2:df")
    monkeypatch.setattr(scanner, "arp_scan", fake_scan)
    monkeypatch.setattr(names, "resolve_names", lambda ips: {"192.168.0.1": "router.lan"})
    monkeypatch.setattr("socket.gethostname", lambda: "my-laptop")
    return calls
