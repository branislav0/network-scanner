import struct

from scapy.all import DNS, DNSRR

from netscan import names
from netscan.names import parse_mdns_response, parse_netbios_response, resolve_name


def test_mdns_answer_gives_the_host_name():
    answer = DNS(
        id=0,
        qr=1,
        aa=1,
        an=[DNSRR(rrname="5.0.168.192.in-addr.arpa", type="PTR", rdata="branislav.local.")],
    )
    assert parse_mdns_response(bytes(answer)) == "branislav.local"


def test_mdns_without_answer_gives_none():
    assert parse_mdns_response(bytes(DNS(id=0, qr=1))) is None


def test_mdns_garbage_gives_none():
    assert parse_mdns_response(b"\x00\x01") is None


def netbios_response(entries):
    """Node status answer: 56 bytes of header, a count and 18-byte name entries."""
    data = bytearray(56) + bytes([len(entries)])
    for name, suffix, flags in entries:
        data += name.encode().ljust(15) + bytes([suffix]) + struct.pack(">H", flags)
    return bytes(data)


def test_netbios_answer_gives_the_computer_name():
    data = netbios_response(
        [
            ("WORKGROUP", 0x00, 0x8400),  # group name, skipped
            ("DESKTOP-4F2K", 0x20, 0x0400),  # file server service, skipped
            ("DESKTOP-4F2K", 0x00, 0x0400),
        ]
    )
    assert parse_netbios_response(data) == "DESKTOP-4F2K"


def test_truncated_netbios_answer_gives_none():
    assert parse_netbios_response(b"\x00" * 10) is None


def test_first_method_with_an_answer_wins():
    methods = (lambda ip: None, lambda ip: "from-netbios", lambda ip: "from-dns")
    assert resolve_name("192.168.0.9", methods) == "from-netbios"


def test_no_method_with_an_answer_gives_none():
    assert resolve_name("192.168.0.9", (lambda ip: None,)) is None


def test_resolve_names_maps_every_address(monkeypatch):
    monkeypatch.setattr(names, "resolve_name", lambda ip: f"host-{ip.split('.')[-1]}")
    assert names.resolve_names(["192.168.0.1", "192.168.0.2"]) == {
        "192.168.0.1": "host-1",
        "192.168.0.2": "host-2",
    }


def test_resolve_names_of_nothing():
    assert names.resolve_names([]) == {}
