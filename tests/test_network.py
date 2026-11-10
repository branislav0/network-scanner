from ipaddress import IPv4Network

from conftest import ROUTES, ip

from netscan.network import choose_scan_range, find_subnet


def test_finds_the_subnet_of_our_address():
    assert find_subnet("192.168.0.5", "wlan0", ROUTES) == IPv4Network("192.168.0.0/24")


def test_ignores_routes_of_other_interfaces():
    assert find_subnet("192.168.0.5", "eth0", ROUTES) is None


def test_prefers_the_most_specific_subnet():
    routes = [
        (ip("192.168.0.0"), ip("255.255.0.0"), "0.0.0.0", "eth0", "192.168.0.5", 0),
        (ip("192.168.0.0"), ip("255.255.255.0"), "0.0.0.0", "eth0", "192.168.0.5", 0),
    ]
    assert find_subnet("192.168.0.5", "eth0", routes) == IPv4Network("192.168.0.0/24")


def test_scans_the_detected_subnet():
    assert choose_scan_range("192.168.0.5", "wlan0", ROUTES) == (
        IPv4Network("192.168.0.0/24"),
        None,
    )


def test_big_networks_fall_back_to_the_surrounding_24():
    routes = [(ip("10.0.0.0"), ip("255.0.0.0"), "0.0.0.0", "eth0", "10.1.2.3", 0)]
    target, warning = choose_scan_range("10.1.2.3", "eth0", routes)
    assert target == IPv4Network("10.1.2.0/24")
    assert "10.0.0.0/8 is too big" in warning


def test_unknown_subnet_falls_back_to_the_surrounding_24():
    target, warning = choose_scan_range("172.16.5.9", "eth0", [])
    assert target == IPv4Network("172.16.5.0/24")
    assert "Could not detect" in warning
