import pytest
from scapy.all import conf

from netscan.vendor import RANDOM_MAC, is_random_mac, lookup_vendor


@pytest.mark.parametrize("mac", ["5e:11:22:33:44:55", "f2:aa:bb:cc:dd:ee", "de:2e:0c:7e:16:c2"])
def test_private_macs_are_reported_as_random(mac):
    assert is_random_mac(mac)
    assert lookup_vendor(mac) == RANDOM_MAC


def test_vendor_from_the_offline_database():
    assert not is_random_mac("dc:a6:32:00:00:01")
    assert "Raspberry Pi" in lookup_vendor("dc:a6:32:00:00:01")


def test_unknown_vendor_is_none(monkeypatch):
    # scapy returns the MAC itself when it does not know the vendor
    monkeypatch.setattr(conf.manufdb, "_get_manuf", lambda mac: mac)
    assert lookup_vendor("00:11:22:33:44:55") is None


def test_malformed_mac_is_not_random():
    assert not is_random_mac("zz:11:22:33:44:55")
