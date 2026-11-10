import gzip
import io

import pytest
from scapy.all import conf

from netscan import vendor
from netscan.vendor import RANDOM_MAC, is_random_mac, lookup_vendor, parse_manuf


@pytest.mark.parametrize("mac", ["5e:11:22:33:44:55", "f2:aa:bb:cc:dd:ee", "02:00:00:00:00:20"])
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


MANUF = """\
# comment
88:A2:9E         \tRaspberryPi \tRaspberry Pi (Trading) Ltd
00:55:DA         \tShinkoTechno\tShinko Technos co.,ltd.
00:55:DA:10/28   \tKoolPOS     \tKoolPOS Inc.
00:1B:C5:00:10/36\tOpenRBcomDir\tOpenRB.com, Direct SIA
AA:BB:CC         \tShortOnly
"""


def gzipped(text):
    return gzip.compress(text.encode())


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_parses_all_block_sizes():
    database = parse_manuf(MANUF)
    assert sorted(database) == [24, 28, 36]
    assert database[24][0x88A29E] == "Raspberry Pi (Trading) Ltd"
    assert database[24][0xAABBCC] == "ShortOnly"


def test_downloaded_list_wins_and_the_most_specific_block_is_used(config_home, monkeypatch):
    path = vendor.database_path()
    path.parent.mkdir(parents=True)
    path.write_text(MANUF)

    assert lookup_vendor("88:a2:9e:00:00:48") == "Raspberry Pi (Trading) Ltd"
    assert lookup_vendor("00:55:da:1f:00:01") == "KoolPOS Inc."
    assert lookup_vendor("00:55:da:20:00:01") == "Shinko Technos co.,ltd."
    assert lookup_vendor("00:1b:c5:00:1a:bc") == "OpenRB.com, Direct SIA"


def test_falls_back_to_scapy_without_a_downloaded_list():
    assert not vendor.has_database()
    assert "Raspberry Pi" in lookup_vendor("dc:a6:32:00:00:01")


def test_update_downloads_and_saves_the_list(monkeypatch):
    big = MANUF + "".join(
        f"{i >> 16:02X}:{(i >> 8) & 255:02X}:{i & 255:02X}\tV\tVendor {i}\n"
        for i in range(0x100000, 0x100000 + 1500)
    )
    monkeypatch.setattr(
        vendor.urllib.request, "urlopen", lambda request, timeout: FakeResponse(gzipped(big))
    )

    count = vendor.update_database()

    assert count > 1500
    assert vendor.database_path().read_text() == big
    assert lookup_vendor("88:a2:9e:00:00:01") == "Raspberry Pi (Trading) Ltd"


def test_update_refuses_a_broken_list(monkeypatch):
    monkeypatch.setattr(
        vendor.urllib.request, "urlopen", lambda request, timeout: FakeResponse(gzipped(MANUF))
    )
    with pytest.raises(vendor.UpdateError, match="looks broken"):
        vendor.update_database()
    assert not vendor.database_path().exists()


def test_update_reports_download_errors(monkeypatch):
    def offline(request, timeout):
        raise OSError("Network is unreachable")

    monkeypatch.setattr(vendor.urllib.request, "urlopen", offline)
    with pytest.raises(vendor.UpdateError, match="could not download"):
        vendor.update_database()


def test_update_reports_a_corrupt_download(monkeypatch):
    monkeypatch.setattr(
        vendor.urllib.request, "urlopen", lambda request, timeout: FakeResponse(b"not gzip")
    )
    with pytest.raises(vendor.UpdateError):
        vendor.update_database()


def test_vendor_names_are_cleaned():
    database = parse_manuf("88:A2:9E\tShort\tNice\x1b[2J Vendor\n11:22:33\tX\t\x1b\x07\n")
    assert database[24][0x88A29E] == "Nice[2J Vendor"
    assert 0x112233 not in database[24]


def test_update_refuses_a_huge_download(monkeypatch):
    monkeypatch.setattr(vendor, "MAX_DOWNLOAD", 100)
    monkeypatch.setattr(
        vendor.urllib.request, "urlopen", lambda request, timeout: FakeResponse(b"x" * 500)
    )
    with pytest.raises(vendor.UpdateError, match="suspiciously big"):
        vendor.update_database()


def test_update_refuses_a_decompression_bomb(monkeypatch):
    monkeypatch.setattr(vendor, "MAX_UNPACKED", 10_000)
    bomb = gzip.compress(b"0" * 1_000_000)  # 1 KB that unpacks to 1 MB
    monkeypatch.setattr(
        vendor.urllib.request, "urlopen", lambda request, timeout: FakeResponse(bomb)
    )
    with pytest.raises(vendor.UpdateError, match="suspiciously big"):
        vendor.update_database()


def test_update_refuses_a_cut_off_download(monkeypatch):
    cut = gzip.compress(MANUF.encode() * 50)[:-20]
    monkeypatch.setattr(
        vendor.urllib.request, "urlopen", lambda request, timeout: FakeResponse(cut)
    )
    with pytest.raises(vendor.UpdateError):
        vendor.update_database()
