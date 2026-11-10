import os
import re

import pytest

from netscan import inventory
from netscan.inventory import InventoryError, KnownDevice, append, load, match
from netscan.scanner import Device


def write(tmp_path, text):
    path = tmp_path / "devices.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_loads_devices_and_normalizes_macs(tmp_path):
    path = write(
        tmp_path,
        """
[[device]]
name = "Router"
mac = "94-8F-CF-9A-25-89"

[[device]]
name = "Anna's phone"
hostname = "Annas-iPhone.local"
""",
    )
    assert load(path) == [
        KnownDevice(name="Router", mac="94:8f:cf:9a:25:89"),
        KnownDevice(name="Anna's phone", hostname="Annas-iPhone.local"),
    ]


def test_empty_file_has_no_devices(tmp_path):
    assert load(write(tmp_path, "")) == []


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('[[device]]\nmac = "aa:bb:cc:dd:ee:ff"\n', "device 1 has no name"),
        ('[[device]]\nname = "TV"\n', "device 1 (TV) needs a mac or a hostname"),
        ('device = "TV"\n', "use [[device]] tables"),
        ("[[device]\n", "devices.toml"),
    ],
)
def test_invalid_files_explain_what_is_wrong(tmp_path, text, message):
    with pytest.raises(InventoryError, match=re.escape(message)):
        load(write(tmp_path, text))


KNOWN = [
    KnownDevice(name="Router", mac="94:8f:cf:9a:25:89"),
    KnownDevice(name="Anna's phone", hostname="Annas-iPhone.local"),
    KnownDevice(name="Laptop", mac="8c:8b:5b:76:f2:df", hostname="laptop"),
]


def test_matches_by_mac_in_any_case():
    device = Device(ip="192.168.0.1", mac="94:8F:CF:9A:25:89")
    assert match(device, KNOWN).name == "Router"


def test_matches_a_changing_mac_by_hostname_with_any_suffix():
    device = Device(ip="192.168.0.20", mac="de:2e:0c:7e:16:c2", hostname="annas-iphone.lan")
    assert match(device, KNOWN).name == "Anna's phone"


def test_mac_wins_over_hostname():
    device = Device(ip="192.168.0.5", mac="8c:8b:5b:76:f2:df", hostname="Annas-iPhone")
    assert match(device, KNOWN).name == "Laptop"


def test_unknown_device_has_no_match():
    assert match(Device(ip="192.168.0.9", mac="00:11:22:33:44:55", hostname="tv"), KNOWN) is None


def test_append_creates_a_file_that_loads_back(tmp_path):
    path = tmp_path / "netscan" / "devices.toml"
    devices = [
        Device(ip="192.168.0.40", mac="dc:a6:32:00:00:28", hostname="raspberrypi.local"),
        Device(ip="192.168.0.41", mac="dc:a6:32:00:00:29", vendor="Raspberry Pi Trading Ltd"),
        Device(ip="192.168.0.62", mac="f2:aa:bb:cc:dd:ee", vendor="(random MAC)"),
    ]

    added = append(path, devices)

    assert [d.name for d in added] == [
        "raspberrypi.local",
        "Raspberry Pi Trading Ltd device",
        "Unnamed device",
    ]
    assert path.read_text().startswith("# Devices netscan knows")
    assert load(path) == added


def test_append_keeps_existing_devices_and_escapes_names(tmp_path):
    path = write(tmp_path, '[[device]]\nname = "Router"\nmac = "94:8f:cf:9a:25:89"\n')
    append(path, [Device(ip="192.168.0.7", mac="aa:aa:aa:aa:aa:aa", hostname='TV "Living"')])

    assert [d.name for d in load(path)] == ["Router", 'TV "Living"']
    assert "# Devices netscan knows" not in path.read_text()


def test_default_path_follows_xdg(config_home):
    assert inventory.default_path() == config_home / "netscan" / "devices.toml"


class FakePasswd:
    pw_dir = "/home/anna"


def test_default_path_under_sudo_is_in_the_real_users_home(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setenv("SUDO_USER", "anna")
    monkeypatch.setattr("pwd.getpwnam", lambda user: FakePasswd)

    assert str(inventory.default_path()) == "/home/anna/.config/netscan/devices.toml"


def test_files_written_under_sudo_belong_to_the_real_user(tmp_path, monkeypatch):
    owners = []
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: owners.append((uid, gid)))
    monkeypatch.setenv("SUDO_USER", "anna")
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")

    append(
        tmp_path / "new-dir" / "devices.toml", [Device(ip="192.168.0.9", mac="aa:aa:aa:aa:aa:aa")]
    )

    assert owners == [(1000, 1000), (1000, 1000)]  # the file and the new directory
