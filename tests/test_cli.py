import sys
from ipaddress import IPv4Network

import pytest

from netscan import cli, names, network, vendor


def test_scans_the_network_we_are_on(home_network, capsys):
    assert cli.main([]) == 0
    out, err = capsys.readouterr()

    assert home_network["target"] == IPv4Network("192.168.0.0/24")
    assert home_network["iface"] == "wlan0"
    assert "Scanning 192.168.0.0/24 on wlan0" in err
    assert "router.lan" in out
    assert "(random MAC)" in out
    assert "my-laptop" in out and "<-- this computer" in out
    assert "Other devices found: 2" in out


def test_scans_an_explicit_range_without_adding_this_computer(home_network, capsys):
    assert cli.main(["10.0.0.0/28", "--timeout", "3"]) == 0
    out, _ = capsys.readouterr()

    assert home_network["target"] == IPv4Network("10.0.0.0/28")
    assert home_network["timeout"] == 3.0
    assert "this computer" not in out


def test_no_names_skips_name_lookups(home_network, monkeypatch, capsys):
    def fail(ips):
        raise AssertionError("names should not be resolved")

    monkeypatch.setattr(names, "resolve_names", fail)
    assert cli.main(["--no-names"]) == 0
    assert "router.lan" not in capsys.readouterr().out


@pytest.mark.parametrize("bad", ["nonsense", "192.168.0.0/33", "fe80::/64"])
def test_invalid_range_fails_before_asking_for_sudo(bad, monkeypatch):
    def fail(argv):
        raise AssertionError("sudo should not be needed for invalid input")

    monkeypatch.setattr(cli, "ensure_root", fail)
    with pytest.raises(SystemExit) as exit_info:
        cli.main([bad])
    assert exit_info.value.code == 2


def test_offline_machine_asks_for_a_range(home_network, monkeypatch, capsys):
    monkeypatch.setattr(network, "route_for", lambda ip: ("lo", None))
    assert cli.main([]) == 1
    assert "could not find your network" in capsys.readouterr().err


def test_reruns_through_sudo_when_not_root(monkeypatch):
    calls = []
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/sudo")
    monkeypatch.setattr(cli.os, "execvp", lambda file, args: calls.append(args))

    cli.ensure_root(["-t", "3"])

    assert calls == [["sudo", sys.executable, "-m", "netscan", "-t", "3"]]


def test_root_runs_directly(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(cli.os, "execvp", lambda *a: pytest.fail("should not re-run"))
    cli.ensure_root([])


ROUTER = '[[device]]\nname = "Router"\nmac = "94:8f:cf:9a:25:89"\n'


def test_known_devices_get_their_names_and_strangers_are_flagged(home_network, tmp_path, capsys):
    devices = tmp_path / "devices.toml"
    devices.write_text(ROUTER)

    assert cli.main(["--devices", str(devices)]) == 0
    out = capsys.readouterr().out

    router = next(line for line in out.splitlines() if "192.168.0.1 " in line)
    stranger = next(line for line in out.splitlines() if "192.168.0.20" in line)
    assert "Router" in router and "unknown" not in router
    assert stranger.endswith("<-- unknown")
    assert "Other devices found: 2 (1 unknown)" in out


def test_without_a_devices_file_nothing_is_flagged(home_network, capsys):
    assert cli.main([]) == 0
    out = capsys.readouterr().out
    assert "unknown" not in out.replace("(random MAC)", "")


def test_save_unknown_adds_strangers_to_the_default_file(home_network, config_home, capsys):
    assert cli.main(["--save-unknown"]) == 0
    _, err = capsys.readouterr()

    saved = config_home / "netscan" / "devices.toml"
    assert "Added 2 device(s)" in err
    assert "router.lan" in saved.read_text()

    assert cli.main([]) == 0
    out = capsys.readouterr().out
    assert "Other devices found: 2 (0 unknown)" in out


def test_save_unknown_with_nothing_new(home_network, tmp_path, capsys):
    devices = tmp_path / "devices.toml"
    devices.write_text(ROUTER + '\n[[device]]\nname = "Phone"\nmac = "de:2e:0c:7e:16:c2"\n')

    assert cli.main(["--devices", str(devices), "--save-unknown"]) == 0
    assert "No unknown devices to add" in capsys.readouterr().err


def test_missing_devices_file_is_an_error(home_network, tmp_path, capsys):
    assert cli.main(["--devices", str(tmp_path / "nope.toml")]) == 1
    assert "devices file not found" in capsys.readouterr().err


def test_broken_devices_file_is_an_error(home_network, tmp_path, capsys):
    devices = tmp_path / "devices.toml"
    devices.write_text("[[device]\n")

    assert cli.main(["--devices", str(devices)]) == 1
    assert "devices.toml" in capsys.readouterr().err


def test_update_vendors_needs_no_root(monkeypatch, capsys):
    monkeypatch.setattr(cli, "ensure_root", lambda argv: pytest.fail("no root needed"))
    monkeypatch.setattr(vendor, "update_database", lambda: 58765)

    assert cli.main(["--update-vendors"]) == 0
    assert "Saved 58765 vendors" in capsys.readouterr().out


def test_failed_vendor_update_is_an_error(monkeypatch, capsys):
    def offline():
        raise vendor.UpdateError("could not download the vendor list: offline")

    monkeypatch.setattr(vendor, "update_database", offline)
    assert cli.main(["--update-vendors"]) == 1
    assert "could not download" in capsys.readouterr().err


def test_suggests_updating_vendors_when_some_are_unknown(home_network, monkeypatch, capsys):
    monkeypatch.setattr(vendor, "lookup_vendor", lambda mac: None)
    assert cli.main([]) == 0
    assert "netscan --update-vendors" in capsys.readouterr().err
