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
    monkeypatch.setattr(cli, "can_send_raw", lambda: False)
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/sudo")
    monkeypatch.setattr(cli.os, "execvp", lambda file, args: calls.append(args))

    cli.ensure_root(["-t", "3"])

    assert calls == [["sudo", sys.executable, "-I", "-m", "netscan", "-t", "3"]]


def test_root_runs_directly(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(cli.os, "execvp", lambda *a: pytest.fail("should not re-run"))
    cli.ensure_root([])


class FakeSocket:
    def close(self):
        pass


def test_a_user_with_the_net_raw_capability_needs_no_sudo(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(cli.socket, "AF_PACKET", 17, raising=False)
    monkeypatch.setattr(cli.socket, "socket", lambda *args: FakeSocket())
    monkeypatch.setattr(cli.os, "execvp", lambda *a: pytest.fail("should not re-run"))
    cli.ensure_root([])


def test_a_user_without_the_capability_cannot_send_raw(monkeypatch):
    def refuse(*args):
        raise PermissionError("Operation not permitted")

    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(cli.socket, "AF_PACKET", 17, raising=False)
    monkeypatch.setattr(cli.socket, "socket", refuse)
    assert cli.can_send_raw() is False


ROUTER = '[[device]]\nname = "Router"\nmac = "00:00:5e:00:53:01"\n'


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
    devices.write_text(ROUTER + '\n[[device]]\nname = "Phone"\nmac = "02:00:00:00:00:20"\n')

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


class StopWatching(Exception):
    pass


def stop_after(rounds):
    calls = []

    def fake_sleep(seconds):
        calls.append(seconds)
        if len(calls) >= rounds:
            raise StopWatching

    return calls, fake_sleep


def test_watch_prints_the_network_first_and_then_only_changes(
    home_network, monkeypatch, tmp_path, capsys
):
    from netscan import scanner
    from netscan.scanner import Device

    rounds = [
        [Device(ip="192.168.0.1", mac="00:00:5e:00:53:01")],
        [Device(ip="192.168.0.1", mac="00:00:5e:00:53:01")],
        [
            Device(ip="192.168.0.1", mac="00:00:5e:00:53:01"),
            Device(ip="192.168.0.66", mac="02:66:66:66:66:66"),
        ],
    ]
    monkeypatch.setattr(scanner, "arp_scan", lambda target, iface, timeout: rounds.pop(0))
    monkeypatch.setattr(vendor, "database_is_fresh", lambda: True)
    sleeps, fake_sleep = stop_after(3)
    monkeypatch.setattr(cli.time, "sleep", fake_sleep)
    state = tmp_path / "state.json"

    with pytest.raises(StopWatching):
        cli.main(["--watch", "60", "--state", str(state)])
    out, err = capsys.readouterr()

    assert sleeps == [60, 60, 60]
    assert "Watching 192.168.0.0/24 on wlan0 every 60s" in err
    assert out.count("IP Address") == 1  # the table only once
    joined = [line for line in out.splitlines() if "joined" in line]
    assert len(joined) == 1 and "192.168.0.66" in joined[0]
    assert state.exists()


def test_watch_reports_to_uptime_kuma(home_network, monkeypatch, tmp_path, config_home):
    pushes = []
    monkeypatch.setattr(vendor, "database_is_fresh", lambda: True)
    monkeypatch.setattr("netscan.watch.push_status", lambda url, state: pushes.append(url) or True)
    monkeypatch.setattr(cli.time, "sleep", stop_after(1)[1])
    monkeypatch.setenv("NETSCAN_PUSH_URL", "http://kuma/api/push/abc")

    with pytest.raises(StopWatching):
        cli.main(["--watch", "300", "--state", str(tmp_path / "s.json")])
    assert pushes == ["http://kuma/api/push/abc"]


def test_watch_survives_a_broken_vendor_download(home_network, monkeypatch, tmp_path, capsys):
    def offline():
        raise vendor.UpdateError("could not download the vendor list: offline")

    monkeypatch.setattr(vendor, "database_is_fresh", lambda: False)
    monkeypatch.setattr(vendor, "update_database", offline)
    monkeypatch.setattr(cli.time, "sleep", stop_after(2)[1])

    with pytest.raises(StopWatching):
        cli.main(["--watch", "60", "--state", str(tmp_path / "s.json")])
    err = capsys.readouterr().err
    assert err.count("Keeping the old vendor list") == 1  # retried only after an hour


def test_watch_keeps_going_while_the_devices_file_is_broken(
    home_network, monkeypatch, tmp_path, capsys
):
    devices = tmp_path / "devices.toml"
    devices.write_text(ROUTER)
    monkeypatch.setattr(vendor, "database_is_fresh", lambda: True)

    def break_file(seconds):
        devices.write_text("[[device]\n")
        monkeypatch.setattr(cli.time, "sleep", stop_after(1)[1])

    monkeypatch.setattr(cli.time, "sleep", break_file)
    with pytest.raises(StopWatching):
        cli.main(["--watch", "60", "-d", str(devices), "--state", str(tmp_path / "s.json")])
    assert "Using the previous known devices" in capsys.readouterr().err


@pytest.mark.parametrize(
    "args", [["--watch", "10"], ["--watch", "x"], ["-w", "60", "--save-unknown"]]
)
def test_invalid_watch_options(args):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(args)
    assert exit_info.value.code == 2


@pytest.mark.parametrize("url", ["file:///etc/shadow", "kuma:3001/api/push/x", "ftp://kuma/x"])
def test_push_url_must_be_http(url, monkeypatch):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--watch", "60", "--push-url", url])
    assert exit_info.value.code == 2


def test_push_url_from_the_environment_is_checked_too(monkeypatch):
    monkeypatch.setenv("NETSCAN_PUSH_URL", "file:///etc/shadow")
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--watch", "60"])
    assert exit_info.value.code == 2
