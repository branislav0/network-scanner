import sys
from ipaddress import IPv4Network

import pytest

from netscan import cli, names, network


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
