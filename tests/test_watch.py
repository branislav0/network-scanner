import json
import urllib.parse

import pytest

from netscan import watch
from netscan.inventory import KnownDevice
from netscan.scanner import Device
from netscan.watch import State, format_event, push_status

T0 = 1_800_000_000.0
MINUTE = 60


def router(**extra):
    return Device(ip="192.168.0.1", mac="94:8f:cf:9a:25:89", hostname="router.lan", **extra)


def phone(**extra):
    return Device(ip="192.168.0.20", mac="de:2e:0c:7e:16:c2", vendor="(random MAC)", **extra)


def kinds(events):
    return [(e.kind, e.device.mac, e.first_time) for e in events]


def test_new_devices_join_once():
    state = State()
    assert kinds(state.update([router(), phone()], T0)) == [
        ("joined", "94:8f:cf:9a:25:89", True),
        ("joined", "de:2e:0c:7e:16:c2", True),
    ]
    assert state.update([router(), phone()], T0 + 5 * MINUTE) == []


def test_this_computer_is_not_tracked():
    me = Device(ip="192.168.0.5", mac="8c:8b:5b:76:f2:df", is_me=True)
    state = State()
    assert state.update([me], T0) == []
    assert state.devices == {}


def test_a_missed_scan_is_not_leaving():
    state = State()
    state.update([router(), phone()], T0)
    assert state.update([router()], T0 + 10 * MINUTE) == []
    assert [s.mac for s in state.present()] == ["94:8f:cf:9a:25:89", "de:2e:0c:7e:16:c2"]


def test_device_leaves_after_the_away_time_and_can_come_back():
    state = State()
    state.update([router(), phone()], T0)

    left = state.update([router()], T0 + 30 * MINUTE)
    assert kinds(left) == [("left", "de:2e:0c:7e:16:c2", False)]
    assert [s.mac for s in state.present()] == ["94:8f:cf:9a:25:89"]

    back = state.update([router(), phone()], T0 + 60 * MINUTE)
    assert kinds(back) == [("joined", "de:2e:0c:7e:16:c2", False)]
    assert state.devices["de:2e:0c:7e:16:c2"].first_seen == T0


def test_custom_away_time():
    state = State()
    state.update([phone()], T0)
    assert state.update([], T0 + 4 * MINUTE, away_after=5 * MINUTE) == []
    assert kinds(state.update([], T0 + 5 * MINUTE, away_after=5 * MINUTE)) == [
        ("left", "de:2e:0c:7e:16:c2", False)
    ]


def test_unknown_devices_are_tracked_until_they_are_named():
    state = State()
    state.update([router(known=True, label="Router"), phone(known=False)], T0)
    assert [s.mac for s in state.unknown_present()] == ["de:2e:0c:7e:16:c2"]

    # the phone skips a scan, but was added to the file in the meantime
    known = [
        KnownDevice(name="Router", mac="94:8f:cf:9a:25:89"),
        KnownDevice(name="Anna's phone", mac="de:2e:0c:7e:16:c2"),
    ]
    state.update([router(known=True, label="Router")], T0 + 5 * MINUTE, known)

    assert state.unknown_present() == []
    assert state.devices["de:2e:0c:7e:16:c2"].name == "Anna's phone"


def test_hostname_is_kept_when_a_lookup_fails():
    state = State()
    state.update([router()], T0)
    state.update([Device(ip="192.168.0.1", mac="94:8f:cf:9a:25:89")], T0 + MINUTE)
    assert state.devices["94:8f:cf:9a:25:89"].hostname == "router.lan"


def test_state_survives_a_restart(tmp_path):
    path = tmp_path / "netscan" / "state.json"
    state = State()
    state.update([router(), phone(known=False)], T0)
    state.save(path)

    again = State.load(path)
    assert again.devices == state.devices
    assert again.update([router(), phone(known=False)], T0 + MINUTE) == []


@pytest.mark.parametrize("content", [None, "", "not json", '{"devices": 5}', '{"x": 1}'])
def test_missing_or_broken_state_starts_fresh(tmp_path, content):
    path = tmp_path / "state.json"
    if content is not None:
        path.write_text(content)
    assert State.load(path).devices == {}


def test_event_lines_are_readable():
    state = State()
    event = state.update([phone(known=False)], T0)[0]
    line = format_event(event, T0)
    assert "joined  192.168.0.20 de:2e:0c:7e:16:c2 (random MAC)  [unknown, first time]" in line


def test_descriptions_name_the_device_and_its_vendor():
    state = State()
    state.update([router(vendor="ARRIS Group, Inc.", label="Router", known=True)], T0)
    assert state.devices["94:8f:cf:9a:25:89"].describe() == (
        "192.168.0.1 94:8f:cf:9a:25:89 Router (ARRIS Group, Inc.)"
    )


class Recorder:
    def __init__(self, status=200, error=None):
        self.urls = []
        self.status = status
        self.error = error

    def __call__(self, request, timeout):
        self.urls.append(request.full_url)
        if self.error:
            raise self.error
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def sent(recorder):
    parts = urllib.parse.urlsplit(recorder.urls[-1])
    return parts._replace(query="").geturl(), dict(urllib.parse.parse_qsl(parts.query, True))


KUMA = "http://192.168.0.72:3001/api/push/AbC123?status=up&msg=OK&ping="


def test_push_is_down_while_unknown_devices_are_around(monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr(watch.urllib.request, "urlopen", recorder)
    state = State()
    state.update([router(known=True, label="Router"), phone(known=False)], T0)

    assert push_status(KUMA, state)
    url, query = sent(recorder)
    assert url == "http://192.168.0.72:3001/api/push/AbC123"
    assert query["status"] == "down"
    assert query["msg"].startswith("1 unknown device(s): 192.168.0.20 de:2e:0c:7e:16:c2")


def test_push_is_up_when_every_device_is_known(monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr(watch.urllib.request, "urlopen", recorder)
    state = State()
    state.update([router(known=True, label="Router")], T0)

    push_status(KUMA, state)
    assert sent(recorder)[1] == {"status": "up", "msg": "1 devices, all known", "ping": ""}


def test_push_without_a_devices_file_only_counts(monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr(watch.urllib.request, "urlopen", recorder)
    state = State()
    state.update([router(), phone()], T0)

    push_status("http://kuma/api/push/x", state)
    assert sent(recorder)[1]["msg"] == "2 devices"


def test_long_push_messages_are_cut(monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr(watch.urllib.request, "urlopen", recorder)
    state = State()
    strangers = [
        Device(ip=f"192.168.0.{i}", mac=f"02:00:00:00:00:{i:02x}", known=False)
        for i in range(10, 40)
    ]
    state.update(strangers, T0)

    push_status(KUMA, state)
    message = sent(recorder)[1]["msg"]
    assert len(message) == watch.PUSH_MESSAGE_LIMIT
    assert message.endswith("...")


def test_failed_push_is_reported_not_raised(monkeypatch):
    monkeypatch.setattr(watch.urllib.request, "urlopen", Recorder(error=OSError("refused")))
    assert push_status(KUMA, State()) is False


def test_state_file_is_plain_json(tmp_path):
    path = tmp_path / "state.json"
    state = State()
    state.update([router()], T0)
    state.save(path)
    assert json.loads(path.read_text())["devices"]["94:8f:cf:9a:25:89"]["ip"] == "192.168.0.1"
