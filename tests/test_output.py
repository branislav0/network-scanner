from netscan.output import GREEN, YELLOW, render_table
from netscan.scanner import Device

DEVICES = [
    Device(ip="192.168.0.1", mac="00:00:5e:00:53:01", hostname="router.lan", vendor="ARRIS"),
    Device(ip="192.168.0.5", mac="00:00:5e:00:53:05", hostname="my-laptop", is_me=True),
    Device(ip="192.168.0.20", mac="02:00:00:00:00:20", vendor="(random MAC)"),
]


def lines_with(text, needle):
    return [line for line in text.splitlines() if needle in line]


def test_lists_every_device():
    text = render_table(DEVICES)
    assert "router.lan" in text
    assert len(lines_with(text, "192.168.0.")) == 3


def test_marks_this_computer_and_does_not_count_it():
    text = render_table(DEVICES)
    assert lines_with(text, "192.168.0.5")[0].endswith("<-- this computer")
    assert "Other devices found: 2" in text


def test_missing_values_are_question_marks():
    row = lines_with(render_table(DEVICES), "192.168.0.20")[0]
    assert row.split()[2] == "?"


def test_colors_only_when_asked():
    assert "\033[" not in render_table(DEVICES)
    assert GREEN in render_table(DEVICES, color=True)


def test_empty_network():
    assert "Other devices found: 0" in render_table([])


def test_unknown_devices_are_flagged_and_counted():
    devices = [
        Device(ip="192.168.0.1", mac="00:00:5e:00:53:01", label="Router", known=True),
        Device(ip="192.168.0.20", mac="02:00:00:00:00:20", hostname="android-1", known=False),
    ]
    text = render_table(devices, color=True)

    assert "Router" in text
    assert YELLOW in lines_with(text, "192.168.0.20")[0]
    assert "<-- unknown" in lines_with(text, "192.168.0.20")[0]
    assert "Other devices found: 2 (1 unknown)" in text


def test_escape_sequences_never_reach_the_terminal():
    device = Device(
        ip="192.168.0.66",
        mac="02:66:66:66:66:66",
        hostname="tv\x1b]0;pwned\x07\x1b[2J",
        vendor="Evil\x1b[8m Corp",
        known=False,
    )
    text = render_table([device])
    assert "\x1b" not in text and "\x07" not in text
