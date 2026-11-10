from netscan.output import GREEN, render_table
from netscan.scanner import Device

DEVICES = [
    Device(ip="192.168.0.1", mac="94:8f:cf:9a:25:89", hostname="router.lan", vendor="ARRIS"),
    Device(ip="192.168.0.5", mac="8c:8b:5b:76:f2:df", hostname="my-laptop", is_me=True),
    Device(ip="192.168.0.20", mac="de:2e:0c:7e:16:c2", vendor="(random MAC)"),
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
