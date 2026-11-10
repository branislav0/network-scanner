import pytest

from netscan.text import clean


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("router.lan", "router.lan"),
        ("evil\x1b]52;c;cm0gLXJmIH4=\x07-tv", "evil]52;c;cm0gLXJmIH4=-tv"),  # clipboard write
        ("printer\x1b[2J\x1b[H", "printer[2J[H"),  # clear screen
        (
            "phone\n2026-11-10 22:40:05  left  192.168.0.1",
            "phone 2026-11-10 22:40:05 left 192.168.0.1",
        ),
        ("Anna‮enohp", "Annaenohp"),  # right-to-left override
        ("  spaced   out  ", "spaced out"),
        ("Žilina-NAS", "Žilina-NAS"),
        ("\x00\x01", None),
        ("", None),
        (None, None),
    ],
)
def test_clean(raw, expected):
    assert clean(raw) == expected


def test_long_names_are_cut():
    assert clean("x" * 500) == "x" * 64
    assert len(clean("y" * 500, limit=80)) == 80
