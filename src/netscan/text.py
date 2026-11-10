"""Cleaning text that other devices send us."""

import unicodedata

NAME_LIMIT = 64


def clean(text, limit=NAME_LIMIT):
    """Drop control and format characters and cap the length.

    Any device on the network chooses its own name. Without this, a name with
    terminal escape sequences could rewrite your terminal or forge log lines,
    and bidi characters could make it read like another name.
    """
    if not text:
        return None
    kept = "".join(
        " " if ch.isspace() else ch
        for ch in text
        if ch.isspace() or not unicodedata.category(ch).startswith("C")
    )
    kept = " ".join(kept.split())[:limit].strip()
    return kept or None
