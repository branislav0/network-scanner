"""Printing the scan result."""

GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

HEADERS = ("IP Address", "MAC Address", "Name", "Vendor")


def _row(device):
    name = device.label or device.hostname or "?"
    return (device.ip, device.mac or "?", name, device.vendor or "?")


def _note(device):
    """Text after the row and its color, or (None, None)."""
    if device.is_me:
        return "<-- this computer", GREEN
    if device.known is False:
        return "<-- unknown", YELLOW
    return None, None


def render_table(devices, color=False):
    rows = [_row(d) for d in devices]
    widths = [max([len(h), *(len(r[i]) for r in rows)]) for i, h in enumerate(HEADERS)]

    def line(cells):
        return "   ".join(c.ljust(w) for c, w in zip(cells, widths, strict=True)).rstrip()

    rule = "-" * len(line(tuple("x" * w for w in widths)))
    out = [rule, line(HEADERS), rule]
    for device, row in zip(devices, rows, strict=True):
        text = line(row)
        note, note_color = _note(device)
        if note:
            text = f"{text}   {note}"
            if color:
                text = f"{note_color}{text}{RESET}"
        out.append(text)
    out.append(rule)

    others = [d for d in devices if not d.is_me]
    summary = f"Other devices found: {len(others)}"
    if any(d.known is not None for d in others):
        unknown = sum(1 for d in others if d.known is False)
        summary += f" ({unknown} unknown)"
    out.append(summary)
    return "\n".join(out)
