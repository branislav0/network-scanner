"""Printing the scan result."""

GREEN = "\033[92m"
RESET = "\033[0m"

HEADERS = ("IP Address", "MAC Address", "Name", "Vendor")


def _row(device):
    return (device.ip, device.mac or "?", device.hostname or "?", device.vendor or "?")


def render_table(devices, color=False):
    rows = [_row(d) for d in devices]
    widths = [max([len(h), *(len(r[i]) for r in rows)]) for i, h in enumerate(HEADERS)]

    def line(cells):
        return "   ".join(c.ljust(w) for c, w in zip(cells, widths, strict=True)).rstrip()

    rule = "-" * len(line(tuple("x" * w for w in widths)))
    out = [rule, line(HEADERS), rule]
    for device, row in zip(devices, rows, strict=True):
        text = line(row)
        if device.is_me:
            text = f"{text}   <-- this computer"
            if color:
                text = f"{GREEN}{text}{RESET}"
        out.append(text)
    out.append(rule)

    others = [d for d in devices if not d.is_me]
    out.append(f"Other devices found: {len(others)}")
    return "\n".join(out)
