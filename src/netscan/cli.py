"""Command line entry point: `netscan`."""

import argparse
import ipaddress
import os
import shutil
import socket
import sys
from pathlib import Path

from netscan import __version__, inventory, names, network, output, scanner, vendor


class UsageError(Exception):
    pass


def ipv4_range(text):
    """argparse type: an IPv4 address or range, checked before asking for sudo."""
    try:
        target = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a valid IPv4 range: {text}") from None
    if target.version != 4:
        raise argparse.ArgumentTypeError("only IPv4 ranges can be scanned with ARP")
    return target


def build_parser():
    parser = argparse.ArgumentParser(
        prog="netscan",
        description="List the devices on your local network with their names and vendors.",
    )
    parser.add_argument(
        "range",
        nargs="?",
        type=ipv4_range,
        help="network to scan, e.g. 192.168.1.0/24 (default: the network you are on)",
    )
    parser.add_argument(
        "-d",
        "--devices",
        type=Path,
        metavar="FILE",
        help="known devices file (default: ~/.config/netscan/devices.toml)",
    )
    parser.add_argument(
        "--save-unknown",
        action="store_true",
        help="add devices that are not known yet to the devices file",
    )
    parser.add_argument(
        "--no-names",
        action="store_true",
        help="do not ask devices for their names (faster)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=2.0,
        help="seconds to wait for ARP replies (default: %(default)s)",
    )
    parser.add_argument("--no-color", action="store_true", help="plain output without colors")
    parser.add_argument(
        "--update-vendors",
        action="store_true",
        help="download the latest MAC vendor list and exit",
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def ensure_root(argv):
    """Sending raw ARP packets needs root, so re-run through sudo when needed."""
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        return
    if shutil.which("sudo") is None:
        raise UsageError("sending ARP packets needs root, run netscan as root")
    print("netscan needs root to send ARP packets, re-running with sudo...", file=sys.stderr)
    sys.stderr.flush()
    os.execvp("sudo", ["sudo", sys.executable, "-m", "netscan", *argv])


def pick_target(target):
    """Return (network, interface, our IP) for the scan."""
    if target is not None:
        probe = target.network_address + (1 if target.num_addresses > 1 else 0)
        iface, my_ip = network.route_for(probe)
        return target, iface, my_ip

    iface, my_ip = network.route_for("8.8.8.8")
    if my_ip is None:
        raise UsageError("could not find your network, pass the range, e.g. 192.168.1.0/24")
    target, warning = network.choose_scan_range(my_ip, iface, network.routing_table())
    if warning:
        print(warning, file=sys.stderr)
    return target, iface, my_ip


def add_this_computer(devices, target, iface, my_ip):
    """We never answer our own ARP request, so add ourselves to the list."""
    if not my_ip or ipaddress.ip_address(my_ip) not in target:
        return devices
    for device in devices:
        if device.ip == my_ip:
            device.is_me = True
            return devices
    me = scanner.Device(ip=my_ip, mac=network.get_mac(iface), is_me=True)
    return sorted([*devices, me], key=scanner.sort_key)


def apply_known_devices(devices, path_arg, save_unknown):
    """Label devices from the known devices file and optionally add new ones."""
    path = path_arg or inventory.default_path()
    others = [d for d in devices if not d.is_me]

    if path.exists():
        known = inventory.load(path)
        for device in others:
            entry = inventory.match(device, known)
            device.known = entry is not None
            device.label = entry.name if entry else None
    elif path_arg and not save_unknown:
        raise UsageError(f"devices file not found: {path}")

    if not save_unknown:
        return
    new = [d for d in others if not d.known]
    if not new:
        print("No unknown devices to add.", file=sys.stderr)
        return
    added = inventory.append(path, new)
    for device, entry in zip(new, added, strict=True):
        device.known, device.label = True, entry.name
    print(
        f"Added {len(added)} device(s) to {path} - rename them to something you recognise.",
        file=sys.stderr,
    )


def run(args):
    target, iface, my_ip = pick_target(args.range)
    print(f"Scanning {target} on {iface}...", file=sys.stderr)

    devices = scanner.arp_scan(target, iface, timeout=args.timeout)
    devices = add_this_computer(devices, target, iface, my_ip)

    if not args.no_names:
        found = names.resolve_names(d.ip for d in devices if not d.is_me)
        for device in devices:
            device.hostname = socket.gethostname() if device.is_me else found.get(device.ip)
    for device in devices:
        device.vendor = vendor.lookup_vendor(device.mac) if device.mac else None

    apply_known_devices(devices, args.devices, args.save_unknown)

    color = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    print(output.render_table(devices, color=color), flush=True)

    if any(d.mac and not d.vendor for d in devices) and not vendor.has_database():
        print(
            "Tip: run `netscan --update-vendors` to look up vendors of newer devices.",
            file=sys.stderr,
        )
    return 0


def update_vendors():
    count = vendor.update_database()
    print(f"Saved {count} vendors to {vendor.database_path()}")
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    args = build_parser().parse_args(argv)
    try:
        if args.update_vendors:
            return update_vendors()  # no root needed
        ensure_root(argv)
        return run(args)
    except (UsageError, inventory.InventoryError, vendor.UpdateError) as error:
        print(f"netscan: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
