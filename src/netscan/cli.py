"""Command line entry point: `netscan`."""

import argparse
import ipaddress
import os
import shutil
import socket
import sys

from netscan import __version__, names, network, output, scanner, vendor


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

    color = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    print(output.render_table(devices, color=color))
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    args = build_parser().parse_args(argv)
    try:
        ensure_root(argv)
        return run(args)
    except UsageError as error:
        print(f"netscan: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
