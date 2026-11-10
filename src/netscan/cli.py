"""Command line entry point: `netscan`."""

import argparse
import ipaddress
import os
import shutil
import signal
import socket
import sys
import time
from pathlib import Path

from netscan import __version__, inventory, names, network, output, scanner, vendor, watch

VENDOR_RETRY = 3600  # seconds between attempts when the vendor download fails


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


def interval(text):
    """argparse type: seconds between scans in watch mode."""
    try:
        seconds = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number of seconds: {text}") from None
    if seconds < 30:
        raise argparse.ArgumentTypeError("scan at most every 30 seconds")
    return seconds


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

    watching = parser.add_argument_group("watch mode")
    watching.add_argument(
        "-w",
        "--watch",
        type=interval,
        metavar="SECONDS",
        help="keep scanning every SECONDS and report devices that join or leave",
    )
    watching.add_argument(
        "--away-after",
        type=int,
        default=30,
        metavar="MINUTES",
        help="count a device as gone after MINUTES unseen (default: %(default)s)",
    )
    watching.add_argument(
        "--state",
        type=Path,
        metavar="FILE",
        help="where to remember devices (default: ~/.local/state/netscan/state.json)",
    )
    watching.add_argument(
        "--push-url",
        default=os.environ.get("NETSCAN_PUSH_URL") or None,
        metavar="URL",
        help="Uptime Kuma push URL: down while unknown devices are on the network "
        "(default: $NETSCAN_PUSH_URL)",
    )
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


def scan_devices(args, target, iface, my_ip):
    """ARP sweep plus names and vendors."""
    devices = scanner.arp_scan(target, iface, timeout=args.timeout)
    devices = add_this_computer(devices, target, iface, my_ip)

    if not args.no_names:
        found = names.resolve_names(d.ip for d in devices if not d.is_me)
        for device in devices:
            device.hostname = socket.gethostname() if device.is_me else found.get(device.ip)
    for device in devices:
        device.vendor = vendor.lookup_vendor(device.mac) if device.mac else None
    return devices


def load_known(path_arg, required=True):
    """Return (path, known devices or None when there is no file)."""
    path = path_arg or inventory.default_path()
    if path.exists():
        return path, inventory.load(path)
    if path_arg and required:
        raise UsageError(f"devices file not found: {path}")
    return path, None


def label_devices(devices, known):
    """Mark devices as known or unknown; leave them unmarked without a file."""
    if known is None:
        return
    for device in devices:
        if device.is_me:
            continue
        entry = inventory.match(device, known)
        device.known = entry is not None
        device.label = entry.name if entry else None


def save_unknown(devices, path):
    new = [d for d in devices if not d.is_me and not d.known]
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

    devices = scan_devices(args, target, iface, my_ip)
    path, known = load_known(args.devices, required=not args.save_unknown)
    label_devices(devices, known)
    if args.save_unknown:
        save_unknown(devices, path)

    color = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    print(output.render_table(devices, color=color), flush=True)

    if any(d.mac and not d.vendor for d in devices) and not vendor.has_database():
        print(
            "Tip: run `netscan --update-vendors` to look up vendors of newer devices.",
            file=sys.stderr,
        )
    return 0


def log(message):
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"{stamp}  {message}", file=sys.stderr, flush=True)


def run_watch(args):
    """Scan forever; print who joined or left and keep Uptime Kuma informed."""
    target, iface, my_ip = pick_target(args.range)
    state_path = args.state or watch.default_state_path()
    state = watch.State.load(state_path)
    _, known = load_known(args.devices)
    report = " and reporting to Uptime Kuma" if args.push_url else ""
    log(f"Watching {target} on {iface} every {args.watch}s{report}")

    next_vendor_check = 0.0
    while True:
        if time.time() >= next_vendor_check and not vendor.database_is_fresh():
            try:
                log(f"Updated the vendor list ({vendor.update_database()} vendors)")
            except vendor.UpdateError as error:
                log(f"Keeping the old vendor list: {error}")
                next_vendor_check = time.time() + VENDOR_RETRY

        devices = scan_devices(args, target, iface, my_ip)
        try:
            _, known = load_known(args.devices)
        except (UsageError, inventory.InventoryError) as error:
            log(f"Using the previous known devices: {error}")  # e.g. a file being edited
        label_devices(devices, known)

        now = time.time()
        first_round = not state.devices
        events = state.update(devices, now, known, away_after=args.away_after * 60)
        if first_round:
            print(output.render_table(devices), flush=True)
        for event in [] if first_round else events:
            print(watch.format_event(event, now), flush=True)

        if args.push_url and not watch.push_status(args.push_url, state):
            log("Could not reach the push URL")
        state.save(state_path)
        time.sleep(args.watch)


def update_vendors():
    count = vendor.update_database()
    print(f"Saved {count} vendors to {vendor.database_path()}")
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.watch and args.save_unknown:
        parser.error("--save-unknown cannot be used with --watch")
    try:
        if args.update_vendors:
            return update_vendors()  # no root needed
        ensure_root(argv)
        if args.watch:
            # docker stop sends SIGTERM; exit cleanly, the state is saved every round
            signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
            return run_watch(args)
        return run(args)
    except (UsageError, inventory.InventoryError, vendor.UpdateError) as error:
        print(f"netscan: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
