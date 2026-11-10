"""Our own address and the network range to scan."""

import ipaddress

from scapy.all import conf, get_if_hwaddr

# Sweeping anything bigger than a /22 takes minutes, so auto-detection
# scans only the /24 around our own address in that case.
MAX_AUTO_PREFIX = 22


def route_for(ip):
    """Return (interface, our source IP) that would be used to reach ip."""
    iface, src, _gateway = conf.route.route(str(ip))
    iface = getattr(iface, "name", iface)
    return iface, (None if src == "0.0.0.0" else src)


def routing_table():
    """Scapy's IPv4 routes: (net, mask, gateway, iface, address, metric)."""
    return conf.route.routes


def get_mac(iface):
    """Return the MAC address of an interface, or None."""
    try:
        return get_if_hwaddr(iface).lower()
    except Exception:
        return None


def find_subnet(my_ip, iface, routes):
    """Return the most specific local subnet of my_ip on iface, or None."""
    me = ipaddress.IPv4Address(my_ip)
    best = None
    for net, mask, _gateway, route_iface, *_ in routes:
        if getattr(route_iface, "name", route_iface) != iface:
            continue
        if mask in (0, 0xFFFFFFFF):  # default route or a single host
            continue
        try:
            network = ipaddress.IPv4Network(
                f"{ipaddress.IPv4Address(net)}/{ipaddress.IPv4Address(mask)}",
                strict=False,
            )
        except ValueError:
            continue
        if me in network and (best is None or network.prefixlen > best.prefixlen):
            best = network
    return best


def choose_scan_range(my_ip, iface, routes):
    """Return (network to scan, warning or None) for the network we are on."""
    subnet = find_subnet(my_ip, iface, routes)
    if subnet is not None and subnet.prefixlen >= MAX_AUTO_PREFIX:
        return subnet, None

    fallback = ipaddress.IPv4Network(f"{my_ip}/24", strict=False)
    if subnet is None:
        warning = f"Could not detect your subnet, scanning {fallback} instead."
    else:
        warning = (
            f"Your network {subnet} is too big for a quick scan, scanning {fallback} "
            f"instead. Pass the range explicitly to scan all of it."
        )
    return fallback, warning
