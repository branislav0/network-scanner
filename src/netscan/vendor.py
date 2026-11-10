"""Device maker from the MAC address."""

from scapy.all import conf

RANDOM_MAC = "(random MAC)"


def is_random_mac(mac):
    """Phones use private, randomized MACs per Wi-Fi network (locally administered bit)."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except ValueError:
        return False


def lookup_vendor(mac):
    """Return the vendor from scapy's offline database, or None."""
    if is_random_mac(mac):
        return RANDOM_MAC
    try:
        vendor = conf.manufdb._get_manuf(mac)
    except Exception:
        return None
    if not vendor or vendor.lower() == mac.lower():
        return None
    return vendor
