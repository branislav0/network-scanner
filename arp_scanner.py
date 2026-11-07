from scapy.all import Ether, ARP, DNS, DNSQR, srp, conf, get_if_hwaddr
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import socket
import struct
import sys

GREEN = "\033[92m"
RESET = "\033[0m"
TIMEOUT = 1.0


def get_my_ip():
    """Zistí a vráti lokálnu IP adresu."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        my_ip = s.getsockname()[0]
        s.close()
        return my_ip
    except Exception:
        return None


def get_my_mac(my_ip):
    """Zistí MAC adresu rozhrania, cez ktoré ide komunikácia z my_ip."""
    try:
        iface = conf.route.route(my_ip)[0]
        return get_if_hwaddr(iface)
    except Exception:
        return "N/A"


def in_range(ip, target):
    """Vráti True, ak IP patrí do skenovaného rozsahu."""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False


# --- Zisťovanie mien ---------------------------------------------------------

def name_from_dns(ip):
    """Reverse DNS – meno, ktoré pozná router alebo DNS server (napr. Pi-hole)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def name_from_mdns(ip):
    """mDNS/Bonjour – opýta sa priamo zariadenia (Apple, Linux, tlačiarne)."""
    reverse = ipaddress.ip_address(ip).reverse_pointer
    query = bytes(DNS(id=0, rd=0, qd=DNSQR(qname=reverse, qtype="PTR")))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(TIMEOUT)
            s.sendto(query, (ip, 5353))
            data, _ = s.recvfrom(4096)
        answer = DNS(data).an
        if answer is not None:
            name = answer.rdata
            if isinstance(name, bytes):
                name = name.decode(errors="ignore")
            return name.rstrip(".") or None
    except (OSError, AttributeError, IndexError):
        pass
    return None


def name_from_netbios(ip):
    """NetBIOS – meno počítača s Windows."""
    # NBSTAT dotaz na meno "*" (zakódované ako "CK" + 30x "A")
    query = (struct.pack(">HHHHHH", 0x1337, 0, 1, 0, 0, 0)
             + b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
             + struct.pack(">HH", 0x21, 1))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(TIMEOUT)
            s.sendto(query, (ip, 137))
            data, _ = s.recvfrom(4096)
        count = data[56]
        for i in range(count):
            entry = data[57 + i * 18: 57 + (i + 1) * 18]
            name, suffix, flags = entry[:15], entry[15], struct.unpack(">H", entry[16:18])[0]
            if suffix == 0x00 and not flags & 0x8000:  # meno počítača, nie skupiny
                return name.decode(errors="ignore").strip()
    except (OSError, IndexError, struct.error):
        pass
    return None


def resolve_name(ip):
    # Najprv meno, ktoré si zariadenie nastavilo samo, až potom meno z DNS
    for method in (name_from_mdns, name_from_netbios, name_from_dns):
        name = method(ip)
        if name:
            return name
    return "?"


def get_vendor(mac):
    """Výrobca podľa MAC adresy (offline databáza zo Scapy)."""
    try:
        if int(mac.split(":")[0], 16) & 0x02:
            return "(random MAC)"  # súkromná MAC – mobily ju menia pre každú Wi-Fi
        vendor = conf.manufdb._get_manuf(mac)
        return vendor if vendor and vendor != mac else "?"
    except (ValueError, AttributeError):
        return "?"


# --- Sken a výpis ------------------------------------------------------------

def scan(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []

    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


def print_result(results_list, my_ip, my_mac, target):
    # Vlastný počítač na vlastnú ARP otázku neodpovedá – doplníme ho sami,
    # ale len keď patrí do skenovaného rozsahu, a do počtu ho nerátame.
    rows = list(results_list)
    if my_ip and in_range(my_ip, target) and not any(c["ip"] == my_ip for c in rows):
        rows.append({"ip": my_ip, "mac": my_mac})
    rows.sort(key=lambda c: ipaddress.ip_address(c["ip"]))

    # Mená zisťujeme paralelne, aby sken siete s mnohými zariadeniami netrval dlho
    others = [c["ip"] for c in rows if c["ip"] != my_ip]
    with ThreadPoolExecutor(max_workers=32) as pool:
        names = dict(zip(others, pool.map(resolve_name, others)))
    names[my_ip] = socket.gethostname()

    line = "-" * 100
    print(line)
    print(f"{'IP Address':<17}{'MAC Address':<20}{'Name':<35}Vendor")
    print(line)

    for client in rows:
        text = (f"{client['ip']:<17}{client['mac']:<20}"
                f"{names.get(client['ip'], '?'):<35}{get_vendor(client['mac'])}")
        if client["ip"] == my_ip:
            print(f"{GREEN}{text}   <-- My IP{RESET}")
        else:
            print(text)

    print(line)
    print(f"Other devices found: {len(others)}")
    print(f"Your IP identified as: {my_ip}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 arp_scanner.py <IP_address/range>")
        print("Example: python3 arp_scanner.py 192.168.1.0/24")
        sys.exit(1)

    target_ip = sys.argv[1]
    my_ip = get_my_ip()
    my_mac = get_my_mac(my_ip) if my_ip else "N/A"

    print(f"Scanning network: {target_ip}...")
    scan_result = scan(target_ip)
    print_result(scan_result, my_ip, my_mac, target_ip)
