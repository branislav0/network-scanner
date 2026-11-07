from scapy.all import Ether, ARP, srp, conf, get_if_hwaddr
import ipaddress
import sys
import socket

GREEN = "\033[92m"
RESET = "\033[0m"


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

    print("----------------------------------------------------")
    print("IP Address\t\t\tMAC Address")
    print("----------------------------------------------------")

    for client in rows:
        if client["ip"] == my_ip:
            print(f"{GREEN}{client['ip']}\t\t\t{client['mac']}   <-- My IP{RESET}")
        else:
            print(f"{client['ip']}\t\t\t{client['mac']}")

    others = sum(1 for c in rows if c["ip"] != my_ip)
    print("----------------------------------------------------")
    print(f"Other devices found: {others}")
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
