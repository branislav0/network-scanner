from scapy.all import Ether, ARP, srp
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


def print_result(results_list, my_ip):
    print("----------------------------------------------------")
    print("IP Address\t\t\tMAC Address")
    print("----------------------------------------------------")

    found_my_ip = any(client["ip"] == my_ip for client in results_list)
    if not found_my_ip:
        results_list.append({"ip": my_ip, "mac": "N/A"})

    for client in results_list:
        if client["ip"] == my_ip:
            print(f"{GREEN}{client['ip']}\t\t\t{client['mac']}   <-- My IP{RESET}")
        else:
            print(f"{client['ip']}\t\t\t{client['mac']}")

    print("----------------------------------------------------")
    print(f"Active devices found: {len(results_list)}")
    print(f"Your IP identified as: {my_ip}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 arp_scanner.py <IP_address/range>")
        print("Example: python3 arp_scanner.py 192.168.1.1/24")
        sys.exit(1)

    target_ip = sys.argv[1]
    my_ip = get_my_ip()

    print(f"Scanning network: {target_ip}...")
    scan_result = scan(target_ip)
    print_result(scan_result, my_ip)
