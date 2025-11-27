# Network Scanner

Simple ARP network scanner built on top of Scapy for discovering active devices in a `/24` subnet.

## Run

```bash
sudo python3 arp_scanner.py 192.168.1.1/24
```

Determine your actual `/24` range in the terminal (e.g., using `ip addr`) and replace the example above with it.
