# Network Scanner

Simple ARP network scanner built on top of [Scapy](https://scapy.net) for discovering active devices in a local subnet. Your own IP address is highlighted in the output.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Run

Sending raw ARP packets needs root privileges:

```bash
sudo .venv/bin/python arp_scanner.py 192.168.1.0/24
```

Replace `192.168.1.0/24` with your own network range – you can find it with `ip addr` (Linux) or `ipconfig` (Windows).

## Example output

```
----------------------------------------------------
IP Address			MAC Address
----------------------------------------------------
192.168.1.1			aa:bb:cc:dd:ee:01
192.168.1.23			aa:bb:cc:dd:ee:17   <-- My IP
----------------------------------------------------
Active devices found: 2
Your IP identified as: 192.168.1.23
```
