# Network Scanner

Simple ARP network scanner built on top of [Scapy](https://scapy.net) for discovering active devices in a local subnet.

For every device it shows:

- **IP and MAC address**
- **Name** – asked from the device itself via mDNS/Bonjour (Apple, Linux, printers) or NetBIOS (Windows), falling back to reverse DNS from your router or DNS server. `?` means the device did not tell its name – common for Android phones.
- **Vendor** – looked up from the MAC address in Scapy's offline database. `(random MAC)` means the device uses a private, randomized address (modern phones do this per Wi-Fi network).

Your own machine is listed with its real MAC address and highlighted, but not counted among the found devices.

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
----------------------------------------------------------------------------------------------------
IP Address       MAC Address         Name                               Vendor
----------------------------------------------------------------------------------------------------
192.168.1.1      aa:bb:cc:dd:ee:01   router.local                       ARRIS Group, Inc.
192.168.1.23     aa:bb:cc:dd:ee:17   my-laptop                          ?   <-- My IP
192.168.1.40     aa:bb:cc:dd:ee:28   raspberrypi.local                  Raspberry Pi Trading Ltd
192.168.1.57     5e:11:22:33:44:55   Johns-iPhone.local                 (random MAC)
192.168.1.62     f2:aa:bb:cc:dd:ee   ?                                  (random MAC)
----------------------------------------------------------------------------------------------------
Other devices found: 4
Your IP identified as: 192.168.1.23
```

Only scan networks you own or have permission to scan.
