# netscan

[![CI](https://github.com/branislav0/network-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/branislav0/network-scanner/actions/workflows/ci.yml)

See which devices are on your local network – with their names and vendors – in one command.

```
$ netscan
Scanning 192.168.1.0/24 on wlan0...
-----------------------------------------------------------------------------------------
IP Address     MAC Address         Name                 Vendor
-----------------------------------------------------------------------------------------
192.168.1.1    aa:bb:cc:dd:ee:01   router.lan           ARRIS Group, Inc.
192.168.1.23   aa:bb:cc:dd:ee:17   my-laptop            Intel Corporate   <-- this computer
192.168.1.40   dc:a6:32:00:00:28   raspberrypi.local    Raspberry Pi Trading Ltd
192.168.1.57   5e:11:22:33:44:55   Johns-iPhone.local   (random MAC)
192.168.1.62   f2:aa:bb:cc:dd:ee   ?                    (random MAC)
-----------------------------------------------------------------------------------------
Other devices found: 4
```

For every device it shows:

- **IP and MAC address** – found with an ARP sweep, so it sees devices that ignore ping too.
- **Name** – asked from the device itself via mDNS/Bonjour (Apple, Linux, printers) or NetBIOS (Windows), falling back to reverse DNS from your router or DNS server. `?` means the device did not tell its name – common for Android phones.
- **Vendor** – looked up from the MAC address in an offline database. `(random MAC)` means the device uses a private, randomized address (modern phones do this per Wi-Fi network).

## Install

Needs Python 3.11+ on Linux or macOS. With [pipx](https://pipx.pypa.io):

```bash
sudo apt install pipx        # Debian, Ubuntu, Mint, Raspberry Pi OS
pipx install git+https://github.com/branislav0/network-scanner
```

## Usage

```bash
netscan                      # scan the network you are on
netscan 192.168.1.0/24       # scan a specific range
netscan --no-names           # skip name lookups (faster)
netscan --help
```

Sending raw ARP packets needs root, so `netscan` re-runs itself through `sudo` and asks for your password when needed.

Only scan networks you own or have permission to scan.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check .
.venv/bin/pytest
```

The tests fake the network, so they need neither root nor a real LAN.

## License

MIT
