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
- **Vendor** – looked up from the MAC address in an offline database. `(random MAC)` means the device uses a private, randomized address (modern phones do this per Wi-Fi network). Run `netscan --update-vendors` once to download Wireshark's current vendor list – the built-in one does not know newer devices such as the Raspberry Pi 5.

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
netscan --update-vendors     # download the latest MAC vendor list (no root needed)
netscan --watch 300          # keep watching, see below
netscan --help
```

Sending raw ARP packets needs root, so `netscan` re-runs itself through `sudo` and asks for your password when needed.

## Known devices

Tell netscan which devices are yours, and it shows your names for them and flags everything else:

```bash
netscan --save-unknown       # adds every device it sees now to the list
```

This writes `~/.config/netscan/devices.toml`. Rename the devices to something you recognise:

```toml
[[device]]
name = "Router"
mac = "94:8f:cf:9a:25:89"

[[device]]
name = "Anna's phone"
hostname = "Annas-iPhone"    # no mac: matches by name, for phones whose MAC changes
```

From then on a device that is not in the list stands out:

```
192.168.1.1    94:8f:cf:9a:25:89   Router           ARRIS Group, Inc.
192.168.1.57   5e:11:22:33:44:55   Anna's phone     (random MAC)
192.168.1.62   f2:aa:bb:cc:dd:ee   ?                (random MAC)   <-- unknown
-----------------------------------------------------------------------------
Other devices found: 3 (1 unknown)
```

Entries with a `mac` match only by MAC. Matching by `hostname` works only for entries without a `mac`, because any device can pick any name – use it just for phones whose MAC changes.

Run `netscan --save-unknown` again to add new devices you trust. Use `--devices FILE` for a list somewhere else.

## Watch mode

Keep an eye on the network and see who comes and goes:

```bash
netscan --watch 300          # scan every 5 minutes
```

The first round prints the table, then one line per change:

```
2026-11-10 22:40:05  joined  192.168.1.66 02:66:66:66:66:66 (random MAC)  [unknown, first time]
2026-11-10 23:25:10  left    192.168.1.57 5e:11:22:33:44:55 Anna's phone (random MAC)
```

A device counts as gone only after 30 minutes unseen (`--away-after`), because sleeping phones skip replies. What netscan saw is kept in `~/.local/state/netscan/state.json`, so a restart does not report everything again. Edits to the known devices file apply on the next round.

### Alerts with Uptime Kuma

Create a **Push** monitor in [Uptime Kuma](https://github.com/louislam/uptime-kuma) (heartbeat interval a bit longer than the scan interval, e.g. 900 s) and give netscan its push URL:

```bash
netscan --watch 300 --push-url "http://kuma:3001/api/push/AbC123?status=up&msg=OK&ping="
```

Every round netscan reports **down** while unknown devices are on the network – the message lists them – and **up** otherwise. Kuma sends you its usual notifications (Telegram, e-mail, Discord, ...) when that changes, and also when netscan stops reporting. Add the device to `devices.toml` to clear the alert.

## Docker

The image is the easiest way to run the watcher on a Raspberry Pi or a home server (amd64, arm64 and armv7). It needs Linux: Docker Desktop on macOS and Windows cannot see your LAN.

```bash
mkdir netscan && cd netscan
curl -O https://raw.githubusercontent.com/branislav0/network-scanner/master/docker-compose.yml
echo 'NETSCAN_PUSH_URL=http://127.0.0.1:3001/api/push/AbC123' > .env   # optional
docker compose up -d
docker logs -f netscan
```

The container uses the host network and the `NET_RAW` capability to send ARP packets. Everything it keeps is in `./data`:

| File | What |
|---|---|
| `data/devices.toml` | your known devices – edit it on the host |
| `data/state.json` | who is on the network now |
| `data/manuf` | vendor list, refreshed weekly |

To add the devices that are on the network now to the list:

```bash
docker exec netscan netscan --save-unknown
```

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
