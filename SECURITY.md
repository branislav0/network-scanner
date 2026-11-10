# Security policy

## Reporting a vulnerability

Please report security problems privately through
[GitHub's private vulnerability reporting](https://github.com/branislav0/network-scanner/security/advisories/new),
not in a public issue. You will get an answer within a week.

Helpful to include: the netscan version (`netscan --version`), how you run it
(pipx, sudo, Docker) and the steps to reproduce.

## Supported versions

Only the latest release and the `latest` Docker image get fixes.

## Scope

netscan runs with raw-socket privileges and parses data that any device on the
network can send, so these matter most:

- code execution or privilege escalation through `sudo netscan` or the Docker image
- crafted mDNS, NetBIOS, DNS or ARP replies affecting netscan or its output
- reading or writing files outside netscan's own files

Out of scope: devices hiding from the scan (for example by cloning a MAC
address) – netscan is an early warning, not intrusion detection.
