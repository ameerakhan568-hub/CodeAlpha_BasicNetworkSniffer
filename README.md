# CodeAlpha_BasicNetworkSniffer

**Author:** Zainab Batool, BS Business Data Analytics, COMSATS University Islamabad
**Internship:** CodeAlpha Cyber Security - Task 1

## About
A basic Python network sniffer built with `scapy`. It captures packets and shows:
source/destination IP, protocol (TCP/UDP/ICMP), ports, TCP flags, TTL, length and the first 50 bytes of payload.

## Requirements
- Python 3
- `pip install scapy`
- Windows: install [Npcap](https://npcap.com)

## Run
```
sudo python3 sniffer.py        # Linux / Mac
python sniffer.py              # Windows (Run as Administrator)
```

## How it works
1. `sniff()` captures packets from the network interface.
2. `process_packet()` runs on every packet.
3. IP layer gives IPs, TTL; TCP/UDP layer gives ports; Raw layer gives payload.

## Learning
- IP = addressing, TCP = reliable, UDP = fast, ICMP = ping/errors.
- Unencrypted traffic (HTTP) payload readable hota hai; HTTPS ka payload encrypted hota hai.

## Disclaimer
For educational use only. Sirf apne own network par use karein.
