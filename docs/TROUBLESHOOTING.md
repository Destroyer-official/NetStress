# NetStress Troubleshooting Guide

Solutions for common problems and errors.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Permission Errors](#permission-errors)
- [Network Errors](#network-errors)
- [Performance Issues](#performance-issues)
- [Platform-Specific Issues](#platform-specific-issues)
- [Error Messages Reference](#error-messages-reference)
- [Getting Help](#getting-help)

---

## Installation Issues

### "pip: command not found"

**Problem:** pip is not installed or not in PATH.

**Solution:**

```bash
# Try pip3
pip3 install -r requirements.txt

# Or use python -m pip
python -m pip install -r requirements.txt
python3 -m pip install -r requirements.txt
```

---

### "No module named 'scapy'"

**Problem:** Scapy failed to install or import.

**Solution:**

**Linux:**

```bash
pip uninstall scapy
pip install scapy
```

**Windows:**

1. Install Npcap from https://npcap.com/
2. Check "WinPcap API-compatible Mode" during installation
3. Reinstall scapy:

```powershell
pip uninstall scapy
pip install scapy
```

**macOS:**

```bash
pip uninstall scapy
pip install scapy
```

---

### "error: Microsoft Visual C++ 14.0 is required"

**Problem:** Windows needs C++ build tools for some packages.

**Solution:**

1. Download Visual C++ Build Tools from:
   https://visualstudio.microsoft.com/visual-cpp-build-tools/
2. Install "Desktop development with C++"
3. Restart and try again

---

### "fatal error: Python.h: No such file or directory"

**Problem:** Python development headers not installed.

**Solution:**

```bash
# Debian/Ubuntu
sudo apt install python3-dev

# Fedora/RHEL
sudo dnf install python3-devel

# Arch
sudo pacman -S python
```

---

### "Could not find a version that satisfies the requirement"

**Problem:** Package version conflict or Python version mismatch.

**Solution:**

```bash
# Check Python version (need 3.8+)
python --version

# Upgrade pip
pip install --upgrade pip

# Try installing without version constraints
pip install aiohttp numpy scapy cryptography pyyaml faker psutil colorama requests
```

---

## Permission Errors

### "Permission denied" or "Operation not permitted"

**Problem:** Raw socket operations require elevated privileges.

**Solution:**

**Linux:**

```bash
# Option 1: Use sudo
sudo python3 ddos.py -i TARGET -p 80 -t TCP-SYN -d 60

# Option 2: Set capabilities (persistent, more secure)
sudo setcap cap_net_raw+ep $(which python3)
python3 ddos.py -i TARGET -p 80 -t TCP-SYN -d 60
```

**Windows:**

1. Right-click PowerShell
2. Select "Run as administrator"
3. Navigate to NetStress folder
4. Run your command

**macOS:**

```bash
sudo python3 ddos.py -i TARGET -p 80 -t TCP-SYN -d 60
```

---

### "socket.error: [Errno 1] Operation not permitted"

**Problem:** Trying to use raw sockets without root.

**Solution:**

- Use `sudo` (Linux/macOS)
- Run as Administrator (Windows)
- Or use protocols that don't require raw sockets: UDP, TCP, HTTP, HTTPS, DNS, SLOW

---

### "OSError: [Errno 99] Cannot assign requested address"

**Problem:** Trying to bind to an unavailable address.

**Solution:**

```bash
# Check if address is available
ip addr show  # Linux
ipconfig      # Windows

# Use 0.0.0.0 to bind to all interfaces
# Or use a valid local IP
```

---

## Network Errors

### "socket.gaierror: [Errno -2] Name or service not known"

**Problem:** Cannot resolve hostname.

**Solution:**

```bash
# Check DNS resolution
nslookup example.com
ping example.com

# Use IP address instead of hostname
python ddos.py -i 93.184.216.34 -p 80 -t UDP

# Check /etc/resolv.conf (Linux)
cat /etc/resolv.conf
```

---

### "Connection refused"

**Problem:** Target is not accepting connections on that port.

**Solution:**

```bash
# Verify target is listening
nc -zv TARGET PORT
nmap -p PORT TARGET

# Check if port is correct
# Check if service is running on target
```

---

### "Network is unreachable"

**Problem:** No route to target.

**Solution:**

```bash
# Check network connectivity
ping TARGET
traceroute TARGET  # Linux/macOS
tracert TARGET     # Windows

# Check routing table
ip route  # Linux
route print  # Windows
netstat -rn  # macOS
```

---

### "Address already in use"

**Problem:** Socket is still bound from previous run.

**Solution:**

```bash
# Wait 30-60 seconds for TIME_WAIT to expire
# Or use different source port

# Check what's using the port
lsof -i :PORT  # Linux/macOS
netstat -ano | findstr :PORT  # Windows
```

---

### "Too many open files"

**Problem:** Reached file descriptor limit.

**Solution:**

**Linux:**

```bash
# Check current limit
ulimit -n

# Increase limit (temporary)
ulimit -n 65535

# Increase limit (permanent)
echo "* soft nofile 65535" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65535" | sudo tee -a /etc/security/limits.conf
# Log out and back in
```

**macOS:**

```bash
# Increase limit
sudo launchctl limit maxfiles 65535 200000
ulimit -n 65535
```

---

## Performance Issues

### Low PPS (Packets Per Second)

**Problem:** Getting fewer packets than expected.

**Solutions:**

1. **Use more threads:**

   ```bash
   python ddos.py -i TARGET -p 80 -t UDP -x 8
   ```

2. **Use smaller packets:**

   ```bash
   python ddos.py -i TARGET -p 80 -t UDP -s 64
   ```

3. **Install native engine:**

   ```bash
   python scripts/install_native.py
   ```

4. **Check system resources:**

   ```bash
   # CPU usage
   top  # Linux/macOS

   # Network interface
   ifconfig  # Linux/macOS
   ipconfig  # Windows
   ```

5. **Disable firewall temporarily:**

   ```bash
   # Linux
   sudo systemctl stop firewalld

   # Windows (PowerShell as Admin)
   Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
   ```

---

### High CPU Usage

**Problem:** CPU at 100% but low PPS.

**Solutions:**

1. **Reduce threads:**

   ```bash
   python ddos.py -i TARGET -p 80 -t UDP -x 2
   ```

2. **Use native engine:**

   ```bash
   python scripts/install_native.py
   ```

3. **Check for other processes:**
   ```bash
   top -c  # Linux
   ```

---

### Memory Issues

**Problem:** Running out of memory.

**Solutions:**

1. **Reduce threads:**

   ```bash
   python ddos.py -i TARGET -p 80 -t UDP -x 2
   ```

2. **Use smaller packet size:**

   ```bash
   python ddos.py -i TARGET -p 80 -t UDP -s 64
   ```

3. **Close other applications**

---

## Platform-Specific Issues

### Windows

**"WinError 10013: An attempt was made to access a socket in a way forbidden by its access permissions"**

**Solution:**

1. Run PowerShell as Administrator
2. Check Windows Firewall settings
3. Disable antivirus temporarily

**"ImportError: DLL load failed"**

**Solution:**

1. Install Visual C++ Redistributable
2. Reinstall Python
3. Check PATH environment variable

---

### Linux

**"RTNETLINK answers: Operation not permitted"**

**Solution:**

```bash
# Use sudo
sudo python3 ddos.py ...

# Or set capabilities
sudo setcap cap_net_admin,cap_net_raw+ep $(which python3)
```

**"Cannot open /dev/net/tun"**

**Solution:**

```bash
# Load tun module
sudo modprobe tun

# Check permissions
ls -la /dev/net/tun
sudo chmod 666 /dev/net/tun
```

---

### macOS

**"Operation not permitted" even with sudo**

**Solution:**
System Integrity Protection (SIP) may be blocking. Options:

1. Use protocols that don't need raw sockets (UDP, TCP, HTTP)
2. Disable SIP (not recommended for daily use):
   - Restart and hold Cmd+R
   - Terminal → `csrutil disable`
   - Restart

**"socket.error: [Errno 49] Can't assign requested address"**

**Solution:**

```bash
# Check network interface
ifconfig

# Use correct interface IP or 0.0.0.0
```

---

## Error Messages Reference

| Error                     | Cause           | Solution                   |
| ------------------------- | --------------- | -------------------------- |
| `Permission denied`       | Need root/admin | Use sudo or run as admin   |
| `Connection refused`      | Port not open   | Check target service       |
| `Network unreachable`     | No route        | Check network config       |
| `Name resolution failed`  | DNS issue       | Use IP instead             |
| `Address in use`          | Socket busy     | Wait or use different port |
| `Too many open files`     | FD limit        | Increase ulimit            |
| `Operation not permitted` | Need privileges | Use sudo/admin             |
| `Module not found`        | Missing package | pip install package        |
| `Invalid argument`        | Wrong parameter | Check argument format      |

---

## Getting Help

### Before Asking for Help

1. **Check system status:**

   ```bash
   python ddos.py --status
   ```

2. **Run with verbose mode:**

   ```bash
   python ddos.py -i TARGET -p 80 -t UDP -v
   ```

3. **Check Python version:**

   ```bash
   python --version
   ```

4. **Check installed packages:**
   ```bash
   pip list
   ```

### Information to Include

When opening an issue, include:

1. Operating system and version
2. Python version
3. Output of `python ddos.py --status`
4. Exact command you ran
5. Complete error message
6. Steps to reproduce

### Where to Get Help

1. Check [FAQ.md](FAQ.md)
2. Search existing GitHub issues
3. Open a new issue with details above

---

## See Also

- [INSTALLATION.md](INSTALLATION.md) - Installation guide
- [CLI_USAGE.md](CLI_USAGE.md) - Command reference
- [FAQ.md](FAQ.md) - Frequently asked questions
- [PERFORMANCE_TUNING.md](PERFORMANCE_TUNING.md) - Optimization guide
