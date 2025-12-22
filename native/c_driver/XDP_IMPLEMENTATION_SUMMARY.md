# XDP/eBPF Implementation Summary

## Overview

This implementation provides a complete XDP (eXpress Data Path) packet filtering system for NetStress, designed to drop backscatter traffic (SYN-ACK and RST packets) at the kernel level before they can overwhelm the attacking system.

## Components

### 1. XDP Program Loader (`xdp_loader.c` / `xdp_loader.h`)

**Core Functions:**

- `xdp_load_program()` - Load eBPF bytecode and attach to network interface
- `xdp_unload_program()` - Gracefully detach and cleanup XDP program
- `xdp_get_stats()` - Retrieve packet statistics from BPF maps
- `xdp_is_supported()` - Check if XDP is available on the system

**Features:**

- Support for multiple XDP modes (hardware, native, generic)
- Automatic fallback to iptables when XDP is unavailable
- Real-time statistics collection via BPF maps
- Graceful error handling and cleanup

### 2. Backscatter Filter Program (`xdp_backscatter_filter.c`)

**eBPF Program Features:**

- Parses Ethernet, IP, and TCP headers at line rate
- Drops incoming SYN-ACK packets (prevents connection flood responses)
- Drops incoming RST packets (prevents connection reset floods)
- Maintains detailed statistics in BPF maps
- Passes all other traffic unchanged

**Statistics Tracked:**

- Total packets dropped/passed
- Total bytes dropped/passed
- Specific SYN-ACK packets dropped
- Specific RST packets dropped

### 3. Test Programs

**`test_xdp_stats.c`** - Real-time statistics monitoring
**`test_xdp_fallback.c`** - Fallback mechanism testing
**`test_xdp_integration.c`** - Comprehensive functionality test

## Requirements

### Linux Kernel

- Kernel 4.8+ for basic XDP support
- Kernel 4.18+ for AF_XDP support
- Kernel 5.1+ for optimal performance

### Dependencies

- `libbpf` - BPF program loading and management
- `clang` - eBPF program compilation
- `iptables` - Fallback packet filtering

### Privileges

- Root privileges required for:
  - Loading eBPF programs into kernel
  - Attaching XDP programs to network interfaces
  - Installing iptables rules

## Compilation

```bash
# Compile eBPF program
clang -O2 -target bpf -c xdp_backscatter_filter.c -o xdp_backscatter_filter.o

# Compile loader and tests (with libbpf)
gcc -DHAS_LIBBPF -o test_xdp_integration test_xdp_integration.c xdp_loader.c -lbpf

# Compile without libbpf (stubs only)
gcc -o test_xdp_integration test_xdp_integration.c xdp_loader.c
```

## Usage

### Basic XDP Loading

```c
#include "xdp_loader.h"

// Load XDP program
xdp_context_t* ctx = xdp_load_program("eth0", "xdp_backscatter_filter.o", XDP_FLAGS_SKB_MODE);
if (!ctx) {
    // Fallback to iptables
    install_iptables_fallback("eth0");
}

// Monitor statistics
xdp_stats_t stats;
xdp_get_stats(ctx, &stats);
printf("Dropped: %lu, Passed: %lu\n", stats.packets_dropped, stats.packets_passed);

// Cleanup
xdp_unload_program(ctx);
xdp_free_context(ctx);
```

### Command Line Testing

```bash
# Test XDP support
sudo ./test_xdp_integration

# Monitor statistics in real-time
sudo ./test_xdp_stats eth0

# Test fallback mechanism
sudo ./test_xdp_fallback eth0
```

## XDP Modes

### 1. Hardware Mode (XDP_FLAGS_HW_MODE)

- Offloaded to NIC hardware
- Highest performance (line rate)
- Limited NIC support

### 2. Native Mode (XDP_FLAGS_DRV_MODE)

- Runs in NIC driver
- Very high performance
- Most NICs support this

### 3. Generic Mode (XDP_FLAGS_SKB_MODE)

- Runs in kernel network stack
- Lower performance but universal
- Fallback when driver mode unavailable

## Fallback Mechanism

When XDP is unavailable, the system automatically falls back to iptables rules:

```bash
# Installed rules
iptables -I INPUT -i eth0 -p tcp --tcp-flags SYN,ACK SYN,ACK -j DROP
iptables -I INPUT -i eth0 -p tcp --tcp-flags RST RST -j DROP
```

## Performance Characteristics

### XDP Performance

- **Hardware Mode**: 100M+ PPS (line rate)
- **Native Mode**: 50M+ PPS
- **Generic Mode**: 10M+ PPS

### iptables Fallback

- **Performance**: 1M+ PPS
- **CPU Usage**: Higher than XDP
- **Compatibility**: Universal

## Integration with NetStress

The XDP system integrates with NetStress through the driver shim layer:

```c
// Check XDP availability
if (xdp_is_supported(interface)) {
    // Use XDP for maximum performance
    ctx = xdp_load_program(interface, "xdp_backscatter_filter.o", XDP_FLAGS_DRV_MODE);
} else if (iptables_available()) {
    // Fallback to iptables
    install_iptables_fallback(interface);
} else {
    // No protection available
    fprintf(stderr, "Warning: No backscatter protection available\n");
}
```

## Security Considerations

### Privileges

- XDP requires CAP_SYS_ADMIN capability
- iptables requires CAP_NET_ADMIN capability
- Both typically require root privileges

### Attack Surface

- eBPF programs are verified by kernel
- Cannot crash kernel or access arbitrary memory
- Limited instruction set prevents malicious code

### Resource Limits

- BPF programs have instruction limits
- Map sizes are bounded
- Automatic cleanup on program exit

## Troubleshooting

### Common Issues

**"XDP not supported"**

- Check kernel version: `uname -r`
- Verify interface exists: `ip link show`
- Check for libbpf: `ldconfig -p | grep bpf`

**"Permission denied"**

- Run with sudo: `sudo ./test_program`
- Check capabilities: `getcap ./test_program`

**"Program loading failed"**

- Verify eBPF program compiled: `ls -la *.o`
- Check program format: `file xdp_backscatter_filter.o`
- Verify clang version: `clang --version`

### Debug Commands

```bash
# Check XDP programs
sudo bpftool prog list

# Check BPF maps
sudo bpftool map list

# Monitor XDP statistics
sudo bpftool map dump name stats_map

# Check interface XDP status
sudo ip link show dev eth0
```

## Future Enhancements

### Planned Features

- IPv6 support in eBPF program
- UDP backscatter filtering
- Rate limiting in XDP program
- Integration with AF_XDP for zero-copy

### Performance Optimizations

- SIMD instructions in eBPF (when available)
- Per-CPU statistics maps
- Batch statistics updates
- Hardware timestamp support

## References

- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [eBPF Documentation](https://ebpf.io/)
- [libbpf API](https://libbpf.readthedocs.io/)
- [Linux XDP Documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
