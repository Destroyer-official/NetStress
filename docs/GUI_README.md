# GUI Interface

Graphical user interface for NetStress.

---

## Quick Start

### Launch GUI

```bash
# Windows
python gui_main.py

# Linux/macOS
python3 gui_main.py

# Or use launcher
python launcher.py
```

### Requirements

- Python 3.8+
- dearpygui >= 1.10.1
- All base framework dependencies

Install GUI dependencies:

```bash
pip install dearpygui
```

---

## Features

### Attack Configuration

- Target IP/hostname input
- Port selection
- Protocol dropdown (all 15 protocols)
- Duration, threads, packet size controls
- Advanced options (AI, spoofing, custom payload)

### Real-time Monitoring

- Packets per second (PPS)
- Throughput (Mbps/Gbps)
- Success/error rates
- System resource usage (CPU, memory, network)

### Safety Controls

- Safety system status
- Target validation indicator
- Resource limit warnings
- Emergency stop button

### Logging

- Live log viewer
- Log filtering
- Export functionality

---

## Interface Tabs

### 1. Attack Config

Configure and launch attacks.

- Target settings
- Protocol selection
- Parameter controls
- Start/Stop buttons

### 2. Monitoring

Real-time performance data.

- Live graphs
- Statistics display
- Protocol breakdown

### 3. Safety

Safety system status.

- Validation status
- Resource usage
- Audit log viewer

### 4. Logs

Application logs.

- Log viewer
- Filter controls
- Export options

---

## Configuration

### GUI Settings

File: `gui_settings.json`

```json
{
  "theme": "dark",
  "window_width": 1400,
  "window_height": 900,
  "update_interval": 1.0,
  "max_log_entries": 10000
}
```

### Default Attack Config

File: `default_config.json`

```json
{
  "target": "",
  "port": 80,
  "protocol": "TCP",
  "duration": 60,
  "threads": 4,
  "packet_size": 1024
}
```

---

## Keyboard Shortcuts

| Key    | Action         |
| ------ | -------------- |
| Ctrl+S | Start attack   |
| Ctrl+X | Stop attack    |
| Ctrl+E | Emergency stop |
| Ctrl+L | Clear logs     |
| Ctrl+Q | Quit           |

---

## Troubleshooting

### GUI Won't Start

```bash
# Check dearpygui installation
pip install --upgrade dearpygui

# Check Python version
python --version  # Must be 3.8+
```

### Slow Performance

- Reduce update interval in settings
- Lower thread count
- Close other applications

### Display Issues

- Update graphics drivers
- Try different theme
- Resize window

---

## Files

| File                  | Purpose                 |
| --------------------- | ----------------------- |
| `gui_main.py`         | Main GUI application    |
| `launch_gui.py`       | GUI launcher            |
| `gui_settings.json`   | GUI configuration       |
| `default_config.json` | Default attack settings |

---

## Legal Notice

For authorized security testing only.

---

**Version**: 1.0.0
