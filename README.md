# ⚡ syshealth — Linux System Health Dashboard

A lightweight, terminal-based system monitoring tool built with Python.
Monitor CPU, memory, disk, network, and processes — all from the command line.

---

## Features

- **CPU** — overall usage, per-core breakdown, frequency
- **Memory** — RAM and swap with usage bars
- **Disk** — all mounted partitions with used/free/total
- **Network** — bytes and packets sent/received
- **Processes** — top N processes sorted by CPU usage
- **Live mode** — auto-refresh dashboard every N seconds
- Color-coded bars: 🟢 healthy → 🟡 moderate → 🔴 high

---

## Installation

**1. Clone the repo**

```bash
git clone https://github.com/yourusername/syshealth.git
cd syshealth
```

**2. Install dependencies**

```bash
pip install -r requirements.txt
```

That's it. No root access needed.

---

## Usage

### Full dashboard snapshot

```bash
python syshealth.py show
```

### Live auto-refresh (every 5 seconds)

```bash
python syshealth.py watch
```

### Live refresh with custom interval (e.g. every 2 seconds)

```bash
python syshealth.py watch --interval 2
```

### Individual sections

```bash
python syshealth.py cpu
python syshealth.py memory
python syshealth.py disk
python syshealth.py network
python syshealth.py processes
```

### Show top 15 processes

```bash
python syshealth.py processes --count 15
```

### Help

```bash
python syshealth.py --help
python syshealth.py watch --help
```

---

## Requirements

- Python 3.8+
- Linux / macOS (works on Windows too, some metrics may differ)
- Libraries: `psutil`, `rich`, `click`

---

## Project Structure

```
syshealth/
├── syshealth.py      # Main CLI tool
├── requirements.txt  # Dependencies
└── README.md         # This file
```

---

## Tech Stack

| Library  | Purpose                                                     |
| -------- | ----------------------------------------------------------- |
| `psutil` | Read system metrics (CPU, memory, disk, network, processes) |
| `rich`   | Beautiful terminal UI (tables, panels, color bars)          |
| `click`  | CLI commands and options                                    |

---

## Why I built this

A practical learning project to explore Linux system internals, CLI design, and Python tooling — inspired by tools like `htop` and `glances`.

---
