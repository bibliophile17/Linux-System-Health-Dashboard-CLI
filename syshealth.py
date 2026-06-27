"""
syshealth - Linux System Health Dashboard
A simple CLI tool to monitor your system's health at a glance.
"""

import psutil
import platform
import datetime
import time
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.progress import BarColumn, Progress, TextColumn
from rich import box
from rich.text import Text
from rich.live import Live
from rich.layout import Layout

console = Console()


def get_cpu_info():
    cpu_percent = psutil.cpu_percent(interval=1)
    cpu_count = psutil.cpu_count()
    cpu_freq = psutil.cpu_freq()
    freq_str = f"{cpu_freq.current:.0f} MHz" if cpu_freq else "N/A"
    return cpu_percent, cpu_count, freq_str


def get_memory_info():
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return mem, swap


def get_disk_info():
    partitions = []
    for part in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(part.mountpoint)
            partitions.append((part.mountpoint, usage))
        except PermissionError:
            continue
    return partitions


def get_network_info():
    net = psutil.net_io_counters()
    return net


def get_top_processes(n=5):
    procs = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            procs.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    procs = sorted(procs, key=lambda x: x['cpu_percent'] or 0, reverse=True)
    return procs[:n]


def bytes_to_human(n):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def color_for_percent(pct):
    if pct < 50:
        return "green"
    elif pct < 80:
        return "yellow"
    return "red"


def make_bar(pct, width=20):
    filled = int(width * pct / 100)
    bar = "█" * filled + "░" * (width - filled)
    color = color_for_percent(pct)
    return f"[{color}]{bar}[/{color}] {pct:.1f}%"


def render_dashboard():
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    uname = platform.uname()

    # Header 
    header = Text()
    header.append("⚡ syshealth", style="bold cyan")
    header.append(f"  •  {uname.node}", style="dim")
    header.append(f"  •  {uname.system} {uname.release}", style="dim")
    header.append(f"  •  {now}", style="dim")
    console.print(Panel(header, box=box.HORIZONTALS, padding=(0, 1)))

    # CPU 
    cpu_pct, cpu_count, freq = get_cpu_info()
    cpu_per_core = psutil.cpu_percent(percpu=True)

    cpu_table = Table(box=None, padding=(0, 1), show_header=False)
    cpu_table.add_column(width=12)
    cpu_table.add_column()

    cpu_table.add_row("[bold]Overall[/bold]", make_bar(cpu_pct))
    cpu_table.add_row("[dim]Cores[/dim]", f"[cyan]{cpu_count}[/cyan]")
    cpu_table.add_row("[dim]Frequency[/dim]", f"[cyan]{freq}[/cyan]")
    for i, core_pct in enumerate(cpu_per_core):
        cpu_table.add_row(f"[dim]Core {i}[/dim]", make_bar(core_pct))

    console.print(Panel(cpu_table, title="[bold cyan]CPU[/bold cyan]", box=box.ROUNDED))

    # Memory 
    mem, swap = get_memory_info()

    mem_table = Table(box=None, padding=(0, 1), show_header=False)
    mem_table.add_column(width=12)
    mem_table.add_column()

    mem_table.add_row("[bold]RAM[/bold]", make_bar(mem.percent))
    mem_table.add_row(
        "[dim]Used / Total[/dim]",
        f"[cyan]{bytes_to_human(mem.used)}[/cyan] / {bytes_to_human(mem.total)}"
    )
    mem_table.add_row(
        "[dim]Available[/dim]",
        f"[green]{bytes_to_human(mem.available)}[/green]"
    )
    mem_table.add_row("[bold]Swap[/bold]", make_bar(swap.percent))
    mem_table.add_row(
        "[dim]Used / Total[/dim]",
        f"[cyan]{bytes_to_human(swap.used)}[/cyan] / {bytes_to_human(swap.total)}"
    )

    console.print(Panel(mem_table, title="[bold cyan]Memory[/bold cyan]", box=box.ROUNDED))

    # Disk 
    disk_table = Table(box=box.SIMPLE, padding=(0, 1))
    disk_table.add_column("Mount", style="cyan", width=15)
    disk_table.add_column("Usage", width=30)
    disk_table.add_column("Used", justify="right")
    disk_table.add_column("Free", justify="right", style="green")
    disk_table.add_column("Total", justify="right")

    for mountpoint, usage in get_disk_info():
        disk_table.add_row(
            mountpoint,
            make_bar(usage.percent),
            bytes_to_human(usage.used),
            bytes_to_human(usage.free),
            bytes_to_human(usage.total),
        )

    console.print(Panel(disk_table, title="[bold cyan]Disk[/bold cyan]", box=box.ROUNDED))

    # Network
    net = get_network_info()
    net_table = Table(box=None, padding=(0, 1), show_header=False)
    net_table.add_column(width=18)
    net_table.add_column()
    net_table.add_row("[dim]Bytes Sent[/dim]", f"[cyan]{bytes_to_human(net.bytes_sent)}[/cyan]")
    net_table.add_row("[dim]Bytes Received[/dim]", f"[cyan]{bytes_to_human(net.bytes_recv)}[/cyan]")
    net_table.add_row("[dim]Packets Sent[/dim]", f"{net.packets_sent:,}")
    net_table.add_row("[dim]Packets Received[/dim]", f"{net.packets_recv:,}")

    console.print(Panel(net_table, title="[bold cyan]Network[/bold cyan]", box=box.ROUNDED))

    # Top Processes 
    proc_table = Table(box=box.SIMPLE, padding=(0, 1))
    proc_table.add_column("PID", style="dim", width=8)
    proc_table.add_column("Name", style="cyan", width=20)
    proc_table.add_column("CPU %", justify="right", width=10)
    proc_table.add_column("MEM %", justify="right", width=10)

    for proc in get_top_processes():
        cpu_p = proc['cpu_percent'] or 0
        mem_p = proc['memory_percent'] or 0
        proc_table.add_row(
            str(proc['pid']),
            proc['name'],
            f"[{color_for_percent(cpu_p)}]{cpu_p:.1f}[/{color_for_percent(cpu_p)}]",
            f"[{color_for_percent(mem_p)}]{mem_p:.1f}[/{color_for_percent(mem_p)}]",
        )

    console.print(Panel(proc_table, title="[bold cyan]Top Processes (by CPU)[/bold cyan]", box=box.ROUNDED))


# CLI Commands 

@click.group()
def cli():
    """⚡ syshealth — Linux System Health Dashboard"""
    pass


@cli.command()
def show():
    """Show a full system health snapshot."""
    render_dashboard()


@cli.command()
@click.option('--interval', '-i', default=5, help='Refresh interval in seconds (default: 5)')
def watch(interval):
    """Live-refresh the dashboard every N seconds. Press Ctrl+C to stop."""
    console.print(f"[dim]Refreshing every {interval}s — press Ctrl+C to stop[/dim]\n")
    try:
        while True:
            console.clear()
            render_dashboard()
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped.[/yellow]")


@cli.command()
def cpu():
    """Show CPU usage only."""
    cpu_pct, cpu_count, freq = get_cpu_info()
    per_core = psutil.cpu_percent(percpu=True)

    table = Table(box=None, padding=(0, 1), show_header=False)
    table.add_column(width=12)
    table.add_column()
    table.add_row("[bold]Overall[/bold]", make_bar(cpu_pct))
    table.add_row("[dim]Cores[/dim]", f"[cyan]{cpu_count}[/cyan]")
    table.add_row("[dim]Frequency[/dim]", f"[cyan]{freq}[/cyan]")
    for i, p in enumerate(per_core):
        table.add_row(f"[dim]Core {i}[/dim]", make_bar(p))

    console.print(Panel(table, title="[bold cyan]CPU[/bold cyan]", box=box.ROUNDED))


@cli.command()
def memory():
    """Show memory and swap usage only."""
    mem, swap = get_memory_info()

    table = Table(box=None, padding=(0, 1), show_header=False)
    table.add_column(width=18)
    table.add_column()
    table.add_row("[bold]RAM[/bold]", make_bar(mem.percent))
    table.add_row("[dim]Used / Total[/dim]",
                  f"[cyan]{bytes_to_human(mem.used)}[/cyan] / {bytes_to_human(mem.total)}")
    table.add_row("[dim]Available[/dim]", f"[green]{bytes_to_human(mem.available)}[/green]")
    table.add_row("[bold]Swap[/bold]", make_bar(swap.percent))
    table.add_row("[dim]Used / Total[/dim]",
                  f"[cyan]{bytes_to_human(swap.used)}[/cyan] / {bytes_to_human(swap.total)}")

    console.print(Panel(table, title="[bold cyan]Memory[/bold cyan]", box=box.ROUNDED))


@cli.command()
def disk():
    """Show disk usage for all mounted partitions."""
    table = Table(box=box.SIMPLE, padding=(0, 1))
    table.add_column("Mount", style="cyan", width=15)
    table.add_column("Usage", width=30)
    table.add_column("Used", justify="right")
    table.add_column("Free", justify="right", style="green")
    table.add_column("Total", justify="right")

    for mountpoint, usage in get_disk_info():
        table.add_row(
            mountpoint,
            make_bar(usage.percent),
            bytes_to_human(usage.used),
            bytes_to_human(usage.free),
            bytes_to_human(usage.total),
        )

    console.print(Panel(table, title="[bold cyan]Disk[/bold cyan]", box=box.ROUNDED))


@cli.command()
def network():
    """Show network I/O stats."""
    net = get_network_info()
    table = Table(box=None, padding=(0, 1), show_header=False)
    table.add_column(width=20)
    table.add_column()
    table.add_row("[dim]Bytes Sent[/dim]", f"[cyan]{bytes_to_human(net.bytes_sent)}[/cyan]")
    table.add_row("[dim]Bytes Received[/dim]", f"[cyan]{bytes_to_human(net.bytes_recv)}[/cyan]")
    table.add_row("[dim]Packets Sent[/dim]", f"{net.packets_sent:,}")
    table.add_row("[dim]Packets Received[/dim]", f"{net.packets_recv:,}")

    console.print(Panel(table, title="[bold cyan]Network[/bold cyan]", box=box.ROUNDED))


@cli.command()
@click.option('--count', '-n', default=10, help='Number of processes to show (default: 10)')
def processes(count):
    """Show top N processes by CPU usage."""
    table = Table(box=box.SIMPLE, padding=(0, 1))
    table.add_column("PID", style="dim", width=8)
    table.add_column("Name", style="cyan", width=25)
    table.add_column("CPU %", justify="right", width=10)
    table.add_column("MEM %", justify="right", width=10)

    for proc in get_top_processes(count):
        cpu_p = proc['cpu_percent'] or 0
        mem_p = proc['memory_percent'] or 0
        table.add_row(
            str(proc['pid']),
            proc['name'],
            f"[{color_for_percent(cpu_p)}]{cpu_p:.1f}[/{color_for_percent(cpu_p)}]",
            f"[{color_for_percent(mem_p)}]{mem_p:.1f}[/{color_for_percent(mem_p)}]",
        )

    console.print(Panel(table, title=f"[bold cyan]Top {count} Processes[/bold cyan]", box=box.ROUNDED))


if __name__ == '__main__':
    cli()
