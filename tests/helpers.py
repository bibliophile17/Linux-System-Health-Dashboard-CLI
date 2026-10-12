"""Synthetic snapshots so alert/CLI tests are deterministic and need no /proc."""
from syshealth.collectors import DiskUsage, Memory, NetIface, ProcInfo, Snapshot
from syshealth.evidence import DiskIORate, Evidence, Listener, Pressure, SocketSummary

T0 = 1_800_000_000.0  # fixed epoch -> reproducible timestamps


def make_snap(cpu=10.0, mem=20.0, swap=None, disks=None, load1=0.1, cores=2, procs=100, ts=T0):
    """Pass None for a metric to simulate it being unreadable."""
    memory = None if mem is None and swap is None else Memory(
        total=1000, available=None if mem is None else int(1000 * (100 - mem) / 100),
        used=None if mem is None else int(1000 * mem / 100), percent=mem,
        swap_total=0 if swap is None else 1000, swap_used=None if swap is None else int(10 * swap),
        swap_percent=swap)
    if disks is None:
        disk_list = [DiskUsage("/", "ext4", 100, 30, 70, 30.0)]
    elif disks == "unreadable":
        disk_list = None
    else:
        disk_list = [DiskUsage(m, "ext4", 100, int(p), 100 - int(p), float(p)) for m, p in disks.items()]
    snap = Snapshot(
        timestamp=ts, hostname="testhost", kernel="Linux 0", interval=1.0,
        cpu_percent=cpu, cpu_per_core=[cpu] * cores if cpu is not None else [None] * cores,
        cpu_count=cores, loadavg=None if load1 is None else (load1, load1, load1),
        uptime_seconds=1000.0, memory=memory, disks=disk_list, network=[], process_count=procs)
    if cpu is None and mem is None and procs is None:
        snap.unavailable.append("everything")
    return snap


# ---- evidence ---------------------------------------------------------------

def make_evidence(snap_kw=None, diskio="quiet", sockets="quiet", pressure=None, oom=0, failed=(),
                  net=None, net_deltas="quiet", commands_run=True, top_cpu=None, top_mem=None):
    """Healthy evidence by default; override pieces to trigger rules. None = unreadable."""
    snap = make_snap(**(snap_kw or {}))
    snap.top_cpu = top_cpu or []
    snap.top_mem = top_mem or []
    snap.network = [NetIface("eth0", 1, 1, 0, 0, 1, 1, 0, 0)] if net is None else (None if net == "unreadable" else net)
    if diskio == "quiet":
        diskio = [DiskIORate("sda", 5.0, 1e6, 1e6, 100.0, 0.5)]
    if sockets == "quiet":
        sockets = SocketSummary([Listener("127.0.0.1", 8080), Listener("0.0.0.0", 22)], {"LISTEN": 2, "ESTABLISHED": 5})
    if net_deltas == "quiet":
        net_deltas = {"eth0": {"errors": 0, "drops": 0}}
    return Evidence(snap, diskio, sockets, pressure, oom, None if failed is None else list(failed),
                    net_deltas, commands_run)


def proc(pid, name, cpu, mem):
    return ProcInfo(pid, name, cpu, mem)


def everything_bad():
    """Triggers every rule at least once."""
    return make_evidence(
        snap_kw=dict(cpu=97.0, mem=97.0, swap=90.0, disks={"/": 95}, load1=6.0, cores=2, procs=9000),
        diskio=[DiskIORate("sda", 97.0, 5e7, 5e7, 9000.0, 80.0)],
        sockets=SocketSummary([Listener("0.0.0.0", 80)], {"CLOSE_WAIT": 500, "TIME_WAIT": 9000, "SYN_RECV": 300}),
        pressure={"cpu": Pressure(40.0, None), "memory": Pressure(35.0, 20.0), "io": Pressure(50.0, 30.0)},
        oom=3, failed=["nginx.service", "weird name.service"],
        net=[NetIface("eth0", 1, 1, 5, 9, 1, 1, 0, 0)], net_deltas={"eth0": {"errors": 5, "drops": 9}},
        top_cpu=[proc(10, "hog", 180.0, 1.0)], top_mem=[proc(11, "bigmem", 5.0, 60.0)])
