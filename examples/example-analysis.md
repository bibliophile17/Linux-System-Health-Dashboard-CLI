# Example analysis output (synthetic data, not from a real host)

### mem-02: OOM kill takes down a service (cause and consequence)
(synthetic case; injected condition: Memory exhaustion triggers the kernel OOM killer, which kills the order gateway.)

```
== Incident analysis (rule-based/v1 (deterministic)) ==
  status: diagnosed
  Best-supported explanation: Memory pressure (strong evidence).
  1. Memory pressure - strong evidence, 9 pts   [HYPOTHESIS]
       Supporting observations:
         - RAM used 97.0% (15.5 GiB of 16.0 GiB, 491.5 MiB available; warn 85, crit 95)
         - swap used 95.0% (3.8 GiB of 4.0 GiB)
         - memory pressure (PSI, last 10 s): some 45.0%, full 30.0% of time stalled
         - OOM-killer invocations since boot: 4
         - failed systemd units: 1
         - top memory process: java_pricing (pid 2210) 55.0% of RAM
       Next steps (read-only, run by you):
         $ free -h
         $ ps -eo pid,comm,rss --sort=-rss | head -10
         $ cat /proc/pressure/memory
         $ dmesg | grep -i 'out of memory'   # may need privileges
         $ vmstat 1 5
  2. Service/process failure - moderate evidence, 4 pts (consequence of Memory pressure)   [HYPOTHESIS]
       Supporting observations:
         - failed systemd units: 1
         - OOM-killer invocations since boot: 4
       Missing evidence:
         - The OOM counter is cumulative and untimestamped: a link to these failures is not established.
       Next steps (read-only, run by you):
         $ systemctl --failed
         $ systemctl status order-gateway.service --no-pager
         $ journalctl -u order-gateway.service -n 50 --no-pager
  Uncertainties:
    - Based on a single ~1s sampling window; intermittent problems can be missed.
    - Memory pressure: A leak versus a legitimately large working set cannot be distinguished from one snapshot.
    - Service/process failure: The exit code, signal and reason for the failure are not captured.
    - Service/process failure: The OOM counter is cumulative and untimestamped: a link to these failures is not established.
    - Service/process failure is treated as a consequence of Memory pressure; this is inferred from co-occurrence, not proven.
  Causes are ranked hypotheses derived from evidence strength, not established root causes. Confidence is an evidence-strength label, not a probability. No commands are executed.
```

### h-load-unexplained: Load high but no resource explains it
(synthetic case; injected condition: Tasks blocked on a lock or throttled by a cgroup: load is high while CPU, I/O and memory are quiet.)

```
== Incident analysis (rule-based/v1 (deterministic)) ==
  status: inconclusive
  Inconclusive: the evidence is weak or conflicting. Weakest hypotheses only: High load with no resource explanation (weak).
  1. High load with no resource explanation - weak evidence, 1 pts   [HYPOTHESIS]
       Supporting observations:
         - 1-min load average 7.00 on 4 CPUs = 1.75 per CPU (warn 1, crit 2)
       Contradicting evidence:
         - CPU busy 11.0% averaged over 1.0s (warn 80, crit 95) -- CPU is not busy, so the load is not CPU-bound
       Missing evidence:
         - No CPU, memory or I/O stall pressure was observed to explain the load.
       Next steps (read-only, run by you):
         $ ps -eo pid,stat,wchan:20,comm | awk '$2 ~ /D/'
         $ cat /proc/pressure/cpu
         $ cat /sys/fs/cgroup/cpu.stat
         $ vmstat 1 5
  Uncertainties:
    - Based on a single ~1s sampling window; intermittent problems can be missed.
    - High load with no resource explanation: Blocked tasks, lock contention and cgroup throttling are not observable by these checks (the load figure alone does not say what the tasks are waiting for).
    - High load with no resource explanation: No CPU, memory or I/O stall pressure was observed to explain the load.
    - High load with no resource explanation: the evidence is weak; this is a hypothesis to check, not a finding.
  Causes are ranked hypotheses derived from evidence strength, not established root causes. Confidence is an evidence-strength label, not a probability. No commands are executed.
```
