# Optional monitoring: Prometheus exporter, Grafana dashboard, alert rules

Everything here is **optional**. The CLI (`show`, `check`, `diagnose`, `incident`, ...) works without Prometheus,
Grafana or Docker. All components are free and open source.

```
 /proc ──► syshealth exporter ──► Prometheus ──► Grafana
           (127.0.0.1:9877)        (127.0.0.1:9090)  (127.0.0.1:3000)
                                       └─► alert rules (alerts.yml)
```

## 1. The exporter

```bash
python3 -m syshealth exporter                 # http://127.0.0.1:9877/metrics
curl -s http://127.0.0.1:9877/metrics | head
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:9877/healthz     # 200 = fresh data, 503 = stale
```

Options: `--port`, `--refresh SEC` (background collection period, default 15), `--sample SEC` (rate window, default 1),
plus the same `--config`, `--warn` and `--crit` as the CLI so alert metrics follow your thresholds.
Stop with Ctrl+C or SIGTERM.

**How it stays cheap:** a background thread collects every `--refresh` seconds and caches the result. A scrape only
reads the cache, so scraping cannot add load to the host.

### Security model

- Binds to **loopback** by default; there is no authentication on a loopback bind.
- A non-loopback bind is refused unless you pass **both** `--allow-remote` and `--token-file FILE`:

  ```bash
  head -c 32 /dev/urandom | base64 > syshealth.token && chmod 600 syshealth.token
  python3 -m syshealth exporter --host 0.0.0.0 --allow-remote --token-file syshealth.token
  ```

  Clients must send `Authorization: Bearer <token>` (Prometheus: `authorization.credentials_file`, see
  `prometheus.yml`). The token is read from a file so it never appears in the process list. The token travels in
  clear text over HTTP: use a firewall, a VPN, or a TLS-terminating proxy for anything beyond a trusted network.
- Only `GET /metrics` and `GET /healthz` exist. No query parameters are interpreted.
- Metrics contain no per-process labels (no pid, name or command line).

### Metrics

| Metric | Type | Labels |
|---|---|---|
| `syshealth_cpu_utilization_ratio` | gauge | |
| `syshealth_cpu_count`, `syshealth_uptime_seconds`, `syshealth_processes` | gauge | |
| `syshealth_load_average` | gauge | `period` (1m, 5m, 15m) |
| `syshealth_memory_total_bytes`, `_available_bytes`, `_utilization_ratio` | gauge | |
| `syshealth_swap_total_bytes`, `syshealth_swap_utilization_ratio` | gauge | |
| `syshealth_filesystem_utilization_ratio`, `_size_bytes`, `_available_bytes` | gauge | `mountpoint`, `fstype` |
| `syshealth_network_{receive,transmit}_{bytes,errors,drops}_total` | counter | `device` |
| `syshealth_alerts_active` | gauge | `severity` |
| `syshealth_alert_active` | gauge | `metric`, `target`, `severity` |
| `syshealth_metric_unavailable` | gauge | `metric` |
| `syshealth_collection_errors_total` | counter | |
| `syshealth_last_collection_timestamp_seconds`, `syshealth_collection_duration_seconds` | gauge | |
| `syshealth_build_info` | gauge | `version` |

A metric that could not be read is **omitted**, never exported as 0; `syshealth_metric_unavailable` says which.
Mountpoints and network devices are capped at 64 series each.

## 2. Prometheus (without Docker)

Install Prometheus OSS from your distribution (`sudo apt install prometheus` on Ubuntu) or from the official
release tarball, then use the shipped files:

```bash
promtool check config monitoring/prometheus/prometheus.yml     # if promtool is installed
promtool check rules  monitoring/prometheus/alerts.yml
prometheus --config.file=monitoring/prometheus/prometheus.yml \
           --web.listen-address=127.0.0.1:9090 --storage.tsdb.path=./prom-data
```

- `prometheus.yml`: scrape job for `127.0.0.1:9877` (and a commented Node Exporter job for deeper host metrics).
- `alerts.yml`: rules for exporter down/stale/erroring, high CPU and memory, filesystems nearly full or filling fast,
  interface errors, and any critical syshealth alert. Thresholds are starting points; tune them.

## 3. Grafana

Install Grafana OSS from the official packages, open `http://127.0.0.1:3000`, add a Prometheus data source at
`http://127.0.0.1:9090`, then **Dashboards → Import → Upload JSON file** and choose
`monitoring/grafana/syshealth-dashboard.json`. Pick the data source in the dashboard's *Data source* dropdown.

## 4. Prometheus + Grafana in Docker (optional)

`docker-compose.yml` runs both on loopback with host networking (Linux), so Prometheus can reach the exporter on the
host's `127.0.0.1`. Grafana is provisioned automatically with the data source and the dashboard. There is no default
password: it must be supplied.

```bash
python3 -m syshealth exporter &                                    # on the host
export GRAFANA_ADMIN_PASSWORD='choose-a-strong-one'
docker compose -f monitoring/docker-compose.yml up -d
# Prometheus: http://127.0.0.1:9090   Grafana: http://127.0.0.1:3000
```

## 5. Run the exporter as a service (optional, systemd)

`syshealth-exporter.service` is a hardened unit (dynamic unprivileged user, read-only filesystem, loopback only).
Adjust `ExecStart` to where syshealth is installed.

```bash
sudo cp monitoring/syshealth-exporter.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now syshealth-exporter
journalctl -u syshealth-exporter -n 20 --no-pager
```

## 6. Cleanup

```bash
# Docker stack: stop and delete containers AND stored data (volumes)
docker compose -f monitoring/docker-compose.yml down -v
# systemd service
sudo systemctl disable --now syshealth-exporter && sudo rm /etc/systemd/system/syshealth-exporter.service
sudo systemctl daemon-reload
# plain exporter: Ctrl+C (or kill the process); local Prometheus data: rm -r ./prom-data
```

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `refusing to bind to non-loopback address` | By design; see the security model above. |
| `cannot listen on 127.0.0.1:9877` | Port in use; choose another with `--port` and update `prometheus.yml`. |
| `/metrics` returns 503 | The first collection failed; check that `/proc` is readable. It recovers on its own. |
| Target `DOWN` in Prometheus (Docker) | Host networking is Linux-only; on Docker Desktop use `host.docker.internal` as the target. |
| `/healthz` returns 503 | No successful collection within about three refresh periods. |

## Limitations

- Cumulative network counters reset on reboot or driver reload, as with any `/proc/net/dev` source.
- No TLS; the bearer token protects access, not confidentiality (see the security model).
- The alert rules, dashboard and compose file are validated structurally and for consistency with the exporter's
  metric names, but see the README for what has not been run against real Prometheus and Grafana instances.
