# SOSreport Analyzer V7

A **Streamlit web application** that analyzes Linux SOSreport archives — parsing SAR performance metrics and system logs, detecting critical events, and pushing everything to **InfluxDB + Loki + Grafana** for interactive visualization.

Upload a `.tar.gz` / `.tar.xz` SOSreport and get instant analysis with auto-generated Grafana dashboards.

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Streamlit   │────▶│  InfluxDB    │────▶│   Grafana    │
│  Web App     │     │  (SAR data)  │     │  Dashboards  │
│  :8501       │     │  :8086       │     │  :3000       │
│              │────▶│  Loki        │────▶│              │
│              │     │  (Logs)      │     │              │
│              │     │  :3100       │     │              │
└──────────────┘     └──────────────┘     └──────────────┘
```

## Features

### Analysis
- **SAR Metrics Parsing** — CPU, memory, disk I/O, network, load, hugepages, NFS, sockets, context switches
- **Log Parsing** — messages, syslog, secure, audit, dmesg, journalctl, kern, boot, maillog, yum/dnf
- **Critical Event Detection** — 40+ regex patterns across 7 categories (disk, OOM, kernel panic, network, security, service, hardware)
- **Severity Classification** — Events classified as critical/warning/info with noise filtering
- **Performance Anomaly Detection** — Peaks, sustained high usage, IOWait spikes
- **Timestamp Correlation** — Maps critical events to SAR metrics in ±5 min windows
- **Patch Compliance Check** — Kernel age, security advisories, CVE extraction
- **Crash Dump Discovery** — vmcore-dmesg analysis
- **Cloud Provider Detection** — Azure/AWS/GCP/Oracle with provider-specific metadata
- **OS Flavor Detection** — RHEL, Oracle Linux, SUSE, Ubuntu with per-distro kernel analysis

### Performance (V7 Optimizations)
- **Parallel SAR + Log parsing** — Runs concurrently (Step 7)
- **Streaming file reads** — Generator-based, avoids loading entire files into memory (Step 8)
- **Pre-compiled regex** — Single mega-regex pre-filter rejects 99%+ of lines instantly (Step 9)
- **Multiprocessing for regex** — ProcessPoolExecutor bypasses GIL for large log sets (Step 10)
- **Batched data push** — 10K batches, gzip compression, session pooling, retry with backoff
- **ThreadPoolExecutor I/O** — Up to 8 workers for parallel log file decompression

### Data Pipeline
- **InfluxDB** — SAR time-series metrics with per-host tagging
- **Loki** — Structured log storage with labels (host, source, program, severity)
- **Grafana** — Auto-generated dashboards with CPU, memory, disk, network, load panels + log integration
- **Cleanup on re-upload** — Deletes old InfluxDB + Loki data before pushing to avoid stale data

## Prerequisites

- **Python 3.8+**
- **Docker Desktop** (for InfluxDB, Loki, Grafana)

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/madamshafie_microsoft/sar_analyzer.git
cd sar_analyzer
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your actual tokens
```

### 3. Start backend services

```bash
docker-compose up -d
```

This starts:
| Service | Port | Purpose |
|---------|------|---------|
| **InfluxDB** | 8086 | SAR time-series storage |
| **Loki** | 3100 | Log aggregation |
| **Grafana** | 3000 | Dashboards & visualization |

### 4. Run the web app

```bash
streamlit run streamlit_app_v7.local.py --server.port 8501
```

Open **http://localhost:8501** and upload a SOSreport archive.

## Configuration

All secrets are stored in `.env` (not committed to git):

```env
# InfluxDB
INFLUXDB_URL=http://localhost:8086
INFLUXDB_TOKEN=your-influxdb-token
INFLUXDB_ORG_ID=your-org-id
INFLUXDB_BUCKET=sar_metrics

# Loki
LOKI_URL=http://localhost:3100

# Grafana
GRAFANA_URL=http://localhost:3000
GRAFANA_API_KEY=your-grafana-api-key
```

See [.env.example](.env.example) for the template.

## Files

| File | Description |
|------|-------------|
| `streamlit_app_v7.local.py` | **Main app** — local Docker version |
| `streamlit_app_v7.py` | Remote/cloud version (Azure endpoints) |
| `docker-compose.yml` | InfluxDB + Loki + Grafana stack |
| `loki-config.yaml` | Loki configuration (retention, ingestion, delete API) |
| `.env.example` | Environment variable template |
| `requirements.txt` | Python dependencies |
| `streamlit_app_v[1-6].py` | Legacy versions (kept for reference) |

## SOSreport File Locations

The tool searches for data in these paths within the extracted SOSreport:

**SAR data:**
- `sos_commands/sar/*`
- `var/log/sa/*` (binary sa files + XML)

**Log files:**
- `var/log/messages*`, `var/log/syslog*`, `var/log/secure*`
- `var/log/audit/audit.log*`
- `var/log/kern.log*`, `var/log/boot.log`, `var/log/cron*`
- `var/log/yum.log`, `var/log/dnf.log`
- `sos_commands/kernel/dmesg*`
- `sos_commands/logs/journalctl*`

## Grafana

After uploading a SOSreport, a Grafana dashboard is auto-created at:

```
http://localhost:3000/d/web-<hostname>/
```

Panels include: CPU usage (stacked), memory, disk I/O, network, load average, system logs (via Loki).

## Troubleshooting

| Problem | Solution |
|---------|----------|
| No SAR files found | Ensure SOSreport is a valid `.tar.gz`/`.tar.xz` |
| InfluxDB connection refused | Run `docker-compose up -d` and check port 8086 |
| Loki "entry too far behind" | App auto-cleans old data; restart Loki if persists |
| Grafana 401 Unauthorized | Regenerate API key in Grafana → Service Accounts |
| Slow parsing (>10 min) | Normal for 70MB+ sosreports; V7 optimizations help |

## License

MIT License
