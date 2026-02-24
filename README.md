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

- **Python 3.8+** (only when running outside Docker)
- **Docker Engine** — via Docker Desktop **or** WSL2 (see below)

---

## Quick Start — One-Command Docker Bundle (Recommended)

Everything (Streamlit app + InfluxDB + Loki + Grafana) runs inside Docker.
No Python install needed on the host.

### Option A: Windows with WSL2 (no Docker Desktop required)

1. **Ensure WSL2 is enabled** (one-time):
   ```powershell
   wsl --install          # installs Ubuntu by default
   wsl --set-default-version 2
   ```
2. **Clone the repo** (in Windows or inside WSL):
   ```bash
   git clone https://github.com/mdadamshafie/sar_analyzer.git
   ```
3. **Double-click `start.bat`** — or run from PowerShell:
   ```powershell
   .\start.ps1
   ```
   This will:
   - Install Docker Engine inside WSL (if not already present)
   - Build the Streamlit app image
   - Start all four services
   - Open your browser at **http://localhost:8501**

### Option B: Linux / macOS (or WSL shell directly)

```bash
git clone https://github.com/mdadamshafie/sar_analyzer.git
cd sar_analyzer
chmod +x setup.sh
./setup.sh
```

### Option C: Already have Docker Desktop?

```bash
docker compose -f docker-compose.all.yml up --build -d
```

### Services

| Service | Port | Purpose |
|---------|------|---------|
| **Streamlit App** | 8501 | SOSreport upload & analysis |
| **InfluxDB** | 8086 | SAR time-series storage |
| **Loki** | 3100 | Log aggregation |
| **Grafana** | 3000 | Dashboards & visualization |

### Common commands

```bash
# View logs
docker compose -f docker-compose.all.yml logs -f app

# Stop everything
docker compose -f docker-compose.all.yml down

# Stop + wipe all data volumes
docker compose -f docker-compose.all.yml down -v

# Rebuild after code changes
docker compose -f docker-compose.all.yml up --build -d
```

---

## Quick Start — Manual (Development)

If you prefer running the Streamlit app outside Docker (hot-reload, debugging):

### 1. Clone and install

```bash
git clone https://github.com/mdadamshafie/sar_analyzer.git
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

This starts InfluxDB (8086), Loki (3100), and Grafana (3000).

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
INFLUXDB_ORG=sosanalyzer
INFLUXDB_ORG_ID=your-org-id
INFLUXDB_BUCKET=sar_metrics

# Loki
LOKI_URL=http://localhost:3100

# Grafana
GRAFANA_URL=http://localhost:3000
GRAFANA_API_KEY=your-grafana-api-key
```

See [.env.example](.env.example) for the template.

> **Note:** If you used the Docker bundle (`docker-compose.all.yml`), the token, org, and bucket are pre-configured automatically — you only need the steps below if you changed the defaults or are running a standalone InfluxDB/Grafana.

### How to get the InfluxDB Token

1. Open InfluxDB UI: **http://localhost:8086**
2. Log in with `admin` / `sosreport2026` (the default from docker-compose)
3. Go to **Load Data → API Tokens** (left sidebar → the upward arrow icon)
4. You will see a token named **admin's Token** — click on it to reveal the full token string
5. Copy the token and paste it into your `.env` as `INFLUXDB_TOKEN`

> The Docker bundle auto-creates the token `local-sosreport-token-2026`. If you haven't changed anything, use that value.

### How to get the InfluxDB Org ID

1. Open InfluxDB UI: **http://localhost:8086**
2. Log in, then click your **user avatar** (bottom-left corner) → **About**
3. The **Organization ID** is displayed (a 16-character hex string like `9cc27eb671d7c96a`)
4. Copy it into your `.env` as `INFLUXDB_ORG_ID`

Alternatively, use the API:
```bash
curl -s http://localhost:8086/api/v2/orgs \
  -H "Authorization: Token local-sosreport-token-2026" \
  | python -m json.tool
```
Look for the `"id"` field in the response.

### How to get the InfluxDB Bucket

1. Open InfluxDB UI: **http://localhost:8086**
2. Go to **Load Data → Buckets**
3. The default bucket created by docker-compose is `sar_metrics`
4. Use this name as `INFLUXDB_BUCKET` in your `.env`

> You can create a custom bucket here if needed — just update the `.env` to match.

### How to get the Grafana API Key

1. Open Grafana: **http://localhost:3000**
2. Log in with `admin` / `sosreport2026`
3. Go to **Administration → Service Accounts** (left sidebar → gear icon → Service Accounts)
4. Click **Add service account**
   - Name: `sosreport-analyzer`
   - Role: **Admin**
5. Click **Create**
6. On the service account page, click **Add service account token**
   - Name: `sar-token`
   - Expiration: set as desired (or **No expiration**)
7. Click **Generate token**
8. **Copy the token immediately** (it starts with `glsa_...`) — it won't be shown again
9. Paste it into your `.env` as `GRAFANA_API_KEY`

> The API key is needed for auto-creating dashboards. Without it, the app still works for SAR/log analysis — you just won't get auto-generated Grafana dashboards.

## Files

| File | Description |
|------|-------------|
| `streamlit_app_v7.local.py` | **Main app** — local Docker version |
| `streamlit_app_v7.py` | Remote/cloud version (Azure endpoints) |
| `docker-compose.all.yml` | **Full bundle** — App + InfluxDB + Loki + Grafana |
| `docker-compose.yml` | Backend only — InfluxDB + Loki + Grafana (dev mode) |
| `Dockerfile` | Streamlit app container image |
| `setup.sh` | WSL2 / Linux bootstrap (installs Docker, builds, starts) |
| `start.bat` | Windows launcher (calls WSL) |
| `start.ps1` | Windows launcher (PowerShell version) |
| `loki-config.yaml` | Loki configuration (retention, ingestion, delete API) |
| `grafana/provisioning/` | Auto-provisioned Grafana datasources |
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
