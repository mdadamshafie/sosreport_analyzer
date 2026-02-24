"""
Combined SOSreport Dashboard Generator
Creates a unified Grafana dashboard with SAR metrics and Log analysis
"""

import re
import json
import requests
import argparse

# ============================================================================
# CONFIGURATION
# ============================================================================
INFLUXDB_URL = "http://localhost:8086"
INFLUXDB_ORG = "889b684a77fa68d6"
INFLUXDB_BUCKET = "sar_metrics"

LOKI_URL = "http://localhost:3100"

GRAFANA_URL = "http://localhost:3000"
GRAFANA_API_KEY = "YOUR_GRAFANA_API_KEY"
# ============================================================================


def get_datasource_uids() -> dict:
    """Get UIDs for InfluxDB and Loki datasources"""
    session = requests.Session()
    session.headers['Authorization'] = f'Bearer {GRAFANA_API_KEY}'
    
    response = session.get(f"{GRAFANA_URL}/api/datasources")
    
    uids = {"influxdb": None, "loki": None}
    
    if response.status_code == 200:
        for ds in response.json():
            if ds.get('type') == 'influxdb':
                uids['influxdb'] = ds.get('uid')
                print(f"Found InfluxDB datasource: {ds.get('name')} (uid: {uids['influxdb']})")
            elif ds.get('type') == 'loki':
                uids['loki'] = ds.get('uid')
                print(f"Found Loki datasource: {ds.get('name')} (uid: {uids['loki']})")
    
    return uids


def create_combined_dashboard(hostname: str, influx_uid: str, loki_uid: str) -> dict:
    """Create a combined SAR + Logs dashboard"""
    
    safe_host = re.sub(r'[^a-zA-Z0-9_-]', '-', hostname)[:36]
    
    panels = []
    panel_id = 1
    y_pos = 0
    
    # ========================================================================
    # SECTION 1: SAR METRICS (from InfluxDB)
    # ========================================================================
    
    # Row: SAR Metrics Header
    panels.append({
        "gridPos": {"h": 1, "w": 24, "x": 0, "y": y_pos},
        "id": panel_id,
        "title": "ðŸ“Š SAR Performance Metrics",
        "type": "row",
        "collapsed": False
    })
    panel_id += 1
    y_pos += 1
    
    # CPU Load Average (1, 5, 15 min)
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "palette-classic"},
                "custom": {"lineWidth": 2, "fillOpacity": 10},
                "unit": "short"
            },
            "overrides": []
        },
        "gridPos": {"h": 6, "w": 12, "x": 0, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        "targets": [{
            "datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'''from(bucket: "{INFLUXDB_BUCKET}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "sar_load")
  |> filter(fn: (r) => r["host"] == "{hostname}")
  |> filter(fn: (r) => r["_field"] == "ldavg_1" or r["_field"] == "ldavg_5" or r["_field"] == "ldavg_15")''',
            "refId": "A"
        }],
        "title": "CPU Load Average",
        "type": "timeseries"
    })
    panel_id += 1
    
    # Run Queue Size & Blocked Processes
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "palette-classic"},
                "custom": {"lineWidth": 2, "fillOpacity": 10},
                "unit": "short"
            },
            "overrides": []
        },
        "gridPos": {"h": 6, "w": 12, "x": 12, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        "targets": [{
            "datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'''from(bucket: "{INFLUXDB_BUCKET}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "sar_load")
  |> filter(fn: (r) => r["host"] == "{hostname}")
  |> filter(fn: (r) => r["_field"] == "runq_sz" or r["_field"] == "blocked" or r["_field"] == "plist_sz")''',
            "refId": "A"
        }],
        "title": "Run Queue & Blocked Processes",
        "type": "timeseries"
    })
    panel_id += 1
    y_pos += 6
    
    # Memory Usage %
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "palette-classic"},
                "custom": {"lineWidth": 2, "fillOpacity": 10},
                "unit": "percent",
                "max": 100
            },
            "overrides": []
        },
        "gridPos": {"h": 6, "w": 12, "x": 0, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        "targets": [{
            "datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'''from(bucket: "{INFLUXDB_BUCKET}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "sar_memory")
  |> filter(fn: (r) => r["host"] == "{hostname}")
  |> filter(fn: (r) => r["_field"] == "pct_memused" or r["_field"] == "pct_commit")''',
            "refId": "A"
        }],
        "title": "Memory Usage (%)",
        "type": "timeseries"
    })
    panel_id += 1
    
    # Memory (KB)
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "palette-classic"},
                "custom": {"lineWidth": 2, "fillOpacity": 10},
                "unit": "deckbytes"
            },
            "overrides": []
        },
        "gridPos": {"h": 6, "w": 12, "x": 12, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        "targets": [{
            "datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'''from(bucket: "{INFLUXDB_BUCKET}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "sar_memory")
  |> filter(fn: (r) => r["host"] == "{hostname}")
  |> filter(fn: (r) => r["_field"] == "kbmemused" or r["_field"] == "kbmemfree" or r["_field"] == "kbcached" or r["_field"] == "kbbuffers")''',
            "refId": "A"
        }],
        "title": "Memory (Used/Free/Cached/Buffers)",
        "type": "timeseries"
    })
    panel_id += 1
    y_pos += 6
    
    # Disk I/O (KB/s)
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "palette-classic"},
                "custom": {"lineWidth": 2, "fillOpacity": 10},
                "unit": "KBs"
            },
            "overrides": []
        },
        "gridPos": {"h": 6, "w": 12, "x": 0, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        "targets": [{
            "datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'''from(bucket: "{INFLUXDB_BUCKET}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "sar_disk")
  |> filter(fn: (r) => r["host"] == "{hostname}")
  |> filter(fn: (r) => r["_field"] == "rkB/s" or r["_field"] == "wkB/s")''',
            "refId": "A"
        }],
        "title": "Disk I/O (KB/s)",
        "type": "timeseries"
    })
    panel_id += 1
    
    # Disk Utilization %
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "palette-classic"},
                "custom": {"lineWidth": 2, "fillOpacity": 10},
                "unit": "percent",
                "max": 100
            },
            "overrides": []
        },
        "gridPos": {"h": 6, "w": 12, "x": 12, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        "targets": [{
            "datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'''from(bucket: "{INFLUXDB_BUCKET}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "sar_disk")
  |> filter(fn: (r) => r["host"] == "{hostname}")
  |> filter(fn: (r) => r["_field"] == "%util")''',
            "refId": "A"
        }],
        "title": "Disk Utilization (%)",
        "type": "timeseries"
    })
    panel_id += 1
    y_pos += 6
    
    # Network I/O
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "palette-classic"},
                "custom": {"lineWidth": 2, "fillOpacity": 10},
                "unit": "KBs"
            },
            "overrides": []
        },
        "gridPos": {"h": 6, "w": 24, "x": 0, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        "targets": [{
            "datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'''from(bucket: "{INFLUXDB_BUCKET}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "sar_network")
  |> filter(fn: (r) => r["host"] == "{hostname}")
  |> filter(fn: (r) => r["_field"] == "rxkB_s" or r["_field"] == "txkB_s")''',
            "refId": "A"
        }],
        "title": "Network I/O (KB/s)",
        "type": "timeseries"
    })
    panel_id += 1
    y_pos += 6
    
    # ========================================================================
    # SECTION 2: LOG ANALYSIS (from Loki)
    # ========================================================================
    
    # Row: Log Analysis Header
    panels.append({
        "gridPos": {"h": 1, "w": 24, "x": 0, "y": y_pos},
        "id": panel_id,
        "title": "ðŸ“‹ Log Analysis",
        "type": "row",
        "collapsed": False
    })
    panel_id += 1
    y_pos += 1
    
    # Log Volume Graph
    panels.append({
        "datasource": {"type": "loki", "uid": loki_uid},
        "fieldConfig": {
            "defaults": {"color": {"mode": "palette-classic"}},
            "overrides": []
        },
        "gridPos": {"h": 5, "w": 24, "x": 0, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "right"}},
        "targets": [{
            "datasource": {"type": "loki", "uid": loki_uid},
            "expr": f'sum by (source) (count_over_time({{host="{hostname}"}}[1h]))',
            "refId": "A"
        }],
        "title": "Log Volume by Source (per hour)",
        "type": "timeseries"
    })
    panel_id += 1
    y_pos += 5
    
    # System Messages
    panels.append({
        "datasource": {"type": "loki", "uid": loki_uid},
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": y_pos},
        "id": panel_id,
        "options": {
            "dedupStrategy": "none",
            "enableLogDetails": True,
            "showTime": True,
            "sortOrder": "Descending",
            "wrapLogMessage": True
        },
        "targets": [{
            "datasource": {"type": "loki", "uid": loki_uid},
            "expr": f'{{host="{hostname}", source="messages"}}',
            "refId": "A"
        }],
        "title": "ðŸ“„ System Messages (/var/log/messages)",
        "type": "logs"
    })
    panel_id += 1
    y_pos += 8
    
    # Security/Auth Logs
    panels.append({
        "datasource": {"type": "loki", "uid": loki_uid},
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": y_pos},
        "id": panel_id,
        "options": {
            "dedupStrategy": "none",
            "enableLogDetails": True,
            "showTime": True,
            "sortOrder": "Descending",
            "wrapLogMessage": True
        },
        "targets": [{
            "datasource": {"type": "loki", "uid": loki_uid},
            "expr": f'{{host="{hostname}", source="secure"}}',
            "refId": "A"
        }],
        "title": "ðŸ” Security/Auth Logs (/var/log/secure)",
        "type": "logs"
    })
    panel_id += 1
    y_pos += 8
    
    # Audit Logs
    panels.append({
        "datasource": {"type": "loki", "uid": loki_uid},
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": y_pos},
        "id": panel_id,
        "options": {
            "dedupStrategy": "none",
            "enableLogDetails": True,
            "showTime": True,
            "sortOrder": "Descending",
            "wrapLogMessage": True
        },
        "targets": [{
            "datasource": {"type": "loki", "uid": loki_uid},
            "expr": f'{{host="{hostname}", source="audit"}}',
            "refId": "A"
        }],
        "title": "ðŸ›¡ï¸ Audit Logs (/var/log/audit/audit.log)",
        "type": "logs"
    })
    panel_id += 1
    y_pos += 8
    
    # Cron Logs
    panels.append({
        "datasource": {"type": "loki", "uid": loki_uid},
        "gridPos": {"h": 6, "w": 24, "x": 0, "y": y_pos},
        "id": panel_id,
        "options": {
            "dedupStrategy": "none",
            "enableLogDetails": True,
            "showTime": True,
            "sortOrder": "Descending",
            "wrapLogMessage": True
        },
        "targets": [{
            "datasource": {"type": "loki", "uid": loki_uid},
            "expr": f'{{host="{hostname}", source="cron"}}',
            "refId": "A"
        }],
        "title": "â° Cron Logs (/var/log/cron)",
        "type": "logs"
    })
    
    # Build dashboard
    dashboard = {
        "annotations": {"list": []},
        "editable": True,
        "id": None,
        "panels": panels,
        "schemaVersion": 38,
        "tags": ["sosreport", "sar", "logs", hostname],
        "templating": {"list": []},
        "time": {"from": "now-1y", "to": "now"},
        "title": f"SOSreport Analysis - {hostname}",
        "uid": f"combined-{safe_host}",
        "version": 1
    }
    
    return dashboard


def import_dashboard(hostname: str):
    """Import the combined dashboard to Grafana"""
    print("=" * 60)
    print("Combined SOSreport Dashboard Generator")
    print("=" * 60)
    
    print(f"\nHostname: {hostname}")
    
    # Get datasource UIDs
    print("\nLooking for datasources...")
    uids = get_datasource_uids()
    
    if not uids['influxdb']:
        print("ERROR: InfluxDB datasource not found in Grafana!")
        return False
    
    if not uids['loki']:
        print("ERROR: Loki datasource not found in Grafana!")
        return False
    
    # Create dashboard
    print("\nCreating combined dashboard...")
    dashboard = create_combined_dashboard(hostname, uids['influxdb'], uids['loki'])
    
    # Import to Grafana
    print("Importing to Grafana...")
    session = requests.Session()
    session.headers['Authorization'] = f'Bearer {GRAFANA_API_KEY}'
    
    payload = {
        "dashboard": dashboard,
        "folderId": 0,
        "overwrite": True
    }
    
    response = session.post(f"{GRAFANA_URL}/api/dashboards/db", json=payload)
    
    if response.status_code == 200:
        result = response.json()
        url = f"{GRAFANA_URL}{result.get('url', '')}"
        print(f"\nâœ… Dashboard imported successfully!")
        print(f"   URL: {url}")
        return True
    else:
        print(f"\nâŒ Failed: {response.status_code} - {response.text}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Create combined SAR + Logs dashboard for SOSreport"
    )
    parser.add_argument(
        "hostname",
        help="Hostname to create dashboard for (e.g., lxazueu21004.emea.adecco.net)"
    )
    
    args = parser.parse_args()
    
    import_dashboard(args.hostname)
    
    print("\n" + "=" * 60)
    print("Done!")
    print("=" * 60)


if __name__ == "__main__":
    main()
