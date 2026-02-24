"""
Simple Log Uploader for Grafana Loki
Parses log files from SOSreport with correct timestamps
"""

import os
import re
import json
import gzip
import requests
import argparse
import tarfile
import tempfile
import shutil
from datetime import datetime
from typing import List, Tuple

# ============================================================================
# CONFIGURATION
# ============================================================================
LOKI_URL = "http://localhost:3100"
GRAFANA_URL = "http://localhost:3000"
GRAFANA_API_KEY = "YOUR_GRAFANA_API_KEY"
# ============================================================================


def extract_year_from_path(path: str) -> int:
    """Extract year from sosreport path like sosreport-hostname-2025-10-24"""
    match = re.search(r'-(\d{4})-\d{2}-\d{2}', path)
    if match:
        return int(match.group(1))
    return datetime.now().year


def parse_syslog_line(line: str, default_year: int) -> Tuple[datetime, str, str]:
    """
    Parse a syslog line and return (timestamp, program, message)
    Format: Oct 24 11:41:25 hostname program[pid]: message
    """
    # Pattern: Month Day HH:MM:SS hostname program: message
    pattern = r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s*(.*)$'
    match = re.match(pattern, line)
    
    if match:
        month_str, day, time_str, hostname, program, message = match.groups()
        try:
            # Parse timestamp with the correct year
            ts_str = f"{default_year} {month_str} {day} {time_str}"
            timestamp = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
            return timestamp, program, message
        except ValueError:
            pass
    
    return None, None, line


def parse_audit_line(line: str) -> Tuple[datetime, str, str]:
    """
    Parse audit log line
    Format: type=TYPE msg=audit(1729770085.123:456): message
    """
    pattern = r'^type=(\S+)\s+msg=audit\((\d+)\.\d+:\d+\):\s*(.*)$'
    match = re.match(pattern, line)
    
    if match:
        audit_type, epoch_str, message = match.groups()
        try:
            timestamp = datetime.fromtimestamp(int(epoch_str))
            return timestamp, audit_type, message
        except (ValueError, OSError):
            pass
    
    return None, "unknown", line


def read_log_file(filepath: str) -> List[str]:
    """Read a log file, handling gzipped files"""
    try:
        if filepath.endswith('.gz'):
            with gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore') as f:
                return f.readlines()
        else:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return f.readlines()
    except Exception as e:
        print(f"  Warning: Could not read {filepath}: {e}")
        return []


def push_to_loki(logs: List[dict], labels: dict, batch_size: int = 500) -> int:
    """Push logs to Loki"""
    url = f"{LOKI_URL}/loki/api/v1/push"
    
    # Sort logs by timestamp
    logs.sort(key=lambda x: x['ts'])
    
    pushed = 0
    total = len(logs)
    
    for i in range(0, total, batch_size):
        batch = logs[i:i + batch_size]
        
        # Convert to Loki format [timestamp_ns, message]
        values = []
        for log in batch:
            ts_ns = str(int(log['ts'].timestamp() * 1e9))
            values.append([ts_ns, log['msg']])
        
        payload = {
            "streams": [{
                "stream": labels,
                "values": values
            }]
        }
        
        try:
            response = requests.post(url, json=payload, timeout=30)
            if response.status_code == 204:
                pushed += len(batch)
            else:
                print(f"  Error: {response.status_code} - {response.text[:200]}")
        except Exception as e:
            print(f"  Error: {e}")
        
        # Progress
        if pushed > 0 and pushed % 5000 == 0:
            print(f"  Progress: {pushed}/{total}")
    
    return pushed


def process_messages_file(filepath: str, hostname: str, year: int) -> int:
    """Process /var/log/messages file"""
    print(f"\nProcessing: {os.path.basename(filepath)}")
    
    lines = read_log_file(filepath)
    logs = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        ts, program, msg = parse_syslog_line(line, year)
        if ts:
            logs.append({'ts': ts, 'msg': f"[{program}] {msg}"})
    
    print(f"  Parsed {len(logs)} entries")
    
    if logs:
        labels = {
            "host": hostname,
            "source": "messages",
            "job": "sosreport"
        }
        pushed = push_to_loki(logs, labels)
        print(f"  Pushed {pushed} entries to Loki")
        return pushed
    
    return 0


def process_secure_file(filepath: str, hostname: str, year: int) -> int:
    """Process /var/log/secure file"""
    print(f"\nProcessing: {os.path.basename(filepath)}")
    
    lines = read_log_file(filepath)
    logs = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        ts, program, msg = parse_syslog_line(line, year)
        if ts:
            logs.append({'ts': ts, 'msg': f"[{program}] {msg}"})
    
    print(f"  Parsed {len(logs)} entries")
    
    if logs:
        labels = {
            "host": hostname,
            "source": "secure",
            "job": "sosreport"
        }
        pushed = push_to_loki(logs, labels)
        print(f"  Pushed {pushed} entries to Loki")
        return pushed
    
    return 0


def process_audit_file(filepath: str, hostname: str) -> int:
    """Process /var/log/audit/audit.log file"""
    print(f"\nProcessing: {os.path.basename(filepath)}")
    
    lines = read_log_file(filepath)
    logs = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        ts, audit_type, msg = parse_audit_line(line)
        if ts:
            logs.append({'ts': ts, 'msg': f"[{audit_type}] {msg}"})
    
    print(f"  Parsed {len(logs)} entries")
    
    if logs:
        labels = {
            "host": hostname,
            "source": "audit",
            "job": "sosreport"
        }
        pushed = push_to_loki(logs, labels)
        print(f"  Pushed {pushed} entries to Loki")
        return pushed
    
    return 0


def process_cron_file(filepath: str, hostname: str, year: int) -> int:
    """Process /var/log/cron file"""
    print(f"\nProcessing: {os.path.basename(filepath)}")
    
    lines = read_log_file(filepath)
    logs = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        ts, program, msg = parse_syslog_line(line, year)
        if ts:
            logs.append({'ts': ts, 'msg': f"[{program}] {msg}"})
    
    print(f"  Parsed {len(logs)} entries")
    
    if logs:
        labels = {
            "host": hostname,
            "source": "cron",
            "job": "sosreport"
        }
        pushed = push_to_loki(logs, labels)
        print(f"  Pushed {pushed} entries to Loki")
        return pushed
    
    return 0


def is_compressed(path: str) -> bool:
    return path.endswith(('.tar.gz', '.tgz', '.tar.xz', '.tar.bz2', '.tar'))


def extract_sosreport(archive_path: str) -> str:
    """Extract sosreport archive"""
    extract_dir = tempfile.mkdtemp(prefix='sosreport_')
    
    print(f"Extracting {os.path.basename(archive_path)}...")
    
    if archive_path.endswith('.tar.xz'):
        mode = 'r:xz'
    elif archive_path.endswith(('.tar.gz', '.tgz')):
        mode = 'r:gz'
    elif archive_path.endswith('.tar.bz2'):
        mode = 'r:bz2'
    else:
        mode = 'r'
    
    with tarfile.open(archive_path, mode) as tar:
        members = tar.getmembers()
        
        # Find top directory
        top_dir = None
        for m in members:
            if m.name and '/' in m.name:
                top_dir = m.name.split('/')[0]
                break
            elif m.isdir():
                top_dir = m.name
                break
        
        # Extract only log files to avoid path length issues
        for member in members:
            name = member.name
            if any(p in name for p in ['/var/log/', '/etc/hostname', '/hostname']):
                if len(os.path.join(extract_dir, name)) < 250:
                    try:
                        tar.extract(member, extract_dir, filter='data')
                    except:
                        pass
    
    return os.path.join(extract_dir, top_dir) if top_dir else extract_dir


def detect_hostname(sosreport_path: str) -> str:
    """Detect hostname from sosreport"""
    for hf in [
        os.path.join(sosreport_path, "etc", "hostname"),
        os.path.join(sosreport_path, "hostname"),
    ]:
        if os.path.isfile(hf):
            try:
                with open(hf, 'r') as f:
                    hostname = f.read().strip()
                    if hostname:
                        return hostname
            except:
                pass
    
    # Extract from directory name
    dirname = os.path.basename(sosreport_path)
    if dirname.startswith("sosreport-"):
        parts = dirname.split("-")
        if len(parts) >= 2:
            return parts[1]
    
    return "unknown"


def create_dashboard(hostname: str, loki_uid: str) -> dict:
    """Create a dashboard organized by log source"""
    safe_host = re.sub(r'[^a-zA-Z0-9_-]', '-', hostname)[:36]
    
    return {
        "annotations": {"list": []},
        "editable": True,
        "id": None,
        "panels": [
            # Messages panel
            {
                "datasource": {"type": "loki", "uid": loki_uid},
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 0},
                "id": 1,
                "options": {
                    "dedupStrategy": "none",
                    "enableLogDetails": True,
                    "showTime": True,
                    "sortOrder": "Descending",
                    "wrapLogMessage": True
                },
                "targets": [{
                    "datasource": {"type": "loki", "uid": loki_uid},
                    "expr": '{host="' + hostname + '", source="messages"}',
                    "refId": "A"
                }],
                "title": "System Messages (/var/log/messages)",
                "type": "logs"
            },
            # Secure panel
            {
                "datasource": {"type": "loki", "uid": loki_uid},
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8},
                "id": 2,
                "options": {
                    "dedupStrategy": "none",
                    "enableLogDetails": True,
                    "showTime": True,
                    "sortOrder": "Descending",
                    "wrapLogMessage": True
                },
                "targets": [{
                    "datasource": {"type": "loki", "uid": loki_uid},
                    "expr": '{host="' + hostname + '", source="secure"}',
                    "refId": "A"
                }],
                "title": "Security/Auth Logs (/var/log/secure)",
                "type": "logs"
            },
            # Audit panel
            {
                "datasource": {"type": "loki", "uid": loki_uid},
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 16},
                "id": 3,
                "options": {
                    "dedupStrategy": "none",
                    "enableLogDetails": True,
                    "showTime": True,
                    "sortOrder": "Descending",
                    "wrapLogMessage": True
                },
                "targets": [{
                    "datasource": {"type": "loki", "uid": loki_uid},
                    "expr": '{host="' + hostname + '", source="audit"}',
                    "refId": "A"
                }],
                "title": "Audit Logs (/var/log/audit/audit.log)",
                "type": "logs"
            },
            # Cron panel
            {
                "datasource": {"type": "loki", "uid": loki_uid},
                "gridPos": {"h": 6, "w": 24, "x": 0, "y": 24},
                "id": 4,
                "options": {
                    "dedupStrategy": "none",
                    "enableLogDetails": True,
                    "showTime": True,
                    "sortOrder": "Descending",
                    "wrapLogMessage": True
                },
                "targets": [{
                    "datasource": {"type": "loki", "uid": loki_uid},
                    "expr": '{host="' + hostname + '", source="cron"}',
                    "refId": "A"
                }],
                "title": "Cron Logs (/var/log/cron)",
                "type": "logs"
            },
            # Log volume graph
            {
                "datasource": {"type": "loki", "uid": loki_uid},
                "fieldConfig": {
                    "defaults": {"color": {"mode": "palette-classic"}},
                    "overrides": []
                },
                "gridPos": {"h": 6, "w": 24, "x": 0, "y": 30},
                "id": 5,
                "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
                "targets": [{
                    "datasource": {"type": "loki", "uid": loki_uid},
                    "expr": 'sum by (source) (count_over_time({host="' + hostname + '"}[1h]))',
                    "refId": "A"
                }],
                "title": "Log Volume by Source (per hour)",
                "type": "timeseries"
            }
        ],
        "schemaVersion": 38,
        "tags": ["logs", "sosreport", hostname],
        "templating": {"list": []},
        "time": {"from": "now-1y", "to": "now"},
        "title": f"SOSreport Logs - {hostname}",
        "uid": f"logs-{safe_host}",
        "version": 1
    }


def import_dashboard(hostname: str):
    """Import dashboard to Grafana"""
    print("\nImporting dashboard to Grafana...")
    
    session = requests.Session()
    session.headers['Authorization'] = f'Bearer {GRAFANA_API_KEY}'
    
    # Check/create Loki datasource
    response = session.get(f"{GRAFANA_URL}/api/datasources")
    loki_uid = None
    
    if response.status_code == 200:
        for ds in response.json():
            if ds.get('type') == 'loki':
                loki_uid = ds.get('uid')
                print(f"  Found Loki datasource: {ds.get('name')} (uid: {loki_uid})")
                break
    
    if not loki_uid:
        # Create Loki datasource
        payload = {
            "name": "Loki",
            "type": "loki",
            "url": LOKI_URL,
            "access": "proxy",
            "isDefault": False
        }
        response = session.post(f"{GRAFANA_URL}/api/datasources", json=payload)
        if response.status_code == 200:
            loki_uid = response.json().get('datasource', {}).get('uid')
            print(f"  Created Loki datasource (uid: {loki_uid})")
        else:
            print(f"  Failed to create datasource: {response.text}")
            return
    
    # Create and import dashboard
    dashboard = create_dashboard(hostname, loki_uid)
    
    payload = {
        "dashboard": dashboard,
        "folderId": 0,
        "overwrite": True
    }
    
    response = session.post(f"{GRAFANA_URL}/api/dashboards/db", json=payload)
    
    if response.status_code == 200:
        result = response.json()
        print(f"  Dashboard imported: {GRAFANA_URL}{result.get('url', '')}")
    else:
        print(f"  Failed: {response.status_code} - {response.text}")


def main():
    parser = argparse.ArgumentParser(description="Simple SOSreport Log Uploader for Loki")
    parser.add_argument("sosreport_path", help="Path to SOSreport directory or archive")
    parser.add_argument("--import-dashboard", action="store_true", help="Import dashboard to Grafana")
    parser.add_argument("--dry-run", action="store_true", help="Parse only, don't push to Loki")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Simple Log Uploader for Grafana Loki")
    print("=" * 60)
    
    temp_dir = None
    sosreport_path = args.sosreport_path
    
    try:
        # Handle compressed files
        if is_compressed(args.sosreport_path):
            temp_dir = extract_sosreport(args.sosreport_path)
            sosreport_path = temp_dir
        
        # Detect hostname and year
        hostname = detect_hostname(sosreport_path)
        year = extract_year_from_path(args.sosreport_path)
        
        print(f"\nHostname: {hostname}")
        print(f"Year: {year}")
        
        # Find log files
        log_files = {
            'messages': os.path.join(sosreport_path, 'var', 'log', 'messages'),
            'secure': os.path.join(sosreport_path, 'var', 'log', 'secure'),
            'audit': os.path.join(sosreport_path, 'var', 'log', 'audit', 'audit.log'),
            'cron': os.path.join(sosreport_path, 'var', 'log', 'cron'),
        }
        
        total_pushed = 0
        
        for log_type, filepath in log_files.items():
            if os.path.isfile(filepath):
                if args.dry_run:
                    lines = read_log_file(filepath)
                    print(f"\n{log_type}: {len(lines)} lines (dry run)")
                else:
                    if log_type == 'messages':
                        total_pushed += process_messages_file(filepath, hostname, year)
                    elif log_type == 'secure':
                        total_pushed += process_secure_file(filepath, hostname, year)
                    elif log_type == 'audit':
                        total_pushed += process_audit_file(filepath, hostname)
                    elif log_type == 'cron':
                        total_pushed += process_cron_file(filepath, hostname, year)
            else:
                print(f"\n{log_type}: not found")
        
        if not args.dry_run:
            print(f"\n{'=' * 60}")
            print(f"Total log entries pushed: {total_pushed}")
        
        # Import dashboard
        if args.import_dashboard and not args.dry_run:
            import_dashboard(hostname)
        
        print(f"\n{'=' * 60}")
        print("Done!")
        print("=" * 60)
    
    finally:
        # Cleanup
        if temp_dir and os.path.exists(temp_dir):
            parent = os.path.dirname(temp_dir)
            if parent.startswith(tempfile.gettempdir()):
                shutil.rmtree(parent, ignore_errors=True)


if __name__ == "__main__":
    main()
