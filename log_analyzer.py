"""
SOSreport Log Analyzer for Grafana Loki
Parses log files from SOSreport and pushes to Loki for visualization in Grafana
"""

# ============================================================================
# LOKI CONFIGURATION
# ============================================================================
LOKI_URL = "http://localhost:3100"       # Loki server URL
# ============================================================================
# GRAFANA CONFIGURATION
# ============================================================================
GRAFANA_URL = "http://localhost:3000"
GRAFANA_API_KEY = "YOUR_GRAFANA_API_KEY"
# ============================================================================

import os
import re
import json
import gzip
import requests
import argparse
import tarfile
import tempfile
import shutil
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class LogEntry:
    """Represents a single log entry"""
    timestamp: datetime
    message: str
    level: str
    source: str
    host: str
    labels: Dict[str, str] = None


class LokiPusher:
    """Pushes log entries to Grafana Loki"""
    
    def __init__(self, url: str):
        self.url = url.rstrip('/')
        self.push_url = f"{self.url}/loki/api/v1/push"
        
    def test_connection(self) -> bool:
        """Test if Loki is reachable"""
        try:
            response = requests.get(f"{self.url}/ready", timeout=5)
            return response.status_code == 200
        except Exception as e:
            print(f"Loki connection failed: {e}")
            return False
    
    def push_logs(self, logs: List[LogEntry], batch_size: int = 1000) -> int:
        """Push log entries to Loki in batches"""
        if not logs:
            return 0
        
        total = len(logs)
        pushed = 0
        
        print(f"Pushing {total} log entries to Loki...")
        
        # Group logs by labels (Loki requirement)
        streams = {}
        for log in logs:
            # Create label key
            labels = {
                "host": log.host,
                "source": log.source,
                "level": log.level,
                "job": "sosreport"
            }
            if log.labels:
                labels.update(log.labels)
            
            label_key = json.dumps(labels, sort_keys=True)
            
            if label_key not in streams:
                streams[label_key] = {
                    "stream": labels,
                    "values": []
                }
            
            # Loki expects nanosecond timestamps as strings
            ts_ns = str(int(log.timestamp.timestamp() * 1e9))
            streams[label_key]["values"].append([ts_ns, log.message])
        
        # Push each stream
        for label_key, stream_data in streams.items():
            values = stream_data["values"]
            
            # Push in batches
            for i in range(0, len(values), batch_size):
                batch = values[i:i + batch_size]
                payload = {
                    "streams": [{
                        "stream": stream_data["stream"],
                        "values": batch
                    }]
                }
                
                try:
                    response = requests.post(
                        self.push_url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=30
                    )
                    
                    if response.status_code == 204:
                        pushed += len(batch)
                    else:
                        print(f"  Error pushing batch: {response.status_code} - {response.text}")
                except Exception as e:
                    print(f"  Error pushing batch: {e}")
                
                # Progress update
                if pushed % 5000 == 0:
                    print(f"  Progress: {pushed}/{total} ({100*pushed//total}%)")
        
        print(f"Successfully pushed {pushed} log entries to Loki")
        return pushed


class LogParser:
    """Parser for various log files from SOSreport"""
    
    # Common syslog timestamp patterns
    SYSLOG_PATTERN = re.compile(
        r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s*(.*)$'
    )
    
    # Systemd journal pattern
    JOURNAL_PATTERN = re.compile(
        r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s*(.*)$'
    )
    
    # Dmesg pattern with timestamp
    DMESG_PATTERN = re.compile(
        r'^\[\s*(\d+\.\d+)\]\s*(.*)$'
    )
    
    # Audit log pattern
    AUDIT_PATTERN = re.compile(
        r'^type=(\S+)\s+msg=audit\((\d+\.\d+):\d+\):\s*(.*)$'
    )
    
    def __init__(self, sosreport_path: str, hostname: str, sosreport_date: datetime = None):
        self.sosreport_path = sosreport_path
        self.hostname = hostname
        self.logs: List[LogEntry] = []
        self.sosreport_date = sosreport_date or datetime.now()
        self.year = self.sosreport_date.year  # Use year from sosreport, not current year
        
    def find_log_files(self) -> Dict[str, List[str]]:
        """Find all log files in the SOSreport"""
        log_locations = {
            "messages": [
                os.path.join(self.sosreport_path, "var", "log", "messages"),
                os.path.join(self.sosreport_path, "var", "log", "messages.1"),
            ],
            "secure": [
                os.path.join(self.sosreport_path, "var", "log", "secure"),
                os.path.join(self.sosreport_path, "var", "log", "secure.1"),
            ],
            "dmesg": [
                os.path.join(self.sosreport_path, "sos_commands", "kernel", "dmesg"),
                os.path.join(self.sosreport_path, "var", "log", "dmesg"),
            ],
            "audit": [
                os.path.join(self.sosreport_path, "var", "log", "audit", "audit.log"),
                os.path.join(self.sosreport_path, "var", "log", "audit", "audit.log.1"),
            ],
            "cron": [
                os.path.join(self.sosreport_path, "var", "log", "cron"),
            ],
            "boot": [
                os.path.join(self.sosreport_path, "var", "log", "boot.log"),
            ],
            "journal": [
                os.path.join(self.sosreport_path, "sos_commands", "logs", "journalctl_--no-pager"),
                os.path.join(self.sosreport_path, "sos_commands", "logs", "journalctl_--no-pager_--boot"),
            ],
        }
        
        found_files = {}
        for log_type, paths in log_locations.items():
            for path in paths:
                if os.path.isfile(path):
                    if log_type not in found_files:
                        found_files[log_type] = []
                    found_files[log_type].append(path)
                # Check for gzipped versions
                gz_path = path + ".gz"
                if os.path.isfile(gz_path):
                    if log_type not in found_files:
                        found_files[log_type] = []
                    found_files[log_type].append(gz_path)
        
        return found_files
    
    def parse_syslog_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse syslog timestamp (e.g., 'Jan 15 10:30:45')"""
        try:
            # Add year since syslog doesn't include it
            ts_with_year = f"{self.year} {ts_str}"
            return datetime.strptime(ts_with_year, "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
    
    def detect_log_level(self, message: str, program: str = "") -> str:
        """Detect log level from message content"""
        message_lower = message.lower()
        
        if any(word in message_lower for word in ['error', 'fail', 'critical', 'fatal', 'panic']):
            return "error"
        elif any(word in message_lower for word in ['warn', 'warning']):
            return "warning"
        elif any(word in message_lower for word in ['info', 'notice', 'started', 'stopped']):
            return "info"
        elif any(word in message_lower for word in ['debug', 'trace']):
            return "debug"
        else:
            return "info"
    
    def read_file(self, filepath: str) -> List[str]:
        """Read a file, handling gzipped files"""
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
    
    def parse_messages(self, filepath: str) -> List[LogEntry]:
        """Parse /var/log/messages or similar syslog files"""
        entries = []
        lines = self.read_file(filepath)
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            match = self.SYSLOG_PATTERN.match(line)
            if match:
                ts_str, host, program, message = match.groups()
                timestamp = self.parse_syslog_timestamp(ts_str)
                
                if timestamp:
                    entries.append(LogEntry(
                        timestamp=timestamp,
                        message=message,
                        level=self.detect_log_level(message, program),
                        source=os.path.basename(filepath),
                        host=self.hostname,
                        labels={"program": program}
                    ))
        
        return entries
    
    def parse_dmesg(self, filepath: str) -> List[LogEntry]:
        """Parse dmesg output"""
        entries = []
        lines = self.read_file(filepath)
        
        # Use sosreport date as base time for dmesg entries
        base_time = self.sosreport_date
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            match = self.DMESG_PATTERN.match(line)
            if match:
                seconds, message = match.groups()
                # Use seconds since boot
                try:
                    offset = float(seconds)
                    timestamp = base_time  # Simplified - just use current time
                    
                    entries.append(LogEntry(
                        timestamp=timestamp,
                        message=f"[{seconds}] {message}",
                        level=self.detect_log_level(message),
                        source="dmesg",
                        host=self.hostname,
                        labels={"subsystem": "kernel"}
                    ))
                except ValueError:
                    pass
            else:
                # Lines without timestamp
                if line:
                    entries.append(LogEntry(
                        timestamp=base_time,
                        message=line,
                        level=self.detect_log_level(line),
                        source="dmesg",
                        host=self.hostname,
                        labels={"subsystem": "kernel"}
                    ))
        
        return entries
    
    def parse_audit(self, filepath: str) -> List[LogEntry]:
        """Parse audit logs"""
        entries = []
        lines = self.read_file(filepath)
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            match = self.AUDIT_PATTERN.match(line)
            if match:
                audit_type, ts_str, message = match.groups()
                try:
                    timestamp = datetime.fromtimestamp(float(ts_str))
                    
                    # Determine level based on audit type
                    level = "info"
                    if audit_type in ["AVC", "SELINUX_ERR", "USER_AUTH"]:
                        level = "warning"
                    elif "FAIL" in audit_type:
                        level = "error"
                    
                    entries.append(LogEntry(
                        timestamp=timestamp,
                        message=f"type={audit_type} {message}",
                        level=level,
                        source="audit",
                        host=self.hostname,
                        labels={"audit_type": audit_type}
                    ))
                except ValueError:
                    pass
        
        return entries
    
    def parse_all(self) -> List[LogEntry]:
        """Parse all log files"""
        log_files = self.find_log_files()
        
        total_files = sum(len(files) for files in log_files.values())
        print(f"Found {total_files} log files")
        
        for log_type, files in log_files.items():
            for filepath in files:
                print(f"Parsing: {os.path.basename(filepath)} ({log_type})")
                
                if log_type in ["messages", "secure", "cron", "boot", "journal"]:
                    entries = self.parse_messages(filepath)
                elif log_type == "dmesg":
                    entries = self.parse_dmesg(filepath)
                elif log_type == "audit":
                    entries = self.parse_audit(filepath)
                else:
                    entries = self.parse_messages(filepath)  # Default to syslog format
                
                self.logs.extend(entries)
                print(f"  Extracted {len(entries)} log entries")
        
        return self.logs


def is_compressed_file(path: str) -> bool:
    """Check if the path is a compressed sosreport file"""
    return path.endswith(('.tar.gz', '.tgz', '.tar.xz', '.tar.bz2', '.tar'))


def extract_sosreport(archive_path: str, extract_dir: str = None) -> str:
    """Extract a compressed sosreport - only log-related files"""
    if extract_dir is None:
        extract_dir = tempfile.mkdtemp(prefix='sosreport_logs_')
    
    print(f"Extracting {os.path.basename(archive_path)}...")
    
    try:
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
            if not members:
                raise Exception("Archive is empty")
            
            top_dir = None
            for member in members:
                parts = member.name.split('/')
                if parts[0]:
                    top_dir = parts[0]
                    break
            
            if not top_dir:
                raise Exception("Could not determine sosreport directory name")
            
            # Extract log files and hostname
            files_to_extract = []
            for member in members:
                name = member.name
                if any(pattern in name for pattern in [
                    '/var/log/',
                    '/sos_commands/logs/',
                    '/sos_commands/kernel/dmesg',
                    '/etc/hostname',
                    '/hostname'
                ]):
                    if len(os.path.join(extract_dir, name)) < 250:
                        files_to_extract.append(member)
                elif member.isdir() and any(pattern in name for pattern in [
                    '/var/log', '/var',
                    '/sos_commands/logs', '/sos_commands/kernel', '/sos_commands',
                    '/etc'
                ]):
                    files_to_extract.append(member)
            
            for member in members:
                if member.name == top_dir and member.isdir():
                    files_to_extract.insert(0, member)
                    break
            
            print(f"  Extracting {len(files_to_extract)} log-related files...")
            
            for member in files_to_extract:
                try:
                    tar.extract(member, extract_dir, filter='data')
                except:
                    pass
            
            sosreport_dir = os.path.join(extract_dir, top_dir)
            print(f"  Extracted to: {sosreport_dir}")
            return sosreport_dir
                
    except Exception as e:
        print(f"Error extracting archive: {e}")
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir, ignore_errors=True)
        raise


def detect_sosreport_date(sosreport_path: str) -> datetime:
    """Extract date from sosreport directory name (e.g., sosreport-hostname-2025-10-24-xxx)"""
    dirname = os.path.basename(sosreport_path.rstrip(os.sep))
    
    # Pattern: sosreport-hostname-YYYY-MM-DD-randomstring
    date_pattern = re.search(r'(\d{4})-(\d{2})-(\d{2})', dirname)
    if date_pattern:
        year, month, day = map(int, date_pattern.groups())
        date = datetime(year, month, day, 12, 0, 0)  # Use noon as default time
        print(f"Auto-detected sosreport date: {date.strftime('%Y-%m-%d')}")
        return date
    
    # Fallback to current date
    print("Warning: Could not detect sosreport date, using current date")
    return datetime.now()


def detect_hostname(sosreport_path: str) -> str:
    """Auto-detect hostname from sosreport"""
    hostname_files = [
        os.path.join(sosreport_path, "etc", "hostname"),
        os.path.join(sosreport_path, "hostname"),
    ]
    
    for hf in hostname_files:
        if os.path.isfile(hf):
            try:
                with open(hf, 'r') as f:
                    hostname = f.read().strip()
                    if hostname:
                        print(f"Auto-detected hostname: {hostname}")
                        return hostname
            except:
                continue
    
    # Extract from directory name
    dirname = os.path.basename(sosreport_path.rstrip(os.sep))
    if dirname.startswith("sosreport-"):
        parts = dirname.split("-")
        if len(parts) >= 2:
            return parts[1]
    
    return "unknown"


class GrafanaImporter:
    """Import Loki datasource and dashboard to Grafana"""
    
    def __init__(self, url: str, api_key: str):
        self.url = url.rstrip('/')
        self.session = requests.Session()
        self.session.headers['Authorization'] = f'Bearer {api_key}'
    
    def ensure_loki_datasource(self, loki_url: str) -> Optional[str]:
        """Ensure Loki datasource exists, create if needed"""
        # Check existing datasources
        response = self.session.get(f"{self.url}/api/datasources")
        if response.status_code == 200:
            for ds in response.json():
                if ds.get('type') == 'loki':
                    print(f"Found existing Loki datasource: {ds.get('name')}")
                    return ds.get('uid')
        
        # Create Loki datasource
        payload = {
            "name": "Loki",
            "type": "loki",
            "url": loki_url,
            "access": "proxy",
            "isDefault": False
        }
        
        response = self.session.post(
            f"{self.url}/api/datasources",
            json=payload
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"Created Loki datasource: {result.get('name')}")
            return result.get('datasource', {}).get('uid')
        else:
            print(f"Failed to create Loki datasource: {response.text}")
            return None
    
    def import_dashboard(self, hostname: str, loki_uid: str) -> bool:
        """Import a log analysis dashboard - organized by source"""
        
        def log_panel(panel_id, title, query, y_pos, height=6, width=12, x_pos=0):
            """Helper to create a log panel"""
            return {
                "datasource": {"type": "loki", "uid": loki_uid},
                "gridPos": {"h": height, "w": width, "x": x_pos, "y": y_pos},
                "id": panel_id,
                "options": {
                    "dedupStrategy": "none",
                    "enableLogDetails": True,
                    "prettifyLogMessage": False,
                    "showCommonLabels": False,
                    "showLabels": True,
                    "showTime": True,
                    "sortOrder": "Descending",
                    "wrapLogMessage": True
                },
                "targets": [{
                    "datasource": {"type": "loki", "uid": loki_uid},
                    "expr": query,
                    "refId": "A"
                }],
                "title": title,
                "type": "logs"
            }
        
        dashboard = {
            "annotations": {"list": []},
            "editable": True,
            "id": None,
            "panels": [
                # Row 1: Overview - Log Volume Graph (full width)
                {
                    "datasource": {"type": "loki", "uid": loki_uid},
                    "fieldConfig": {
                        "defaults": {
                            "color": {"mode": "palette-classic"},
                            "custom": {"fillOpacity": 20, "stacking": {"mode": "normal"}}
                        },
                        "overrides": [
                            {"matcher": {"id": "byName", "options": "error"}, "properties": [{"id": "color", "value": {"fixedColor": "red", "mode": "fixed"}}]},
                            {"matcher": {"id": "byName", "options": "warning"}, "properties": [{"id": "color", "value": {"fixedColor": "yellow", "mode": "fixed"}}]},
                            {"matcher": {"id": "byName", "options": "info"}, "properties": [{"id": "color", "value": {"fixedColor": "green", "mode": "fixed"}}]}
                        ]
                    },
                    "gridPos": {"h": 5, "w": 24, "x": 0, "y": 0},
                    "id": 1,
                    "options": {"legend": {"displayMode": "list", "placement": "right"}},
                    "targets": [{
                        "datasource": {"type": "loki", "uid": loki_uid},
                        "expr": f'sum by (level) (count_over_time({{host="{hostname}"}}[5m]))',
                        "refId": "A"
                    }],
                    "title": "ðŸ“Š Log Volume Overview (Errors=Red, Warnings=Yellow, Info=Green)",
                    "type": "timeseries"
                },
                
                # Row 2: System Messages (left) and Secure/Auth (right)
                log_panel(2, "ðŸ“ System Messages (/var/log/messages)", 
                         f'{{host="{hostname}", source="messages"}}', 5, 8, 12, 0),
                log_panel(3, "ðŸ” Security & Authentication (/var/log/secure)", 
                         f'{{host="{hostname}", source="secure"}}', 5, 8, 12, 12),
                
                # Row 3: Audit Logs (left) and Kernel/Dmesg (right)
                log_panel(4, "ðŸ›¡ï¸ Audit Logs (/var/log/audit)", 
                         f'{{host="{hostname}", source="audit"}}', 13, 8, 12, 0),
                log_panel(5, "âš™ï¸ Kernel Messages (dmesg)", 
                         f'{{host="{hostname}", source="dmesg"}}', 13, 8, 12, 12),
                
                # Row 4: Cron Jobs (left) and Journal (right)
                log_panel(6, "â° Cron Jobs (/var/log/cron)", 
                         f'{{host="{hostname}", source="cron"}}', 21, 8, 12, 0),
                log_panel(7, "ðŸ“œ Systemd Journal (journalctl)", 
                         f'{{host="{hostname}", source=~"journalctl.*"}}', 21, 8, 12, 12),
                
                # Row 5: Errors Only (full width) - Most Important
                log_panel(8, "ðŸš¨ ALL ERRORS (from all sources)", 
                         f'{{host="{hostname}", level="error"}}', 29, 8, 24, 0),
                
                # Row 6: Warnings Only (full width)
                log_panel(9, "âš ï¸ ALL WARNINGS (from all sources)", 
                         f'{{host="{hostname}", level="warning"}}', 37, 6, 24, 0),
            ],
            "schemaVersion": 38,
            "tags": ["logs", "sosreport", hostname],
            "templating": {"list": []},
            "time": {"from": "now-90d", "to": "now"},
            "title": f"SOSreport Logs - {hostname}",
            "uid": "logs-" + re.sub(r'[^a-zA-Z0-9_-]', '-', hostname)[:36],
            "version": 1
        }
        
        payload = {
            "dashboard": dashboard,
            "folderId": 0,
            "overwrite": True
        }
        
        response = self.session.post(
            f"{self.url}/api/dashboards/db",
            json=payload
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"Dashboard imported: {self.url}{result.get('url', '')}")
            return True
        else:
            print(f"Failed to import dashboard: {response.status_code} - {response.text}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Parse SOSreport logs and push to Grafana Loki"
    )
    parser.add_argument(
        "sosreport_path",
        help="Path to SOSreport directory or compressed file (.tar.gz, .tar.xz)"
    )
    parser.add_argument(
        "--hostname",
        default=None,
        help="Hostname for labeling logs (default: auto-detect)"
    )
    parser.add_argument(
        "--loki-url",
        default=LOKI_URL,
        help=f"Loki URL (default: {LOKI_URL})"
    )
    parser.add_argument(
        "--grafana-url",
        default=GRAFANA_URL,
        help=f"Grafana URL (default: {GRAFANA_URL})"
    )
    parser.add_argument(
        "--import-dashboard",
        action="store_true",
        help="Import dashboard to Grafana"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse logs but don't push to Loki"
    )
    parser.add_argument(
        "--keep-extracted",
        action="store_true",
        help="Keep extracted files after processing"
    )
    
    args = parser.parse_args()
    
    temp_extract_dir = None
    sosreport_path = args.sosreport_path
    
    print(f"\n{'='*60}")
    print("SOSreport Log Analyzer for Grafana Loki")
    print(f"{'='*60}\n")
    
    try:
        # Handle compressed files
        if is_compressed_file(args.sosreport_path):
            if not os.path.isfile(args.sosreport_path):
                print(f"Error: File not found: {args.sosreport_path}")
                return
            temp_extract_dir = tempfile.mkdtemp(prefix='sosreport_logs_')
            sosreport_path = extract_sosreport(args.sosreport_path, temp_extract_dir)
            print()
        elif not os.path.isdir(args.sosreport_path):
            print(f"Error: Directory not found: {args.sosreport_path}")
            return
        
        # Auto-detect hostname and date
        hostname = args.hostname if args.hostname else detect_hostname(sosreport_path)
        sosreport_date = detect_sosreport_date(sosreport_path)
        
        # Parse logs with correct date
        log_parser = LogParser(sosreport_path, hostname, sosreport_date)
        logs = log_parser.parse_all()
        
        print(f"\nTotal log entries: {len(logs)}")
        
        if not logs:
            print("No log entries found. Exiting.")
            return
        
        # Summary by source
        sources = {}
        levels = {}
        for log in logs:
            sources[log.source] = sources.get(log.source, 0) + 1
            levels[log.level] = levels.get(log.level, 0) + 1
        
        print("\nLog entries by source:")
        for src, count in sorted(sources.items()):
            print(f"  {src}: {count}")
        
        print("\nLog entries by level:")
        for lvl, count in sorted(levels.items()):
            print(f"  {lvl}: {count}")
        
        # Push to Loki
        if not args.dry_run:
            print(f"\n{'='*60}")
            print("Pushing to Loki")
            print(f"{'='*60}\n")
            
            pusher = LokiPusher(args.loki_url)
            
            if not pusher.test_connection():
                print(f"\nError: Cannot connect to Loki at {args.loki_url}")
                print("Make sure Loki is installed and running.")
                print("\nTo install Loki on your server:")
                print("  1. Download: wget https://github.com/grafana/loki/releases/download/v2.9.0/loki-linux-amd64.zip")
                print("  2. Unzip and run: ./loki-linux-amd64 -config.file=loki-config.yaml")
                return
            
            pusher.push_logs(logs)
        else:
            print("\nDry run mode - logs not pushed to Loki")
        
        # Import dashboard
        if args.import_dashboard:
            print(f"\n{'='*60}")
            print("Importing dashboard to Grafana")
            print(f"{'='*60}\n")
            
            importer = GrafanaImporter(args.grafana_url, GRAFANA_API_KEY)
            loki_uid = importer.ensure_loki_datasource(args.loki_url)
            
            if loki_uid:
                importer.import_dashboard(hostname, loki_uid)
        
        print(f"\n{'='*60}")
        print("Done!")
        print(f"{'='*60}\n")
    
    finally:
        # Clean up
        if temp_extract_dir and os.path.exists(temp_extract_dir):
            if args.keep_extracted:
                print(f"Extracted files kept at: {temp_extract_dir}")
            else:
                print("Cleaning up extracted files...")
                shutil.rmtree(temp_extract_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
