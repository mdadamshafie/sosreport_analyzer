"""
SOSreport SAR Data Analyzer
Parses SAR data from SOSreport and pushes metrics to InfluxDB for Grafana visualization
"""
# ============================================================================
# INFLUXDB CONFIGURATION - Set your defaults here to avoid passing arguments
# ============================================================================
INFLUXDB_URL = "http://localhost:8086"
INFLUXDB_TOKEN = "YOUR_INFLUXDB_TOKEN"
INFLUXDB_ORG = "889b684a77fa68d6"
INFLUXDB_BUCKET = "sar_metrics"
# ============================================================================
# GRAFANA CONFIGURATION - For automatic dashboard import
# ============================================================================
GRAFANA_URL = "http://localhost:3000"   # Grafana server URL
GRAFANA_API_KEY = "YOUR_GRAFANA_API_KEY"  # Grafana API key
GRAFANA_USER = "admin"                        # Or use basic auth: username
GRAFANA_PASSWORD = "admin"                    # Or use basic auth: password
# ============================================================================
import os
import json
import requests
import re
import glob
import argparse
import tarfile
import tempfile
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS


@dataclass
class SARMetric:
    """Represents a single SAR metric data point"""
    timestamp: datetime
    metric_type: str
    metric_name: str
    value: float
    host: str
    tags: Dict[str, str] = None


def is_compressed_file(path: str) -> bool:
    """Check if the path is a compressed sosreport file"""
    return path.endswith(('.tar.gz', '.tgz', '.tar.xz', '.tar.bz2', '.tar'))


def extract_sosreport(archive_path: str, extract_dir: str = None) -> str:
    """Extract a compressed sosreport to a temporary directory
    
    Only extracts SAR-related files and hostname to avoid Windows path length issues.
    Returns the path to the extracted sosreport directory
    """
    if extract_dir is None:
        extract_dir = tempfile.mkdtemp(prefix='sosreport_')
    
    print(f"Extracting {os.path.basename(archive_path)}...")
    
    try:
        # Determine compression type
        if archive_path.endswith('.tar.xz'):
            mode = 'r:xz'
        elif archive_path.endswith(('.tar.gz', '.tgz')):
            mode = 'r:gz'
        elif archive_path.endswith('.tar.bz2'):
            mode = 'r:bz2'
        else:
            mode = 'r'
        
        with tarfile.open(archive_path, mode) as tar:
            # Get the top-level directory name from the archive
            members = tar.getmembers()
            if not members:
                raise Exception("Archive is empty")
            
            # Find the common prefix (sosreport directory name)
            top_dir = None
            for member in members:
                parts = member.name.split('/')
                if parts[0]:
                    top_dir = parts[0]
                    break
            
            if not top_dir:
                raise Exception("Could not determine sosreport directory name")
            
            # Filter to only extract SAR files and hostname
            # This avoids Windows path length issues with other files
            files_to_extract = []
            for member in members:
                name = member.name
                # Extract: var/log/sa/*, sos_commands/sar/*, etc/hostname
                if any(pattern in name for pattern in [
                    '/var/log/sa/',
                    '/sos_commands/sar/',
                    '/etc/hostname',
                    '/hostname'
                ]):
                    # Skip files with very long names (Windows limit)
                    if len(os.path.join(extract_dir, name)) < 250:
                        files_to_extract.append(member)
                # Also extract directory structure for the patterns
                elif member.isdir() and any(pattern in name for pattern in [
                    '/var/log/sa', '/var/log', '/var',
                    '/sos_commands/sar', '/sos_commands',
                    '/etc'
                ]):
                    files_to_extract.append(member)
            
            # Also include the top-level directory
            for member in members:
                if member.name == top_dir and member.isdir():
                    files_to_extract.insert(0, member)
                    break
            
            print(f"  Extracting {len(files_to_extract)} SAR-related files...")
            
            # Extract only the filtered files
            for member in files_to_extract:
                try:
                    tar.extract(member, extract_dir, filter='data')
                except Exception as e:
                    # Skip files that fail (usually due to path length)
                    pass
            
            sosreport_dir = os.path.join(extract_dir, top_dir)
            print(f"  Extracted to: {sosreport_dir}")
            return sosreport_dir
                
    except Exception as e:
        print(f"Error extracting archive: {e}")
        # Clean up on error
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir, ignore_errors=True)
        raise


def detect_hostname_from_sosreport(sosreport_path: str) -> str:
    """Auto-detect hostname from sosreport's /etc/hostname or other sources"""
    hostname_sources = [
        os.path.join(sosreport_path, "etc", "hostname"),
        os.path.join(sosreport_path, "hostname"),
        os.path.join(sosreport_path, "sos_commands", "host", "hostname"),
    ]
    
    for hostname_file in hostname_sources:
        if os.path.isfile(hostname_file):
            try:
                with open(hostname_file, 'r') as f:
                    hostname = f.read().strip()
                    if hostname:
                        print(f"Auto-detected hostname: {hostname} (from {hostname_file})")
                        return hostname
            except Exception:
                continue
    
    # Try to extract from sosreport directory name (often contains hostname)
    dirname = os.path.basename(sosreport_path.rstrip(os.sep))
    # sosreport names are typically: sosreport-hostname-date
    if dirname.startswith("sosreport-"):
        parts = dirname.split("-")
        if len(parts) >= 2:
            hostname = parts[1]
            print(f"Auto-detected hostname from directory name: {hostname}")
            return hostname
    
    return "unknown"


class SARParser:
    """Parser for SAR data files from SOSreport"""
    
    # Regex patterns for different SAR sections
    TIMESTAMP_PATTERN = r'^(\d{2}:\d{2}:\d{2})\s+(AM|PM)?'
    DATE_PATTERN = r'^Linux.*\s+(\d{2}/\d{2}/\d{4}|\d{4}-\d{2}-\d{2})'
    
    def __init__(self, sosreport_path: str, hostname: str = "unknown"):
        self.sosreport_path = sosreport_path
        self.hostname = hostname
        self.date = None
        self.metrics: List[SARMetric] = []
        
    def find_sar_files(self) -> List[str]:
        """Find all SAR data files in the SOSreport directory"""
        sar_paths = [
            os.path.join(self.sosreport_path, "sos_commands", "sar", "*"),
            os.path.join(self.sosreport_path, "var", "log", "sa", "*"),
            os.path.join(self.sosreport_path, "sar", "*"),
        ]
        
        sar_files = []
        for pattern in sar_paths:
            sar_files.extend(glob.glob(pattern))
        
        # Filter for actual SAR text files
        return [f for f in sar_files if os.path.isfile(f) and not f.endswith('.bin')]
    
    def parse_date_from_header(self, line: str) -> Optional[str]:
        """Extract date from SAR header line"""
        match = re.search(self.DATE_PATTERN, line)
        if match:
            return match.group(1)
        return None
    
    def parse_timestamp(self, time_str: str, am_pm: str = None) -> Optional[datetime]:
        """Convert SAR timestamp to datetime object"""
        if not self.date:
            return None
            
        try:
            if am_pm:
                time_str = f"{time_str} {am_pm}"
                time_obj = datetime.strptime(time_str, "%H:%M:%S %p")
            else:
                time_obj = datetime.strptime(time_str, "%H:%M:%S")
            
            # Combine date and time
            if '/' in self.date:
                date_obj = datetime.strptime(self.date, "%m/%d/%Y")
            else:
                date_obj = datetime.strptime(self.date, "%Y-%m-%d")
                
            return datetime.combine(date_obj.date(), time_obj.time())
        except ValueError:
            return None
    
    def parse_cpu_metrics(self, lines: List[str]) -> List[SARMetric]:
        """Parse CPU utilization metrics"""
        metrics = []
        header_found = False
        columns = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Check for CPU header
            if '%user' in line and '%system' in line:
                header_found = True
                columns = line.split()
                continue
            
            if header_found:
                timestamp_match = re.match(self.TIMESTAMP_PATTERN, line)
                if timestamp_match:
                    parts = line.split()
                    if len(parts) >= len(columns):
                        am_pm = parts[1] if parts[1] in ['AM', 'PM'] else None
                        offset = 2 if am_pm else 1
                        
                        timestamp = self.parse_timestamp(parts[0], am_pm)
                        if timestamp:
                            cpu_id = parts[offset]  # CPU identifier (all, 0, 1, etc.)
                            
                            # Map column names to values
                            for i, col in enumerate(columns[1:], start=offset + 1):
                                if i < len(parts):
                                    try:
                                        value = float(parts[i])
                                        metrics.append(SARMetric(
                                            timestamp=timestamp,
                                            metric_type="cpu",
                                            metric_name=col.replace('%', 'pct_'),
                                            value=value,
                                            host=self.hostname,
                                            tags={"cpu": cpu_id}
                                        ))
                                    except ValueError:
                                        continue
        return metrics
    
    def parse_memory_metrics(self, lines: List[str]) -> List[SARMetric]:
        """Parse memory utilization metrics"""
        metrics = []
        header_found = False
        columns = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Check for memory header
            if 'kbmemfree' in line or 'memfree' in line.lower():
                header_found = True
                columns = line.split()
                continue
            
            if header_found:
                timestamp_match = re.match(self.TIMESTAMP_PATTERN, line)
                if timestamp_match:
                    parts = line.split()
                    am_pm = parts[1] if len(parts) > 1 and parts[1] in ['AM', 'PM'] else None
                    offset = 2 if am_pm else 1
                    
                    timestamp = self.parse_timestamp(parts[0], am_pm)
                    if timestamp and len(parts) >= offset + len(columns) - 1:
                        for i, col in enumerate(columns[1:], start=offset):
                            if i < len(parts):
                                try:
                                    value = float(parts[i])
                                    metrics.append(SARMetric(
                                        timestamp=timestamp,
                                        metric_type="memory",
                                        metric_name=col.replace('%', 'pct_'),
                                        value=value,
                                        host=self.hostname,
                                        tags={}
                                    ))
                                except ValueError:
                                    continue
        return metrics
    
    def parse_disk_metrics(self, lines: List[str]) -> List[SARMetric]:
        """Parse disk I/O metrics"""
        metrics = []
        header_found = False
        columns = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Check for disk header
            if 'DEV' in line and ('tps' in line or 'rd_sec' in line):
                header_found = True
                columns = line.split()
                continue
            
            if header_found:
                timestamp_match = re.match(self.TIMESTAMP_PATTERN, line)
                if timestamp_match:
                    parts = line.split()
                    am_pm = parts[1] if len(parts) > 1 and parts[1] in ['AM', 'PM'] else None
                    offset = 2 if am_pm else 1
                    
                    timestamp = self.parse_timestamp(parts[0], am_pm)
                    if timestamp and len(parts) > offset:
                        device = parts[offset]
                        
                        for i, col in enumerate(columns[1:], start=offset + 1):
                            if i < len(parts):
                                try:
                                    value = float(parts[i])
                                    metrics.append(SARMetric(
                                        timestamp=timestamp,
                                        metric_type="disk",
                                        metric_name=col,
                                        value=value,
                                        host=self.hostname,
                                        tags={"device": device}
                                    ))
                                except ValueError:
                                    continue
        return metrics
    
    def parse_network_metrics(self, lines: List[str]) -> List[SARMetric]:
        """Parse network interface metrics"""
        metrics = []
        header_found = False
        columns = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Check for network header
            if 'IFACE' in line and ('rxpck' in line or 'rxkB' in line):
                header_found = True
                columns = line.split()
                continue
            
            if header_found:
                timestamp_match = re.match(self.TIMESTAMP_PATTERN, line)
                if timestamp_match:
                    parts = line.split()
                    am_pm = parts[1] if len(parts) > 1 and parts[1] in ['AM', 'PM'] else None
                    offset = 2 if am_pm else 1
                    
                    timestamp = self.parse_timestamp(parts[0], am_pm)
                    if timestamp and len(parts) > offset:
                        interface = parts[offset]
                        
                        for i, col in enumerate(columns[1:], start=offset + 1):
                            if i < len(parts):
                                try:
                                    value = float(parts[i])
                                    metrics.append(SARMetric(
                                        timestamp=timestamp,
                                        metric_type="network",
                                        metric_name=col.replace('/', '_'),
                                        value=value,
                                        host=self.hostname,
                                        tags={"interface": interface}
                                    ))
                                except ValueError:
                                    continue
        return metrics
    
    def parse_load_metrics(self, lines: List[str]) -> List[SARMetric]:
        """Parse system load average metrics"""
        metrics = []
        header_found = False
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Check for load header
            if 'ldavg-1' in line or 'runq-sz' in line:
                header_found = True
                continue
            
            if header_found:
                timestamp_match = re.match(self.TIMESTAMP_PATTERN, line)
                if timestamp_match:
                    parts = line.split()
                    am_pm = parts[1] if len(parts) > 1 and parts[1] in ['AM', 'PM'] else None
                    
                    timestamp = self.parse_timestamp(parts[0], am_pm)
                    if timestamp:
                        # Typical load columns: runq-sz, plist-sz, ldavg-1, ldavg-5, ldavg-15
                        metric_names = ['runq_sz', 'plist_sz', 'ldavg_1', 'ldavg_5', 'ldavg_15', 'blocked']
                        offset = 2 if am_pm else 1
                        
                        for i, name in enumerate(metric_names):
                            idx = offset + i
                            if idx < len(parts):
                                try:
                                    value = float(parts[idx])
                                    metrics.append(SARMetric(
                                        timestamp=timestamp,
                                        metric_type="load",
                                        metric_name=name,
                                        value=value,
                                        host=self.hostname,
                                        tags={}
                                    ))
                                except ValueError:
                                    continue
        return metrics
    
    def parse_file(self, filepath: str) -> List[SARMetric]:
        """Parse a single SAR file and extract all metrics"""
        metrics = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            print(f"Error reading file {filepath}: {e}")
            return metrics
        
        # Extract date from header
        for line in lines[:10]:
            date = self.parse_date_from_header(line)
            if date:
                self.date = date
                break
        
        if not self.date:
            print(f"Warning: Could not extract date from {filepath}")
            return metrics
        
        # Parse different metric types
        metrics.extend(self.parse_cpu_metrics(lines))
        metrics.extend(self.parse_memory_metrics(lines))
        metrics.extend(self.parse_disk_metrics(lines))
        metrics.extend(self.parse_network_metrics(lines))
        metrics.extend(self.parse_load_metrics(lines))
        
        return metrics
    
    def parse_all(self) -> List[SARMetric]:
        """Parse all SAR files in the SOSreport"""
        sar_files = self.find_sar_files()
        
        if not sar_files:
            print(f"No SAR files found in {self.sosreport_path}")
            return []
        
        print(f"Found {len(sar_files)} SAR files")
        
        for filepath in sar_files:
            print(f"Parsing: {filepath}")
            file_metrics = self.parse_file(filepath)
            self.metrics.extend(file_metrics)
            print(f"  Extracted {len(file_metrics)} metrics")
        
        return self.metrics


class InfluxDBPusher:
    """Pushes SAR metrics to InfluxDB for Grafana visualization"""
    
    def __init__(self, url: str, token: str, org: str, bucket: str):
        self.url = url
        self.token = token
        self.org = org
        self.bucket = bucket
        self.client = None
        self.write_api = None
    
    def connect(self):
        """Establish connection to InfluxDB"""
        self.client = InfluxDBClient(
            url=self.url,
            token=self.token,
            org=self.org
        )
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
        print(f"Connected to InfluxDB at {self.url}")
    
    def disconnect(self):
        """Close the InfluxDB connection"""
        if self.client:
            self.client.close()
            print("Disconnected from InfluxDB")
    
    def metric_to_point(self, metric: SARMetric) -> Point:
        """Convert a SARMetric to an InfluxDB Point"""
        point = Point(f"sar_{metric.metric_type}") \
            .tag("host", metric.host) \
            .field(metric.metric_name, metric.value) \
            .time(metric.timestamp, WritePrecision.S)
        
        # Add additional tags
        if metric.tags:
            for key, value in metric.tags.items():
                point = point.tag(key, value)
        
        return point
    
    def push_metrics(self, metrics: List[SARMetric], batch_size: int = 1000):
        """Push metrics to InfluxDB in batches"""
        if not metrics:
            print("No metrics to push")
            return
        
        total = len(metrics)
        pushed = 0
        
        print(f"Pushing {total} metrics to InfluxDB...")
        
        for i in range(0, total, batch_size):
            batch = metrics[i:i + batch_size]
            points = [self.metric_to_point(m) for m in batch]
            
            try:
                self.write_api.write(bucket=self.bucket, org=self.org, record=points)
                pushed += len(batch)
                print(f"  Progress: {pushed}/{total} ({100*pushed//total}%)")
            except Exception as e:
                print(f"  Error pushing batch: {e}")
        
        print(f"Successfully pushed {pushed} metrics to InfluxDB")


class GrafanaDashboardGenerator:
    """Generates Grafana dashboard JSON for SAR metrics"""
    
    @staticmethod
    def generate_dashboard(bucket: str, hostname: str) -> dict:
        """Generate a basic Grafana dashboard configuration"""
        return {
            "dashboard": {
                "id": None,
                "title": f"SAR Metrics - {hostname}",
                "tags": ["sar", "sosreport", "performance"],
                "timezone": "browser",
                "schemaVersion": 30,
                "panels": [
                    {
                        "id": 1,
                        "title": "CPU Usage",
                        "type": "timeseries",
                        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
                        "targets": [
                            {
                                "query": f'from(bucket: "{bucket}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r._measurement == "sar_cpu" and r.host == "{hostname}" and r.cpu == "all")',
                                "refId": "A"
                            }
                        ]
                    },
                    {
                        "id": 2,
                        "title": "Memory Usage",
                        "type": "timeseries",
                        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
                        "targets": [
                            {
                                "query": f'from(bucket: "{bucket}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r._measurement == "sar_memory" and r.host == "{hostname}")',
                                "refId": "A"
                            }
                        ]
                    },
                    {
                        "id": 3,
                        "title": "System Load",
                        "type": "timeseries",
                        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
                        "targets": [
                            {
                                "query": f'from(bucket: "{bucket}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r._measurement == "sar_load" and r.host == "{hostname}")',
                                "refId": "A"
                            }
                        ]
                    },
                    {
                        "id": 4,
                        "title": "Disk I/O",
                        "type": "timeseries",
                        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8},
                        "targets": [
                            {
                                "query": f'from(bucket: "{bucket}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r._measurement == "sar_disk" and r.host == "{hostname}")',
                                "refId": "A"
                            }
                        ]
                    },
                    {
                        "id": 5,
                        "title": "Network Traffic",
                        "type": "timeseries",
                        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 16},
                        "targets": [
                            {
                                "query": f'from(bucket: "{bucket}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r._measurement == "sar_network" and r.host == "{hostname}")',
                                "refId": "A"
                            }
                        ]
                    }
                ]
            },
            "overwrite": True
        }


def generate_full_dashboard(bucket: str, hostname: str, metrics: list) -> dict:
    """Generate a complete Grafana dashboard with proper structure"""
    
    # Find the date range from metrics
    timestamps = [m.timestamp for m in metrics if m.timestamp]
    if timestamps:
        min_time = min(timestamps).strftime("%Y-%m-%dT00:00:00.000Z")
        max_time = max(timestamps).strftime("%Y-%m-%dT23:59:59.000Z")
    else:
        min_time = "now-90d"
        max_time = "now"
    
    return {
        "annotations": {"list": []},
        "editable": True,
        "fiscalYearStartMonth": 0,
        "graphTooltip": 0,
        "id": None,
        "links": [],
        "liveNow": False,
        "panels": [
            {
                "datasource": {"type": "influxdb"},
                "fieldConfig": {
                    "defaults": {
                        "color": {"mode": "palette-classic"},
                        "custom": {
                            "axisBorderShow": False,
                            "axisCenteredZero": False,
                            "axisColorMode": "text",
                            "axisPlacement": "auto",
                            "barAlignment": 0,
                            "drawStyle": "line",
                            "fillOpacity": 10,
                            "lineInterpolation": "linear",
                            "lineWidth": 1,
                            "pointSize": 5,
                            "showPoints": "auto",
                            "spanNulls": False,
                            "stacking": {"group": "A", "mode": "none"},
                            "thresholdsStyle": {"mode": "off"}
                        },
                        "mappings": [],
                        "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}]},
                        "unit": "short"
                    }
                },
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
                "id": 1,
                "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True}},
                "targets": [{
                    "datasource": {"type": "influxdb"},
                    "query": f'from(bucket: "{bucket}")\n  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)\n  |> filter(fn: (r) => r._measurement == "sar_load")\n  |> filter(fn: (r) => r.host == "{hostname}")\n  |> filter(fn: (r) => r._field == "ldavg_1" or r._field == "ldavg_5" or r._field == "ldavg_15")\n  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)',
                    "refId": "A"
                }],
                "title": "System Load Average",
                "type": "timeseries"
            },
            {
                "datasource": {"type": "influxdb"},
                "fieldConfig": {
                    "defaults": {
                        "color": {"mode": "palette-classic"},
                        "custom": {"drawStyle": "line", "fillOpacity": 10, "lineWidth": 1, "pointSize": 5, "showPoints": "auto"},
                        "unit": "percent"
                    }
                },
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
                "id": 2,
                "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True}},
                "targets": [{
                    "datasource": {"type": "influxdb"},
                    "query": f'from(bucket: "{bucket}")\n  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)\n  |> filter(fn: (r) => r._measurement == "sar_memory")\n  |> filter(fn: (r) => r.host == "{hostname}")\n  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)',
                    "refId": "A"
                }],
                "title": "Memory Usage",
                "type": "timeseries"
            },
            {
                "datasource": {"type": "influxdb"},
                "fieldConfig": {
                    "defaults": {
                        "color": {"mode": "palette-classic"},
                        "custom": {"drawStyle": "line", "fillOpacity": 10, "lineWidth": 1},
                        "unit": "short"
                    }
                },
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
                "id": 3,
                "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True}},
                "targets": [{
                    "datasource": {"type": "influxdb"},
                    "query": f'from(bucket: "{bucket}")\n  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)\n  |> filter(fn: (r) => r._measurement == "sar_load")\n  |> filter(fn: (r) => r.host == "{hostname}")\n  |> filter(fn: (r) => r._field == "runq_sz" or r._field == "plist_sz" or r._field == "blocked")\n  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)',
                    "refId": "A"
                }],
                "title": "Run Queue & Process List",
                "type": "timeseries"
            },
            {
                "datasource": {"type": "influxdb"},
                "fieldConfig": {
                    "defaults": {
                        "color": {"mode": "palette-classic"},
                        "custom": {"drawStyle": "line", "fillOpacity": 10, "lineWidth": 1},
                        "unit": "KBs"
                    }
                },
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8},
                "id": 4,
                "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True}},
                "targets": [{
                    "datasource": {"type": "influxdb"},
                    "query": f'from(bucket: "{bucket}")\n  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)\n  |> filter(fn: (r) => r._measurement == "sar_disk")\n  |> filter(fn: (r) => r.host == "{hostname}")\n  |> filter(fn: (r) => r._field == "rkB_s" or r._field == "wkB_s")\n  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)',
                    "refId": "A"
                }],
                "title": "Disk I/O - Read/Write KB/s",
                "type": "timeseries"
            },
            {
                "datasource": {"type": "influxdb"},
                "fieldConfig": {
                    "defaults": {
                        "color": {"mode": "palette-classic"},
                        "custom": {"drawStyle": "line", "fillOpacity": 10, "lineWidth": 1},
                        "unit": "percent",
                        "max": 100
                    }
                },
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16},
                "id": 5,
                "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True}},
                "targets": [{
                    "datasource": {"type": "influxdb"},
                    "query": f'from(bucket: "{bucket}")\n  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)\n  |> filter(fn: (r) => r._measurement == "sar_disk")\n  |> filter(fn: (r) => r.host == "{hostname}")\n  |> filter(fn: (r) => r._field == "util_pct")\n  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)',
                    "refId": "A"
                }],
                "title": "Disk Utilization %",
                "type": "timeseries"
            },
            {
                "datasource": {"type": "influxdb"},
                "fieldConfig": {
                    "defaults": {
                        "color": {"mode": "palette-classic"},
                        "custom": {"drawStyle": "line", "fillOpacity": 10, "lineWidth": 1},
                        "unit": "ms"
                    }
                },
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16},
                "id": 6,
                "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True}},
                "targets": [{
                    "datasource": {"type": "influxdb"},
                    "query": f'from(bucket: "{bucket}")\n  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)\n  |> filter(fn: (r) => r._measurement == "sar_disk")\n  |> filter(fn: (r) => r.host == "{hostname}")\n  |> filter(fn: (r) => r._field == "await" or r._field == "r_await" or r._field == "w_await")\n  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)',
                    "refId": "A"
                }],
                "title": "Disk I/O Await (ms)",
                "type": "timeseries"
            },
            {
                "datasource": {"type": "influxdb"},
                "fieldConfig": {
                    "defaults": {
                        "color": {"mode": "palette-classic"},
                        "custom": {"drawStyle": "line", "fillOpacity": 10, "lineWidth": 1},
                        "unit": "KBs"
                    }
                },
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 24},
                "id": 7,
                "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True}},
                "targets": [{
                    "datasource": {"type": "influxdb"},
                    "query": f'from(bucket: "{bucket}")\n  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)\n  |> filter(fn: (r) => r._measurement == "sar_network")\n  |> filter(fn: (r) => r.host == "{hostname}")\n  |> filter(fn: (r) => r._field == "rxkB_s" or r._field == "txkB_s")\n  |> filter(fn: (r) => r.interface != "lo")\n  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)',
                    "refId": "A"
                }],
                "title": "Network Traffic KB/s",
                "type": "timeseries"
            },
            {
                "datasource": {"type": "influxdb"},
                "fieldConfig": {
                    "defaults": {
                        "color": {"mode": "palette-classic"},
                        "custom": {"drawStyle": "line", "fillOpacity": 10, "lineWidth": 1},
                        "unit": "pps"
                    }
                },
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 24},
                "id": 8,
                "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True}},
                "targets": [{
                    "datasource": {"type": "influxdb"},
                    "query": f'from(bucket: "{bucket}")\n  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)\n  |> filter(fn: (r) => r._measurement == "sar_network")\n  |> filter(fn: (r) => r.host == "{hostname}")\n  |> filter(fn: (r) => r._field == "rxpck_s" or r._field == "txpck_s")\n  |> filter(fn: (r) => r.interface != "lo")\n  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)',
                    "refId": "A"
                }],
                "title": "Network Packets/s",
                "type": "timeseries"
            }
        ],
        "schemaVersion": 38,
        "tags": ["sar", "sosreport", "performance", hostname],
        "templating": {"list": []},
        "time": {"from": min_time, "to": max_time},
        "timepicker": {},
        "timezone": "browser",
        "title": f"SAR Metrics - {hostname}",
        "uid": "sar-" + re.sub(r'[^a-zA-Z0-9_-]', '-', hostname)[:36],  # Sanitize UID for Grafana
        "version": 1
    }


class GrafanaImporter:
    """Imports dashboards directly to Grafana via API"""
    
    def __init__(self, url: str, api_key: str = None, username: str = None, password: str = None):
        self.url = url.rstrip('/')
        self.api_key = api_key
        self.username = username
        self.password = password
        self.session = requests.Session()
        
        # Set authentication
        if api_key:
            self.session.headers['Authorization'] = f'Bearer {api_key}'
        elif username and password:
            self.session.auth = (username, password)
    
    def get_datasource_uid(self, datasource_name: str = "InfluxDB") -> Optional[str]:
        """Get the UID of the InfluxDB datasource"""
        try:
            response = self.session.get(f"{self.url}/api/datasources")
            if response.status_code == 200:
                datasources = response.json()
                for ds in datasources:
                    if ds.get('type') == 'influxdb' or datasource_name.lower() in ds.get('name', '').lower():
                        return ds.get('uid')
            return None
        except Exception as e:
            print(f"Error getting datasource: {e}")
            return None
    
    def import_dashboard(self, dashboard_json: dict, folder_id: int = 0) -> bool:
        """Import a dashboard to Grafana"""
        try:
            # Get datasource UID
            ds_uid = self.get_datasource_uid()
            if not ds_uid:
                print("Warning: Could not find InfluxDB datasource, using default")
                ds_uid = "influxdb"
            
            # Update datasource UIDs in all panels
            if 'panels' in dashboard_json:
                for panel in dashboard_json['panels']:
                    if 'datasource' in panel:
                        panel['datasource']['uid'] = ds_uid
                    if 'targets' in panel:
                        for target in panel['targets']:
                            if 'datasource' in target:
                                target['datasource']['uid'] = ds_uid
            
            # Prepare import payload
            payload = {
                "dashboard": dashboard_json,
                "folderId": folder_id,
                "overwrite": True
            }
            
            response = self.session.post(
                f"{self.url}/api/dashboards/db",
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result = response.json()
                dashboard_url = f"{self.url}{result.get('url', '')}"
                print(f"Dashboard imported successfully!")
                print(f"Dashboard URL: {dashboard_url}")
                return True
            else:
                print(f"Failed to import dashboard: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"Error importing dashboard: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Parse SOSreport SAR data and push to InfluxDB for Grafana"
    )
    parser.add_argument(
        "sosreport_path",
        help="Path to SOSreport directory or compressed file (.tar.gz, .tar.xz, .tgz)"
    )
    parser.add_argument(
        "--hostname",
        default=None,
        help="Hostname for tagging metrics (default: auto-detect from sosreport)"
    )
    parser.add_argument(
        "--influx-url",
        default=INFLUXDB_URL,
        help=f"InfluxDB URL (default: {INFLUXDB_URL})"
    )
    parser.add_argument(
        "--influx-token",
        default=INFLUXDB_TOKEN,
        help="InfluxDB API token (set INFLUXDB_TOKEN in script or pass here)"
    )
    parser.add_argument(
        "--influx-org",
        default=INFLUXDB_ORG,
        help="InfluxDB organization (set INFLUXDB_ORG in script or pass here)"
    )
    parser.add_argument(
        "--influx-bucket",
        default=INFLUXDB_BUCKET,
        help=f"InfluxDB bucket name (default: {INFLUXDB_BUCKET})"
    )
    parser.add_argument(
        "--generate-dashboard",
        action="store_true",
        help="Generate Grafana dashboard JSON file"
    )
    parser.add_argument(
        "--import-dashboard",
        action="store_true",
        help="Automatically import dashboard to Grafana"
    )
    parser.add_argument(
        "--grafana-url",
        default=GRAFANA_URL,
        help=f"Grafana URL (default: {GRAFANA_URL})"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse SAR data but don't push to InfluxDB"
    )
    parser.add_argument(
        "--keep-extracted",
        action="store_true",
        help="Keep extracted files after processing (only for compressed inputs)"
    )
    
    args = parser.parse_args()
    
    # Track if we need to clean up extracted files
    temp_extract_dir = None
    sosreport_path = args.sosreport_path
    
    # Parse SAR data
    print(f"\n{'='*60}")
    print("SOSreport SAR Data Analyzer")
    print(f"{'='*60}\n")
    
    try:
        # Handle compressed sosreport files
        if is_compressed_file(args.sosreport_path):
            if not os.path.isfile(args.sosreport_path):
                print(f"Error: File not found: {args.sosreport_path}")
                return
            temp_extract_dir = tempfile.mkdtemp(prefix='sosreport_extract_')
            sosreport_path = extract_sosreport(args.sosreport_path, temp_extract_dir)
            print()
        elif not os.path.isdir(args.sosreport_path):
            print(f"Error: Directory not found: {args.sosreport_path}")
            return
        
        # Auto-detect hostname if not provided
        hostname = args.hostname if args.hostname else detect_hostname_from_sosreport(sosreport_path)
        
        sar_parser = SARParser(sosreport_path, hostname)
        metrics = sar_parser.parse_all()
        
        print(f"\nTotal metrics extracted: {len(metrics)}")
        
        if not metrics:
            print("No metrics found. Exiting.")
            return
        
        # Show summary by metric type
        metric_types = {}
        for m in metrics:
            key = m.metric_type
            metric_types[key] = metric_types.get(key, 0) + 1
        
        print("\nMetrics by type:")
        for mtype, count in sorted(metric_types.items()):
            print(f"  {mtype}: {count}")
        
        # Push to InfluxDB
        if not args.dry_run:
            # Validate required InfluxDB settings
            if not args.influx_token or not args.influx_org:
                print("\nError: InfluxDB token and org are required!")
                print("Either set INFLUXDB_TOKEN and INFLUXDB_ORG at the top of the script,")
                print("or pass --influx-token and --influx-org arguments.")
                return
            
            print(f"\n{'='*60}")
            print("Pushing to InfluxDB")
            print(f"{'='*60}\n")
            
            pusher = InfluxDBPusher(
                url=args.influx_url,
                token=args.influx_token,
                org=args.influx_org,
                bucket=args.influx_bucket
            )
            
            try:
                pusher.connect()
                pusher.push_metrics(metrics)
            finally:
                pusher.disconnect()
        else:
            print("\nDry run mode - metrics not pushed to InfluxDB")
        
        # Generate Grafana dashboard
        if args.generate_dashboard or args.import_dashboard:
            dashboard = generate_full_dashboard(args.influx_bucket, hostname, metrics)
            
            dashboard_file = f"grafana_dashboard_{hostname}.json"
            with open(dashboard_file, 'w') as f:
                json.dump(dashboard, f, indent=2)
            print(f"\nGrafana dashboard saved to: {dashboard_file}")
            
            # Auto-import to Grafana
            if args.import_dashboard:
                print(f"\n{'='*60}")
                print("Importing dashboard to Grafana")
                print(f"{'='*60}\n")
                
                importer = GrafanaImporter(
                    url=args.grafana_url,
                    api_key=GRAFANA_API_KEY if GRAFANA_API_KEY else None,
                    username=GRAFANA_USER if not GRAFANA_API_KEY else None,
                    password=GRAFANA_PASSWORD if not GRAFANA_API_KEY else None
                )
                importer.import_dashboard(dashboard)
        
        print(f"\n{'='*60}")
        print("Done!")
        print(f"{'='*60}\n")
    
    finally:
        # Clean up extracted files
        if temp_extract_dir and os.path.exists(temp_extract_dir):
            if args.keep_extracted:
                print(f"Extracted files kept at: {temp_extract_dir}")
            else:
                print(f"Cleaning up extracted files...")
                shutil.rmtree(temp_extract_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
