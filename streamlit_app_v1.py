"""
SOSreport Analyzer V1 - Streamlit Web Application
Upload SOSreport files and analyze SAR metrics + Logs with automatic Grafana integration

Multi-user optimized with caching and resource management.
Simplified version without Critical Events Detection and Timeline.
"""

import streamlit as st
import streamlit.components.v1 as components
import os
import re
import json
import gzip
import requests
import tarfile
import tempfile
import shutil
import hashlib
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
import pandas as pd

# ============================================================================
# CONFIGURATION
# ============================================================================
INFLUXDB_URL = "http://localhost:8086"
INFLUXDB_TOKEN = "YOUR_INFLUXDB_TOKEN"
INFLUXDB_ORG = "889b684a77fa68d6"
INFLUXDB_BUCKET = "sar_metrics"

LOKI_URL = "http://localhost:3100"

GRAFANA_URL = "http://localhost:3000"
GRAFANA_API_KEY = "YOUR_GRAFANA_API_KEY"

# Performance Configuration
MAX_CONCURRENT_EXTRACTIONS = 3  # Limit concurrent heavy operations
MAX_LOG_LINES = 500000  # Limit log lines to prevent memory issues
MAX_SAR_METRICS = 1000000  # Limit SAR metrics
EXTRACTION_TIMEOUT = 300  # 5 minute timeout for extraction
# ============================================================================

# Thread pool for extraction (shared across sessions but limited)
_extraction_semaphore = threading.Semaphore(MAX_CONCURRENT_EXTRACTIONS)

st.set_page_config(
    page_title="SOSreport Analyzer V1",
    page_icon="ðŸ“Š",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        border-radius: 10px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .success-box {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        border-radius: 5px;
        padding: 1rem;
        margin: 1rem 0;
    }
    .info-box {
        background-color: #cce5ff;
        border: 1px solid #b8daff;
        border-radius: 5px;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def is_compressed_file(filename: str) -> bool:
    """Check if file is a compressed sosreport"""
    return filename.endswith(('.tar.gz', '.tgz', '.tar.xz', '.tar.bz2', '.tar'))


def get_file_hash(uploaded_file) -> str:
    """Get hash of uploaded file for caching"""
    return hashlib.md5(uploaded_file.name.encode() + str(uploaded_file.size).encode()).hexdigest()[:16]


def extract_sosreport(uploaded_file, progress_bar, status_text=None) -> Tuple[str, str]:
    """Extract uploaded sosreport to temp directory with concurrency control"""
    
    # Acquire semaphore to limit concurrent extractions
    if status_text:
        status_text.text("â³ Waiting for extraction slot...")
    
    with _extraction_semaphore:
        if status_text:
            status_text.text("ðŸ“¦ Starting extraction...")
        
        temp_dir = tempfile.mkdtemp(prefix='sosreport_web_')
        
        # Save uploaded file
        temp_archive = os.path.join(temp_dir, uploaded_file.name)
        with open(temp_archive, 'wb') as f:
            f.write(uploaded_file.getbuffer())
        
        file_size_mb = uploaded_file.size / (1024 * 1024)
        progress_bar.progress(20, f"Extracting archive ({file_size_mb:.1f} MB)...")
        
        # Determine compression type
        if uploaded_file.name.endswith('.tar.xz'):
            mode = 'r:xz'
        elif uploaded_file.name.endswith(('.tar.gz', '.tgz')):
            mode = 'r:gz'
        elif uploaded_file.name.endswith('.tar.bz2'):
            mode = 'r:bz2'
        else:
            mode = 'r'
        
        # Extract with resource management
        try:
            with tarfile.open(temp_archive, mode) as tar:
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
                
                # Extract relevant files - SAR, logs, and hostname
                files_to_extract = []
                for member in members:
                    name = member.name
                    # Include SAR files, all log files, system info, and hostname
                    if any(p in name for p in [
                        '/var/log/sa/',        # SAR binary and text files
                        '/sos_commands/sar/',  # SAR command outputs
                        '/sos_commands/logs/',
                        '/sos_commands/auditd/',
                        '/sos_commands/date/',  # Date command output
                        '/sos_commands/general/', # General commands (uptime, etc)
                        '/sos_commands/host/',  # Host commands
                        '/etc/hostname',
                        '/etc/redhat-release',  # OS release info
                        '/etc/centos-release',
                        '/etc/system-release',
                        '/etc/os-release',
                        '/etc/oracle-release',
                        '/hostname',
                        '/uptime',
                        '/date',
                    ]):
                        if len(os.path.join(temp_dir, name)) < 250:
                            files_to_extract.append(member)
                    # Extract ALL files under /var/log/ (not just specific ones)
                    elif '/var/log/' in name and not member.isdir():
                        if len(os.path.join(temp_dir, name)) < 250:
                            files_to_extract.append(member)
                    # Also extract directory structure
                    elif member.isdir() and any(p in name for p in [
                        '/var/log/sa', '/var/log/audit', '/var/log', '/var',
                        '/sos_commands/sar', '/sos_commands/logs', '/sos_commands',
                        '/sos_commands/date', '/sos_commands/general', '/sos_commands/host',
                        '/etc'
                    ]):
                        files_to_extract.append(member)
                
                # Include top directory
                for member in members:
                    if member.name == top_dir and member.isdir():
                        files_to_extract.insert(0, member)
                        break
                
                progress_bar.progress(40, f"Extracting {len(files_to_extract)} files...")
                
                # Extract files with progress updates
                extracted_count = 0
                for member in files_to_extract:
                    try:
                        tar.extract(member, temp_dir, filter='data')
                        extracted_count += 1
                        if extracted_count % 50 == 0:
                            pct = 40 + int((extracted_count / len(files_to_extract)) * 10)
                            progress_bar.progress(pct, f"Extracting... {extracted_count}/{len(files_to_extract)}")
                    except Exception:
                        pass
        
        finally:
            # Remove the archive to free disk space
            try:
                os.remove(temp_archive)
            except:
                pass
        
        sosreport_dir = os.path.join(temp_dir, top_dir) if top_dir else temp_dir
        return temp_dir, sosreport_dir


def detect_hostname(sosreport_path: str) -> str:
    """Detect hostname from sosreport"""
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
                        return hostname
            except:
                continue
    
    # Extract from directory name
    dirname = os.path.basename(sosreport_path)
    if dirname.startswith("sosreport-"):
        parts = dirname.split("-")
        if len(parts) >= 2:
            return parts[1]
    
    return "unknown"


def detect_uptime(sosreport_path: str) -> str:
    """Detect uptime from sosreport"""
    uptime_files = [
        os.path.join(sosreport_path, "uptime"),
        os.path.join(sosreport_path, "sos_commands", "general", "uptime"),
        os.path.join(sosreport_path, "sos_commands", "host", "uptime"),
    ]
    
    for uf in uptime_files:
        if os.path.isfile(uf):
            try:
                with open(uf, 'r') as f:
                    uptime = f.read().strip()
                    if uptime:
                        return uptime
            except:
                continue
    
    return "N/A"


def detect_date(sosreport_path: str) -> str:
    """Detect date command output from sosreport"""
    # Priority order - check sos_commands/date/date first
    date_files = [
        os.path.join(sosreport_path, "sos_commands", "date", "date"),
        os.path.join(sosreport_path, "date"),
        os.path.join(sosreport_path, "sos_commands", "general", "date"),
    ]
    
    for df in date_files:
        if os.path.isfile(df):
            try:
                with open(df, 'r') as f:
                    content = f.read().strip()
                    # Return first line only (the actual date output)
                    if content:
                        first_line = content.split('\n')[0].strip()
                        # Make sure it looks like a date (not timedatectl output)
                        if first_line and not first_line.startswith('Local time:'):
                            return first_line
            except:
                continue
    
    return "N/A"


def extract_year_from_date(date_str: str) -> Optional[int]:
    """Extract year from date string like 'Thu Dec 11 10:30:45 UTC 2025'"""
    if not date_str or date_str == "N/A":
        return None
    
    # Try to find a 4-digit year in the date string
    match = re.search(r'\b(20\d{2})\b', date_str)
    if match:
        return int(match.group(1))
    return None


def detect_os_release(sosreport_path: str) -> str:
    """Detect OS release version from sosreport"""
    release_files = [
        os.path.join(sosreport_path, "etc", "redhat-release"),
        os.path.join(sosreport_path, "etc", "centos-release"),
        os.path.join(sosreport_path, "etc", "system-release"),
        os.path.join(sosreport_path, "etc", "os-release"),
        os.path.join(sosreport_path, "etc", "oracle-release"),
        os.path.join(sosreport_path, "etc", "fedora-release"),
    ]
    
    for rf in release_files:
        if os.path.isfile(rf):
            try:
                with open(rf, 'r') as f:
                    content = f.read().strip()
                    if content:
                        # For os-release, extract PRETTY_NAME
                        if 'os-release' in rf:
                            for line in content.split('\n'):
                                if line.startswith('PRETTY_NAME='):
                                    return line.split('=', 1)[1].strip('"\'')
                        else:
                            # Return first line for other release files
                            return content.split('\n')[0]
            except:
                continue
    
    return "N/A"


def get_system_info(sosreport_path: str) -> dict:
    """Get all system information from sosreport"""
    return {
        'hostname': detect_hostname(sosreport_path),
        'uptime': detect_uptime(sosreport_path),
        'date': detect_date(sosreport_path),
        'os_release': detect_os_release(sosreport_path),
    }


def extract_year_from_path(path: str) -> int:
    """Extract year from sosreport filename"""
    match = re.search(r'-(\d{4})-\d{2}-\d{2}', path)
    if match:
        return int(match.group(1))
    return datetime.now().year


def get_report_year(sosreport_path: str, filename: str) -> int:
    """Get the year of the sosreport - tries multiple methods"""
    # Method 1: Extract from filename
    year = extract_year_from_path(filename)
    if year != datetime.now().year:
        return year
    
    # Method 2: Extract from date command output
    date_str = detect_date(sosreport_path)
    date_year = extract_year_from_date(date_str)
    if date_year:
        return date_year
    
    # Method 3: Check uptime file date
    uptime_file = os.path.join(sosreport_path, "uptime")
    if os.path.isfile(uptime_file):
        try:
            mtime = os.path.getmtime(uptime_file)
            return datetime.fromtimestamp(mtime).year
        except:
            pass
    
    return datetime.now().year


def get_time_range(sar_metrics: List[dict], logs: List[dict]) -> Tuple[Optional[datetime], Optional[datetime]]:
    """Get min and max timestamps from SAR metrics and logs for auto time range
    
    Filters out any timestamps in the future to prevent date detection bugs
    from causing invalid time ranges.
    """
    now = datetime.now()
    all_timestamps = []
    future_count = 0
    
    # Collect timestamps from SAR metrics (filter out future dates)
    for m in sar_metrics:
        ts = m.get('timestamp')
        if ts and isinstance(ts, datetime):
            if ts <= now:
                all_timestamps.append(ts)
            else:
                future_count += 1
    
    # Collect timestamps from logs (filter out future dates)
    for log in logs:
        ts = log.get('timestamp')
        if ts and isinstance(ts, datetime):
            if ts <= now:
                all_timestamps.append(ts)
            else:
                future_count += 1
    
    if not all_timestamps:
        return None, None
    
    min_ts = min(all_timestamps)
    max_ts = max(all_timestamps)
    
    # Add a small buffer (1 hour before and after) for better visibility
    min_ts = min_ts - timedelta(hours=1)
    max_ts = max_ts + timedelta(hours=1)
    
    # Ensure max doesn't exceed current time
    if max_ts > now:
        max_ts = now
    
    return min_ts, max_ts


# ============================================================================
# SAR PARSER
# ============================================================================

class SARParser:
    """Parse SAR data from sosreport - improved version"""
    
    TIMESTAMP_PATTERN = r'^(\d{2}:\d{2}:\d{2})\s*(AM|PM)?'
    DATE_PATTERN = r'(\d{2}/\d{2}/\d{4}|\d{4}-\d{2}-\d{2})'
    
    def __init__(self, sosreport_path: str, hostname: str, report_year: int = None, report_date_str: str = None):
        self.sosreport_path = sosreport_path
        self.hostname = hostname
        self.report_year = report_year or datetime.now().year
        self.report_date_str = report_date_str  # e.g., "Thu Dec 11 10:30:45 UTC 2025"
        self.report_month = self._extract_month_from_date(report_date_str)
        self.report_day = self._extract_day_from_date(report_date_str)
        self.metrics = []
        self.date = None
        self.sar_source = "none"  # Track which source was used
        self.summary = {
            'load': 0,
            'memory': 0,
            'disk': 0,
            'network': 0,
            'cpu': 0
        }
    
    def _extract_month_from_date(self, date_str: str) -> Optional[int]:
        """Extract month number from date string like 'Thu Dec 11 10:30:45 UTC 2025'"""
        if not date_str or date_str == "N/A":
            return None
        month_map = {
            'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
            'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12
        }
        date_lower = date_str.lower()
        for month_name, month_num in month_map.items():
            if month_name in date_lower:
                return month_num
        return None
    
    def _extract_day_from_date(self, date_str: str) -> Optional[int]:
        """Extract day number from date string like 'Thu Feb 06 10:30:45 UTC 2025'"""
        if not date_str or date_str == "N/A":
            return None
        # Look for day number after month name (e.g., "Feb 06" or "Feb  6")
        match = re.search(r'(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\s+(\d{1,2})\b', date_str, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return None
    
    def find_sar_files(self) -> List[str]:
        """Find SAR files in sosreport
        
        Priority: sos_commands/sar/ first (processed output), 
        fallback to var/log/sa/ only if sos_commands is empty
        """
        import glob
        
        def filter_sar_files(files: List[str]) -> List[str]:
            """Filter for valid SAR files (text or XML, not binary .bin files)"""
            result = []
            for f in files:
                if os.path.isfile(f) and not f.endswith('.bin'):
                    # XML files from sadf -x command
                    if f.endswith('.xml'):
                        result.append(f)
                        continue
                    # Check if it's a text file by reading first line
                    try:
                        with open(f, 'r', encoding='utf-8', errors='ignore') as file:
                            first_line = file.readline()
                            # SAR text files usually start with Linux or have timestamps
                            # Also accept XML files (start with <?)
                            if 'Linux' in first_line or '<?xml' in first_line or any(c.isdigit() for c in first_line[:20]):
                                result.append(f)
                    except:
                        pass
            return result
        
        # Priority 1: Check sos_commands/sar/ first (contains processed SAR output)
        sos_sar_path = os.path.join(self.sosreport_path, "sos_commands", "sar", "*")
        sos_sar_files = glob.glob(sos_sar_path)
        sos_sar_files = filter_sar_files(sos_sar_files)
        
        if sos_sar_files:
            # Found files in sos_commands/sar/ - use these (preferred source)
            self.sar_source = "sos_commands/sar/"
            return sos_sar_files
        
        # Priority 2: Fallback to var/log/sa/ only if sos_commands/sar/ is empty
        var_log_patterns = [
            os.path.join(self.sosreport_path, "var", "log", "sa", "sar*"),
            os.path.join(self.sosreport_path, "var", "log", "sa", "sa[0-9]*"),
        ]
        
        var_log_files = []
        for pattern in var_log_patterns:
            var_log_files.extend(glob.glob(pattern))
        
        var_log_files = filter_sar_files(var_log_files)
        
        if var_log_files:
            self.sar_source = "var/log/sa/"
        else:
            self.sar_source = "none"
        
        return var_log_files
    
    def parse_date_from_header(self, line: str) -> Optional[str]:
        """Extract date from SAR header"""
        match = re.search(self.DATE_PATTERN, line)
        if match:
            return match.group(1)
        return None
    
    def parse_timestamp(self, time_str: str, am_pm: str = None) -> Optional[datetime]:
        """Convert SAR timestamp to datetime"""
        if not self.date:
            return None
        
        try:
            if am_pm:
                # Use %I for 12-hour format when AM/PM is present
                time_obj = datetime.strptime(f"{time_str} {am_pm}", "%I:%M:%S %p")
            else:
                time_obj = datetime.strptime(time_str, "%H:%M:%S")
            
            if '/' in self.date:
                date_obj = datetime.strptime(self.date, "%m/%d/%Y")
            else:
                date_obj = datetime.strptime(self.date, "%Y-%m-%d")
            
            return datetime.combine(date_obj.date(), time_obj.time())
        except ValueError:
            return None
    
    def parse_load_metrics(self, lines: List[str]) -> List[dict]:
        """Parse load average metrics"""
        metrics = []
        header_found = False
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if 'ldavg-1' in line or 'runq-sz' in line:
                header_found = True
                continue
            
            if header_found:
                match = re.match(self.TIMESTAMP_PATTERN, line)
                if match:
                    parts = line.split()
                    am_pm = parts[1] if len(parts) > 1 and parts[1] in ['AM', 'PM'] else None
                    offset = 2 if am_pm else 1
                    
                    timestamp = self.parse_timestamp(parts[0], am_pm)
                    if timestamp and len(parts) > offset + 4:
                        try:
                            metrics.append({
                                'measurement': 'sar_load',
                                'timestamp': timestamp,
                                'fields': {
                                    'runq_sz': float(parts[offset]),
                                    'plist_sz': float(parts[offset + 1]),
                                    'ldavg_1': float(parts[offset + 2]),
                                    'ldavg_5': float(parts[offset + 3]),
                                    'ldavg_15': float(parts[offset + 4]),
                                    'blocked': float(parts[offset + 5]) if len(parts) > offset + 5 else 0
                                }
                            })
                            self.summary['load'] += 1
                        except (ValueError, IndexError):
                            pass
        return metrics
    
    def parse_memory_metrics(self, lines: List[str]) -> List[dict]:
        """Parse memory metrics"""
        metrics = []
        header_found = False
        columns = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if 'kbmemfree' in line:
                header_found = True
                columns = line.split()
                continue
            
            if header_found:
                match = re.match(self.TIMESTAMP_PATTERN, line)
                if match:
                    parts = line.split()
                    am_pm = parts[1] if len(parts) > 1 and parts[1] in ['AM', 'PM'] else None
                    offset = 2 if am_pm else 1
                    
                    timestamp = self.parse_timestamp(parts[0], am_pm)
                    if timestamp and len(parts) > offset:
                        fields = {}
                        for i, col in enumerate(columns[1:]):
                            idx = offset + i
                            if idx < len(parts):
                                try:
                                    col_name = col.replace('%', 'pct_').replace('-', '_')
                                    fields[col_name] = float(parts[idx])
                                except ValueError:
                                    pass
                        
                        if fields:
                            metrics.append({
                                'measurement': 'sar_memory',
                                'timestamp': timestamp,
                                'fields': fields
                            })
                            self.summary['memory'] += 1
        return metrics
    
    def parse_disk_metrics(self, lines: List[str]) -> List[dict]:
        """Parse disk I/O metrics"""
        metrics = []
        header_found = False
        columns = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if 'DEV' in line and ('tps' in line or 'rd_sec' in line or 'rkB' in line):
                header_found = True
                columns = line.split()
                continue
            
            if header_found:
                match = re.match(self.TIMESTAMP_PATTERN, line)
                if match:
                    parts = line.split()
                    am_pm = parts[1] if len(parts) > 1 and parts[1] in ['AM', 'PM'] else None
                    offset = 2 if am_pm else 1
                    
                    timestamp = self.parse_timestamp(parts[0], am_pm)
                    if timestamp and len(parts) > offset:
                        device = parts[offset]
                        fields = {'DEV': device}
                        
                        for i, col in enumerate(columns[1:]):
                            idx = offset + 1 + i
                            if idx < len(parts):
                                try:
                                    fields[col] = float(parts[idx])
                                except ValueError:
                                    pass
                        
                        if len(fields) > 1:
                            metrics.append({
                                'measurement': 'sar_disk',
                                'timestamp': timestamp,
                                'device': device,
                                'fields': fields
                            })
                            self.summary['disk'] += 1
        return metrics
    
    def parse_network_metrics(self, lines: List[str]) -> List[dict]:
        """Parse network metrics"""
        metrics = []
        header_found = False
        columns = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if 'IFACE' in line and ('rxpck' in line or 'rxkB' in line):
                header_found = True
                columns = line.split()
                continue
            
            if header_found:
                match = re.match(self.TIMESTAMP_PATTERN, line)
                if match:
                    parts = line.split()
                    am_pm = parts[1] if len(parts) > 1 and parts[1] in ['AM', 'PM'] else None
                    offset = 2 if am_pm else 1
                    
                    timestamp = self.parse_timestamp(parts[0], am_pm)
                    if timestamp and len(parts) > offset:
                        interface = parts[offset]
                        fields = {'IFACE': interface}
                        
                        for i, col in enumerate(columns[1:]):
                            idx = offset + 1 + i
                            if idx < len(parts):
                                try:
                                    fields[col.replace('/', '_')] = float(parts[idx])
                                except ValueError:
                                    pass
                        
                        if len(fields) > 1:
                            metrics.append({
                                'measurement': 'sar_network',
                                'timestamp': timestamp,
                                'interface': interface,
                                'fields': fields
                            })
                            self.summary['network'] += 1
        return metrics
    
    def parse_cpu_metrics(self, lines: List[str]) -> List[dict]:
        """Parse CPU utilization metrics"""
        metrics = []
        header_found = False
        columns = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if '%user' in line and '%system' in line:
                header_found = True
                columns = line.split()
                continue
            
            if header_found:
                match = re.match(self.TIMESTAMP_PATTERN, line)
                if match:
                    parts = line.split()
                    am_pm = parts[1] if len(parts) > 1 and parts[1] in ['AM', 'PM'] else None
                    offset = 2 if am_pm else 1
                    
                    timestamp = self.parse_timestamp(parts[0], am_pm)
                    if timestamp and len(parts) > offset:
                        cpu_id = parts[offset]
                        fields = {'cpu': cpu_id}
                        
                        for i, col in enumerate(columns[1:]):
                            idx = offset + 1 + i
                            if idx < len(parts):
                                try:
                                    col_name = col.replace('%', 'pct_')
                                    fields[col_name] = float(parts[idx])
                                except ValueError:
                                    pass
                        
                        if len(fields) > 1:
                            metrics.append({
                                'measurement': 'sar_cpu',
                                'timestamp': timestamp,
                                'cpu': cpu_id,
                                'fields': fields
                            })
                            self.summary['cpu'] += 1
        return metrics
    
    def parse_xml_file(self, filepath: str) -> List[dict]:
        """Parse SAR XML file (from sadf -x command)"""
        import xml.etree.ElementTree as ET
        metrics = []
        basename = os.path.basename(filepath)
        
        # Initialize debug tracking
        if not hasattr(self, 'debug_header_info'):
            self.debug_header_info = {}
        if not hasattr(self, 'debug_file_dates'):
            self.debug_file_dates = {}
        
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
        except Exception as e:
            self.debug_header_info[basename] = {
                'header_lines': [f'XML parse error: {str(e)[:80]}'],
                'date_from_header': None
            }
            self.debug_file_dates[basename] = f"XML_ERROR: {str(e)[:30]}"
            return metrics
        
        # Extract date from XML - try multiple methods
        file_date = None
        xml_debug_info = []
        
        # Define namespace for sysstat XML
        ns = {'sysstat': 'http://pagesperso-orange.fr/sebastien.godard/sysstat'}
        
        # Helper to get local tag name (strip namespace)
        def local_tag(elem):
            return elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
        
        try:
            # Log root element for debugging
            xml_debug_info.append(f"Root: {root.tag}")
            
            # Method 1: Look for <file-date> as CHILD ELEMENT (not attribute)
            # sysstat XML uses: <host><file-date>2026-01-29</file-date></host>
            for elem in root.iter():
                if local_tag(elem) == 'file-date' and elem.text:
                    file_date = elem.text.strip()
                    xml_debug_info.append(f"Found file-date element: {file_date}")
                    break
            
            # Method 2: Look for file-date as attribute (older format)
            if not file_date:
                for elem in root.iter():
                    fd = elem.get('file-date')
                    if fd:
                        file_date = fd
                        xml_debug_info.append(f"Found file-date attr in {local_tag(elem)}: {file_date}")
                        break
            
            # Method 3: Get date from filename as fallback
            if not file_date:
                match = re.search(r'sa(\d{2})', basename)
                if match:
                    day = int(match.group(1))
                    year = self.report_year
                    month = self.report_month if self.report_month else 2
                    report_day = self.report_day
                    
                    # If SAR file day > report day, it's from previous month
                    if report_day and day > report_day:
                        month = month - 1 if month > 1 else 12
                        if month == 12:
                            year = year - 1
                    
                    file_date = f"{year}-{month:02d}-{day:02d}"
                    xml_debug_info.append(f"From filename: day={day} -> {file_date}")
            
            if not file_date:
                xml_debug_info.append("No date found in XML")
        except Exception as e:
            xml_debug_info.append(f"XML search error: {str(e)[:50]}")
        
        # Store debug info
        self.debug_header_info[basename] = {
            'header_lines': xml_debug_info[:3] if xml_debug_info else ['XML file'],
            'date_from_header': file_date
        }
        self.debug_file_dates[basename] = file_date
        
        if not file_date:
            return metrics
        
        # Helper function to find elements with any namespace
        def find_elements(parent, local_name):
            """Find all elements matching local name regardless of namespace"""
            results = []
            for elem in parent.iter():
                # Get local name (strip namespace)
                tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                if tag == local_name:
                    results.append(elem)
            return results
        
        # Parse all timestamp elements (handles namespaced XML)
        timestamp_elements = find_elements(root, 'timestamp')
        
        # Debug: track elements found for this file
        xml_elements_found = {
            'timestamps': len(timestamp_elements),
            'cpu': 0, 'queue': 0, 'memory': 0, 'disk': 0, 'net': 0,
            'sample_cpu_attrs': None, 'sample_mem_attrs': None,
            'sample_ts_date': None
        }
        
        for timestamp_elem in timestamp_elements:
            time_str = timestamp_elem.get('time')
            # The timestamp element itself has the date attribute!
            date_str = timestamp_elem.get('date') or file_date
            
            # Debug: capture first timestamp's date
            if xml_elements_found['sample_ts_date'] is None:
                xml_elements_found['sample_ts_date'] = date_str
            
            if not time_str:
                continue
            
            try:
                # Parse timestamp - the date is already in YYYY-MM-DD format
                ts = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
            except Exception as e:
                continue
            
            # Parse CPU stats
            cpu_elements = find_elements(timestamp_elem, 'cpu')
            xml_elements_found['cpu'] += len(cpu_elements)
            for cpu in cpu_elements:
                # Debug: capture sample attributes on first element
                if xml_elements_found['sample_cpu_attrs'] is None and cpu.attrib:
                    xml_elements_found['sample_cpu_attrs'] = list(cpu.attrib.keys())[:8]
                cpu_id = cpu.get('number', 'all')
                fields = {'cpu': cpu_id}
                # sysstat XML uses abbreviated names: usr, sys instead of user, system
                attr_map = {
                    'usr': 'pct_user', 'user': 'pct_user',
                    'nice': 'pct_nice',
                    'sys': 'pct_system', 'system': 'pct_system',
                    'iowait': 'pct_iowait',
                    'steal': 'pct_steal',
                    'idle': 'pct_idle',
                    'irq': 'pct_irq',
                    'soft': 'pct_soft',
                    'guest': 'pct_guest',
                    'gnice': 'pct_gnice'
                }
                for attr, field_name in attr_map.items():
                    val = cpu.get(attr)
                    if val:
                        try:
                            fields[field_name] = float(val)
                        except:
                            pass
                if len(fields) > 1:
                    metrics.append({
                        'measurement': 'sar_cpu',
                        'timestamp': ts,
                        'cpu': cpu_id,
                        'fields': fields
                    })
                    self.summary['cpu'] += 1
            
            # Parse load stats
            queue_elements = find_elements(timestamp_elem, 'queue')
            xml_elements_found['queue'] += len(queue_elements)
            for queue in queue_elements:
                fields = {}
                for attr in ['runq-sz', 'plist-sz', 'ldavg-1', 'ldavg-5', 'ldavg-15', 'blocked']:
                    val = queue.get(attr)
                    if val:
                        try:
                            field_name = attr.replace('-', '_')
                            fields[field_name] = float(val)
                        except:
                            pass
                if fields:
                    metrics.append({
                        'measurement': 'sar_load',
                        'timestamp': ts,
                        'fields': fields
                    })
                    self.summary['load'] += 1
            
            # Parse memory stats - sysstat XML uses child elements for values
            # e.g., <memory per="second"><memfree>1219672</memfree>...</memory>
            memory_elements = find_elements(timestamp_elem, 'memory')
            xml_elements_found['memory'] += len(memory_elements)
            for memory in memory_elements:
                # Debug: capture child element names (not per/unit attributes)
                if xml_elements_found['sample_mem_attrs'] is None:
                    children = [local_tag(child) for child in memory][:10]
                    xml_elements_found['sample_mem_attrs'] = children if children else list(memory.attrib.keys())[:8]
                
                fields = {}
                # Comprehensive map of child element names in sysstat XML
                attr_map = {
                    # Memory
                    'memfree': 'kbmemfree', 'kbmemfree': 'kbmemfree',
                    'avail': 'kbavail',  # Available memory
                    'memused': 'kbmemused', 'kbmemused': 'kbmemused', 
                    'memused-percent': 'pct_memused', 'percent-memused': 'pct_memused',
                    'buffers': 'kbbuffers', 'kbbuffers': 'kbbuffers',
                    'cached': 'kbcached', 'kbcached': 'kbcached',
                    'commit': 'kbcommit', 'kbcommit': 'kbcommit',
                    'commit-percent': 'pct_commit', 'percent-commit': 'pct_commit',
                    'active': 'kbactive', 'kbactive': 'kbactive',
                    'inactive': 'kbinact', 'kbinact': 'kbinact',
                    'dirty': 'kbdirty', 'kbdirty': 'kbdirty',
                    'anonpg': 'kbanonpg', 'kbanonpg': 'kbanonpg',
                    'slab': 'kbslab', 'kbslab': 'kbslab',
                    'kstack': 'kbkstack', 'kbkstack': 'kbkstack',
                    'pgtbl': 'kbpgtbl', 'kbpgtbl': 'kbpgtbl',
                    'vmused': 'kbvmused', 'kbvmused': 'kbvmused',
                    # Swap
                    'swpfree': 'kbswpfree',
                    'swpused': 'kbswpused',
                    'swpused-percent': 'pct_swpused',
                    'swpcad': 'kbswpcad',
                    'swpcad-percent': 'pct_swpcad',
                }
                
                # sysstat 12.x uses child elements like <memfree>value</memfree>
                for child in memory:
                    child_tag = local_tag(child)
                    if child_tag in attr_map and child.text:
                        try:
                            fields[attr_map[child_tag]] = float(child.text.strip())
                        except:
                            pass
                
                # Also try attributes (older sysstat versions)
                if not fields:
                    for attr, field_name in attr_map.items():
                        val = memory.get(attr)
                        if val:
                            try:
                                fields[field_name] = float(val)
                            except:
                                pass
                
                if fields:
                    metrics.append({
                        'measurement': 'sar_memory',
                        'timestamp': ts,
                        'fields': fields
                    })
                    self.summary['memory'] += 1
            
            # Parse disk stats - sysstat 12.x XML uses:
            # <io per="second"><disk dev="sda"><tps>1.5</tps><rkB>100</rkB>...</disk></io>
            disk_elements = find_elements(timestamp_elem, 'disk')
            # Also try disk-device directly
            disk_device_elements = find_elements(timestamp_elem, 'disk-device')
            # Also try inside io element
            io_elements = find_elements(timestamp_elem, 'io')
            for io_elem in io_elements:
                disk_elements.extend(find_elements(io_elem, 'disk'))
            
            # Combine all disk sources
            all_disk_elements = disk_elements + disk_device_elements
            xml_elements_found['disk'] += len(all_disk_elements)
            
            # Debug: capture sample disk element structure
            if not hasattr(self, 'debug_disk_sample') and all_disk_elements:
                first_disk = all_disk_elements[0]
                self.debug_disk_sample = {
                    'attrs': list(first_disk.attrib.keys())[:5],
                    'children': [local_tag(c) for c in first_disk][:8]
                }
            
            for disk in all_disk_elements:
                dev = disk.get('dev', disk.get('name', 'unknown'))
                # If no dev attribute, skip (it might be a container element)
                if dev == 'unknown' and not disk.attrib:
                    # Check for child disk-device elements
                    for child in disk:
                        if local_tag(child) == 'disk-device':
                            all_disk_elements.append(child)
                    continue
                
                # Debug: capture sample disk element structure (child element names)
                if not hasattr(self, 'debug_disk_children') and disk:
                    self.debug_disk_children = [local_tag(c) for c in disk][:15]
                
                fields = {'DEV': dev}
                # Comprehensive map of element/attribute names in sysstat XML
                attr_map = {
                    'tps': 'tps',
                    # Read KB/s or sectors
                    'rkB': 'rkB_s', 'rd_sec': 'rd_sec_s', 'rd-sec': 'rd_sec_s', 'rd_sec_s': 'rd_sec_s',
                    # Write KB/s or sectors
                    'wkB': 'wkB_s', 'wr_sec': 'wr_sec_s', 'wr-sec': 'wr_sec_s', 'wr_sec_s': 'wr_sec_s',
                    # Discard KB (newer kernels)
                    'dkB': 'dkB_s',
                    # Request sizes and queue
                    'areq-sz': 'avgrq_sz', 'avgrq-sz': 'avgrq_sz', 'avgrq_sz': 'avgrq_sz',
                    'aqu-sz': 'avgqu_sz', 'avgqu-sz': 'avgqu_sz', 'avgqu_sz': 'avgqu_sz',
                    # Timing
                    'await': 'await',
                    'r_await': 'r_await',
                    'w_await': 'w_await',
                    'd_await': 'd_await',
                    'svctm': 'svctm',
                    # Utilization - multiple possible names (util-percent is sysstat 12.x format!)
                    'util': 'pct_util', '%util': 'pct_util', 'percent-util': 'pct_util',
                    'utilization': 'pct_util', 'pct-util': 'pct_util',
                    'util-percent': 'pct_util',  # sysstat 12.x uses util-percent attribute
                }
                
                # Try ATTRIBUTES first (sysstat 12.x disk-device uses attributes like util-percent)
                for attr, field_name in attr_map.items():
                    val = disk.get(attr)
                    if val:
                        try:
                            fields[field_name] = float(val)
                        except:
                            pass
                
                # If no attributes found, try child elements (some versions use child elements)
                if len(fields) <= 1:
                    for child in disk:
                        child_tag = local_tag(child)
                        if child_tag in attr_map and child.text:
                            try:
                                fields[attr_map[child_tag]] = float(child.text.strip())
                            except:
                                pass
                
                if len(fields) > 1:
                    metrics.append({
                        'measurement': 'sar_disk',
                        'timestamp': ts,
                        'device': dev,
                        'fields': fields
                    })
                    self.summary['disk'] += 1
            
            # Parse network stats - search for net-dev or net elements
            net_elements = find_elements(timestamp_elem, 'net-dev')
            if not net_elements:
                net_elements = find_elements(timestamp_elem, 'net')
            xml_elements_found['net'] += len(net_elements)
            for net in net_elements:
                iface = net.get('iface', net.get('name', 'unknown'))
                if iface == 'unknown':
                    continue
                fields = {'IFACE': iface}
                # Map of possible attribute names in sysstat XML
                attr_map = {
                    'rxpck': 'rxpck_s', 'rxpck/s': 'rxpck_s',
                    'txpck': 'txpck_s', 'txpck/s': 'txpck_s',
                    'rxkB': 'rxkB_s', 'rxkB/s': 'rxkB_s', 'rxbyt': 'rxbyt_s',
                    'txkB': 'txkB_s', 'txkB/s': 'txkB_s', 'txbyt': 'txbyt_s',
                    'rxcmp': 'rxcmp_s', 'rxcmp/s': 'rxcmp_s',
                    'txcmp': 'txcmp_s', 'txcmp/s': 'txcmp_s',
                    'rxmcst': 'rxmcst_s', 'rxmcst/s': 'rxmcst_s',
                }
                for attr, field_name in attr_map.items():
                    val = net.get(attr)
                    if val:
                        try:
                            fields[field_name] = float(val)
                        except:
                            pass
                if len(fields) > 1:
                    metrics.append({
                        'measurement': 'sar_network',
                        'timestamp': ts,
                        'interface': iface,
                        'fields': fields
                    })
                    self.summary['network'] += 1
        
        # Store XML parsing debug info
        if not hasattr(self, 'debug_xml_elements'):
            self.debug_xml_elements = {}
        self.debug_xml_elements[basename] = xml_elements_found
        
        return metrics
    
    def parse_file(self, filepath: str) -> List[dict]:
        """Parse a single SAR file"""
        metrics = []
        
        # IMPORTANT: Reset date for each file to avoid carryover
        self.date = None
        
        # Check if this is an XML file
        if filepath.endswith('.xml'):
            return self.parse_xml_file(filepath)
        
        # Also check content for XML
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline()
                if '<?xml' in first_line or '<sysstat' in first_line:
                    return self.parse_xml_file(filepath)
        except:
            pass
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            return metrics
        
        # Extract date from header (most reliable method)
        header_info = []
        for line in lines[:10]:
            header_info.append(line.strip()[:100])  # Store first 100 chars for debug
            date = self.parse_date_from_header(line)
            if date:
                self.date = date
                break
        
        # Track header info for debugging
        if not hasattr(self, 'debug_header_info'):
            self.debug_header_info = {}
        self.debug_header_info[os.path.basename(filepath)] = {
            'header_lines': header_info[:3],
            'date_from_header': self.date
        }
        
        if not self.date:
            # Try to extract date from file name (like sar20)
            basename = os.path.basename(filepath)
            match = re.search(r'sar(\d{2})', basename)
            if match:
                day = int(match.group(1))
                year = self.report_year
                
                # Smart month detection: if the day is greater than the sosreport day,
                # the file is likely from the previous month
                report_day = None
                if self.report_date_str and self.report_date_str != "N/A":
                    # Extract day from date string like "Thu Feb 06 10:30:45 UTC 2026"
                    day_match = re.search(r'\b(\d{1,2})\b', self.report_date_str)
                    if day_match:
                        report_day = int(day_match.group(1))
                
                month = self.report_month if self.report_month else 1
                
                # If SAR file day > sosreport day, it's likely from previous month
                if report_day and day > report_day:
                    month = month - 1 if month > 1 else 12
                    if month == 12:
                        year = year - 1
                
                self.date = f"{month:02d}/{day:02d}/{year}"
        
        # Track parsed dates for debugging
        if not hasattr(self, 'debug_file_dates'):
            self.debug_file_dates = {}
        self.debug_file_dates[os.path.basename(filepath)] = self.date
        
        if not self.date:
            return metrics
        
        # Parse all metric types
        metrics.extend(self.parse_load_metrics(lines))
        metrics.extend(self.parse_memory_metrics(lines))
        metrics.extend(self.parse_disk_metrics(lines))
        metrics.extend(self.parse_network_metrics(lines))
        metrics.extend(self.parse_cpu_metrics(lines))
        
        return metrics
    
    def parse_all(self) -> List[dict]:
        """Parse all SAR files"""
        sar_files = self.find_sar_files()
        
        for filepath in sar_files:
            file_metrics = self.parse_file(filepath)
            self.metrics.extend(file_metrics)
        
        # Calculate metrics by date for debugging
        self.metrics_by_date = {}
        for m in self.metrics:
            ts = m.get('timestamp')
            if ts:
                date_str = ts.strftime('%Y-%m-%d')
                if date_str not in self.metrics_by_date:
                    self.metrics_by_date[date_str] = 0
                self.metrics_by_date[date_str] += 1
        
        return self.metrics


# ============================================================================
# LOG PARSER
# ============================================================================

class LogParser:
    """Parse log files from sosreport"""
    
    def __init__(self, sosreport_path: str, hostname: str, year: int):
        self.sosreport_path = sosreport_path
        self.hostname = hostname
        self.year = year
        self.logs = []
        self.summary = {
            'messages': 0,
            'secure': 0,
            'audit': 0,
            'cron': 0
        }
    
    def read_file(self, filepath: str) -> List[str]:
        """Read log file - supports plain text, gzip, xz, and bz2 compressed files"""
        try:
            if filepath.endswith('.gz'):
                with gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore') as f:
                    return f.readlines()
            elif filepath.endswith('.xz'):
                import lzma
                with lzma.open(filepath, 'rt', encoding='utf-8', errors='ignore') as f:
                    return f.readlines()
            elif filepath.endswith('.bz2'):
                import bz2
                with bz2.open(filepath, 'rt', encoding='utf-8', errors='ignore') as f:
                    return f.readlines()
            else:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.readlines()
        except Exception:
            return []
    
    def parse_syslog_line(self, line: str) -> Tuple[Optional[datetime], str, str]:
        """Parse syslog format line"""
        pattern = r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s*(.*)$'
        match = re.match(pattern, line)
        
        if match:
            month_str, day, time_str, hostname, program, message = match.groups()
            try:
                ts_str = f"{self.year} {month_str} {day} {time_str}"
                timestamp = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
                return timestamp, program, message
            except ValueError:
                pass
        
        return None, "", line
    
    def parse_audit_line(self, line: str) -> Tuple[Optional[datetime], str, str]:
        """Parse audit log line"""
        pattern = r'^type=(\S+)\s+msg=audit\((\d+)\.\d+:\d+\):\s*(.*)$'
        match = re.match(pattern, line)
        
        if match:
            audit_type, epoch_str, message = match.groups()
            try:
                timestamp = datetime.fromtimestamp(int(epoch_str))
                return timestamp, audit_type, message
            except:
                pass
        
        return None, "unknown", line
    
    def parse_messages(self, filepath: str, source: str) -> List[dict]:
        """Parse syslog-format file"""
        entries = []
        lines = self.read_file(filepath)
        
        # Debug: track dates found in this file
        dates_in_file = set()
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            ts, program, msg = self.parse_syslog_line(line)
            if ts:
                dates_in_file.add(ts.strftime('%Y-%m-%d'))
                entries.append({
                    'timestamp': ts,
                    'source': source,
                    'program': program,
                    'message': msg
                })
        
        # Store debug info about dates in each file
        if not hasattr(self, 'debug_file_dates'):
            self.debug_file_dates = {}
        self.debug_file_dates[os.path.basename(filepath)] = sorted(dates_in_file)
        
        return entries
    
    def parse_audit(self, filepath: str) -> List[dict]:
        """Parse audit log"""
        entries = []
        lines = self.read_file(filepath)
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            ts, audit_type, msg = self.parse_audit_line(line)
            if ts:
                entries.append({
                    'timestamp': ts,
                    'source': 'audit',
                    'program': audit_type,
                    'message': msg
                })
        
        return entries
    
    def find_log_files(self) -> dict:
        """Find all log files including rotated ones and sos_commands outputs"""
        import glob
        
        found_files = {
            'messages': [],
            'secure': [],
            'audit': [],
            'cron': [],
        }
        
        var_log = os.path.join(self.sosreport_path, 'var', 'log')
        
        # Messages - all variations including rotated and compressed (.gz, .xz, .bz2)
        patterns = [
            os.path.join(var_log, 'messages'),
            os.path.join(var_log, 'messages-*'),
            os.path.join(var_log, 'messages.[0-9]*'),
            os.path.join(var_log, 'messages*.gz'),
            os.path.join(var_log, 'messages*.xz'),
            os.path.join(var_log, 'messages*.bz2'),
            os.path.join(self.sosreport_path, 'sos_commands', 'logs', '*messages*'),
        ]
        for p in patterns:
            found_files['messages'].extend(glob.glob(p))
        
        # Secure - all variations including rotated and compressed (.gz, .xz, .bz2)
        patterns = [
            os.path.join(var_log, 'secure'),
            os.path.join(var_log, 'secure-*'),
            os.path.join(var_log, 'secure.[0-9]*'),
            os.path.join(var_log, 'secure*.gz'),
            os.path.join(var_log, 'secure*.xz'),
            os.path.join(var_log, 'secure*.bz2'),
            os.path.join(self.sosreport_path, 'sos_commands', 'logs', '*secure*'),
        ]
        for p in patterns:
            found_files['secure'].extend(glob.glob(p))
        
        # Audit - all variations including rotated and compressed (.gz, .xz, .bz2)
        audit_log = os.path.join(var_log, 'audit')
        patterns = [
            os.path.join(audit_log, 'audit.log'),
            os.path.join(audit_log, 'audit.log.[0-9]*'),
            os.path.join(audit_log, 'audit.log*.gz'),
            os.path.join(audit_log, 'audit.log*.xz'),
            os.path.join(audit_log, 'audit.log*.bz2'),
            os.path.join(self.sosreport_path, 'sos_commands', 'auditd', '*'),
        ]
        for p in patterns:
            found_files['audit'].extend(glob.glob(p))
        
        # Cron - all variations including rotated and compressed (.gz, .xz, .bz2)
        patterns = [
            os.path.join(var_log, 'cron'),
            os.path.join(var_log, 'cron-*'),
            os.path.join(var_log, 'cron.[0-9]*'),
            os.path.join(var_log, 'cron*.gz'),
            os.path.join(var_log, 'cron*.xz'),
            os.path.join(var_log, 'cron*.bz2'),
            os.path.join(self.sosreport_path, 'sos_commands', 'logs', '*cron*'),
        ]
        for p in patterns:
            found_files['cron'].extend(glob.glob(p))
        
        # Filter to only existing files (not directories) and remove duplicates
        for key in found_files:
            found_files[key] = list(set([f for f in found_files[key] if os.path.isfile(f)]))
            found_files[key].sort()
        
        # Debug - also list what's in sos_commands/logs
        self.debug_sos_logs_dir = []
        sos_logs_path = os.path.join(self.sosreport_path, 'sos_commands', 'logs')
        if os.path.isdir(sos_logs_path):
            self.debug_sos_logs_dir = os.listdir(sos_logs_path)
        
        return found_files
    
    def parse_all(self) -> List[dict]:
        """Parse all log files"""
        log_files = self.find_log_files()
        
        for log_type, filepaths in log_files.items():
            for filepath in filepaths:
                if log_type == 'audit':
                    entries = self.parse_audit(filepath)
                else:
                    entries = self.parse_messages(filepath, log_type)
                
                self.logs.extend(entries)
                self.summary[log_type] += len(entries)
        
        # Store found files for debugging
        self.found_files = log_files
        
        # Calculate log entries by date for debugging
        self.logs_by_date = {}
        for log in self.logs:
            ts = log.get('timestamp')
            if ts:
                date_str = ts.strftime('%Y-%m-%d')
                if date_str not in self.logs_by_date:
                    self.logs_by_date[date_str] = 0
                self.logs_by_date[date_str] += 1
        
        return self.logs


# ============================================================================
# DATA PUSHERS
# ============================================================================

def push_sar_to_influxdb(metrics: List[dict], hostname: str, progress_callback=None) -> Tuple[int, str]:
    """Push SAR metrics to InfluxDB with retry logic"""
    if not metrics:
        return 0, "No metrics to push"
    
    url = f"{INFLUXDB_URL}/api/v2/write?org={INFLUXDB_ORG}&bucket={INFLUXDB_BUCKET}&precision=s"
    headers = {
        "Authorization": f"Token {INFLUXDB_TOKEN}",
        "Content-Type": "text/plain"
    }
    
    pushed = 0
    errors = []
    batch_size = 1000  # Smaller batches for more reliable writes
    max_retries = 3
    base_timeout = 60  # Longer timeout for remote server
    
    total_batches = (len(metrics) + batch_size - 1) // batch_size
    
    for i in range(0, len(metrics), batch_size):
        batch = metrics[i:i + batch_size]
        batch_num = i // batch_size
        lines = []
        
        for m in batch:
            measurement = m['measurement']
            
            # Build fields string - only numeric values
            fields_list = []
            for k, v in m['fields'].items():
                if isinstance(v, (int, float)) and k not in ['DEV', 'IFACE', 'cpu']:
                    # Escape special characters in field names
                    field_name = k.replace(' ', '_').replace('/', '_').replace('%', 'pct_')
                    fields_list.append(f'{field_name}={v}')
            
            if not fields_list:
                continue
                
            fields = ','.join(fields_list)
            
            # Build tags - escape special characters
            safe_hostname = hostname.replace(' ', '_').replace(',', '_')
            tags = f"host={safe_hostname}"
            
            if 'device' in m and m['device']:
                safe_device = str(m['device']).replace(' ', '_').replace(',', '_')
                tags += f",device={safe_device}"
            if 'interface' in m and m['interface']:
                safe_iface = str(m['interface']).replace(' ', '_').replace(',', '_')
                tags += f",interface={safe_iface}"
            if 'cpu' in m and m['cpu']:
                safe_cpu = str(m['cpu']).replace(' ', '_').replace(',', '_')
                tags += f",cpu={safe_cpu}"
            
            # Get timestamp
            ts_unix = None
            if 'timestamp' in m and isinstance(m['timestamp'], datetime):
                ts_unix = int(m['timestamp'].timestamp())
            elif 'time' in m:
                try:
                    ts = datetime.strptime(m['time'], "%m/%d/%Y %H:%M:%S")
                    ts_unix = int(ts.timestamp())
                except:
                    pass
            
            if ts_unix:
                lines.append(f"{measurement},{tags} {fields} {ts_unix}")
        
        if lines:
            # Retry logic with exponential backoff
            success = False
            last_error = None
            
            for retry in range(max_retries):
                try:
                    timeout = base_timeout * (retry + 1)  # Increase timeout on retry
                    response = requests.post(url, headers=headers, data='\n'.join(lines), timeout=timeout)
                    if response.status_code == 204:
                        pushed += len(lines)
                        success = True
                        break
                    else:
                        last_error = f"HTTP {response.status_code} - {response.text[:100]}"
                except requests.exceptions.Timeout:
                    last_error = f"Timeout after {timeout}s"
                    if retry < max_retries - 1:
                        import time
                        time.sleep(2 ** retry)  # Wait 1s, 2s, 4s between retries
                except Exception as e:
                    last_error = str(e)[:100]
                    break
            
            if not success and last_error:
                errors.append(f"Batch {batch_num}/{total_batches}: {last_error}")
        
        if progress_callback:
            progress_callback(pushed, len(metrics))
    
    error_msg = "; ".join(errors[:3]) if errors else ""
    return pushed, error_msg


def push_logs_to_loki(logs: List[dict], hostname: str, progress_callback=None) -> Tuple[int, str]:
    """Push logs to Loki with retry logic
    
    Returns: (pushed_count, error_message)
    """
    if not logs:
        return 0, "No logs to push"
    
    url = f"{LOKI_URL}/loki/api/v1/push"
    max_retries = 3
    base_timeout = 60
    
    # Group by source
    streams = {}
    for log in logs:
        source = log['source']
        if source not in streams:
            streams[source] = []
        
        ts_ns = str(int(log['timestamp'].timestamp() * 1e9))
        msg = f"[{log['program']}] {log['message']}"
        streams[source].append([ts_ns, msg])
    
    pushed = 0
    errors = []
    
    for source, values in streams.items():
        # Sort by timestamp
        values.sort(key=lambda x: x[0])
        
        # Push in batches
        batch_size = 300  # Smaller batches for reliability
        total_batches = (len(values) + batch_size - 1) // batch_size
        
        for i in range(0, len(values), batch_size):
            batch = values[i:i + batch_size]
            batch_num = i // batch_size
            
            payload = {
                "streams": [{
                    "stream": {
                        "host": hostname,
                        "source": source,
                        "job": "sosreport"
                    },
                    "values": batch
                }]
            }
            
            # Retry logic with exponential backoff
            success = False
            last_error = None
            
            for retry in range(max_retries):
                try:
                    timeout = base_timeout * (retry + 1)
                    response = requests.post(url, json=payload, timeout=timeout)
                    if response.status_code == 204:
                        pushed += len(batch)
                        success = True
                        break
                    else:
                        last_error = f"HTTP {response.status_code} - {response.text[:100]}"
                        # Don't retry on 4xx errors (client errors)
                        if 400 <= response.status_code < 500:
                            break
                except requests.exceptions.Timeout:
                    last_error = f"Timeout after {timeout}s"
                    if retry < max_retries - 1:
                        import time
                        time.sleep(2 ** retry)
                except Exception as e:
                    last_error = str(e)[:100]
                    break
            
            if not success and last_error:
                errors.append(f"{source} {batch_num}/{total_batches}: {last_error}")
        
        if progress_callback:
            progress_callback(pushed, len(logs))
    
    error_msg = "; ".join(errors[:5]) if errors else ""
    return pushed, error_msg


def create_grafana_dashboard(hostname: str, time_from: datetime = None, time_to: datetime = None) -> Optional[str]:
    """Create combined dashboard in Grafana with all SAR and Log panels
    
    Args:
        hostname: The hostname for the dashboard
        time_from: Start time for the dashboard (auto-detected from data)
        time_to: End time for the dashboard (auto-detected from data)
    """
    session = requests.Session()
    session.headers['Authorization'] = f'Bearer {GRAFANA_API_KEY}'
    
    # Get datasource UIDs
    response = session.get(f"{GRAFANA_URL}/api/datasources")
    influx_uid = None
    loki_uid = None
    
    if response.status_code == 200:
        for ds in response.json():
            if ds.get('type') == 'influxdb':
                influx_uid = ds.get('uid')
            elif ds.get('type') == 'loki':
                loki_uid = ds.get('uid')
    
    if not influx_uid or not loki_uid:
        return None
    
    safe_host = re.sub(r'[^a-zA-Z0-9_-]', '-', hostname)[:36]
    
    panels = []
    panel_id = 1
    y_pos = 0
    
    # ========== SAR METRICS SECTION ==========
    
    # Row Header: SAR Metrics
    panels.append({
        "gridPos": {"h": 1, "w": 24, "x": 0, "y": y_pos},
        "id": panel_id,
        "title": "ðŸ“Š SAR Performance Metrics",
        "type": "row",
        "collapsed": False
    })
    panel_id += 1
    y_pos += 1
    
    # CPU Load Average
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "custom": {"lineWidth": 2, "fillOpacity": 10}, "unit": "short"}},
        "gridPos": {"h": 6, "w": 12, "x": 0, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        "targets": [{"datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'from(bucket: "{INFLUXDB_BUCKET}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r["_measurement"] == "sar_load") |> filter(fn: (r) => r["host"] == "{hostname}") |> filter(fn: (r) => r["_field"] == "ldavg_1" or r["_field"] == "ldavg_5" or r["_field"] == "ldavg_15")',
            "refId": "A"}],
        "title": "CPU Load Average",
        "type": "timeseries"
    })
    panel_id += 1
    
    # Run Queue & Blocked
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "custom": {"lineWidth": 2, "fillOpacity": 10}, "unit": "short"}},
        "gridPos": {"h": 6, "w": 12, "x": 12, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        "targets": [{"datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'from(bucket: "{INFLUXDB_BUCKET}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r["_measurement"] == "sar_load") |> filter(fn: (r) => r["host"] == "{hostname}") |> filter(fn: (r) => r["_field"] == "runq_sz" or r["_field"] == "blocked" or r["_field"] == "plist_sz")',
            "refId": "A"}],
        "title": "Run Queue & Blocked Processes",
        "type": "timeseries"
    })
    panel_id += 1
    y_pos += 6
    
    # Memory Usage %
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "custom": {"lineWidth": 2, "fillOpacity": 10}, "unit": "percent", "max": 100}},
        "gridPos": {"h": 6, "w": 12, "x": 0, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        "targets": [{"datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'from(bucket: "{INFLUXDB_BUCKET}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r["_measurement"] == "sar_memory") |> filter(fn: (r) => r["host"] == "{hostname}") |> filter(fn: (r) => r["_field"] == "pct_memused" or r["_field"] == "pct_commit")',
            "refId": "A"}],
        "title": "Memory Usage (%)",
        "type": "timeseries"
    })
    panel_id += 1
    
    # Memory KB
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "custom": {"lineWidth": 2, "fillOpacity": 10}, "unit": "deckbytes"}},
        "gridPos": {"h": 6, "w": 12, "x": 12, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        "targets": [{"datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'from(bucket: "{INFLUXDB_BUCKET}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r["_measurement"] == "sar_memory") |> filter(fn: (r) => r["host"] == "{hostname}") |> filter(fn: (r) => r["_field"] == "kbmemused" or r["_field"] == "kbmemfree" or r["_field"] == "kbcached" or r["_field"] == "kbbuffers")',
            "refId": "A"}],
        "title": "Memory (Used/Free/Cached/Buffers)",
        "type": "timeseries"
    })
    panel_id += 1
    y_pos += 6
    
    # Disk I/O KB/s - handles both old SAR (rd_sec_s/wr_sec_s) and new SAR (rkB_s/wkB_s)
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "custom": {"lineWidth": 2, "fillOpacity": 10}, "unit": "KBs"}},
        "gridPos": {"h": 6, "w": 12, "x": 0, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        "targets": [{"datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'from(bucket: "{INFLUXDB_BUCKET}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r["_measurement"] == "sar_disk") |> filter(fn: (r) => r["host"] == "{hostname}") |> filter(fn: (r) => r["_field"] == "rkB_s" or r["_field"] == "wkB_s" or r["_field"] == "rd_sec_s" or r["_field"] == "wr_sec_s" or r["_field"] == "avgrq_sz" or r["_field"] == "tps")',
            "refId": "A"}],
        "title": "Disk I/O (KB/s or sectors/s)",
        "type": "timeseries"
    })
    panel_id += 1
    
    # Disk Utilization %
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "custom": {"lineWidth": 2, "fillOpacity": 10}, "unit": "percent", "max": 100}},
        "gridPos": {"h": 6, "w": 12, "x": 12, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        "targets": [{"datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'from(bucket: "{INFLUXDB_BUCKET}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r["_measurement"] == "sar_disk") |> filter(fn: (r) => r["host"] == "{hostname}") |> filter(fn: (r) => r["_field"] == "pct_util")',
            "refId": "A"}],
        "title": "Disk Utilization (%)",
        "type": "timeseries"
    })
    panel_id += 1
    y_pos += 6
    
    # Network I/O
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "custom": {"lineWidth": 2, "fillOpacity": 10}, "unit": "KBs"}},
        "gridPos": {"h": 6, "w": 24, "x": 0, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        "targets": [{"datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'from(bucket: "{INFLUXDB_BUCKET}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r["_measurement"] == "sar_network") |> filter(fn: (r) => r["host"] == "{hostname}") |> filter(fn: (r) => r["_field"] == "rxkB_s" or r["_field"] == "txkB_s")',
            "refId": "A"}],
        "title": "Network I/O (KB/s)",
        "type": "timeseries"
    })
    panel_id += 1
    y_pos += 6
    
    # ========== LOG ANALYSIS SECTION ==========
    
    # Row Header: Log Analysis
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
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}}},
        "gridPos": {"h": 5, "w": 24, "x": 0, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "right"}},
        "targets": [{"datasource": {"type": "loki", "uid": loki_uid},
            "expr": f'sum by (source) (count_over_time({{host="{hostname}"}}[1h]))',
            "refId": "A"}],
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
        "options": {"dedupStrategy": "none", "enableLogDetails": True, "showTime": True, "sortOrder": "Ascending", "wrapLogMessage": True},
        "targets": [{"datasource": {"type": "loki", "uid": loki_uid},
            "expr": f'{{host="{hostname}", source="messages"}}',
            "maxLines": 5000,
            "refId": "A"}],
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
        "options": {"dedupStrategy": "none", "enableLogDetails": True, "showTime": True, "sortOrder": "Ascending", "wrapLogMessage": True},
        "targets": [{"datasource": {"type": "loki", "uid": loki_uid},
            "expr": f'{{host="{hostname}", source="secure"}}',
            "maxLines": 5000,
            "refId": "A"}],
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
        "options": {"dedupStrategy": "none", "enableLogDetails": True, "showTime": True, "sortOrder": "Ascending", "wrapLogMessage": True},
        "targets": [{"datasource": {"type": "loki", "uid": loki_uid},
            "expr": f'{{host="{hostname}", source="audit"}}',
            "maxLines": 5000,
            "refId": "A"}],
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
        "options": {"dedupStrategy": "none", "enableLogDetails": True, "showTime": True, "sortOrder": "Ascending", "wrapLogMessage": True},
        "targets": [{"datasource": {"type": "loki", "uid": loki_uid},
            "expr": f'{{host="{hostname}", source="cron"}}',
            "maxLines": 5000,
            "refId": "A"}],
        "title": "â° Cron Logs (/var/log/cron)",
        "type": "logs"
    })
    
    # Build dashboard with auto time range
    # Use provided timestamps or fallback to last year
    if time_from and time_to:
        # Format as ISO 8601 for Grafana
        time_from_str = time_from.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        time_to_str = time_to.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    else:
        time_from_str = "now-1y"
        time_to_str = "now"
    
    dashboard = {
        "annotations": {"list": []},
        "editable": True,
        "id": None,
        "panels": panels,
        "schemaVersion": 38,
        "tags": ["sosreport", "sar", "logs", hostname],
        "templating": {"list": []},
        "time": {"from": time_from_str, "to": time_to_str},
        "title": f"SOSreport Analysis - {hostname}",
        "uid": f"web-{safe_host}",
        "version": 1
    }
    
    payload = {"dashboard": dashboard, "folderId": 0, "overwrite": True}
    response = session.post(f"{GRAFANA_URL}/api/dashboards/db", json=payload)
    
    if response.status_code == 200:
        result = response.json()
        return f"{GRAFANA_URL}{result.get('url', '')}"
    
    return None


# ============================================================================
# HEALTH CHECK FUNCTIONS
# ============================================================================

def check_influxdb_health() -> Tuple[bool, str]:
    """Check if InfluxDB is healthy
    
    Returns: (is_healthy, message)
    """
    try:
        response = requests.get(f"{INFLUXDB_URL}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            status = data.get('status', 'unknown')
            if status == 'pass':
                return True, "Healthy"
            return False, f"Status: {status}"
        return False, f"HTTP {response.status_code}"
    except requests.exceptions.ConnectionError:
        return False, "Connection refused"
    except requests.exceptions.Timeout:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)[:30]


def check_loki_health() -> Tuple[bool, str]:
    """Check if Loki is healthy
    
    Returns: (is_healthy, message)
    """
    import socket
    
    # First, check if port is reachable (TCP connection test)
    try:
        # Parse host and port from URL
        host = LOKI_URL.replace("http://", "").replace("https://", "").split(":")[0]
        port = int(LOKI_URL.replace("http://", "").replace("https://", "").split(":")[1].split("/")[0])
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result != 0:
            return False, "Port unreachable"
    except Exception as e:
        return False, f"Socket error: {str(e)[:20]}"
    
    # Port is open, try HTTP endpoints
    try:
        # Try /ready endpoint first
        response = requests.get(f"{LOKI_URL}/ready", timeout=5)
        if response.status_code == 200:
            return True, "Ready"
        
        # Some Loki versions use /loki/api/v1/status/buildinfo
        response = requests.get(f"{LOKI_URL}/loki/api/v1/status/buildinfo", timeout=5)
        if response.status_code == 200:
            return True, "Ready"
        
        # Try the push endpoint with GET (returns 405 but proves Loki is up)
        response = requests.get(f"{LOKI_URL}/loki/api/v1/push", timeout=5)
        if response.status_code in [200, 204, 405]:  # 405 = Method Not Allowed (expected for GET on push)
            return True, "Ready"
        
        return False, f"HTTP {response.status_code}"
    except requests.exceptions.ConnectionError as e:
        error_str = str(e).lower()
        if "remotedisconnected" in error_str or "connection aborted" in error_str:
            # Port is open but HTTP is failing - likely proxy/config issue
            # Since port is reachable, consider it "up but misconfigured"
            return True, "Port open (HTTP issue)"
        return False, "Connection refused"
    except requests.exceptions.Timeout:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)[:30]


def check_grafana_health() -> Tuple[bool, str]:
    """Check if Grafana is healthy
    
    Returns: (is_healthy, message)
    """
    try:
        response = requests.get(f"{GRAFANA_URL}/api/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('database') == 'ok':
                return True, "Healthy"
            return False, f"DB: {data.get('database', 'unknown')}"
        return False, f"HTTP {response.status_code}"
    except requests.exceptions.ConnectionError:
        return False, "Connection refused"
    except requests.exceptions.Timeout:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)[:30]


def get_all_service_status() -> dict:
    """Check all services and return status dict"""
    return {
        'influxdb': check_influxdb_health(),
        'loki': check_loki_health(),
        'grafana': check_grafana_health()
    }


# ============================================================================
# STREAMLIT UI
# ============================================================================

def main():
    st.markdown('<h1 class="main-header">ðŸ“Š SOSreport Analyzer V1</h1>', unsafe_allow_html=True)
    st.markdown("---")
    
    # Sidebar
    with st.sidebar:
        st.header("âš™ï¸ Configuration")
        
        # Session Info
        st.subheader("ðŸ“Š Session Info")
        import uuid
        if 'session_id' not in st.session_state:
            st.session_state.session_id = str(uuid.uuid4())[:8]
        st.text(f"Session: {st.session_state.session_id}")
        
        # Show active extractions
        active_slots = MAX_CONCURRENT_EXTRACTIONS - _extraction_semaphore._value
        st.text(f"Active extractions: {active_slots}/{MAX_CONCURRENT_EXTRACTIONS}")
        
        # Try to show system resources
        try:
            import psutil
            cpu_pct = psutil.cpu_percent()
            mem = psutil.virtual_memory()
            st.progress(cpu_pct / 100, f"CPU: {cpu_pct:.0f}%")
            st.progress(mem.percent / 100, f"Memory: {mem.percent:.0f}%")
        except ImportError:
            pass
        
        st.markdown("---")
        st.subheader("ðŸ”Œ Backend Services")
        
        # Check service health with a button to refresh
        if st.button("ðŸ”„ Check Status", key="health_check"):
            st.session_state.service_status = get_all_service_status()
            st.session_state.last_health_check = datetime.now()
        
        # Get cached status or check on first load
        if 'service_status' not in st.session_state:
            st.session_state.service_status = get_all_service_status()
            st.session_state.last_health_check = datetime.now()
        
        status = st.session_state.service_status
        
        # Display InfluxDB status
        influx_ok, influx_msg = status['influxdb']
        if influx_ok:
            st.markdown(f"ðŸŸ¢ **InfluxDB**: {influx_msg}")
        else:
            st.markdown(f"ðŸ”´ **InfluxDB**: {influx_msg}")
        st.caption(f"   {INFLUXDB_URL}")
        
        # Display Loki status
        loki_ok, loki_msg = status['loki']
        if loki_ok:
            st.markdown(f"ðŸŸ¢ **Loki**: {loki_msg}")
        else:
            st.markdown(f"ðŸ”´ **Loki**: {loki_msg}")
        st.caption(f"   {LOKI_URL}")
        
        # Display Grafana status
        grafana_ok, grafana_msg = status['grafana']
        if grafana_ok:
            st.markdown(f"ðŸŸ¢ **Grafana**: {grafana_msg}")
        else:
            st.markdown(f"ðŸ”´ **Grafana**: {grafana_msg}")
        st.caption(f"   {GRAFANA_URL}")
        
        # Show last check time
        if 'last_health_check' in st.session_state:
            st.caption(f"Last checked: {st.session_state.last_health_check.strftime('%H:%M:%S')}")
        
        # Show warning if any service is down
        all_ok = influx_ok and loki_ok and grafana_ok
        if not all_ok:
            st.warning("âš ï¸ Some services are down!")
        
        st.markdown("---")
        st.markdown("### ðŸ“– Instructions")
        st.markdown("""
        1. Upload a SOSreport file (.tar.xz, .tar.gz)
        2. Wait for extraction and parsing
        3. Review the analysis summary
        4. Push data to InfluxDB/Loki
        5. View dashboard in Grafana
        """)
        
        st.markdown("---")
        st.caption(f"Max concurrent: {MAX_CONCURRENT_EXTRACTIONS}")
        st.caption(f"Max SAR metrics: {MAX_SAR_METRICS:,}")
        st.caption(f"Max log lines: {MAX_LOG_LINES:,}")
    
    # Main area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.header("ðŸ“ Upload SOSreport")
        uploaded_file = st.file_uploader(
            "Choose a SOSreport file",
            type=['tar.xz', 'tar.gz', 'tgz', 'tar.bz2', 'tar'],
            help="Upload a compressed SOSreport file"
        )
    
    with col2:
        st.header("ðŸŽ¯ Options")
        push_sar = st.checkbox("Push SAR to InfluxDB", value=True)
        push_logs = st.checkbox("Push Logs to Loki", value=True)
        create_dashboard = st.checkbox("Create Grafana Dashboard", value=True)
        
        # Advanced options
        with st.expander("âš™ï¸ Advanced Options"):
            add_unique_suffix = st.checkbox(
                "Add unique suffix to hostname", 
                value=False,
                help="Use this if you're re-uploading and see 'out of order' errors. Adds a timestamp suffix to avoid conflicts."
            )
    
    if uploaded_file is not None:
        st.markdown("---")
        
        # Process button
        if st.button("ðŸš€ Process SOSreport", type="primary", use_container_width=True):
            temp_dir = None
            
            try:
                # Progress tracking
                progress_bar = st.progress(0, "Starting...")
                status_text = st.empty()
                
                # Show file info
                file_size_mb = uploaded_file.size / (1024 * 1024)
                st.info(f"ðŸ“ File: {uploaded_file.name} ({file_size_mb:.1f} MB)")
                
                # Extract with concurrency control
                status_text.text("ðŸ“¦ Extracting SOSreport...")
                temp_dir, sosreport_path = extract_sosreport(uploaded_file, progress_bar, status_text)
                
                # Detect system info
                system_info = get_system_info(sosreport_path)
                hostname = system_info['hostname']
                uptime = system_info['uptime']
                sys_date = system_info['date']
                os_release = system_info['os_release']
                
                # Add unique suffix if requested (to avoid Loki out-of-order issues)
                original_hostname = hostname
                if add_unique_suffix:
                    import time
                    suffix = datetime.now().strftime("%Y%m%d_%H%M%S")
                    hostname = f"{hostname}_{suffix}"
                    st.info(f"ðŸ·ï¸ Using unique hostname: `{hostname}` (original: `{original_hostname}`)")
                
                # Get year using improved detection (from date output or filename)
                year = get_report_year(sosreport_path, uploaded_file.name)
                
                progress_bar.progress(50, "Parsing data...")
                status_text.text(f"ðŸ” Detected hostname: {hostname}, Log Year: {year}")
                
                # Parse SAR with limits - pass year and date for proper timestamp handling
                sar_parser = SARParser(sosreport_path, hostname, report_year=year, report_date_str=sys_date)
                sar_files_found = sar_parser.find_sar_files()
                status_text.text(f"ðŸ” Found {len(sar_files_found)} SAR files (source: {sar_parser.sar_source})")
                sar_metrics = sar_parser.parse_all()
                
                # Apply limits to prevent memory issues
                if len(sar_metrics) > MAX_SAR_METRICS:
                    st.warning(f"âš ï¸ SAR metrics limited to {MAX_SAR_METRICS:,} (total: {len(sar_metrics):,})")
                    sar_metrics = sar_metrics[:MAX_SAR_METRICS]
                
                # Parse Logs
                status_text.text("ðŸ“ Parsing log files...")
                log_parser = LogParser(sosreport_path, hostname, year)
                logs = log_parser.parse_all()
                
                # Apply log limits
                if len(logs) > MAX_LOG_LINES:
                    st.warning(f"âš ï¸ Log entries limited to {MAX_LOG_LINES:,} (total: {len(logs):,})")
                    logs = logs[:MAX_LOG_LINES]
                
                # Debug: Show var/log contents
                var_log_path = os.path.join(sosreport_path, 'var', 'log')
                log_dir_contents = []
                if os.path.isdir(var_log_path):
                    log_dir_contents = os.listdir(var_log_path)
                
                progress_bar.progress(70, "Data parsed!")
                
                # Display summary
                st.markdown("---")
                st.header("ðŸ“Š Analysis Summary")
                
                # System Information Box
                st.subheader("ðŸ–¥ï¸ System Information")
                sys_col1, sys_col2 = st.columns(2)
                
                with sys_col1:
                    st.markdown(f"**Hostname:** `{hostname}`")
                    st.markdown(f"**OS Release:** `{os_release}`")
                    st.markdown(f"**Log Year:** `{year}` _(used for log timestamp parsing)_")
                
                with sys_col2:
                    st.markdown(f"**SOSreport Date:** `{sys_date}`")
                    st.markdown(f"**Uptime:** `{uptime}`")
                
                st.markdown("---")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.subheader("ðŸ“Š Totals")
                    st.metric("Total SAR Metrics", f"{len(sar_metrics):,}")
                    st.metric("Total Log Entries", f"{len(logs):,}")
                    st.metric("SAR Files", len(sar_files_found))
                
                with col2:
                    st.subheader("SAR Breakdown")
                    st.write(f"- Load: {sar_parser.summary['load']:,}")
                    st.write(f"- Memory: {sar_parser.summary['memory']:,}")
                    st.write(f"- Disk: {sar_parser.summary['disk']:,}")
                    st.write(f"- Network: {sar_parser.summary['network']:,}")
                    st.write(f"- CPU: {sar_parser.summary['cpu']:,}")
                    if sar_files_found:
                        with st.expander("Show SAR files"):
                            # Show source location
                            if hasattr(sar_parser, 'sar_source'):
                                st.caption(f"ðŸ“‚ Source: {sar_parser.sar_source}")
                            for f in sar_files_found:
                                st.text(os.path.basename(f))
                    
                    # Debug: Show disk field names found
                    if sar_parser.summary['disk'] > 0:
                        with st.expander("ðŸ” Debug: Disk fields"):
                            disk_fields = set()
                            disk_devices = set()
                            for m in sar_metrics:
                                if m.get('measurement') == 'sar_disk':
                                    disk_devices.add(m.get('device', 'unknown'))
                                    for k in m.get('fields', {}).keys():
                                        if k != 'DEV':
                                            disk_fields.add(k)
                            st.write(f"**Devices:** {', '.join(sorted(disk_devices))}")
                            st.write(f"**Fields:** {', '.join(sorted(disk_fields))}")
                            st.caption("InfluxDB transforms: / â†’ _ and % â†’ pct_")
                    
                    # Debug: Show SAR dates parsed
                    with st.expander("ðŸ“… Debug: SAR dates"):
                        # Show parsing context
                        st.write("**ðŸ”§ Parsing context:**")
                        st.text(f"  Report year: {sar_parser.report_year}")
                        st.text(f"  Report month: {sar_parser.report_month}")
                        st.text(f"  Report day: {sar_parser.report_day}")
                        st.text(f"  Report date str: {sar_parser.report_date_str}")
                        
                        st.write("**Date detected per SAR file:**")
                        if hasattr(sar_parser, 'debug_file_dates') and sar_parser.debug_file_dates:
                            for filename, date_str in sorted(sar_parser.debug_file_dates.items()):
                                st.text(f"  {filename}: {date_str}")
                        else:
                            st.warning("No date info available")
                        
                        # Show header info for debugging
                        st.write("**ðŸ“ SAR file headers (first line):**")
                        if hasattr(sar_parser, 'debug_header_info') and sar_parser.debug_header_info:
                            for filename, info in sorted(sar_parser.debug_header_info.items()):
                                header_lines = info.get('header_lines', [])
                                date_from_header = info.get('date_from_header', 'None')
                                if header_lines:
                                    st.text(f"  {filename}:")
                                    st.text(f"    Header: {header_lines[0][:80]}")
                                    st.text(f"    Date extracted: {date_from_header}")
                        
                        # Show XML elements debug info
                        if hasattr(sar_parser, 'debug_xml_elements') and sar_parser.debug_xml_elements:
                            st.write("**ðŸ” XML elements found (first file sample):**")
                            # Show first file's debug info
                            sample_file = sorted(sar_parser.debug_xml_elements.keys())[0]
                            elem_info = sar_parser.debug_xml_elements[sample_file]
                            st.text(f"  File: {sample_file}")
                            st.text(f"    timestamps: {elem_info.get('timestamps', 0)}, cpu: {elem_info.get('cpu', 0)}, queue: {elem_info.get('queue', 0)}")
                            st.text(f"    memory: {elem_info.get('memory', 0)}, disk: {elem_info.get('disk', 0)}, net: {elem_info.get('net', 0)}")
                            if elem_info.get('sample_ts_date'):
                                st.text(f"    First timestamp date: {elem_info['sample_ts_date']}")
                            if elem_info.get('sample_cpu_attrs'):
                                st.text(f"    CPU attrs: {elem_info['sample_cpu_attrs']}")
                            if elem_info.get('sample_mem_attrs'):
                                st.text(f"    Memory children: {elem_info['sample_mem_attrs']}")
                            # Show disk children (for debugging util field)
                            if hasattr(sar_parser, 'debug_disk_children') and sar_parser.debug_disk_children:
                                st.text(f"    Disk children: {sar_parser.debug_disk_children}")
                        
                        st.write("**ðŸ“Š SAR metrics by date:**")
                        if hasattr(sar_parser, 'metrics_by_date') and sar_parser.metrics_by_date:
                            for date_str in sorted(sar_parser.metrics_by_date.keys()):
                                count = sar_parser.metrics_by_date[date_str]
                                st.text(f"  {date_str}: {count:,} metrics")
                        else:
                            st.warning("No metrics date info")
                        
                        # Show date range
                        if sar_metrics:
                            timestamps = [m['timestamp'] for m in sar_metrics if m.get('timestamp')]
                            if timestamps:
                                min_ts = min(timestamps)
                                max_ts = max(timestamps)
                                st.write(f"**Date range:** {min_ts.strftime('%Y-%m-%d %H:%M')} to {max_ts.strftime('%Y-%m-%d %H:%M')}")
                
                with col3:
                    st.subheader("Log Entries")
                    st.write(f"- Messages: {log_parser.summary['messages']:,}")
                    st.write(f"- Secure: {log_parser.summary['secure']:,}")
                    st.write(f"- Audit: {log_parser.summary['audit']:,}")
                    st.write(f"- Cron: {log_parser.summary['cron']:,}")
                    # Show found log files and var/log contents
                    with st.expander("ðŸ” Debug: Log files info"):
                        st.write("**Files in var/log:**")
                        if log_dir_contents:
                            for item in sorted(log_dir_contents):
                                st.text(f"  {item}")
                        else:
                            st.warning("var/log directory not found or empty")
                        
                        st.write("**Files in sos_commands/logs:**")
                        if hasattr(log_parser, 'debug_sos_logs_dir') and log_parser.debug_sos_logs_dir:
                            for item in sorted(log_parser.debug_sos_logs_dir):
                                st.text(f"  {item}")
                        else:
                            st.warning("sos_commands/logs not found or empty")
                        
                        st.write("**Log files found by parser:**")
                        if hasattr(log_parser, 'found_files'):
                            for log_type, files in log_parser.found_files.items():
                                st.write(f"**{log_type}:** {len(files)} files")
                                for f in files:
                                    st.text(f"  - {os.path.basename(f)}")
                        
                        # Show log entries by date
                        st.write("**ðŸ“… Log entries by date:**")
                        if hasattr(log_parser, 'logs_by_date') and log_parser.logs_by_date:
                            for date_str in sorted(log_parser.logs_by_date.keys()):
                                count = log_parser.logs_by_date[date_str]
                                st.text(f"  {date_str}: {count:,} entries")
                        else:
                            st.warning("No date breakdown available")
                        
                        # Show dates found in each file
                        st.write("**ðŸ“‚ Dates per file (messages only):**")
                        if hasattr(log_parser, 'debug_file_dates') and log_parser.debug_file_dates:
                            for filename, dates in sorted(log_parser.debug_file_dates.items()):
                                if 'messages' in filename.lower():
                                    if dates:
                                        st.text(f"  {filename}: {', '.join(dates)}")
                                    else:
                                        st.text(f"  {filename}: (no dates parsed)")
                        else:
                            st.warning("No per-file date info available")
                    st.metric("Total Logs", f"{len(logs):,}")
                
                # Push data
                st.markdown("---")
                st.header("ðŸ“¤ Data Upload")
                
                results = {}
                
                if push_sar and sar_metrics:
                    progress_bar.progress(75, "Pushing SAR to InfluxDB...")
                    status_text.text(f"ðŸ“¤ Pushing {len(sar_metrics):,} SAR metrics to InfluxDB...")
                    pushed_sar, push_error = push_sar_to_influxdb(sar_metrics, hostname)
                    results['sar'] = pushed_sar
                    if pushed_sar > 0:
                        st.success(f"âœ… Pushed {pushed_sar:,} SAR metrics to InfluxDB")
                        
                        # Verify data in InfluxDB by querying time range
                        try:
                            verify_url = f"{INFLUXDB_URL}/api/v2/query?org={INFLUXDB_ORG}"
                            verify_headers = {
                                "Authorization": f"Token {INFLUXDB_TOKEN}",
                                "Content-Type": "application/vnd.flux"
                            }
                            verify_query = f'''
from(bucket: "{INFLUXDB_BUCKET}")
  |> range(start: -365d)
  |> filter(fn: (r) => r["host"] == "{hostname}")
  |> filter(fn: (r) => r["_measurement"] == "sar_load")
  |> group()
  |> first()
'''
                            verify_query2 = f'''
from(bucket: "{INFLUXDB_BUCKET}")
  |> range(start: -365d)
  |> filter(fn: (r) => r["host"] == "{hostname}")
  |> filter(fn: (r) => r["_measurement"] == "sar_load")
  |> group()
  |> last()
'''
                            resp1 = requests.post(verify_url, headers=verify_headers, data=verify_query, timeout=10)
                            resp2 = requests.post(verify_url, headers=verify_headers, data=verify_query2, timeout=10)
                            
                            if resp1.status_code == 200 and resp2.status_code == 200:
                                st.info(f"ðŸ“Š **InfluxDB Verification:** Query for host='{hostname}' completed. Check Grafana with time range matching your data.")
                                with st.expander("ðŸ” Debug: InfluxDB Query Response"):
                                    st.write("**First record response (truncated):**")
                                    st.code(resp1.text[:500] if resp1.text else "Empty response", language="text")
                                    st.write("**Last record response (truncated):**")
                                    st.code(resp2.text[:500] if resp2.text else "Empty response", language="text")
                        except Exception as e:
                            st.warning(f"Could not verify InfluxDB data: {str(e)[:100]}")
                    else:
                        st.warning(f"âš ï¸ No SAR metrics pushed to InfluxDB")
                    if push_error:
                        st.error(f"âŒ InfluxDB errors: {push_error}")
                
                if push_logs and logs:
                    progress_bar.progress(85, "Pushing Logs to Loki...")
                    status_text.text("ðŸ“¤ Pushing logs to Loki...")
                    pushed_logs, loki_error = push_logs_to_loki(logs, hostname)
                    results['logs'] = pushed_logs
                    if pushed_logs > 0:
                        st.success(f"âœ… Pushed {pushed_logs:,} log entries to Loki")
                    else:
                        st.warning(f"âš ï¸ No log entries pushed to Loki")
                    if loki_error:
                        st.error(f"âŒ Loki errors: {loki_error}")
                        st.info("ðŸ’¡ **Tip**: If you see 'out of order' errors, this means logs for this host with newer timestamps already exist in Loki. Try deleting previous data or using a different host label.")
                
                # Create dashboard with auto time range
                if create_dashboard:
                    progress_bar.progress(95, "Creating Grafana dashboard...")
                    status_text.text("ðŸ“Š Creating Grafana dashboard...")
                    
                    # Get time range from parsed data
                    time_from, time_to = get_time_range(sar_metrics, logs)
                    if time_from and time_to:
                        st.info(f"ðŸ“… Auto time range: {time_from.strftime('%Y-%m-%d %H:%M')} to {time_to.strftime('%Y-%m-%d %H:%M')}")
                    
                    dashboard_url = create_grafana_dashboard(hostname, time_from, time_to)
                    
                    if dashboard_url:
                        results['dashboard'] = dashboard_url
                        st.success(f"âœ… Dashboard created!")
                        st.markdown(f"ðŸ”— [Open Dashboard]({dashboard_url})")
                
                progress_bar.progress(100, "Complete!")
                status_text.text("âœ… Processing complete!")
                
                # Final summary
                st.markdown("---")
                st.header("ðŸŽ‰ Results")
                
                st.markdown(f"""
                <div class="success-box">
                    <h3>Processing Complete!</h3>
                    <p><strong>Hostname:</strong> {hostname}</p>
                    <p><strong>SAR Metrics Pushed:</strong> {results.get('sar', 0):,}</p>
                    <p><strong>Log Entries Pushed:</strong> {results.get('logs', 0):,}</p>
                    <p><strong>Dashboard:</strong> <a href="{results.get('dashboard', '#')}" target="_blank">Open in new tab â†—</a></p>
                </div>
                """, unsafe_allow_html=True)
                
                # Embed Grafana Dashboard
                if results.get('dashboard'):
                    st.markdown("---")
                    st.header("ðŸ“Š Grafana Dashboard")
                    
                    # Convert dashboard URL to embed format
                    dashboard_url = results.get('dashboard')
                    # Add parameters for embedding (hide controls, auto-refresh)
                    if '?' in dashboard_url:
                        embed_url = f"{dashboard_url}&kiosk=tv&refresh=30s"
                    else:
                        embed_url = f"{dashboard_url}?kiosk=tv&refresh=30s"
                    
                    st.markdown(f"""
                    <div style="margin-top: 1rem;">
                        <p>ðŸ’¡ <em>Tip: Set the time range in Grafana to match your SOSreport date to see the data.</em></p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Embed dashboard in iframe
                    components.iframe(
                        src=embed_url,
                        height=800,
                        scrolling=True
                    )
                
            except Exception as e:
                st.error(f"âŒ Error processing SOSreport: {str(e)}")
            
            finally:
                # Cleanup
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
    
    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: gray;'>"
        "SOSreport Analyzer V1 | Powered by Streamlit, InfluxDB, Loki & Grafana"
        "</div>",
        unsafe_allow_html=True
    )


if __name__ == "__main__":
    main()
