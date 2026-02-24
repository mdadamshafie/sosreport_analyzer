"""
SOSreport Analyzer - Streamlit Web Application
Upload SOSreport files and analyze SAR metrics + Logs with automatic Grafana integration

Multi-user optimized with caching and resource management.
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
from datetime import datetime
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

# AI Configuration (GitHub Models - Free Tier)
AI_ENDPOINT = "https://models.github.ai/inference"
AI_MODEL = "openai/gpt-4.1-mini"  # Fast and cost-effective

# Performance Configuration
MAX_CONCURRENT_EXTRACTIONS = 3  # Limit concurrent heavy operations
MAX_LOG_LINES = 500000  # Limit log lines to prevent memory issues
MAX_SAR_METRICS = 1000000  # Limit SAR metrics
EXTRACTION_TIMEOUT = 300  # 5 minute timeout for extraction
# ============================================================================

# Thread pool for extraction (shared across sessions but limited)
_extraction_semaphore = threading.Semaphore(MAX_CONCURRENT_EXTRACTIONS)

st.set_page_config(
    page_title="SOSreport Analyzer",
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


def _detect_date_original(sosreport_path: str) -> str:
    """Original detect date - kept for reference"""
    date_files = [
        os.path.join(sosreport_path, "sos_commands", "date", "date"),
        os.path.join(sosreport_path, "date"),
    ]
    
    for df in date_files:
        if os.path.isfile(df):
            try:
                with open(df, 'r') as f:
                    date_str = f.read().strip()
                    if date_str:
                        return date_str
            except:
                continue
    
    return "N/A"


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


# ============================================================================
# SAR PARSER
# ============================================================================

class SARParser:
    """Parse SAR data from sosreport - improved version"""
    
    TIMESTAMP_PATTERN = r'^(\d{2}:\d{2}:\d{2})\s*(AM|PM)?'
    DATE_PATTERN = r'(\d{2}/\d{2}/\d{4}|\d{4}-\d{2}-\d{2})'
    
    def __init__(self, sosreport_path: str, hostname: str):
        self.sosreport_path = sosreport_path
        self.hostname = hostname
        self.metrics = []
        self.date = None
        self.summary = {
            'load': 0,
            'memory': 0,
            'disk': 0,
            'network': 0,
            'cpu': 0
        }
    
    def find_sar_files(self) -> List[str]:
        """Find SAR files in sosreport"""
        import glob
        sar_paths = [
            os.path.join(self.sosreport_path, "sos_commands", "sar", "*"),
            os.path.join(self.sosreport_path, "var", "log", "sa", "sar*"),
            os.path.join(self.sosreport_path, "var", "log", "sa", "sa[0-9]*"),
        ]
        
        sar_files = []
        for pattern in sar_paths:
            found = glob.glob(pattern)
            sar_files.extend(found)
        
        # Filter for text SAR files only (not binary .bin files)
        result = []
        for f in sar_files:
            if os.path.isfile(f) and not f.endswith('.bin'):
                # Check if it's a text file by reading first line
                try:
                    with open(f, 'r', encoding='utf-8', errors='ignore') as file:
                        first_line = file.readline()
                        # SAR text files usually start with Linux or have timestamps
                        if 'Linux' in first_line or any(c.isdigit() for c in first_line[:20]):
                            result.append(f)
                except:
                    pass
        
        return result
    
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
    
    def parse_file(self, filepath: str) -> List[dict]:
        """Parse a single SAR file"""
        metrics = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            return metrics
        
        # Extract date from header
        for line in lines[:10]:
            date = self.parse_date_from_header(line)
            if date:
                self.date = date
                break
        
        if not self.date:
            # Try to extract date from file name (like sar20)
            basename = os.path.basename(filepath)
            match = re.search(r'sar(\d{2})', basename)
            if match:
                day = match.group(1)
                # Use current year/month as fallback
                from datetime import date as dt_date
                today = dt_date.today()
                self.date = f"{today.month:02d}/{day}/{today.year}"
        
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
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            ts, program, msg = self.parse_syslog_line(line)
            if ts:
                entries.append({
                    'timestamp': ts,
                    'source': source,
                    'program': program,
                    'message': msg
                })
        
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
        
        # Messages - all variations including rotated and compressed
        patterns = [
            os.path.join(var_log, 'messages'),
            os.path.join(var_log, 'messages-*'),        # messages-20260101
            os.path.join(var_log, 'messages.[0-9]*'),   # messages.1, messages.2
            os.path.join(var_log, 'messages*.gz'),      # messages.1.gz, messages-20260101.gz
            os.path.join(self.sosreport_path, 'sos_commands', 'logs', '*messages*'),
        ]
        for p in patterns:
            found_files['messages'].extend(glob.glob(p))
        
        # Secure - all variations including rotated and compressed
        patterns = [
            os.path.join(var_log, 'secure'),
            os.path.join(var_log, 'secure-*'),          # secure-20260101
            os.path.join(var_log, 'secure.[0-9]*'),     # secure.1, secure.2
            os.path.join(var_log, 'secure*.gz'),        # secure.1.gz, secure-20260101.gz
            os.path.join(self.sosreport_path, 'sos_commands', 'logs', '*secure*'),
        ]
        for p in patterns:
            found_files['secure'].extend(glob.glob(p))
        
        # Audit - all variations including rotated and compressed
        audit_log = os.path.join(var_log, 'audit')
        patterns = [
            os.path.join(audit_log, 'audit.log'),
            os.path.join(audit_log, 'audit.log.[0-9]*'),  # audit.log.1, audit.log.2
            os.path.join(audit_log, 'audit.log*.gz'),     # compressed
            os.path.join(self.sosreport_path, 'sos_commands', 'auditd', '*'),
        ]
        for p in patterns:
            found_files['audit'].extend(glob.glob(p))
        
        # Cron - all variations including rotated and compressed
        patterns = [
            os.path.join(var_log, 'cron'),
            os.path.join(var_log, 'cron-*'),            # cron-20260101
            os.path.join(var_log, 'cron.[0-9]*'),       # cron.1, cron.2
            os.path.join(var_log, 'cron*.gz'),          # compressed
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
        
        return self.logs


# ============================================================================
# CRITICAL EVENTS DETECTOR
# ============================================================================

class CriticalEventsDetector:
    """Detect critical system events from logs for RCA"""
    
    # Patterns for critical events
    PATTERNS = {
        'oom_kill': {
            'pattern': r'(Out of memory|oom-killer|Killed process|invoked oom-killer)',
            'severity': 'critical',
            'category': 'Memory',
            'description': 'Out of Memory Killer activated'
        },
        'kernel_panic': {
            'pattern': r'(Kernel panic|BUG:|kernel BUG|Oops:|general protection fault)',
            'severity': 'critical',
            'category': 'Kernel',
            'description': 'Kernel panic or bug detected'
        },
        'disk_error': {
            'pattern': r'(I/O error|Buffer I/O error|EXT4-fs error|XFS.*error|failed command|WRITE FPDMA|READ FPDMA|medium error|sector|blk_update_request)',
            'severity': 'critical',
            'category': 'Disk',
            'description': 'Disk I/O error detected'
        },
        'disk_full': {
            'pattern': r'(No space left on device|filesystem.*full|disk quota exceeded)',
            'severity': 'high',
            'category': 'Disk',
            'description': 'Disk space exhausted'
        },
        'service_failure': {
            'pattern': r'(Failed to start|service.*failed|systemd.*failed|Unit.*failed)',
            'severity': 'high',
            'category': 'Service',
            'description': 'Service/Unit failed to start'
        },
        'segfault': {
            'pattern': r'(segfault at|SIGSEGV|Segmentation fault)',
            'severity': 'high',
            'category': 'Application',
            'description': 'Application segmentation fault'
        },
        'hardware_error': {
            'pattern': r'(Hardware Error|Machine check|MCE|ACPI Error|hardware error)',
            'severity': 'critical',
            'category': 'Hardware',
            'description': 'Hardware error detected'
        },
        'network_error': {
            'pattern': r'(link is not ready|link down|carrier lost|NIC Link is Down|network unreachable)',
            'severity': 'high',
            'category': 'Network',
            'description': 'Network link error'
        },
        'auth_failure': {
            'pattern': r'(authentication failure|Failed password|FAILED LOGIN|pam_unix.*authentication failure)',
            'severity': 'medium',
            'category': 'Security',
            'description': 'Authentication failure'
        },
        'sudo_usage': {
            'pattern': r'(sudo:.*COMMAND=|sudo:.*USER=root)',
            'severity': 'info',
            'category': 'Security',
            'description': 'Sudo command executed'
        },
        'reboot': {
            'pattern': r'(System is rebooting|Shutting down|systemd.*Reached target Shutdown|reboot:|Initializing cgroup)',
            'severity': 'high',
            'category': 'System',
            'description': 'System reboot detected'
        },
        'time_sync': {
            'pattern': r'(time.*(jumped|changed|adjusted)|chronyd|ntpd.*(sync|step))',
            'severity': 'medium',
            'category': 'System',
            'description': 'Time synchronization event'
        },
        'selinux_denial': {
            'pattern': r'(avc:.*denied|SELinux.*denied|type=AVC)',
            'severity': 'medium',
            'category': 'Security',
            'description': 'SELinux denial'
        },
        'memory_pressure': {
            'pattern': r'(page allocation failure|free_kbytes|low on memory)',
            'severity': 'high',
            'category': 'Memory',
            'description': 'Memory pressure detected'
        },
        'cpu_throttle': {
            'pattern': r'(cpu clock throttled|CPU.*throttling|thermal)',
            'severity': 'medium',
            'category': 'CPU',
            'description': 'CPU throttling detected'
        },
    }
    
    def __init__(self):
        self.events = []
        self.summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'info': 0
        }
        self.by_category = {}
    
    def detect_events(self, logs: List[dict]) -> List[dict]:
        """Detect critical events from log entries"""
        self.events = []
        
        for log in logs:
            message = log.get('message', '')
            full_text = f"{log.get('program', '')} {message}"
            
            for event_type, config in self.PATTERNS.items():
                if re.search(config['pattern'], full_text, re.IGNORECASE):
                    event = {
                        'timestamp': log.get('timestamp'),
                        'type': event_type,
                        'severity': config['severity'],
                        'category': config['category'],
                        'description': config['description'],
                        'source': log.get('source', 'unknown'),
                        'program': log.get('program', ''),
                        'message': message[:500]  # Truncate long messages
                    }
                    self.events.append(event)
                    self.summary[config['severity']] += 1
                    
                    # Track by category
                    cat = config['category']
                    if cat not in self.by_category:
                        self.by_category[cat] = []
                    self.by_category[cat].append(event)
                    break  # One event type per log line
        
        return self.events
    
    def get_critical_summary(self) -> dict:
        """Get summary of critical events"""
        return {
            'total': len(self.events),
            'by_severity': self.summary.copy(),
            'by_category': {k: len(v) for k, v in self.by_category.items()},
            'critical_events': [e for e in self.events if e['severity'] == 'critical'][:20],
            'high_events': [e for e in self.events if e['severity'] == 'high'][:20]
        }


# ============================================================================
# TIMELINE BUILDER
# ============================================================================

class TimelineBuilder:
    """Build unified timeline of all events"""
    
    def __init__(self):
        self.events = []
    
    def add_sar_anomalies(self, anomalies: List[dict]):
        """Add SAR anomalies to timeline"""
        for a in anomalies:
            ts = a.get('timestamp')
            if ts:
                self.events.append({
                    'timestamp': ts,
                    'type': 'sar_anomaly',
                    'category': a.get('measurement', 'SAR').replace('sar_', '').title(),
                    'severity': a.get('severity', 'medium'),
                    'description': f"{a['metric']}: {a['value']:.2f} ({a.get('threshold', '')})",
                    'icon': 'ðŸ“Š'
                })
    
    def add_critical_events(self, events: List[dict]):
        """Add critical events to timeline"""
        for e in events:
            ts = e.get('timestamp')
            if ts:
                icon = {
                    'critical': 'ðŸ”´',
                    'high': 'ðŸŸ ',
                    'medium': 'ðŸŸ¡',
                    'info': 'ðŸ”µ'
                }.get(e.get('severity', 'info'), 'âšª')
                
                self.events.append({
                    'timestamp': ts,
                    'type': 'critical_event',
                    'category': e.get('category', 'Unknown'),
                    'severity': e.get('severity', 'medium'),
                    'description': f"{e['description']}: {e['message'][:100]}",
                    'icon': icon
                })
    
    def add_log_events(self, logs: List[dict], sample_rate: int = 100):
        """Add sampled log events to timeline (to avoid overwhelming)"""
        # Only add every Nth log to avoid too many events
        for i, log in enumerate(logs):
            if i % sample_rate == 0:
                ts = log.get('timestamp')
                if ts:
                    self.events.append({
                        'timestamp': ts,
                        'type': 'log',
                        'category': log.get('source', 'log').title(),
                        'severity': 'info',
                        'description': f"[{log.get('program', '')}] {log.get('message', '')[:80]}",
                        'icon': 'ðŸ“'
                    })
    
    def build_timeline(self) -> List[dict]:
        """Build sorted timeline"""
        # Sort by timestamp
        self.events.sort(key=lambda x: x.get('timestamp') or datetime.min)
        return self.events
    
    def get_timeline_df(self) -> pd.DataFrame:
        """Get timeline as DataFrame for display"""
        if not self.events:
            return pd.DataFrame()
        
        data = []
        for e in self.events:
            ts = e.get('timestamp')
            data.append({
                'Time': ts.strftime("%Y-%m-%d %H:%M:%S") if ts else '',
                'Icon': e.get('icon', ''),
                'Category': e.get('category', ''),
                'Severity': e.get('severity', '').upper(),
                'Description': e.get('description', '')[:100]
            })
        
        return pd.DataFrame(data)


# ============================================================================
# SAR METRICS ANALYZER (Per-Device/Per-CPU)
# ============================================================================

class SARMetricsAnalyzer:
    """Analyze SAR metrics with per-device and per-CPU breakdown"""
    
    def __init__(self, metrics: List[dict]):
        self.metrics = metrics
        self.cpu_stats = {}
        self.disk_stats = {}
        self.network_stats = {}
        self.peak_values = {}
        self._analyze()
    
    def _analyze(self):
        """Analyze all metrics"""
        for m in self.metrics:
            measurement = m.get('measurement', '')
            fields = m.get('fields', {})
            timestamp = m.get('timestamp')
            
            if measurement == 'sar_cpu':
                cpu_id = m.get('cpu', fields.get('cpu', 'all'))
                if cpu_id not in self.cpu_stats:
                    self.cpu_stats[cpu_id] = {'samples': 0, 'total_user': 0, 'total_system': 0, 
                                               'total_idle': 0, 'min_idle': 100, 'max_user': 0}
                
                stats = self.cpu_stats[cpu_id]
                stats['samples'] += 1
                user = fields.get('pct_user', 0)
                system = fields.get('pct_system', 0)
                idle = fields.get('pct_idle', 100)
                
                stats['total_user'] += user
                stats['total_system'] += system
                stats['total_idle'] += idle
                stats['min_idle'] = min(stats['min_idle'], idle)
                stats['max_user'] = max(stats['max_user'], user)
                
                if idle < stats.get('min_idle_time', (100, None))[0]:
                    stats['min_idle_time'] = (idle, timestamp)
            
            elif measurement == 'sar_disk':
                device = m.get('device', fields.get('DEV', 'unknown'))
                if device not in self.disk_stats:
                    self.disk_stats[device] = {'samples': 0, 'total_read': 0, 'total_write': 0,
                                                'max_util': 0, 'max_read': 0, 'max_write': 0}
                
                stats = self.disk_stats[device]
                stats['samples'] += 1
                read_kb = fields.get('rkB_s', fields.get('rkB/s', 0))
                write_kb = fields.get('wkB_s', fields.get('wkB/s', 0))
                util = fields.get('pct_util', fields.get('%util', 0))
                
                stats['total_read'] += read_kb
                stats['total_write'] += write_kb
                stats['max_util'] = max(stats['max_util'], util)
                stats['max_read'] = max(stats['max_read'], read_kb)
                stats['max_write'] = max(stats['max_write'], write_kb)
                
                if util > stats.get('max_util_time', (0, None))[0]:
                    stats['max_util_time'] = (util, timestamp)
            
            elif measurement == 'sar_network':
                iface = m.get('interface', fields.get('IFACE', 'unknown'))
                if iface not in self.network_stats:
                    self.network_stats[iface] = {'samples': 0, 'total_rx': 0, 'total_tx': 0,
                                                  'max_rx': 0, 'max_tx': 0}
                
                stats = self.network_stats[iface]
                stats['samples'] += 1
                rx = fields.get('rxkB_s', fields.get('rxkB/s', 0))
                tx = fields.get('txkB_s', fields.get('txkB/s', 0))
                
                stats['total_rx'] += rx
                stats['total_tx'] += tx
                stats['max_rx'] = max(stats['max_rx'], rx)
                stats['max_tx'] = max(stats['max_tx'], tx)
            
            elif measurement == 'sar_load':
                ldavg = fields.get('ldavg_1', 0)
                if ldavg > self.peak_values.get('load', (0, None))[0]:
                    self.peak_values['load'] = (ldavg, timestamp)
            
            elif measurement == 'sar_memory':
                memused = fields.get('pct_memused', 0)
                if memused > self.peak_values.get('memory', (0, None))[0]:
                    self.peak_values['memory'] = (memused, timestamp)
    
    def get_cpu_breakdown(self) -> pd.DataFrame:
        """Get per-CPU breakdown"""
        if not self.cpu_stats:
            return pd.DataFrame()
        
        data = []
        for cpu_id, stats in sorted(self.cpu_stats.items()):
            if stats['samples'] > 0:
                data.append({
                    'CPU': cpu_id,
                    'Avg %User': f"{stats['total_user']/stats['samples']:.1f}",
                    'Avg %System': f"{stats['total_system']/stats['samples']:.1f}",
                    'Avg %Idle': f"{stats['total_idle']/stats['samples']:.1f}",
                    'Min %Idle': f"{stats['min_idle']:.1f}",
                    'Max %User': f"{stats['max_user']:.1f}",
                    'Samples': stats['samples']
                })
        return pd.DataFrame(data)
    
    def get_disk_breakdown(self) -> pd.DataFrame:
        """Get per-disk breakdown"""
        if not self.disk_stats:
            return pd.DataFrame()
        
        data = []
        for device, stats in sorted(self.disk_stats.items()):
            if stats['samples'] > 0 and device not in ['DEV']:
                data.append({
                    'Device': device,
                    'Avg Read KB/s': f"{stats['total_read']/stats['samples']:.1f}",
                    'Avg Write KB/s': f"{stats['total_write']/stats['samples']:.1f}",
                    'Max Read KB/s': f"{stats['max_read']:.1f}",
                    'Max Write KB/s': f"{stats['max_write']:.1f}",
                    'Max %Util': f"{stats['max_util']:.1f}",
                    'Samples': stats['samples']
                })
        return pd.DataFrame(data)
    
    def get_network_breakdown(self) -> pd.DataFrame:
        """Get per-interface breakdown"""
        if not self.network_stats:
            return pd.DataFrame()
        
        data = []
        for iface, stats in sorted(self.network_stats.items()):
            if stats['samples'] > 0 and iface not in ['IFACE']:
                data.append({
                    'Interface': iface,
                    'Avg RX KB/s': f"{stats['total_rx']/stats['samples']:.1f}",
                    'Avg TX KB/s': f"{stats['total_tx']/stats['samples']:.1f}",
                    'Max RX KB/s': f"{stats['max_rx']:.1f}",
                    'Max TX KB/s': f"{stats['max_tx']:.1f}",
                    'Samples': stats['samples']
                })
        return pd.DataFrame(data)
    
    def get_peak_report(self) -> List[dict]:
        """Get peak usage report"""
        peaks = []
        
        if 'load' in self.peak_values:
            val, ts = self.peak_values['load']
            peaks.append({
                'metric': 'Load Average',
                'value': f"{val:.2f}",
                'timestamp': ts.strftime("%Y-%m-%d %H:%M:%S") if ts else 'N/A'
            })
        
        if 'memory' in self.peak_values:
            val, ts = self.peak_values['memory']
            peaks.append({
                'metric': 'Memory Usage',
                'value': f"{val:.1f}%",
                'timestamp': ts.strftime("%Y-%m-%d %H:%M:%S") if ts else 'N/A'
            })
        
        # Add disk peaks
        for device, stats in self.disk_stats.items():
            if stats['max_util'] > 50:  # Only show if notable
                ts_data = stats.get('max_util_time', (0, None))
                ts = ts_data[1] if ts_data else None
                peaks.append({
                    'metric': f'Disk {device} Util',
                    'value': f"{stats['max_util']:.1f}%",
                    'timestamp': ts.strftime("%Y-%m-%d %H:%M:%S") if ts else 'N/A'
                })
        
        # Add CPU peaks
        for cpu_id, stats in self.cpu_stats.items():
            if stats['min_idle'] < 20:  # Only show if CPU was heavily used
                ts_data = stats.get('min_idle_time', (100, None))
                ts = ts_data[1] if ts_data else None
                peaks.append({
                    'metric': f'CPU {cpu_id} (min idle)',
                    'value': f"{stats['min_idle']:.1f}%",
                    'timestamp': ts.strftime("%Y-%m-%d %H:%M:%S") if ts else 'N/A'
                })
        
        return peaks


# ============================================================================
# AI ANALYSIS
# ============================================================================

class AIAnalyzer:
    """AI-powered analysis of SAR metrics and logs"""
    
    def __init__(self, github_token: str = None):
        self.token = github_token or os.environ.get("GITHUB_TOKEN", "")
        self.endpoint = AI_ENDPOINT
        self.model = AI_MODEL
        
    def is_configured(self) -> bool:
        """Check if AI is configured"""
        return bool(self.token)
    
    def detect_anomalies(self, sar_metrics: List[dict]) -> List[dict]:
        """Detect anomalies in SAR metrics based on thresholds"""
        anomalies = []
        
        # Thresholds
        thresholds = {
            'ldavg_1': 4.0,       # Load average > 4 per CPU
            'ldavg_5': 3.0,
            'pct_memused': 90.0,  # Memory usage > 90%
            'pct_commit': 100.0,  # Commit > 100%
            'pct_util': 80.0,     # Disk util > 80%
            '%util': 80.0,
            'pct_idle': 10.0,     # CPU idle < 10% (inverted)
        }
        
        for metric in sar_metrics:
            measurement = metric.get('measurement', '')
            timestamp = metric.get('timestamp')
            fields = metric.get('fields', {})
            
            for field, value in fields.items():
                if not isinstance(value, (int, float)):
                    continue
                    
                threshold = thresholds.get(field)
                if threshold:
                    if field == 'pct_idle':
                        # Inverted - low idle is bad
                        if value < threshold:
                            anomalies.append({
                                'timestamp': timestamp,
                                'measurement': measurement,
                                'metric': field,
                                'value': value,
                                'threshold': f"< {threshold}",
                                'severity': 'high' if value < 5 else 'medium'
                            })
                    else:
                        if value > threshold:
                            anomalies.append({
                                'timestamp': timestamp,
                                'measurement': measurement,
                                'metric': field,
                                'value': value,
                                'threshold': f"> {threshold}",
                                'severity': 'high' if value > threshold * 1.2 else 'medium'
                            })
        
        return anomalies
    
    def correlate_logs_with_anomalies(self, anomalies: List[dict], logs: List[dict], 
                                       time_window_seconds: int = 300) -> List[dict]:
        """Find logs that occurred around anomaly times"""
        correlated = []
        
        for anomaly in anomalies:
            anomaly_time = anomaly.get('timestamp')
            if not anomaly_time:
                continue
                
            related_logs = []
            for log in logs:
                log_time = log.get('timestamp')
                if not log_time:
                    continue
                    
                # Check if log is within time window of anomaly
                time_diff = abs((log_time - anomaly_time).total_seconds())
                if time_diff <= time_window_seconds:
                    related_logs.append({
                        'time': log_time.strftime("%Y-%m-%d %H:%M:%S"),
                        'source': log.get('source', 'unknown'),
                        'program': log.get('program', ''),
                        'message': log.get('message', '')[:200]  # Truncate
                    })
            
            if related_logs:
                correlated.append({
                    'anomaly': anomaly,
                    'related_logs': related_logs[:10]  # Limit to 10 logs per anomaly
                })
        
        return correlated
    
    def generate_ai_summary(self, hostname: str, anomalies: List[dict], 
                           correlated_data: List[dict], sar_summary: dict,
                           log_summary: dict) -> str:
        """Generate AI-powered analysis summary"""
        if not self.is_configured():
            return "âš ï¸ AI analysis not available. Please configure GITHUB_TOKEN in the sidebar."
        
        try:
            from openai import OpenAI
            
            client = OpenAI(
                base_url=self.endpoint,
                api_key=self.token,
            )
            
            # Prepare context for AI
            context = f"""
Analyze this Linux system performance data from host: {hostname}

## SAR Metrics Summary:
- Load metrics: {sar_summary.get('load', 0)} data points
- Memory metrics: {sar_summary.get('memory', 0)} data points
- Disk metrics: {sar_summary.get('disk', 0)} data points
- Network metrics: {sar_summary.get('network', 0)} data points
- CPU metrics: {sar_summary.get('cpu', 0)} data points

## Log Summary:
- Messages: {log_summary.get('messages', 0)} entries
- Secure: {log_summary.get('secure', 0)} entries
- Audit: {log_summary.get('audit', 0)} entries
- Cron: {log_summary.get('cron', 0)} entries

## Detected Anomalies ({len(anomalies)} total):
"""
            # Add top anomalies
            for i, anomaly in enumerate(anomalies[:15]):
                ts = anomaly.get('timestamp')
                ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "unknown"
                context += f"- [{ts_str}] {anomaly['measurement']}/{anomaly['metric']}: {anomaly['value']:.2f} (threshold {anomaly['threshold']}, severity: {anomaly['severity']})\n"
            
            # Add correlated events
            if correlated_data:
                context += f"\n## Correlated Events (anomalies with related logs):\n"
                for i, item in enumerate(correlated_data[:5]):
                    anomaly = item['anomaly']
                    ts = anomaly.get('timestamp')
                    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "unknown"
                    context += f"\n### Event {i+1}: {anomaly['measurement']}/{anomaly['metric']} at {ts_str}\n"
                    context += f"Value: {anomaly['value']:.2f}, Severity: {anomaly['severity']}\n"
                    context += "Related logs:\n"
                    for log in item['related_logs'][:5]:
                        context += f"  - [{log['time']}] {log['source']}/{log['program']}: {log['message'][:100]}\n"
            
            response = client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": """You are an expert Linux system administrator and performance analyst. 
Analyze the provided SAR metrics and log data to:
1. Identify the root cause of any performance issues
2. Explain what the anomalies indicate
3. Correlate system events with log entries
4. Provide specific, actionable recommendations
5. Rate the overall system health

Be concise but thorough. Use bullet points for clarity. Focus on actionable insights."""
                    },
                    {
                        "role": "user",
                        "content": context
                    }
                ],
                temperature=0.3,
                max_tokens=1500,
                model=self.model
            )
            
            return response.choices[0].message.content
            
        except ImportError:
            return "âš ï¸ OpenAI package not installed. Run: `pip install openai`"
        except Exception as e:
            return f"âš ï¸ AI analysis error: {str(e)}"
    
    def get_quick_insights(self, anomalies: List[dict]) -> List[str]:
        """Generate quick insights without AI (rule-based)"""
        insights = []
        
        # Group anomalies by type
        high_load = [a for a in anomalies if 'ldavg' in a['metric']]
        high_memory = [a for a in anomalies if 'memused' in a['metric'] or 'commit' in a['metric']]
        high_disk = [a for a in anomalies if 'util' in a['metric'].lower()]
        high_cpu = [a for a in anomalies if 'idle' in a['metric']]
        
        if high_load:
            max_load = max(a['value'] for a in high_load)
            insights.append(f"ðŸ”´ **High Load Detected**: Peak load average of {max_load:.2f} - indicates CPU saturation or I/O wait")
        
        if high_memory:
            max_mem = max(a['value'] for a in high_memory if 'memused' in a['metric'])
            insights.append(f"ðŸŸ  **Memory Pressure**: Memory usage peaked at {max_mem:.1f}% - consider checking for memory leaks")
        
        if high_disk:
            max_util = max(a['value'] for a in high_disk)
            insights.append(f"ðŸŸ¡ **Disk I/O Bottleneck**: Disk utilization peaked at {max_util:.1f}% - storage may be a bottleneck")
        
        if high_cpu:
            min_idle = min(a['value'] for a in high_cpu)
            insights.append(f"ðŸ”´ **CPU Saturation**: CPU idle dropped to {min_idle:.1f}% - processes are competing for CPU")
        
        if not insights:
            insights.append("âœ… **No significant anomalies detected** - System appears to be running normally")
        
        return insights


# ============================================================================
# DATA PUSHERS
# ============================================================================

def push_sar_to_influxdb(metrics: List[dict], hostname: str, progress_callback=None) -> Tuple[int, str]:
    """Push SAR metrics to InfluxDB"""
    if not metrics:
        return 0, "No metrics to push"
    
    url = f"{INFLUXDB_URL}/api/v2/write?org={INFLUXDB_ORG}&bucket={INFLUXDB_BUCKET}&precision=s"
    headers = {
        "Authorization": f"Token {INFLUXDB_TOKEN}",
        "Content-Type": "text/plain"
    }
    
    pushed = 0
    errors = []
    batch_size = 5000
    
    for i in range(0, len(metrics), batch_size):
        batch = metrics[i:i + batch_size]
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
            try:
                response = requests.post(url, headers=headers, data='\n'.join(lines), timeout=30)
                if response.status_code == 204:
                    pushed += len(lines)
                else:
                    errors.append(f"Batch {i//batch_size}: HTTP {response.status_code} - {response.text[:200]}")
            except Exception as e:
                errors.append(f"Batch {i//batch_size}: {str(e)}")
        
        if progress_callback:
            progress_callback(pushed, len(metrics))
    
    error_msg = "; ".join(errors[:3]) if errors else ""
    return pushed, error_msg


def push_logs_to_loki(logs: List[dict], hostname: str, progress_callback=None) -> int:
    """Push logs to Loki"""
    if not logs:
        return 0
    
    url = f"{LOKI_URL}/loki/api/v1/push"
    
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
    
    for source, values in streams.items():
        # Sort by timestamp
        values.sort(key=lambda x: x[0])
        
        # Push in batches
        batch_size = 500
        for i in range(0, len(values), batch_size):
            batch = values[i:i + batch_size]
            
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
            
            try:
                response = requests.post(url, json=payload, timeout=30)
                if response.status_code == 204:
                    pushed += len(batch)
            except:
                pass
        
        if progress_callback:
            progress_callback(pushed, len(logs))
    
    return pushed


def create_grafana_dashboard(hostname: str) -> Optional[str]:
    """Create combined dashboard in Grafana with all SAR and Log panels"""
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
    
    # Disk I/O KB/s
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "custom": {"lineWidth": 2, "fillOpacity": 10}, "unit": "KBs"}},
        "gridPos": {"h": 6, "w": 12, "x": 0, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        "targets": [{"datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'from(bucket: "{INFLUXDB_BUCKET}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r["_measurement"] == "sar_disk") |> filter(fn: (r) => r["host"] == "{hostname}") |> filter(fn: (r) => r["_field"] == "rkB/s" or r["_field"] == "wkB/s")',
            "refId": "A"}],
        "title": "Disk I/O (KB/s)",
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
            "query": f'from(bucket: "{INFLUXDB_BUCKET}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r["_measurement"] == "sar_disk") |> filter(fn: (r) => r["host"] == "{hostname}") |> filter(fn: (r) => r["_field"] == "%util")',
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
        "options": {"dedupStrategy": "none", "enableLogDetails": True, "showTime": True, "sortOrder": "Descending", "wrapLogMessage": True},
        "targets": [{"datasource": {"type": "loki", "uid": loki_uid},
            "expr": f'{{host="{hostname}", source="messages"}}',
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
        "options": {"dedupStrategy": "none", "enableLogDetails": True, "showTime": True, "sortOrder": "Descending", "wrapLogMessage": True},
        "targets": [{"datasource": {"type": "loki", "uid": loki_uid},
            "expr": f'{{host="{hostname}", source="secure"}}',
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
        "options": {"dedupStrategy": "none", "enableLogDetails": True, "showTime": True, "sortOrder": "Descending", "wrapLogMessage": True},
        "targets": [{"datasource": {"type": "loki", "uid": loki_uid},
            "expr": f'{{host="{hostname}", source="audit"}}',
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
        "options": {"dedupStrategy": "none", "enableLogDetails": True, "showTime": True, "sortOrder": "Descending", "wrapLogMessage": True},
        "targets": [{"datasource": {"type": "loki", "uid": loki_uid},
            "expr": f'{{host="{hostname}", source="cron"}}',
            "refId": "A"}],
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
# STREAMLIT UI
# ============================================================================

def main():
    st.markdown('<h1 class="main-header">ðŸ“Š SOSreport Analyzer</h1>', unsafe_allow_html=True)
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
        st.subheader("ðŸ”Œ Backends")
        
        st.text(f"InfluxDB: {INFLUXDB_URL}")
        st.text(f"Loki: {LOKI_URL}")
        st.text(f"Grafana: {GRAFANA_URL}")
        
        st.markdown("---")
        st.subheader("ðŸ¤– AI Analysis")
        github_token = st.text_input(
            "GitHub Token (for AI)",
            type="password",
            help="Enter your GitHub Personal Access Token for AI-powered analysis. Get one at github.com/settings/tokens"
        )
        enable_ai = st.checkbox("Enable AI Analysis", value=bool(github_token))
        
        st.markdown("---")
        st.markdown("### ðŸ“– Instructions")
        st.markdown("""
        1. Upload a SOSreport file (.tar.xz, .tar.gz)
        2. Wait for extraction and parsing
        3. Review the analysis summary
        4. Push data to InfluxDB/Loki
        5. View dashboard in Grafana
        6. (Optional) Enable AI for insights
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
                
                # Get year using improved detection (from date output or filename)
                year = get_report_year(sosreport_path, uploaded_file.name)
                
                progress_bar.progress(50, "Parsing data...")
                status_text.text(f"ðŸ” Detected hostname: {hostname}, Log Year: {year}")
                
                # Parse SAR with limits
                sar_parser = SARParser(sosreport_path, hostname)
                sar_files_found = sar_parser.find_sar_files()
                status_text.text(f"ðŸ” Found {len(sar_files_found)} SAR files")
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
                            for f in sar_files_found:
                                st.text(os.path.basename(f))
                
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
                    st.metric("Total Logs", f"{len(logs):,}")
                
                # ============================================================
                # CRITICAL EVENTS DETECTION
                # ============================================================
                st.markdown("---")
                st.header("ðŸš¨ Critical Events Detection")
                
                # Detect critical events
                critical_detector = CriticalEventsDetector()
                critical_events = critical_detector.detect_events(logs)
                critical_summary = critical_detector.get_critical_summary()
                
                # Display severity summary
                col_c1, col_c2, col_c3, col_c4 = st.columns(4)
                with col_c1:
                    st.metric("ðŸ”´ Critical", critical_summary['by_severity']['critical'])
                with col_c2:
                    st.metric("ðŸŸ  High", critical_summary['by_severity']['high'])
                with col_c3:
                    st.metric("ðŸŸ¡ Medium", critical_summary['by_severity']['medium'])
                with col_c4:
                    st.metric("ðŸ”µ Info", critical_summary['by_severity']['info'])
                
                # Display by category
                if critical_summary['by_category']:
                    st.subheader("Events by Category")
                    cat_cols = st.columns(min(len(critical_summary['by_category']), 6))
                    for i, (cat, count) in enumerate(critical_summary['by_category'].items()):
                        with cat_cols[i % len(cat_cols)]:
                            st.metric(cat, count)
                
                # Show critical events
                if critical_summary['critical_events']:
                    with st.expander(f"ðŸ”´ Critical Events ({len(critical_summary['critical_events'])})", expanded=True):
                        for event in critical_summary['critical_events'][:15]:
                            ts = event.get('timestamp')
                            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "unknown"
                            st.markdown(f"**[{ts_str}] {event['category']} - {event['description']}**")
                            st.text(f"  Source: {event['source']}/{event['program']}")
                            st.text(f"  Message: {event['message'][:200]}")
                            st.markdown("---")
                
                # Show high severity events
                if critical_summary['high_events']:
                    with st.expander(f"ðŸŸ  High Severity Events ({len(critical_summary['high_events'])})"):
                        for event in critical_summary['high_events'][:15]:
                            ts = event.get('timestamp')
                            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "unknown"
                            st.markdown(f"**[{ts_str}] {event['category']} - {event['description']}**")
                            st.text(f"  {event['message'][:150]}")
                
                # ============================================================
                # SAR METRICS BREAKDOWN (Per-Device/Per-CPU)
                # ============================================================
                st.markdown("---")
                st.header("ðŸ“Š Detailed SAR Metrics")
                
                # Analyze SAR metrics
                sar_analyzer = SARMetricsAnalyzer(sar_metrics)
                
                # Peak Usage Report
                peaks = sar_analyzer.get_peak_report()
                if peaks:
                    st.subheader("ðŸ“ˆ Peak Usage Report")
                    peak_df = pd.DataFrame(peaks)
                    st.dataframe(peak_df, use_container_width=True, hide_index=True)
                
                # Per-CPU Breakdown
                cpu_df = sar_analyzer.get_cpu_breakdown()
                if not cpu_df.empty:
                    with st.expander("ðŸ–¥ï¸ Per-CPU Breakdown", expanded=False):
                        st.dataframe(cpu_df, use_container_width=True, hide_index=True)
                        
                        # Highlight hottest CPUs
                        hottest = cpu_df.sort_values('Min %Idle').head(3)
                        if not hottest.empty:
                            st.markdown("**ðŸ”¥ Hottest CPUs (lowest idle):**")
                            for _, row in hottest.iterrows():
                                st.text(f"  CPU {row['CPU']}: Min Idle {row['Min %Idle']}%, Max User {row['Max %User']}%")
                
                # Per-Disk Breakdown
                disk_df = sar_analyzer.get_disk_breakdown()
                if not disk_df.empty:
                    with st.expander("ðŸ’¾ Per-Disk I/O Breakdown", expanded=False):
                        st.dataframe(disk_df, use_container_width=True, hide_index=True)
                        
                        # Highlight busiest disks
                        busiest = disk_df.sort_values('Max %Util', ascending=False).head(3)
                        if not busiest.empty:
                            st.markdown("**ðŸ”¥ Busiest Disks:**")
                            for _, row in busiest.iterrows():
                                st.text(f"  {row['Device']}: Max Util {row['Max %Util']}%, Max R/W: {row['Max Read KB/s']}/{row['Max Write KB/s']} KB/s")
                
                # Per-Network Interface Breakdown
                net_df = sar_analyzer.get_network_breakdown()
                if not net_df.empty:
                    with st.expander("ðŸŒ Per-Interface Network Breakdown", expanded=False):
                        st.dataframe(net_df, use_container_width=True, hide_index=True)
                
                # ============================================================
                # UNIFIED TIMELINE VIEW
                # ============================================================
                st.markdown("---")
                st.header("â° Unified Timeline")
                
                # Build timeline
                timeline_builder = TimelineBuilder()
                
                # Initialize AI analyzer for anomalies
                ai_analyzer = AIAnalyzer(github_token if enable_ai else None)
                anomalies = ai_analyzer.detect_anomalies(sar_metrics)
                
                timeline_builder.add_sar_anomalies(anomalies)
                timeline_builder.add_critical_events(critical_events)
                timeline = timeline_builder.build_timeline()
                
                if timeline:
                    # Filter options
                    st.subheader("ðŸ” Filter Timeline")
                    filter_cols = st.columns(3)
                    with filter_cols[0]:
                        severity_filter = st.multiselect(
                            "Severity",
                            options=['critical', 'high', 'medium', 'info'],
                            default=['critical', 'high']
                        )
                    with filter_cols[1]:
                        categories = list(set(e.get('category', '') for e in timeline))
                        category_filter = st.multiselect(
                            "Category",
                            options=sorted(categories),
                            default=sorted(categories)
                        )
                    with filter_cols[2]:
                        max_events = st.slider("Max Events", 10, 200, 50)
                    
                    # Filter timeline
                    filtered_timeline = [
                        e for e in timeline 
                        if e.get('severity') in severity_filter 
                        and e.get('category') in category_filter
                    ][:max_events]
                    
                    st.subheader(f"ðŸ“‹ Timeline ({len(filtered_timeline)} events)")
                    
                    # Display as table
                    if filtered_timeline:
                        timeline_data = []
                        for e in filtered_timeline:
                            ts = e.get('timestamp')
                            timeline_data.append({
                                '': e.get('icon', ''),
                                'Time': ts.strftime("%Y-%m-%d %H:%M:%S") if ts else '',
                                'Severity': e.get('severity', '').upper(),
                                'Category': e.get('category', ''),
                                'Description': e.get('description', '')[:80]
                            })
                        
                        timeline_df = pd.DataFrame(timeline_data)
                        st.dataframe(
                            timeline_df,
                            use_container_width=True,
                            hide_index=True,
                            column_config={
                                '': st.column_config.TextColumn(width="small"),
                                'Time': st.column_config.TextColumn(width="medium"),
                                'Severity': st.column_config.TextColumn(width="small"),
                                'Category': st.column_config.TextColumn(width="small"),
                                'Description': st.column_config.TextColumn(width="large"),
                            }
                        )
                else:
                    st.info("No significant events detected in the timeline.")
                
                # ============================================================
                # QUICK INSIGHTS (Rule-based)
                # ============================================================
                st.markdown("---")
                st.header("ðŸ’¡ Quick Insights")
                
                # Quick insights from AI analyzer
                quick_insights = ai_analyzer.get_quick_insights(anomalies)
                for insight in quick_insights:
                    st.markdown(insight)
                
                # Additional insights from critical events
                if critical_summary['by_severity']['critical'] > 0:
                    st.markdown(f"ðŸ”´ **{critical_summary['by_severity']['critical']} Critical Events** detected - Immediate investigation required!")
                
                if 'Memory' in critical_summary['by_category']:
                    st.markdown(f"âš ï¸ **Memory Issues**: {critical_summary['by_category']['Memory']} memory-related events (OOM kills, pressure)")
                
                if 'Disk' in critical_summary['by_category']:
                    st.markdown(f"ðŸ’¾ **Disk Issues**: {critical_summary['by_category']['Disk']} disk-related events (I/O errors, space issues)")
                
                if 'Security' in critical_summary['by_category']:
                    st.markdown(f"ðŸ” **Security Events**: {critical_summary['by_category']['Security']} security-related events")
                
                # Show anomaly summary
                if anomalies:
                    with st.expander(f"ðŸ” SAR Anomalies Details ({len(anomalies)} total)"):
                        high = [a for a in anomalies if a['severity'] == 'high']
                        medium = [a for a in anomalies if a['severity'] == 'medium']
                        
                        if high:
                            st.markdown("**ðŸ”´ High Severity:**")
                            for a in high[:10]:
                                ts = a.get('timestamp')
                                ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "unknown"
                                st.text(f"  [{ts_str}] {a['measurement']}/{a['metric']}: {a['value']:.2f}")
                        
                        if medium:
                            st.markdown("**ðŸŸ  Medium Severity:**")
                            for a in medium[:10]:
                                ts = a.get('timestamp')
                                ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "unknown"
                                st.text(f"  [{ts_str}] {a['measurement']}/{a['metric']}: {a['value']:.2f}")
                
                # AI Analysis (Optional)
                if enable_ai and github_token:
                    st.markdown("---")
                    st.header("ðŸ§  AI Deep Analysis")
                    
                    correlated = ai_analyzer.correlate_logs_with_anomalies(anomalies, logs)
                    
                    if st.button("ðŸ”¬ Generate AI Analysis", type="secondary"):
                        with st.spinner("AI is analyzing your data..."):
                            ai_summary = ai_analyzer.generate_ai_summary(
                                hostname=hostname,
                                anomalies=anomalies,
                                correlated_data=correlated if anomalies else [],
                                sar_summary=sar_parser.summary,
                                log_summary=log_parser.summary
                            )
                            
                            st.markdown("### ðŸ“ AI Analysis Report")
                            st.markdown(ai_summary)
                
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
                    else:
                        st.warning(f"âš ï¸ No SAR metrics pushed to InfluxDB")
                    if push_error:
                        st.error(f"âŒ InfluxDB errors: {push_error}")
                
                if push_logs and logs:
                    progress_bar.progress(85, "Pushing Logs to Loki...")
                    status_text.text("ðŸ“¤ Pushing logs to Loki...")
                    pushed_logs = push_logs_to_loki(logs, hostname)
                    results['logs'] = pushed_logs
                    st.success(f"âœ… Pushed {pushed_logs:,} log entries to Loki")
                
                # Create dashboard
                if create_dashboard:
                    progress_bar.progress(95, "Creating Grafana dashboard...")
                    status_text.text("ðŸ“Š Creating Grafana dashboard...")
                    dashboard_url = create_grafana_dashboard(hostname)
                    
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
        "SOSreport Analyzer v1.0 | Powered by Streamlit, InfluxDB, Loki & Grafana"
        "</div>",
        unsafe_allow_html=True
    )


if __name__ == "__main__":
    main()
