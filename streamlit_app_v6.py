"""
SOSreport Analyzer V6 - Streamlit Web Application
Upload SOSreport files and analyze SAR metrics + Logs with automatic Grafana integration

Multi-user optimized with caching and resource management.
Includes:
- Critical Events Detection for system issues
- Basic System Info (CPU, Memory, Kernel - like xsos)
- Filesystem (DF) Utilization
- Performance Peaks & Anomaly Detection
- Enhanced Grafana Dashboard with System Overview
- Subscription/Patch Compliance Check
- Copy-Paste Summary for tickets
- Timestamp Correlation View
- OS Flavor Detection (RHEL/Oracle Linux/SUSE/etc.) with per-distro kernel analysis (NEW in V6)
- CPU Usage % stacked panel + Per-CPU breakdown in Grafana (NEW in V6)
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

# Critical Events Log Patterns
LOG_PATTERNS = {
    "File System & Disk": [
        'fsck', 'XFS internal error', 'xfs_force_shutdown', 'I/O error', 'Corruption detected',
        'EXT4-fs error', 'blk_update_request', 'Buffer I/O error', 'nvme: I/O optimization', 
        'Read-only file system', 'resetting adapter', 'failed to identify device',
        'SCSI error', 'sd_sbc_read_capacity', 'device offline', 'Remounting filesystem read-only',
        'XFS (', 'EXT4-fs (', 'btrfs:', 'BTRFS error', 'md/raid', 'mdadm',
        'device-mapper:', 'dm-', 'LVM:', 'thin_check', 'lvmetad'
    ],
    "Memory/OOM": [
        'Out of memory:', 'Killed process', 'oom-killer', 'check_panic_on_oom', 'oom_score_adj',
        'page allocation failure', 'LowMemMode', 'invoked oom-killer',
        'SLUB: Unable to allocate', 'memory cgroup out of memory', 'cgroup_memory',
        'Huge page', 'hugepages'
    ],
    "CPU & Kernel Panic": [
        'BUG: soft lockup', 'unable to handle kernel paging request', 'Oops:', 'Kernel panic',
        'Fatal exception', 'NMI watchdog: Watchdog detected hard LOCKUP', 'Machine Check Exception',
        'MCE: Machine Check', 'procs_blocked', 'Error: No such file or directory',
        'RIP:', 'Call Trace:', 'general protection fault', 'divide error',
        'BUG: scheduling while atomic', 'BUG: unable to handle kernel', 'Warning:',
        'watchdog: BUG', 'rcu_sched detected stalls', 'hung_task_timeout_secs'
    ],
    "Security & Antivirus": [
        'falcon_lsm_serviceable', 'twnotify', 'tmhook', 'dsa_filter', 'core_pkt_filter', 
        'symev_hook', 'cshook_network_ops', 'AVC denial', 'selinux',
        'authentication failure', 'Failed password', 'FAILED LOGIN',
        'pam_unix.*authentication failure', 'Invalid user', 'Connection closed by authenticating user',
        'Accepted publickey', 'session opened for user root', 'segfault at'
    ],
    "Network Issues": [
        'NIC Link is Down', 'eth0: link up', 'neighbor table overflow', 'nf_conntrack: table full',
        'TX hang', 'NETDEV WATCHDOG',
        'bond0: link status', 'link is not ready', 'carrier lost', 'no carrier',
        'Connection timed out', 'NetworkManager', 'firewalld',
        'dropped outgoing', 'martian source',
        # Azure / Mellanox / Hyper-V network drivers
        'mlx5_cmd_out_err', 'mlx4_core', 'mlx4_en',
        'hv_netvsc', 'netvsc_send', 'VF link is not ready',
    ],
    "Service & Systemd": [
        'systemd: Failed to start', 'systemd: Dependency failed',
        'service entered failed state', 'Main process exited, code=exited',
        'Start request repeated too quickly', 'Timed out waiting for device',
        'coredump', 'core dump', 'segfault', 'traps:',
        'systemd-coredump', 'dumped core'
    ],
    "Hardware & IPMI": [
        'Hardware Error', 'mce:', 'EDAC', 'pci error', 'PCIe Bus Error',
        'AER:', 'Corrected error', 'Uncorrected error', 'GHES:',
        'ipmi', 'ACPI Error', 'ACPI Warning', 'thermal',
        # Azure / Hyper-V platform drivers
        'hv_storvsc', 'hv_vmbus', 'hv_balloon', 'hv_utils',
        'hyperv_fb', 'Hyper-V', 'PCI#', 'BAR allocation',
    ]
}
# ============================================================================

# Thread pool for extraction (shared across sessions but limited)
_extraction_semaphore = threading.Semaphore(MAX_CONCURRENT_EXTRACTIONS)

st.set_page_config(
    page_title="SOSreport Analyzer V6",
    
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
        status_text.text(" Waiting for extraction slot...")
    
    with _extraction_semaphore:
        if status_text:
            status_text.text(" Starting extraction...")
        
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
                
                # Extract relevant files - SAR, logs, system info, and hostname
                files_to_extract = []
                for member in members:
                    name = member.name
                    # Include SAR files, all log files, system info, and hostname
                # Also extract /sos_commands/subscription_manager, /sos_commands/yum, /sos_commands/dnf
                    if any(p in name for p in [
                        '/var/log/sa/',        # SAR binary and text files
                        '/sos_commands/sar/',  # SAR command outputs
                        '/sos_commands/logs/',
                        '/sos_commands/auditd/',
                        '/sos_commands/date/',  # Date command output
                        '/sos_commands/general/', # General commands (uptime, etc)
                        '/sos_commands/host/',  # Host commands
                        '/sos_commands/kernel/',  # Kernel version, modules
                        '/sos_commands/filesys/',  # df, mount info
                        '/sos_commands/process/',  # ps, top outputs
                        '/sos_commands/rpm/',  # Installed packages
                        '/sos_commands/hardware/',  # Hardware info
                        '/sos_commands/memory/',  # Memory details
                        '/sos_commands/processor/',  # CPU details
                        '/sos_commands/subscription_manager/',  # Subscription info (V5)
                        '/sos_commands/yum/',  # Yum history (V5)
                        '/sos_commands/dnf/',  # DNF history (V5)
                        '/sos_commands/kdump/',  # Kdump status (V5)
                        '/sos_commands/systemd/',  # Systemd service status (V5)
                        '/etc/kdump.conf',  # Kdump config (V5)
                        '/var/crash/',  # Crash dumps (V5)
                        '/proc/cmdline',  # Kernel cmdline for crashkernel= (V5)
                        '/proc/cpuinfo',  # CPU info
                        '/proc/meminfo',  # Memory info
                        '/etc/hostname',
                        '/etc/redhat-release',  # OS release info
                        '/etc/centos-release',
                        '/etc/system-release',
                        '/etc/os-release',
                        '/etc/oracle-release',
                        '/hostname',
                        '/uptime',
                        '/date',
                        '/uname',
                        '/dmidecode',
                        '/free',
                        '/df',
                        '/lscpu',
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
                        '/sos_commands/process',
                        '/sos_commands/subscription_manager', '/sos_commands/yum', '/sos_commands/dnf',
                        '/sos_commands/kdump', '/sos_commands/systemd',
                        '/var/crash',
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
        os.path.join(sosreport_path, "etc", "system-release"),
        os.path.join(sosreport_path, "etc", "os-release"),
        os.path.join(sosreport_path, "etc", "oracle-release"),
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


def detect_os_flavor(os_release: str, kernel_version: str = '') -> str:
    """Detect OS flavor from os-release string and kernel version.
    
    Returns a standardized flavor string:
      'oracle_linux' - Oracle Linux (with or without UEK)
      'rhel'         - Red Hat Enterprise Linux
      'centos'       - CentOS / CentOS Stream
      'rocky'        - Rocky Linux
      'alma'         - AlmaLinux
      'suse'         - SUSE Linux Enterprise (SLES/SLED)
      'ubuntu'       - Ubuntu
      'unknown'      - Unrecognized
    
    This function is designed to be extended: add new elif branches for new distros.
    """
    os_lower = os_release.lower() if os_release else ''
    kernel_lower = kernel_version.lower() if kernel_version else ''
    
    if 'oracle' in os_lower or 'uek' in kernel_lower:
        return 'oracle_linux'
    elif 'red hat' in os_lower or 'rhel' in os_lower:
        return 'rhel'
    elif 'centos' in os_lower:
        return 'centos'
    elif 'rocky' in os_lower:
        return 'rocky'
    elif 'alma' in os_lower:
        return 'alma'
    elif 'suse' in os_lower or 'sles' in os_lower:
        return 'suse'
    elif 'ubuntu' in os_lower:
        return 'ubuntu'
    else:
        return 'unknown'


# â”€â”€â”€ OS-flavor-specific configuration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Each flavor defines:
#   base_kernel_prefix : prefix(es) for the BASE kernel package (not sub-pkgs)
#   kernel_type_tag    : string present in kernel name to identify this track
#   staleness_thresholds : (outdated_min, very_outdated_min) on the "major_update" number
#                          from version string  e.g. 5.14.0-<major_update>.x.y
#   subscription_methods : typical subscription mechanisms for this distro
#
# To add a new distro:  add an entry here + any special logic in detect_patch_compliance.
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
OS_FLAVOR_CONFIG = {
    'oracle_linux': {
        'base_kernel_prefixes': ['kernel-uek-', 'kernel-'],  # UEK first, then standard
        'kernel_type_from_version': lambda kver: 'uek' if 'uek' in kver.lower() else 'standard',
        'staleness_thresholds': {
            'uek':      {'outdated': 200, 'very_outdated': 100},   # UEK numbering
            'standard': {'outdated': 450, 'very_outdated': 300},   # RHCK numbering
        },
        'subscription_methods': ['RHUI', 'ULN', 'subscription-manager'],
    },
    'rhel': {
        'base_kernel_prefixes': ['kernel-'],
        'kernel_type_from_version': lambda kver: 'standard',
        'staleness_thresholds': {
            'standard': {'outdated': 450, 'very_outdated': 300},
        },
        'subscription_methods': ['subscription-manager', 'RHUI'],
    },
    'centos': {
        'base_kernel_prefixes': ['kernel-'],
        'kernel_type_from_version': lambda kver: 'standard',
        'staleness_thresholds': {
            'standard': {'outdated': 450, 'very_outdated': 300},
        },
        'subscription_methods': ['repo-based'],
    },
    'rocky': {
        'base_kernel_prefixes': ['kernel-'],
        'kernel_type_from_version': lambda kver: 'standard',
        'staleness_thresholds': {
            'standard': {'outdated': 450, 'very_outdated': 300},
        },
        'subscription_methods': ['repo-based'],
    },
    'alma': {
        'base_kernel_prefixes': ['kernel-'],
        'kernel_type_from_version': lambda kver: 'standard',
        'staleness_thresholds': {
            'standard': {'outdated': 450, 'very_outdated': 300},
        },
        'subscription_methods': ['repo-based'],
    },
    'suse': {
        'base_kernel_prefixes': ['kernel-default-'],
        'kernel_type_from_version': lambda kver: 'default',
        'staleness_thresholds': {
            'default': {'outdated': 100, 'very_outdated': 50},
        },
        'subscription_methods': ['SUSEConnect', 'RMT', 'SMT'],
    },
}
# Fallback for unrecognized distros
OS_FLAVOR_CONFIG['unknown'] = OS_FLAVOR_CONFIG['rhel']


def detect_cpu_info(sosreport_path: str) -> dict:
    """Detect CPU information from sosreport (like xsos)"""
    cpu_info = {
        'model': 'N/A',
        'cores': 0,
        'sockets': 0,
        'threads_per_core': 0,
        'cpu_mhz': 'N/A',
        'architecture': 'N/A'
    }
    
    # Try lscpu first (more structured)
    lscpu_files = [
        os.path.join(sosreport_path, "sos_commands", "processor", "lscpu"),
        os.path.join(sosreport_path, "sos_commands", "hardware", "lscpu"),
        os.path.join(sosreport_path, "lscpu"),
    ]
    
    for lf in lscpu_files:
        if os.path.isfile(lf):
            try:
                with open(lf, 'r') as f:
                    content = f.read()
                    for line in content.split('\n'):
                        if ':' in line:
                            key, val = line.split(':', 1)
                            key = key.strip().lower()
                            val = val.strip()
                            if 'model name' in key:
                                cpu_info['model'] = val
                            elif key == 'cpu(s)':
                                cpu_info['cores'] = int(val)
                            elif 'socket(s)' in key:
                                cpu_info['sockets'] = int(val)
                            elif 'thread(s) per core' in key:
                                cpu_info['threads_per_core'] = int(val)
                            elif 'cpu mhz' in key or 'cpu max mhz' in key:
                                cpu_info['cpu_mhz'] = val
                            elif key == 'architecture':
                                cpu_info['architecture'] = val
                    if cpu_info['model'] != 'N/A':
                        return cpu_info
            except:
                continue
    
    # Fallback to /proc/cpuinfo
    cpuinfo_files = [
        os.path.join(sosreport_path, "proc", "cpuinfo"),
        os.path.join(sosreport_path, "sos_commands", "processor", "cpuinfo"),
    ]
    
    for cf in cpuinfo_files:
        if os.path.isfile(cf):
            try:
                with open(cf, 'r') as f:
                    content = f.read()
                    processors = content.count('processor')
                    cpu_info['cores'] = processors
                    
                    for line in content.split('\n'):
                        if 'model name' in line.lower():
                            cpu_info['model'] = line.split(':', 1)[1].strip()
                        elif 'cpu mhz' in line.lower():
                            cpu_info['cpu_mhz'] = line.split(':', 1)[1].strip()
                    
                    if cpu_info['cores'] > 0:
                        return cpu_info
            except:
                continue
    
    return cpu_info


def detect_memory_info(sosreport_path: str) -> dict:
    """Detect memory information from sosreport (like xsos)"""
    mem_info = {
        'total_gb': 'N/A',
        'total_kb': 0,
        'free_kb': 0,
        'available_kb': 0,
        'swap_total_kb': 0,
        'swap_free_kb': 0,
        'hugepages_total': 0,
        'hugepages_free': 0,
        'hugepage_size_kb': 0
    }
    
    meminfo_files = [
        os.path.join(sosreport_path, "proc", "meminfo"),
        os.path.join(sosreport_path, "sos_commands", "memory", "meminfo"),
    ]
    
    for mf in meminfo_files:
        if os.path.isfile(mf):
            try:
                with open(mf, 'r') as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 2:
                            key = parts[0].rstrip(':').lower()
                            try:
                                val = int(parts[1])
                            except:
                                continue
                            
                            if key == 'memtotal':
                                mem_info['total_kb'] = val
                                mem_info['total_gb'] = f"{val / 1024 / 1024:.1f} GB"
                            elif key == 'memfree':
                                mem_info['free_kb'] = val
                            elif key == 'memavailable':
                                mem_info['available_kb'] = val
                            elif key == 'swaptotal':
                                mem_info['swap_total_kb'] = val
                            elif key == 'swapfree':
                                mem_info['swap_free_kb'] = val
                            elif key == 'hugepages_total':
                                mem_info['hugepages_total'] = val
                            elif key == 'hugepages_free':
                                mem_info['hugepages_free'] = val
                            elif key == 'hugepagesize':
                                mem_info['hugepage_size_kb'] = val
                    
                    if mem_info['total_kb'] > 0:
                        return mem_info
            except:
                continue
    
    # Try free command output
    free_files = [
        os.path.join(sosreport_path, "free"),
        os.path.join(sosreport_path, "sos_commands", "memory", "free_-m"),
        os.path.join(sosreport_path, "sos_commands", "memory", "free"),
    ]
    
    for ff in free_files:
        if os.path.isfile(ff):
            try:
                with open(ff, 'r') as f:
                    for line in f:
                        if line.startswith('Mem:'):
                            parts = line.split()
                            if len(parts) >= 2:
                                try:
                                    total = int(parts[1])
                                    # Detect if in MB or KB
                                    if total < 100000:  # Likely in MB
                                        mem_info['total_gb'] = f"{total / 1024:.1f} GB"
                                        mem_info['total_kb'] = total * 1024
                                    else:
                                        mem_info['total_gb'] = f"{total / 1024 / 1024:.1f} GB"
                                        mem_info['total_kb'] = total
                                except:
                                    pass
                    if mem_info['total_kb'] > 0:
                        return mem_info
            except:
                continue
    
    return mem_info


def detect_kernel_version(sosreport_path: str) -> str:
    """Detect kernel version from sosreport"""
    uname_files = [
        os.path.join(sosreport_path, "sos_commands", "kernel", "uname_-a"),
        os.path.join(sosreport_path, "sos_commands", "host", "uname_-a"),
        os.path.join(sosreport_path, "uname"),
    ]
    
    for uf in uname_files:
        if os.path.isfile(uf):
            try:
                with open(uf, 'r') as f:
                    content = f.read().strip()
                    if content:
                        # Extract kernel version (usually 3rd field)
                        parts = content.split()
                        if len(parts) >= 3:
                            return parts[2]  # e.g., "5.14.0-427.el9.x86_64"
            except:
                continue
    
    return "N/A"


def detect_df_info(sosreport_path: str) -> List[dict]:
    """Detect filesystem disk usage from sosreport"""
    df_info = []
    
    df_files = [
        os.path.join(sosreport_path, "sos_commands", "filesys", "df_-h"),
        os.path.join(sosreport_path, "sos_commands", "filesys", "df_-al"),
        os.path.join(sosreport_path, "sos_commands", "filesys", "df"),
        os.path.join(sosreport_path, "df"),
    ]
    
    for df_file in df_files:
        if os.path.isfile(df_file):
            try:
                with open(df_file, 'r') as f:
                    lines = f.readlines()
                    for line in lines[1:]:  # Skip header
                        parts = line.split()
                        if len(parts) >= 6:
                            # Handle wrapped lines (filesystem name on separate line)
                            if len(parts) == 1:
                                continue
                            try:
                                filesystem = parts[0]
                                size = parts[1]
                                used = parts[2]
                                avail = parts[3]
                                use_pct = parts[4].rstrip('%')
                                mountpoint = parts[5] if len(parts) > 5 else ''
                                
                                # Skip pseudo/virtual filesystems by type
                                skip_fs_types = [
                                    'tmpfs', 'devtmpfs', 'overlay', 'sysfs', 'proc', 
                                    'cgroup', 'cgroup2', 'devpts', 'securityfs', 'debugfs',
                                    'pstore', 'bpf', 'configfs', 'fusectl', 'hugetlbfs',
                                    'mqueue', 'tracefs', 'autofs', 'rpc_pipefs', 'efivarfs', 'nsfs'
                                ]
                                if any(fs in filesystem.lower() for fs in skip_fs_types):
                                    continue
                                
                                # Skip virtual mountpoints
                                skip_mountpoints = [
                                    '/sys', '/proc', '/dev/', '/run/', '/cgroup',
                                    '/sys/fs/cgroup', '/sys/kernel', '/sys/firmware'
                                ]
                                if any(mountpoint.startswith(mp) for mp in skip_mountpoints):
                                    continue
                                
                                # Skip if mountpoint is exactly /dev or /run
                                if mountpoint in ['/dev', '/run', '/sys', '/proc']:
                                    continue
                                
                                df_info.append({
                                    'filesystem': filesystem,
                                    'size': size,
                                    'used': used,
                                    'available': avail,
                                    'use_percent': int(use_pct) if use_pct.isdigit() else 0,
                                    'mountpoint': mountpoint
                                })
                            except:
                                continue
                    
                    if df_info:
                        return df_info
            except:
                continue
    
    return df_info


def detect_installed_packages(sosreport_path: str) -> dict:
    """Detect important installed packages from sosreport"""
    packages = {
        'rhui': [],
        'kernel': [],
        'python': [],
        'java': [],
        'total_count': 0
    }
    
    # Build list of candidate RPM files
    rpm_files = []
    
    # Priority 1: installed-rpms at sosreport root (most reliable, always present)
    installed_rpms = os.path.join(sosreport_path, "installed-rpms")
    if os.path.isfile(installed_rpms):
        rpm_files.append(installed_rpms)
    
    # Priority 2: sos_commands/rpm/ directory - find any matching files
    rpm_dir = os.path.join(sosreport_path, "sos_commands", "rpm")
    if os.path.isdir(rpm_dir):
        for f in os.listdir(rpm_dir):
            f_lower = f.lower()
            if 'rpm' in f_lower and ('qa' in f_lower or 'list' in f_lower or 'nodigest' in f_lower):
                rpm_files.append(os.path.join(rpm_dir, f))
    
    for rpm_file in rpm_files:
        if os.path.isfile(rpm_file):
            try:
                with open(rpm_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        pkg = line.strip()
                        if not pkg:
                            continue
                        packages['total_count'] += 1
                        
                        # Extract just the package name (remove install date/time if present)
                        # installed-rpms format: "kernel-uek-5.15.0-300.el8uek.x86_64  Tue Jan 27 19:02:30 2026"
                        pkg_name = pkg.split()[0] if pkg.split() else pkg
                        pkg_lower = pkg_name.lower()
                        
                        if 'rhui' in pkg_lower:
                            packages['rhui'].append(pkg_name)
                        elif pkg_lower.startswith('kernel-') or pkg_lower.startswith('kernel_'):
                            packages['kernel'].append(pkg_name)
                        elif 'python' in pkg_lower and len(packages['python']) < 5:
                            packages['python'].append(pkg_name)
                        elif 'java' in pkg_lower and len(packages['java']) < 5:
                            packages['java'].append(pkg_name)
                    
                    if packages['total_count'] > 0:
                        return packages
            except:
                continue
    
    return packages


def detect_selinux_status(sosreport_path: str) -> str:
    """Detect SELinux status from sosreport"""
    selinux_files = [
        os.path.join(sosreport_path, "sos_commands", "selinux", "sestatus_-b"),
        os.path.join(sosreport_path, "sos_commands", "selinux", "sestatus"),
    ]
    
    for sf in selinux_files:
        if os.path.isfile(sf):
            try:
                with open(sf, 'r') as f:
                    for line in f:
                        if 'SELinux status:' in line or 'Current mode:' in line:
                            return line.split(':', 1)[1].strip()
            except:
                continue
    
    return "N/A"


def detect_kdump_status(sosreport_path: str) -> dict:
    """Detect kdump status and crash dump files from sosreport
    
    Checks:
    - kdumpctl status (operational or not)
    - kdump.service enabled/active
    - crashkernel= reservation in /proc/cmdline
    - /var/crash/ for vmcore dump files
    - /etc/kdump.conf for dump target config
    """
    kdump = {
        'enabled': 'Unknown',
        'operational': None,
        'crashkernel': None,
        'dump_target': None,
        'crash_dumps': [],
    }
    
    # 1. Check kdumpctl status
    kdumpctl_files = [
        os.path.join(sosreport_path, "sos_commands", "kdump", "kdumpctl_showmem"),
        os.path.join(sosreport_path, "sos_commands", "kdump", "kdumpctl_status"),
        os.path.join(sosreport_path, "sos_commands", "kdump", "kdumpctl_estimate"),
    ]
    
    for kf in kdumpctl_files:
        if os.path.isfile(kf):
            try:
                with open(kf, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().strip()
                    if 'operational' in content.lower():
                        if 'not operational' in content.lower():
                            kdump['operational'] = False
                            kdump['enabled'] = 'Not Operational'
                        else:
                            kdump['operational'] = True
                            kdump['enabled'] = 'Operational'
            except:
                continue
    
    # 2. Check systemctl for kdump.service
    systemctl_files = [
        os.path.join(sosreport_path, "sos_commands", "systemd", "systemctl_list-units"),
        os.path.join(sosreport_path, "sos_commands", "systemd", "systemctl_list-units_--all"),
        os.path.join(sosreport_path, "sos_commands", "systemd", "systemctl_list-unit-files"),
    ]
    
    for sf in systemctl_files:
        if os.path.isfile(sf):
            try:
                with open(sf, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if 'kdump' in line.lower():
                            if 'active' in line.lower() and 'running' in line.lower():
                                kdump['enabled'] = 'Active (running)'
                                kdump['operational'] = True
                            elif 'enabled' in line.lower():
                                if kdump['enabled'] == 'Unknown':
                                    kdump['enabled'] = 'Enabled'
                            elif 'inactive' in line.lower() or 'dead' in line.lower():
                                if kdump['enabled'] == 'Unknown':
                                    kdump['enabled'] = 'Inactive'
                                    kdump['operational'] = False
                            elif 'disabled' in line.lower():
                                kdump['enabled'] = 'Disabled'
                                kdump['operational'] = False
                            break
            except:
                continue
    
    # 3. Check /proc/cmdline for crashkernel= reservation
    cmdline_files = [
        os.path.join(sosreport_path, "proc", "cmdline"),
        os.path.join(sosreport_path, "sos_commands", "kernel", "cat_.proc.cmdline"),
    ]
    
    for cf in cmdline_files:
        if os.path.isfile(cf):
            try:
                with open(cf, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    match = re.search(r'crashkernel=(\S+)', content)
                    if match:
                        kdump['crashkernel'] = match.group(1)
            except:
                continue
    
    # 4. Check /etc/kdump.conf for dump target
    kdump_conf = os.path.join(sosreport_path, "etc", "kdump.conf")
    if os.path.isfile(kdump_conf):
        try:
            with open(kdump_conf, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if any(line.startswith(k) for k in ['path', 'nfs', 'ssh', 'raw', 'ext4', 'xfs']):
                            kdump['dump_target'] = line
                            break
        except:
            pass
    
    # 5. Check /var/crash/ for vmcore dump files
    crash_dir = os.path.join(sosreport_path, "var", "crash")
    if os.path.isdir(crash_dir):
        try:
            for item in os.listdir(crash_dir):
                item_path = os.path.join(crash_dir, item)
                if os.path.isdir(item_path):
                    # Each crash creates a directory like 127.0.0.1-2025-01-15-10:30:45/
                    vmcore = os.path.join(item_path, "vmcore")
                    vmcore_dmesg = os.path.join(item_path, "vmcore-dmesg.txt")
                    has_vmcore = os.path.isfile(vmcore)
                    has_dmesg = os.path.isfile(vmcore_dmesg)
                    kdump['crash_dumps'].append({
                        'directory': item,
                        'has_vmcore': has_vmcore,
                        'has_dmesg': has_dmesg,
                    })
        except:
            pass
    
    return kdump


def detect_top_processes(sosreport_path: str) -> dict:
    """Detect top CPU and memory consuming processes from sosreport ps output"""
    top_processes = {
        'top_cpu': [],
        'top_mem': []
    }
    
    # Look for ps aux output files - try multiple naming patterns
    process_dir = os.path.join(sosreport_path, "sos_commands", "process")
    ps_files = []
    
    # Method 1: Check if process directory exists and find ps files
    if os.path.isdir(process_dir):
        for f in os.listdir(process_dir):
            f_lower = f.lower()
            # Match ps_aux*, ps_alx* (these have %CPU and %MEM columns)
            if f_lower.startswith('ps_') and ('aux' in f_lower or 'alx' in f_lower):
                ps_files.append(os.path.join(process_dir, f))
    
    # Method 2: Use glob patterns as fallback
    if not ps_files:
        import glob as glob_mod
        glob_patterns = [
            os.path.join(process_dir, "ps_aux*"),
            os.path.join(process_dir, "ps_alx*"),
            os.path.join(process_dir, "ps_*"),
            os.path.join(sosreport_path, "ps"),
        ]
        for pattern in glob_patterns:
            ps_files.extend(glob_mod.glob(pattern))
    
    # Remove duplicates and sort (prefer auxwwwm, then auxfwww, then aux, then alx)
    ps_files = list(set(ps_files))
    ps_files.sort(key=lambda x: (
        0 if 'auxwwwm' in x else 
        1 if 'auxfwww' in x else 
        2 if 'auxwww' in x else 
        3 if 'aux' in x else 
        4 if 'alx' in x else 5
    ))
    
    for ps_file in ps_files:
        if not os.path.isfile(ps_file):
            continue
        try:
            with open(ps_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            if not lines:
                continue
            
            # Parse header to find column positions
            header = lines[0].lower()
            
            # For ps aux format: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
            if '%cpu' in header and '%mem' in header:
                processes = []
                for line in lines[1:]:
                    parts = line.split(None, 10)  # Split into max 11 parts
                    if len(parts) >= 5:  # Relaxed - at least USER PID %CPU %MEM + something
                        try:
                            user = parts[0]
                            pid = parts[1]
                            cpu_pct = float(parts[2])
                            mem_pct = float(parts[3])
                            # Command might be at different positions
                            command = parts[-1][:60] if parts else 'N/A'
                            if len(parts) >= 11:
                                command = parts[10][:60]
                            
                            processes.append({
                                'user': user,
                                'pid': pid,
                                'cpu': cpu_pct,
                                'mem': mem_pct,
                                'command': command
                            })
                        except (ValueError, IndexError):
                            continue
                
                # Sort by CPU and get top 10
                top_processes['top_cpu'] = sorted(processes, key=lambda x: x['cpu'], reverse=True)[:10]
                # Sort by Memory and get top 10
                top_processes['top_mem'] = sorted(processes, key=lambda x: x['mem'], reverse=True)[:10]
                
                if top_processes['top_cpu']:
                    return top_processes
        except Exception:
            continue
    
    return top_processes


def detect_patch_compliance(sosreport_path: str, packages_info: dict, kernel_version: str, 
                            os_release: str, report_date_str: str) -> dict:
    """Detect subscription/patch compliance status from sosreport.
    
    Uses OS-flavor dispatch so RHEL, Oracle Linux, SUSE, etc. each get
    appropriate kernel-analysis logic.  To add a new distro, update
    OS_FLAVOR_CONFIG and (if needed) add an elif in detect_os_flavor().
    
    Checks:
    - RHUI/subscription status
    - Kernel age (how old is the running kernel)
    - Last package update activity
    - Security patches (if yum/dnf history available)
    - Reboot required check (running kernel vs installed kernels)
    """
    # â”€â”€ Identify OS flavor once; every section below can branch on it â”€â”€
    os_flavor = detect_os_flavor(os_release, kernel_version)
    flavor_cfg = OS_FLAVOR_CONFIG.get(os_flavor, OS_FLAVOR_CONFIG['unknown'])
    kernel_type = flavor_cfg['kernel_type_from_version'](kernel_version or '')
    
    compliance = {
        'os_flavor': os_flavor,
        'kernel_type': kernel_type,         # e.g. 'uek', 'standard', 'default'
        'subscription_status': 'Unknown',
        'subscription_details': [],
        'running_kernel': kernel_version,
        'installed_kernels': [],
        'kernel_age_days': None,
        'kernel_status': 'Unknown',  # Current, Outdated, Very Outdated
        'reboot_required': False,
        'last_update_info': 'N/A',
        'yum_history': [],
        'dnf_history': [],
        'security_packages': [],
        'compliance_score': 'Unknown',  # Good, Warning, Critical
        'findings': []
    }
    
    # 1. Check subscription/RHUI status
    sub_files = [
        os.path.join(sosreport_path, "sos_commands", "subscription_manager", "subscription-manager_list_--consumed"),
        os.path.join(sosreport_path, "sos_commands", "subscription_manager", "subscription-manager_identity"),
        os.path.join(sosreport_path, "sos_commands", "yum", "yum_repolist"),
        os.path.join(sosreport_path, "sos_commands", "dnf", "dnf_repolist"),
    ]
    
    for sf in sub_files:
        if os.path.isfile(sf):
            try:
                with open(sf, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if 'subscription-manager' in sf:
                        if 'No consumed subscription pools' in content:
                            compliance['subscription_status'] = 'Not Subscribed'
                            compliance['findings'].append('System has no active subscription')
                        elif 'Subscription Name:' in content:
                            compliance['subscription_status'] = 'Subscribed'
                            # Extract subscription names
                            for line in content.split('\n'):
                                if 'Subscription Name:' in line:
                                    compliance['subscription_details'].append(line.split(':', 1)[1].strip())
                    elif 'repolist' in sf:
                        # Count enabled repos
                        repo_count = 0
                        rhui_found = False
                        for line in content.split('\n'):
                            if line.strip() and not line.startswith('repo id') and not line.startswith('Last metadata'):
                                repo_count += 1
                                if 'rhui' in line.lower() or 'rhel' in line.lower():
                                    rhui_found = True
                        if repo_count > 0:
                            compliance['subscription_details'].append(f"{repo_count} repositories enabled")
                            if rhui_found:
                                compliance['subscription_status'] = 'RHUI Connected'
            except:
                continue
    
    # Check RHUI packages from already-detected packages
    # RHUI overrides 'Not Subscribed' because Azure/cloud VMs use RHUI instead of subscription-manager
    if packages_info.get('rhui'):
        compliance['subscription_details'].append(f"RHUI packages: {', '.join(packages_info['rhui'][:3])}")
        if compliance['subscription_status'] in ['Unknown', 'Not Subscribed']:
            compliance['subscription_status'] = 'RHUI Connected'
            # Remove the 'no active subscription' finding since RHUI is the subscription method
            compliance['findings'] = [f for f in compliance['findings'] if 'no active subscription' not in f.lower()]
    
    # 2. Check kernel age and reboot status  (OS-flavor-aware)
    kernel_packages = packages_info.get('kernel', [])
    compliance['installed_kernels'] = kernel_packages[:10]
    
    if kernel_version and kernel_version != 'N/A' and kernel_packages:
        # â”€â”€ Step A: isolate BASE kernel packages for the SAME kernel track â”€â”€
        # Use flavor config prefixes to find the right prefix for the running kernel type.
        # E.g. Oracle Linux UEK â†’ prefix "kernel-uek-", RHEL standard â†’ "kernel-"
        #
        # The prefix must be followed by a DIGIT to be a base package
        # (kernel-uek-5.15... YES, kernel-uek-core-5.15... NO)
        matched_prefix = None
        for prefix in flavor_cfg['base_kernel_prefixes']:
            # Pick the prefix that matches the kernel type
            # For UEK: "kernel-uek-" contains "uek", for standard: "kernel-" doesn't
            if kernel_type == 'uek' and 'uek' in prefix:
                matched_prefix = prefix
                break
            elif kernel_type != 'uek' and 'uek' not in prefix:
                matched_prefix = prefix
                break
        if not matched_prefix:
            matched_prefix = flavor_cfg['base_kernel_prefixes'][-1]  # fallback
        
        base_kernel_pkgs = []
        for kpkg in kernel_packages:
            kpkg_lower = kpkg.lower()
            if kpkg_lower.startswith(matched_prefix.lower()):
                remainder = kpkg_lower[len(matched_prefix):]
                if remainder and remainder[0].isdigit():
                    base_kernel_pkgs.append(kpkg)
        
        # â”€â”€ Step B: check if running kernel is installed â”€â”€
        running_kernel_found = any(kernel_version in kpkg for kpkg in base_kernel_pkgs)
        if not running_kernel_found:
            # Fallback: check ALL kernel packages (sub-packages might still reference it)
            running_kernel_found = any(kernel_version in kpkg for kpkg in kernel_packages)
        
        # â”€â”€ Step C: compare against latest installed base kernel â”€â”€
        if running_kernel_found and base_kernel_pkgs:
            # Sort descending so the newest version is first
            base_kernel_pkgs_sorted = sorted(base_kernel_pkgs, reverse=True)
            latest_pkg = base_kernel_pkgs_sorted[0]
            
            if kernel_version not in latest_pkg:
                compliance['reboot_required'] = True
                compliance['findings'].append(
                    f'Reboot may be required - running {kernel_type} kernel ({kernel_version}) '
                    f'is not the latest installed ({latest_pkg})'
                )
        elif not running_kernel_found:
            compliance['findings'].append(
                f'Running kernel ({kernel_version}) not found in installed packages list'
            )
    
    # â”€â”€ Step D: kernel staleness heuristic (flavor-aware thresholds) â”€â”€
    if kernel_version and kernel_version != 'N/A':
        kernel_match = re.search(r'(\d+\.\d+\.\d+)-(\d+)\.(\d+)\.(\d+)', kernel_version)
        if kernel_match:
            major_update = int(kernel_match.group(2))
            thresholds = flavor_cfg['staleness_thresholds'].get(
                kernel_type, 
                list(flavor_cfg['staleness_thresholds'].values())[0]  # fallback to first entry
            )
            outdated_min = thresholds['outdated']
            very_outdated_min = thresholds['very_outdated']
            
            if major_update < very_outdated_min:
                compliance['kernel_status'] = 'Very Outdated'
                compliance['findings'].append(
                    f'Kernel appears very outdated for {os_flavor} {kernel_type} '
                    f'(update level {major_update}, threshold < {very_outdated_min})'
                )
            elif major_update < outdated_min:
                compliance['kernel_status'] = 'Outdated'
                compliance['findings'].append(
                    f'Kernel may be outdated for {os_flavor} {kernel_type} '
                    f'(update level {major_update}, threshold < {outdated_min})'
                )
            else:
                compliance['kernel_status'] = 'Recent'
    
    # 3. Check yum/dnf history for last update activity
    history_files = [
        os.path.join(sosreport_path, "sos_commands", "yum", "yum_history"),
        os.path.join(sosreport_path, "sos_commands", "dnf", "dnf_history"),
    ]
    
    for hf in history_files:
        if os.path.isfile(hf):
            try:
                with open(hf, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    # Parse yum/dnf history table
                    # Format: ID | Command line | Date and time | Action(s) | Altered
                    history_entries = []
                    for line in lines:
                        # Look for lines with date patterns
                        date_match = re.search(r'(\d{4}-\d{2}-\d{2})', line)
                        if date_match and '|' in line:
                            parts = [p.strip() for p in line.split('|')]
                            if len(parts) >= 4:
                                history_entries.append({
                                    'id': parts[0],
                                    'command': parts[1][:40] if len(parts) > 1 else '',
                                    'date': parts[2] if len(parts) > 2 else '',
                                    'action': parts[3] if len(parts) > 3 else '',
                                    'altered': parts[4] if len(parts) > 4 else ''
                                })
                    
                    if history_entries:
                        if 'yum' in hf:
                            compliance['yum_history'] = history_entries[:10]
                        else:
                            compliance['dnf_history'] = history_entries[:10]
                        
                        # Get most recent update
                        if history_entries:
                            compliance['last_update_info'] = f"{history_entries[0].get('date', 'N/A')} - {history_entries[0].get('command', 'N/A')}"
                            
                            # Calculate days since last update relative to sosreport date
                            try:
                                last_date_str = history_entries[0].get('date', '')
                                last_date_match = re.search(r'(\d{4}-\d{2}-\d{2})', last_date_str)
                                if last_date_match:
                                    last_update = datetime.strptime(last_date_match.group(1), '%Y-%m-%d')
                                    
                                    # Parse sosreport date to compare against
                                    report_date = None
                                    if report_date_str and report_date_str != 'N/A':
                                        # Try parsing formats like "Thu Feb 06 10:30:45 UTC 2026"
                                        report_year_match = re.search(r'(20\d{2})', report_date_str)
                                        report_month_match = re.search(r'(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)', report_date_str, re.IGNORECASE)
                                        report_day_match = re.search(r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})', report_date_str, re.IGNORECASE)
                                        
                                        if report_year_match and report_month_match and report_day_match:
                                            try:
                                                report_date = datetime.strptime(
                                                    f"{report_year_match.group(1)} {report_month_match.group(1)} {report_day_match.group(1)}", 
                                                    "%Y %b %d"
                                                )
                                            except:
                                                pass
                                    
                                    # Fallback: use current date if sosreport date parsing failed
                                    if not report_date:
                                        report_date = datetime.now()
                                    
                                    days_since = (report_date - last_update).days
                                    # Sanity check: days should be positive
                                    if days_since < 0:
                                        days_since = 0
                                    compliance['kernel_age_days'] = days_since
                                    
                                    if days_since > 180:
                                        compliance['findings'].append(f'Last system update was {days_since} days before sosreport collection')
                                    elif days_since > 90:
                                        compliance['findings'].append(f'Last update was {days_since} days before sosreport - consider more frequent patching')
                            except:
                                pass
            except:
                continue
    
    # 4. Determine overall compliance score
    score_issues = 0
    if compliance['subscription_status'] in ['Not Subscribed', 'Unknown']:
        score_issues += 2
    if compliance['reboot_required']:
        score_issues += 1
    if compliance['kernel_status'] == 'Very Outdated':
        score_issues += 2
    elif compliance['kernel_status'] == 'Outdated':
        score_issues += 1
    if compliance.get('kernel_age_days') and compliance['kernel_age_days'] > 180:
        score_issues += 2
    elif compliance.get('kernel_age_days') and compliance['kernel_age_days'] > 90:
        score_issues += 1
    
    if score_issues == 0:
        compliance['compliance_score'] = 'Good'
    elif score_issues <= 2:
        compliance['compliance_score'] = 'Warning'
    else:
        compliance['compliance_score'] = 'Critical'
    
    return compliance


def generate_copy_paste_summary(hostname: str, system_info: dict, sar_anomalies: dict,
                                critical_events: list, critical_summary: dict,
                                sar_metrics_count: int, logs_count: int,
                                patch_compliance: dict = None,
                                log_summary: dict = None) -> str:
    """Generate a formatted text summary ready to paste into tickets/emails
    
    Returns a pre-formatted plain text summary of the SOSreport analysis.
    """
    cpu_info = system_info.get('cpu_info', {})
    memory_info = system_info.get('memory_info', {})
    df_info = system_info.get('df_info', [])
    
    lines = []
    lines.append("=" * 70)
    lines.append(f"  SOSreport Analysis Summary - {hostname}")
    lines.append("=" * 70)
    lines.append("")
    
    # System Info
    lines.append("--- SYSTEM INFO ---")
    lines.append(f"  Hostname:     {hostname}")
    lines.append(f"  OS Release:   {system_info.get('os_release', 'N/A')}")
    lines.append(f"  Kernel:       {system_info.get('kernel', 'N/A')}")
    lines.append(f"  Architecture: {cpu_info.get('architecture', 'N/A')}")
    lines.append(f"  CPU:          {cpu_info.get('model', 'N/A')}")
    lines.append(f"  CPUs/Cores:   {cpu_info.get('cores', 'N/A')} ({cpu_info.get('sockets', 'N/A')} sockets, {cpu_info.get('threads_per_core', 'N/A')} threads/core)")
    lines.append(f"  Memory:       {memory_info.get('total_gb', 'N/A')}")
    lines.append(f"  SELinux:      {system_info.get('selinux', 'N/A')}")
    kdump = system_info.get('kdump', {})
    kdump_str = kdump.get('enabled', 'Unknown')
    if kdump.get('crashkernel'):
        kdump_str += f" (crashkernel={kdump['crashkernel']})"
    if kdump.get('crash_dumps'):
        kdump_str += f" | {len(kdump['crash_dumps'])} CRASH DUMP(S) FOUND"
    lines.append(f"  Kdump:        {kdump_str}")
    lines.append(f"  Uptime:       {system_info.get('uptime', 'N/A')}")
    lines.append(f"  Date:         {system_info.get('date', 'N/A')}")
    lines.append("")
    
    # Performance Peaks
    lines.append("--- PERFORMANCE PEAKS ---")
    cpu = sar_anomalies.get('cpu', {})
    mem = sar_anomalies.get('memory', {})
    disk = sar_anomalies.get('disk', {})
    load = sar_anomalies.get('load', {})
    net = sar_anomalies.get('network', {})
    
    if cpu.get('samples', 0) > 0:
        cpu_time = cpu['max_time'].strftime('%Y-%m-%d %H:%M') if cpu.get('max_time') else 'N/A'
        lines.append(f"  CPU:    Peak={cpu['max_usage']}% Avg={cpu['avg_usage']}% at {cpu_time}")
    
    if mem.get('samples', 0) > 0:
        mem_time = mem['max_time'].strftime('%Y-%m-%d %H:%M') if mem.get('max_time') else 'N/A'
        lines.append(f"  Memory: Peak={mem['max_usage']}% Avg={mem['avg_usage']}% at {mem_time}")
    
    if disk.get('samples', 0) > 0:
        disk_time = disk['max_time'].strftime('%Y-%m-%d %H:%M') if disk.get('max_time') else 'N/A'
        lines.append(f"  Disk:   Peak={disk['max_util']}% on {disk['max_device']} at {disk_time}")
    
    if load.get('samples', 0) > 0:
        load_time = load['max_time'].strftime('%Y-%m-%d %H:%M') if load.get('max_time') else 'N/A'
        lines.append(f"  Load:   Peak={load['max_load1']}/{load['max_load5']}/{load['max_load15']} at {load_time}")
        if load.get('max_blocked', 0) > 0:
            lines.append(f"          Max blocked processes: {load['max_blocked']}")
    
    if net.get('samples', 0) > 0:
        lines.append(f"  Net:    Peak RX={net['max_rx']:.1f} KB/s TX={net['max_tx']:.1f} KB/s on {net['max_interface']}")
    
    lines.append("")
    
    # Filesystem
    if df_info:
        lines.append("--- FILESYSTEM USAGE ---")
        critical_fs = [fs for fs in df_info if fs.get('use_percent', 0) >= 80]
        for fs in sorted(df_info, key=lambda x: x.get('use_percent', 0), reverse=True):
            use_pct = fs.get('use_percent', 0)
            flag = " *** HIGH ***" if use_pct >= 90 else " * WARNING *" if use_pct >= 80 else ""
            lines.append(f"  {fs.get('mountpoint', ''):<25} {fs.get('use_percent', 0):>3}% used  ({fs.get('used', 'N/A')}/{fs.get('size', 'N/A')}){flag}")
        lines.append("")
    
    # Critical Events
    lines.append("--- CRITICAL EVENTS ---")
    if critical_events:
        lines.append(f"  Total: {len(critical_events)} critical events detected!")
        for category, count in critical_summary.items():
            if count > 0:
                lines.append(f"  - {category}: {count} events")
    else:
        lines.append("  No critical events detected - system logs appear healthy.")
    lines.append("")
    
    # Patch Compliance (if available)
    if patch_compliance:
        lines.append("--- PATCH COMPLIANCE ---")
        flavor_labels = {
            'oracle_linux': 'Oracle Linux', 'rhel': 'RHEL', 'centos': 'CentOS',
            'rocky': 'Rocky Linux', 'alma': 'AlmaLinux', 'suse': 'SUSE', 'ubuntu': 'Ubuntu',
        }
        flavor = patch_compliance.get('os_flavor', 'unknown')
        lines.append(f"  OS Flavor:     {flavor_labels.get(flavor, flavor)} ({patch_compliance.get('kernel_type', 'standard').upper()} kernel)")
        lines.append(f"  Subscription:  {patch_compliance.get('subscription_status', 'Unknown')}")
        lines.append(f"  Kernel Status: {patch_compliance.get('kernel_status', 'Unknown')}")
        lines.append(f"  Last Update:   {patch_compliance.get('last_update_info', 'N/A')}")
        if patch_compliance.get('reboot_required'):
            lines.append(f"  Reboot:        *** REQUIRED ***")
        if patch_compliance.get('findings'):
            lines.append(f"  Findings:")
            for finding in patch_compliance['findings']:
                lines.append(f"    - {finding}")
        lines.append(f"  Compliance:    {patch_compliance.get('compliance_score', 'Unknown')}")
        lines.append("")
    
    # Data Summary
    lines.append("--- DATA SUMMARY ---")
    lines.append(f"  SAR Metrics:   {sar_metrics_count:,}")
    lines.append(f"  Log Entries:   {logs_count:,}")
    if log_summary:
        source_labels = {
            'messages': 'Messages', 'syslog': 'Syslog', 'secure': 'Secure',
            'auth': 'Auth.log', 'audit': 'Audit', 'cron': 'Cron',
            'dmesg': 'Dmesg', 'journal': 'Journalctl', 'kern': 'Kern.log',
            'boot': 'Boot.log', 'maillog': 'Maillog', 'yum_dnf': 'Yum/DNF',
        }
        for key, label in source_labels.items():
            count = log_summary.get(key, 0)
            if count > 0:
                lines.append(f"    {label + ':':<15} {count:,}")
    lines.append("")
    lines.append("=" * 70)
    lines.append(f"  Generated by SOSreport Analyzer V6")
    lines.append("=" * 70)
    
    return '\n'.join(lines)


def correlate_timestamps(sar_metrics: list, critical_events: list, 
                         window_minutes: int = 5) -> list:
    """Correlate critical events with SAR metrics at the same timestamp
    
    For each critical event, find SAR metrics within +/- window_minutes
    to show what was happening on the system when the event occurred.
    
    Returns a list of correlated entries with event + surrounding SAR data.
    """
    if not critical_events or not sar_metrics:
        return []
    
    # Build a time-indexed lookup for SAR metrics (CPU 'all' and memory only)
    sar_by_time = {}
    for m in sar_metrics:
        ts = m.get('timestamp')
        if not ts or not isinstance(ts, datetime):
            continue
        
        measurement = m.get('measurement', '')
        fields = m.get('fields', {})
        
        # Round to nearest minute for matching
        ts_key = ts.replace(second=0, microsecond=0)
        
        if ts_key not in sar_by_time:
            sar_by_time[ts_key] = {}
        
        if measurement == 'sar_cpu':
            cpu_id = m.get('cpu', fields.get('cpu', ''))
            if cpu_id == 'all':
                idle = fields.get('pct_idle', 100)
                sar_by_time[ts_key]['cpu_usage'] = round(100 - idle, 1)
                sar_by_time[ts_key]['cpu_iowait'] = round(fields.get('pct_iowait', 0), 1)
                sar_by_time[ts_key]['cpu_steal'] = round(fields.get('pct_steal', 0), 1)
        
        elif measurement == 'sar_memory':
            sar_by_time[ts_key]['mem_used_pct'] = round(fields.get('pct_memused', 0), 1)
        
        elif measurement == 'sar_load':
            sar_by_time[ts_key]['load_1'] = fields.get('ldavg_1', 0)
            sar_by_time[ts_key]['load_5'] = fields.get('ldavg_5', 0)
            sar_by_time[ts_key]['blocked'] = fields.get('blocked', 0)
        
        elif measurement == 'sar_disk':
            util = fields.get('pct_util', 0)
            device = m.get('device', fields.get('DEV', ''))
            # Keep the highest disk util
            existing_util = sar_by_time[ts_key].get('disk_util', 0)
            if util > existing_util:
                sar_by_time[ts_key]['disk_util'] = round(util, 1)
                sar_by_time[ts_key]['disk_device'] = device
    
    # Sort SAR timestamps for binary search
    sar_times = sorted(sar_by_time.keys())
    
    if not sar_times:
        return []
    
    # For each critical event, find nearest SAR data
    correlations = []
    seen_events = set()  # Deduplicate similar events at same time
    
    for event in critical_events:
        event_ts = event.get('timestamp')
        if not event_ts or not isinstance(event_ts, datetime):
            continue
        
        event_key = f"{event_ts.strftime('%Y-%m-%d %H:%M')}_{event.get('category', '')}"
        if event_key in seen_events:
            continue
        seen_events.add(event_key)
        
        event_ts_rounded = event_ts.replace(second=0, microsecond=0)
        window = timedelta(minutes=window_minutes)
        
        # Find SAR data points within the time window
        matching_sar = {}
        best_match_time = None
        best_match_diff = timedelta.max
        
        for sar_ts in sar_times:
            diff = abs(sar_ts - event_ts_rounded)
            if diff <= window:
                if diff < best_match_diff:
                    best_match_diff = diff
                    best_match_time = sar_ts
                    matching_sar = sar_by_time[sar_ts]
        
        correlation = {
            'event_time': event_ts,
            'category': event.get('category', 'Unknown'),
            'pattern': event.get('pattern', ''),
            'message': event.get('message', '')[:200],
            'source': event.get('source', ''),
            'sar_matched': bool(matching_sar),
            'sar_time': best_match_time,
            'cpu_usage': matching_sar.get('cpu_usage', None),
            'cpu_iowait': matching_sar.get('cpu_iowait', None),
            'cpu_steal': matching_sar.get('cpu_steal', None),
            'mem_used_pct': matching_sar.get('mem_used_pct', None),
            'load_1': matching_sar.get('load_1', None),
            'load_5': matching_sar.get('load_5', None),
            'blocked': matching_sar.get('blocked', None),
            'disk_util': matching_sar.get('disk_util', None),
            'disk_device': matching_sar.get('disk_device', None),
        }
        correlations.append(correlation)
    
    # Sort by event time
    correlations.sort(key=lambda x: x['event_time'])
    
    return correlations


def get_system_info(sosreport_path: str) -> dict:
    """Get all system information from sosreport (like xsos)"""
    return {
        'hostname': detect_hostname(sosreport_path),
        'uptime': detect_uptime(sosreport_path),
        'date': detect_date(sosreport_path),
        'os_release': detect_os_release(sosreport_path),
        'kernel': detect_kernel_version(sosreport_path),
        'cpu_info': detect_cpu_info(sosreport_path),
        'memory_info': detect_memory_info(sosreport_path),
        'df_info': detect_df_info(sosreport_path),
        'packages': detect_installed_packages(sosreport_path),
        'selinux': detect_selinux_status(sosreport_path),
        'top_processes': detect_top_processes(sosreport_path),
        'kdump': detect_kdump_status(sosreport_path),
    }


def analyze_sar_anomalies(sar_metrics: List[dict]) -> dict:
    """Analyze SAR metrics to detect peaks and anomalies
    
    Returns a dict with peak values and timestamps for each metric type.
    """
    anomalies = {
        'cpu': {'max_usage': 0, 'max_time': None, 'avg_usage': 0, 'samples': 0},
        'memory': {'max_usage': 0, 'max_time': None, 'avg_usage': 0, 'samples': 0},
        'disk': {'max_util': 0, 'max_time': None, 'max_device': '', 'samples': 0},
        'network': {'max_rx': 0, 'max_tx': 0, 'max_time': None, 'max_interface': '', 'samples': 0},
        'load': {'max_load1': 0, 'max_load5': 0, 'max_load15': 0, 'max_time': None, 'max_blocked': 0, 'samples': 0}
    }
    
    cpu_totals = []
    mem_totals = []
    
    for m in sar_metrics:
        measurement = m.get('measurement', '')
        fields = m.get('fields', {})
        ts = m.get('timestamp')
        
        if measurement == 'sar_cpu':
            # Only look at 'all' CPU, not individual cores
            cpu_id = m.get('cpu', fields.get('cpu', ''))
            if cpu_id == 'all':
                # CPU usage = 100 - %idle
                idle = fields.get('pct_idle', 100)
                usage = 100 - idle
                cpu_totals.append(usage)
                anomalies['cpu']['samples'] += 1
                
                if usage > anomalies['cpu']['max_usage']:
                    anomalies['cpu']['max_usage'] = round(usage, 2)
                    anomalies['cpu']['max_time'] = ts
        
        elif measurement == 'sar_memory':
            mem_used = fields.get('pct_memused', 0)
            mem_totals.append(mem_used)
            anomalies['memory']['samples'] += 1
            
            if mem_used > anomalies['memory']['max_usage']:
                anomalies['memory']['max_usage'] = round(mem_used, 2)
                anomalies['memory']['max_time'] = ts
        
        elif measurement == 'sar_disk':
            util = fields.get('pct_util', 0)
            device = m.get('device', fields.get('DEV', ''))
            anomalies['disk']['samples'] += 1
            
            if util > anomalies['disk']['max_util']:
                anomalies['disk']['max_util'] = round(util, 2)
                anomalies['disk']['max_time'] = ts
                anomalies['disk']['max_device'] = device
        
        elif measurement == 'sar_network':
            rx = fields.get('rxkB_s', fields.get('rxKB_s', 0))
            tx = fields.get('txkB_s', fields.get('txKB_s', 0))
            iface = m.get('interface', fields.get('IFACE', ''))
            anomalies['network']['samples'] += 1
            
            if rx > anomalies['network']['max_rx']:
                anomalies['network']['max_rx'] = round(rx, 2)
                anomalies['network']['max_time'] = ts
                anomalies['network']['max_interface'] = iface
            if tx > anomalies['network']['max_tx']:
                anomalies['network']['max_tx'] = round(tx, 2)
        
        elif measurement == 'sar_load':
            load1 = fields.get('ldavg_1', 0)
            load5 = fields.get('ldavg_5', 0)
            load15 = fields.get('ldavg_15', 0)
            blocked = fields.get('blocked', 0)
            anomalies['load']['samples'] += 1
            
            if load1 > anomalies['load']['max_load1']:
                anomalies['load']['max_load1'] = round(load1, 2)
                anomalies['load']['max_load5'] = round(load5, 2)
                anomalies['load']['max_load15'] = round(load15, 2)
                anomalies['load']['max_time'] = ts
            if blocked > anomalies['load']['max_blocked']:
                anomalies['load']['max_blocked'] = blocked
    
    # Calculate averages
    if cpu_totals:
        anomalies['cpu']['avg_usage'] = round(sum(cpu_totals) / len(cpu_totals), 2)
    if mem_totals:
        anomalies['memory']['avg_usage'] = round(sum(mem_totals) / len(mem_totals), 2)
    
    return anomalies


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
            'sample_ts_date': None,
            'used_fallback_date': False
        }
        
        for timestamp_elem in timestamp_elements:
            time_str = timestamp_elem.get('time')
            
            # Try multiple ways to get date from timestamp element
            date_str = None
            
            # Method 1: Direct 'date' attribute (standard sysstat XML)
            date_str = timestamp_elem.get('date')
            
            # Method 2: Try with common namespace prefixes
            if not date_str:
                for attr_name in timestamp_elem.attrib:
                    if attr_name.endswith('date') or 'date' in attr_name.lower():
                        date_str = timestamp_elem.attrib[attr_name]
                        break
            
            # Method 3: Look for date child element
            if not date_str:
                for child in timestamp_elem:
                    if local_tag(child) == 'date' and child.text:
                        date_str = child.text.strip()
                        break
            
            # Fallback: Use file_date but subtract 1 day for evening times
            # (file_date is when file was rotated at midnight, data from previous day)
            if not date_str:
                xml_elements_found['used_fallback_date'] = True
                if file_date:
                    try:
                        file_dt = datetime.strptime(file_date, "%Y-%m-%d")
                        # For data times in PM (12:00-23:59), it's from the previous day
                        if time_str:
                            hour = int(time_str.split(':')[0])
                            if hour >= 12:  # PM times likely from previous day
                                file_dt = file_dt - timedelta(days=1)
                        date_str = file_dt.strftime("%Y-%m-%d")
                    except:
                        date_str = file_date
                else:
                    date_str = file_date
            
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
    
    def __init__(self, sosreport_path: str, hostname: str, year: int, report_month: int = None):
        self.sosreport_path = sosreport_path
        self.hostname = hostname
        self.year = year
        self.report_month = report_month  # Month when sosreport was taken (for year correction)
        self.logs = []
        self.critical_events = []  # Store detected critical events
        self.summary = {
            'messages': 0,
            'syslog': 0,
            'secure': 0,
            'auth': 0,
            'audit': 0,
            'cron': 0,
            'dmesg': 0,
            'journal': 0,
            'kern': 0,
            'boot': 0,
            'maillog': 0,
            'yum_dnf': 0,
        }
        self.critical_summary = {}  # Summary by category
    
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
        """Parse syslog format line with smart year detection
        
        If log month > report month, the log is from the previous year.
        e.g., if report is Feb 2026 and log is from Nov, it's Nov 2025.
        """
        pattern = r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s*(.*)$'
        match = re.match(pattern, line)
        
        if match:
            month_str, day, time_str, hostname, program, message = match.groups()
            try:
                # Determine correct year based on month
                year = self.year
                month_map = {
                    'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
                    'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12
                }
                log_month = month_map.get(month_str.lower())
                
                # If log month is greater than report month, it's from previous year
                if log_month and self.report_month and log_month > self.report_month:
                    year = self.year - 1
                
                ts_str = f"{year} {month_str} {day} {time_str}"
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
    
    def _glob_log_variants(self, base_dir: str, base_name: str, extra_patterns: List[str] = None) -> List[str]:
        """Helper: glob a log file + all its rotated/compressed variants.
        
        Matches:  base_name, base_name-*, base_name.[0-9]*, base_name*.gz/xz/bz2
        Plus any extra_patterns supplied (e.g. sos_commands paths).
        """
        import glob
        patterns = [
            os.path.join(base_dir, base_name),
            os.path.join(base_dir, f'{base_name}-*'),
            os.path.join(base_dir, f'{base_name}.[0-9]*'),
            os.path.join(base_dir, f'{base_name}*.gz'),
            os.path.join(base_dir, f'{base_name}*.xz'),
            os.path.join(base_dir, f'{base_name}*.bz2'),
        ]
        if extra_patterns:
            patterns.extend(extra_patterns)
        
        files = []
        for p in patterns:
            files.extend(glob.glob(p))
        return files
    
    def find_log_files(self) -> dict:
        """Find all log files including rotated ones, sos_commands outputs, journalctl, dmesg etc.
        
        Covers: messages, syslog, secure, auth.log, audit, cron, kern.log, boot.log,
                dmesg, journalctl, maillog, yum/dnf logs.
        """
        import glob
        
        found_files = {
            'messages': [],
            'syslog': [],
            'secure': [],
            'auth': [],
            'audit': [],
            'cron': [],
            'dmesg': [],
            'journal': [],
            'kern': [],
            'boot': [],
            'maillog': [],
            'yum_dnf': [],
        }
        
        var_log = os.path.join(self.sosreport_path, 'var', 'log')
        sos_cmds = os.path.join(self.sosreport_path, 'sos_commands')
        
        # â”€â”€ messages (RHEL/OL primary system log) â”€â”€
        found_files['messages'] = self._glob_log_variants(
            var_log, 'messages',
            [os.path.join(sos_cmds, 'logs', '*messages*')]
        )
        
        # â”€â”€ syslog (Debian/Ubuntu primary system log) â”€â”€
        found_files['syslog'] = self._glob_log_variants(
            var_log, 'syslog',
            [os.path.join(sos_cmds, 'logs', '*syslog*')]
        )
        
        # â”€â”€ secure (RHEL/OL auth log) â”€â”€
        found_files['secure'] = self._glob_log_variants(
            var_log, 'secure',
            [os.path.join(sos_cmds, 'logs', '*secure*')]
        )
        
        # â”€â”€ auth.log (Debian/Ubuntu auth log) â”€â”€
        found_files['auth'] = self._glob_log_variants(
            var_log, 'auth.log'
        )
        
        # â”€â”€ audit â”€â”€
        audit_dir = os.path.join(var_log, 'audit')
        found_files['audit'] = self._glob_log_variants(
            audit_dir, 'audit.log',
            [os.path.join(sos_cmds, 'auditd', '*')]
        )
        
        # â”€â”€ cron â”€â”€
        found_files['cron'] = self._glob_log_variants(
            var_log, 'cron',
            [os.path.join(sos_cmds, 'logs', '*cron*')]
        )
        
        # â”€â”€ dmesg (kernel ring buffer â€” critical for hardware/driver errors) â”€â”€
        dmesg_paths = [
            os.path.join(sos_cmds, 'kernel', 'dmesg'),
            os.path.join(sos_cmds, 'kernel', 'dmesg_-T'),  # dmesg with human timestamps
            os.path.join(var_log, 'dmesg'),
            os.path.join(var_log, 'dmesg.old'),
        ]
        found_files['dmesg'] = [f for f in dmesg_paths if os.path.isfile(f)]
        
        # â”€â”€ journalctl (systemd journal â€” primary on Debian/Ubuntu, useful everywhere) â”€â”€
        journal_dirs = [
            os.path.join(sos_cmds, 'logs'),
            os.path.join(sos_cmds, 'systemd'),
        ]
        for jdir in journal_dirs:
            if os.path.isdir(jdir):
                for fname in os.listdir(jdir):
                    if fname.startswith('journalctl') and os.path.isfile(os.path.join(jdir, fname)):
                        # Skip non-log files
                        if 'disk-usage' in fname or 'disk_usage' in fname:
                            continue
                        if 'list-boots' in fname or 'list_boots' in fname:
                            continue
                        found_files['journal'].append(os.path.join(jdir, fname))
        
        # â”€â”€ kern.log (Debian/Ubuntu kernel log) â”€â”€
        found_files['kern'] = self._glob_log_variants(var_log, 'kern.log')
        
        # â”€â”€ boot.log â”€â”€
        boot_path = os.path.join(var_log, 'boot.log')
        if os.path.isfile(boot_path):
            found_files['boot'] = [boot_path]
        
        # â”€â”€ maillog â”€â”€
        found_files['maillog'] = self._glob_log_variants(var_log, 'maillog')
        # Also check mail.log (Debian)
        found_files['maillog'].extend(self._glob_log_variants(var_log, 'mail.log'))
        
        # â”€â”€ yum/dnf logs (package management activity) â”€â”€
        yum_path = os.path.join(var_log, 'yum.log')
        dnf_path = os.path.join(var_log, 'dnf.log')
        dnf_rpm_path = os.path.join(var_log, 'dnf.rpm.log')
        for p in [yum_path, dnf_path, dnf_rpm_path]:
            if os.path.isfile(p):
                found_files['yum_dnf'].append(p)
        # Also rotated variants
        found_files['yum_dnf'].extend(self._glob_log_variants(var_log, 'yum.log'))
        found_files['yum_dnf'].extend(self._glob_log_variants(var_log, 'dnf.log'))
        
        # Filter to only existing files (not directories) and remove duplicates
        for key in found_files:
            found_files[key] = list(set([f for f in found_files[key] if os.path.isfile(f)]))
            found_files[key].sort()
        
        # Debug - list what's in sos_commands/logs and sos_commands/kernel
        self.debug_sos_logs_dir = []
        sos_logs_path = os.path.join(self.sosreport_path, 'sos_commands', 'logs')
        if os.path.isdir(sos_logs_path):
            self.debug_sos_logs_dir = os.listdir(sos_logs_path)
        sos_kernel_path = os.path.join(self.sosreport_path, 'sos_commands', 'kernel')
        if os.path.isdir(sos_kernel_path):
            self.debug_sos_logs_dir.extend([f'kernel/{f}' for f in os.listdir(sos_kernel_path)])
        
        return found_files
    
    def parse_dmesg(self, filepath: str) -> List[dict]:
        """Parse dmesg output â€” handles both epoch timestamps and [seconds.usec] format"""
        entries = []
        lines = self.read_file(filepath)
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            timestamp = None
            message = line
            program = 'kernel'
            
            # Format 1: [epoch timestamp] like dmesg -T â†’ [Mon Dec 23 10:15:32 2025]
            dt_match = re.match(r'^\[([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+\d{4})\]\s*(.*)', line)
            if dt_match:
                try:
                    timestamp = datetime.strptime(dt_match.group(1), '%a %b %d %H:%M:%S %Y')
                    message = dt_match.group(2)
                except ValueError:
                    pass
            
            # Format 2: [seconds.usec] like standard dmesg
            if not timestamp:
                sec_match = re.match(r'^\[\s*([\d.]+)\]\s*(.*)', line)
                if sec_match:
                    message = sec_match.group(2)
                    # No real timestamp â€” use None; we still capture the message
            
            entries.append({
                'timestamp': timestamp,
                'source': 'dmesg',
                'program': program,
                'message': message
            })
        
        return entries
    
    def parse_journal(self, filepath: str) -> List[dict]:
        """Parse journalctl output â€” handles systemd journal format"""
        entries = []
        lines = self.read_file(filepath)
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('--'):
                continue
            
            # journalctl format: "Mon 2025-12-23 10:15:32 UTC hostname program[pid]: message"
            # or: "Dec 23 10:15:32 hostname program[pid]: message"
            ts = None
            program = 'journal'
            message = line
            
            # ISO-ish: Mon 2025-12-23 10:15:32
            iso_match = re.match(r'^\w+\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s*(.*)', line)
            if iso_match:
                try:
                    ts = datetime.strptime(iso_match.group(1), '%Y-%m-%d %H:%M:%S')
                    program = iso_match.group(3)
                    message = iso_match.group(4)
                except ValueError:
                    pass
            
            # Syslog style fallback
            if not ts:
                ts, program, message = self.parse_syslog_line(line)
            
            entries.append({
                'timestamp': ts,
                'source': 'journal',
                'program': program if program else 'journal',
                'message': message
            })
        
        return entries
    
    def parse_all(self) -> List[dict]:
        """Parse all log files â€” messages, syslog, secure, auth, audit, cron,
        dmesg, journalctl, kern.log, boot.log, maillog, yum/dnf"""
        log_files = self.find_log_files()
        
        for log_type, filepaths in log_files.items():
            for filepath in filepaths:
                if log_type == 'audit':
                    entries = self.parse_audit(filepath)
                elif log_type == 'dmesg':
                    entries = self.parse_dmesg(filepath)
                elif log_type == 'journal':
                    entries = self.parse_journal(filepath)
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
        
        # Detect critical events
        self.detect_critical_events()
        
        return self.logs
    
    def detect_critical_events(self):
        """Scan all logs for critical event patterns"""
        self.critical_events = []
        self.critical_summary = {category: 0 for category in LOG_PATTERNS.keys()}
        
        for log in self.logs:
            message = log.get('message', '')
            if not message:
                continue
            
            # Check against each category
            for category, patterns in LOG_PATTERNS.items():
                for pattern in patterns:
                    if pattern.lower() in message.lower():
                        self.critical_events.append({
                            'timestamp': log.get('timestamp'),
                            'source': log.get('source'),
                            'program': log.get('program'),
                            'message': message,
                            'category': category,
                            'pattern': pattern
                        })
                        self.critical_summary[category] += 1
                        break  # Only count once per category per log line


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
    
    # Group by source â€” skip entries without timestamps (e.g. dmesg [seconds] format)
    streams = {}
    for log in logs:
        if not log.get('timestamp'):
            continue  # Can't push to Loki without a timestamp
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


def push_critical_events_to_loki(critical_events: List[dict], hostname: str, progress_callback=None) -> Tuple[int, str]:
    """Push critical events to Loki with category labels
    
    Returns: (pushed_count, error_message)
    """
    if not critical_events:
        return 0, ""
    
    url = f"{LOKI_URL}/loki/api/v1/push"
    
    # Group by category
    streams_by_category = {}
    for event in critical_events:
        category = event.get('category', 'Unknown')
        if category not in streams_by_category:
            streams_by_category[category] = []
        
        ts = event.get('timestamp')
        if ts:
            ts_ns = str(int(ts.timestamp() * 1e9))
            msg = f"[{event.get('pattern', '')}] [{event.get('program', '')}] {event.get('message', '')}"
            streams_by_category[category].append([ts_ns, msg])
    
    pushed = 0
    errors = []
    
    for category, values in streams_by_category.items():
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
                        "category": category,
                        "critical": "true",
                        "job": "sosreport"
                    },
                    "values": batch
                }]
            }
            
            try:
                response = requests.post(url, json=payload, timeout=30)
                if response.status_code == 204:
                    pushed += len(batch)
                else:
                    errors.append(f"{category}: HTTP {response.status_code}")
            except Exception as e:
                errors.append(f"{category}: {str(e)[:50]}")
        
        if progress_callback:
            progress_callback(pushed, len(critical_events))
    
    error_msg = "; ".join(errors[:3]) if errors else ""
    return pushed, error_msg


def create_grafana_dashboard(hostname: str, time_from: datetime = None, time_to: datetime = None, 
                             system_info: dict = None, sar_anomalies: dict = None) -> Optional[str]:
    """Create combined dashboard in Grafana with all SAR and Log panels
    
    Args:
        hostname: The hostname for the dashboard
        time_from: Start time for the dashboard (auto-detected from data)
        time_to: End time for the dashboard (auto-detected from data)
        system_info: System information dict from get_system_info()
        sar_anomalies: SAR anomaly detection results from analyze_sar_anomalies()
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

    # Row Header: SAR Metrics
    panels.append({
        "gridPos": {"h": 1, "w": 24, "x": 0, "y": y_pos},
        "id": panel_id,
        "title": " SAR Performance Metrics",
        "type": "row",
        "collapsed": False
    })
    panel_id += 1
    y_pos += 1
    
    # CPU Usage % (stacked - %user, %system, %iowait, %steal, %irq, %soft - like mpstat)
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {
            "defaults": {"color": {"mode": "palette-classic"}, "custom": {"lineWidth": 1, "fillOpacity": 30, "stacking": {"mode": "normal", "group": "A"}}, "unit": "percent", "max": 100, "min": 0},
            "overrides": [
                {"matcher": {"id": "byName", "options": "pct_user"},   "properties": [{"id": "displayName", "value": "%user"},   {"id": "color", "value": {"fixedColor": "green", "mode": "fixed"}}]},
                {"matcher": {"id": "byName", "options": "pct_system"}, "properties": [{"id": "displayName", "value": "%system"}, {"id": "color", "value": {"fixedColor": "red", "mode": "fixed"}}]},
                {"matcher": {"id": "byName", "options": "pct_iowait"}, "properties": [{"id": "displayName", "value": "%iowait"}, {"id": "color", "value": {"fixedColor": "orange", "mode": "fixed"}}]},
                {"matcher": {"id": "byName", "options": "pct_steal"},  "properties": [{"id": "displayName", "value": "%steal"},  {"id": "color", "value": {"fixedColor": "purple", "mode": "fixed"}}]},
                {"matcher": {"id": "byName", "options": "pct_irq"},    "properties": [{"id": "displayName", "value": "%irq"},    {"id": "color", "value": {"fixedColor": "yellow", "mode": "fixed"}}]},
                {"matcher": {"id": "byName", "options": "pct_soft"},   "properties": [{"id": "displayName", "value": "%soft"},   {"id": "color", "value": {"fixedColor": "blue", "mode": "fixed"}}]},
            ]
        },
        "gridPos": {"h": 6, "w": 12, "x": 0, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi", "sort": "desc"}},
        "targets": [{"datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'from(bucket: "{INFLUXDB_BUCKET}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r["_measurement"] == "sar_cpu") |> filter(fn: (r) => r["host"] == "{hostname}") |> filter(fn: (r) => r["cpu"] == "all") |> filter(fn: (r) => r["_field"] == "pct_user" or r["_field"] == "pct_system" or r["_field"] == "pct_iowait" or r["_field"] == "pct_steal" or r["_field"] == "pct_irq" or r["_field"] == "pct_soft") |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)',
            "refId": "A"}],
        "title": "CPU Usage % (All CPUs - Stacked)",
        "type": "timeseries"
    })
    panel_id += 1

    # CPU Load Average (kept alongside CPU %)
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "custom": {"lineWidth": 2, "fillOpacity": 10}, "unit": "short"}},
        "gridPos": {"h": 6, "w": 12, "x": 12, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        "targets": [{"datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'from(bucket: "{INFLUXDB_BUCKET}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r["_measurement"] == "sar_load") |> filter(fn: (r) => r["host"] == "{hostname}") |> filter(fn: (r) => r["_field"] == "ldavg_1" or r["_field"] == "ldavg_5" or r["_field"] == "ldavg_15")',
            "refId": "A"}],
        "title": "CPU Load Average",
        "type": "timeseries"
    })
    panel_id += 1
    y_pos += 6

    # Per-CPU Usage % (each CPU as a separate line - useful for NUMA/core imbalance detection)
    # Uses pct_user per CPU (most dominant metric) - avoids map() which can cause "No data" on some InfluxDB versions
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "custom": {"lineWidth": 1, "fillOpacity": 5}, "unit": "percent", "max": 100, "min": 0}},
        "gridPos": {"h": 6, "w": 12, "x": 0, "y": y_pos},
        "id": panel_id,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi", "sort": "desc"}},
        "targets": [
            {"datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'from(bucket: "{INFLUXDB_BUCKET}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r["_measurement"] == "sar_cpu") |> filter(fn: (r) => r["host"] == "{hostname}") |> filter(fn: (r) => r["cpu"] != "all") |> filter(fn: (r) => r["_field"] == "pct_user" or r["_field"] == "pct_system" or r["_field"] == "pct_iowait" or r["_field"] == "pct_steal") |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value") |> map(fn: (r) => ({{r with _value: (if exists r.pct_user then r.pct_user else 0.0) + (if exists r.pct_system then r.pct_system else 0.0) + (if exists r.pct_iowait then r.pct_iowait else 0.0) + (if exists r.pct_steal then r.pct_steal else 0.0)}})) |> group(columns: ["host", "cpu"]) |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)',
            "refId": "A"},
            {"datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'from(bucket: "{INFLUXDB_BUCKET}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r["_measurement"] == "sar_cpu") |> filter(fn: (r) => r["host"] == "{hostname}") |> filter(fn: (r) => r["cpu"] != "all") |> filter(fn: (r) => r["_field"] == "pct_user") |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)',
            "refId": "B", "hide": False}
        ],
        "title": "Per-CPU Usage % (user+sys+iowait+steal)",
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
            "maxLines": 1000,
            "queryType": "range",
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
            "maxLines": 1000,
            "queryType": "range",
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
            "maxLines": 1000,
            "queryType": "range",
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
            "maxLines": 1000,
            "queryType": "range",
            "refId": "A"}],
        "title": "â° Cron Logs (/var/log/cron)",
        "type": "logs"
    })
    panel_id += 1
    y_pos += 6
    
    # NOTE: Critical Events are displayed in Streamlit main page only (removed from Grafana to reduce load)
    
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
        "refresh": "",  # Disable auto-refresh (sosreport is historical data)
        "liveNow": False,  # Disable live mode
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
        # Use /api/org endpoint with auth (works better with Azure Grafana which requires auth)
        headers = {"Authorization": f"Bearer {GRAFANA_API_KEY}"}
        response = requests.get(f"{GRAFANA_URL}/api/org", headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            org_name = data.get('name', 'Connected')
            return True, f"Healthy ({org_name})"
        # Fallback: try health endpoint without auth (for self-hosted Grafana)
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
    st.markdown('<h1 class="main-header">ðŸ“Š SOSreport Analyzer V6</h1>', unsafe_allow_html=True)
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
        st.header(" Options")
        push_sar = st.checkbox("Push SAR to InfluxDB", value=True)
        push_logs = st.checkbox("Push Logs to Loki", value=True)
        create_dashboard = st.checkbox("Create Grafana Dashboard", value=True)
        
        # Advanced options
        with st.expander(" Advanced Options"):
            add_unique_suffix = st.checkbox(
                "Add unique suffix to hostname", 
                value=False,
                help="Use this if you're re-uploading and see 'out of order' errors. Adds a timestamp suffix to avoid conflicts."
            )
    
    if uploaded_file is not None:
        st.markdown("---")
        
        # Process button
        if st.button(" Process SOSreport", type="primary", use_container_width=True):
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
                kernel_version = system_info.get('kernel', 'N/A')
                cpu_info = system_info.get('cpu_info', {})
                memory_info = system_info.get('memory_info', {})
                df_info = system_info.get('df_info', [])
                packages_info = system_info.get('packages', {})
                selinux_status = system_info.get('selinux', 'N/A')
                kdump_info = system_info.get('kdump', {})
                top_processes = system_info.get('top_processes', {})
                
                # Add unique suffix if requested (to avoid Loki out-of-order issues)
                original_hostname = hostname
                if add_unique_suffix:
                    import time
                    suffix = datetime.now().strftime("%Y%m%d_%H%M%S")
                    hostname = f"{hostname}_{suffix}"
                    st.info(f" Using unique hostname: `{hostname}` (original: `{original_hostname}`)")
                
                # Get year using improved detection (from date output or filename)
                year = get_report_year(sosreport_path, uploaded_file.name)
                
                progress_bar.progress(50, "Parsing data...")
                status_text.text(f" Detected hostname: {hostname}, Log Year: {year}")
                
                # Parse SAR with limits - pass year and date for proper timestamp handling
                sar_parser = SARParser(sosreport_path, hostname, report_year=year, report_date_str=sys_date)
                sar_files_found = sar_parser.find_sar_files()
                status_text.text(f" Found {len(sar_files_found)} SAR files (source: {sar_parser.sar_source})")
                sar_metrics = sar_parser.parse_all()
                
                # Apply limits to prevent memory issues
                if len(sar_metrics) > MAX_SAR_METRICS:
                    st.warning(f" SAR metrics limited to {MAX_SAR_METRICS:,} (total: {len(sar_metrics):,})")
                    sar_metrics = sar_metrics[:MAX_SAR_METRICS]
                
                # Analyze SAR metrics for peaks and anomalies
                status_text.text(" Analyzing for peaks and anomalies...")
                sar_anomalies = analyze_sar_anomalies(sar_metrics)
                
                # Parse Logs - with smart year detection for Nov/Dec logs
                status_text.text(" Parsing log files...")
                # Extract report month from date string for year correction
                report_month = None
                if sys_date and sys_date != "N/A":
                    month_map = {'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
                                 'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12}
                    for month_name, month_num in month_map.items():
                        if month_name in sys_date.lower():
                            report_month = month_num
                            break
                
                log_parser = LogParser(sosreport_path, hostname, year, report_month=report_month)
                logs = log_parser.parse_all()
                critical_events = log_parser.critical_events
                critical_summary = log_parser.critical_summary
                
                # Apply log limits
                if len(logs) > MAX_LOG_LINES:
                    st.warning(f" Log entries limited to {MAX_LOG_LINES:,} (total: {len(logs):,})")
                    logs = logs[:MAX_LOG_LINES]
                
                # Debug: Show var/log contents
                var_log_path = os.path.join(sosreport_path, 'var', 'log')
                log_dir_contents = []
                if os.path.isdir(var_log_path):
                    log_dir_contents = os.listdir(var_log_path)
                
                progress_bar.progress(70, "Data parsed!")
                
                # Display summary
                st.markdown("---")
                st.header(" Analysis Summary")
                
                # ============= BASIC SYSTEM INFO (like xsos) =============
                st.subheader(" Basic System Information")
                
                # First row: Core system info
                info_col1, info_col2, info_col3, info_col4 = st.columns(4)
                
                with info_col1:
                    st.metric("Hostname", hostname)
                with info_col2:
                    st.metric("CPUs", f"{cpu_info.get('cores', 'N/A')}")
                with info_col3:
                    st.metric("Memory", memory_info.get('total_gb', 'N/A'))
                with info_col4:
                    st.metric("Kernel", kernel_version[:30] if len(kernel_version) > 30 else kernel_version)
                
                # Second row: More details
                detail_col1, detail_col2 = st.columns(2)
                
                with detail_col1:
                    st.markdown("##### System Details")
                    st.markdown(f"**OS Release:** `{os_release}`")
                    st.markdown(f"**Architecture:** `{cpu_info.get('architecture', 'N/A')}`")
                    st.markdown(f"**CPU Model:** `{cpu_info.get('model', 'N/A')}`")
                    if cpu_info.get('sockets'):
                        st.markdown(f"**Sockets/Threads:** `{cpu_info.get('sockets', 'N/A')} sockets, {cpu_info.get('threads_per_core', 'N/A')} threads/core`")
                    st.markdown(f"**SELinux:** `{selinux_status}`")
                    # Kdump status - simple one-liner
                    kdump_status = kdump_info.get('enabled', 'Unknown')
                    kdump_icon = "ðŸŸ¢" if kdump_info.get('operational') else "ðŸ”´" if kdump_info.get('operational') is False else "âšª"
                    kdump_text = f"{kdump_icon} `{kdump_status}`"
                    if kdump_info.get('crashkernel'):
                        kdump_text += f" (crashkernel={kdump_info['crashkernel']})"
                    if kdump_info.get('crash_dumps'):
                        kdump_text += f" | âš ï¸ **{len(kdump_info['crash_dumps'])} crash dump(s) found!**"
                    st.markdown(f"**Kdump:** {kdump_text}")
                    if kdump_info.get('crash_dumps'):
                        for dump in kdump_info['crash_dumps']:
                            dump_details = f"ðŸ“ `{dump['directory']}`"
                            if dump.get('has_vmcore'):
                                dump_details += " (vmcore âœ…)"
                            if dump.get('has_dmesg'):
                                dump_details += " (dmesg âœ…)"
                            st.caption(dump_details)
                    st.markdown(f"**Uptime:** `{uptime}`")
                    st.markdown(f"**SOSreport Date:** `{sys_date}`")
                
                with detail_col2:
                    st.markdown("##### Memory Details")
                    if memory_info.get('total_kb', 0) > 0:
                        total_mb = memory_info['total_kb'] / 1024
                        free_mb = memory_info.get('free_kb', 0) / 1024
                        avail_mb = memory_info.get('available_kb', 0) / 1024
                        swap_total = memory_info.get('swap_total_kb', 0) / 1024 / 1024
                        swap_free = memory_info.get('swap_free_kb', 0) / 1024 / 1024
                        st.markdown(f"**Total:** `{total_mb/1024:.1f} GB` | **Free:** `{free_mb/1024:.1f} GB` | **Available:** `{avail_mb/1024:.1f} GB`")
                        st.markdown(f"**Swap:** `{swap_total:.1f} GB total` | `{swap_free:.1f} GB free`")
                        if memory_info.get('hugepages_total', 0) > 0:
                            hp_size = memory_info.get('hugepage_size_kb', 2048) / 1024
                            st.markdown(f"**HugePages:** `{memory_info['hugepages_total']}` ({hp_size:.0f} MB each)")
                    
                    # RHUI Packages
                    st.markdown("##### Installed Packages")
                    st.markdown(f"**Total Packages:** `{packages_info.get('total_count', 0):,}`")
                    if packages_info.get('rhui'):
                        st.markdown(f"**RHUI Packages:** `{', '.join(packages_info['rhui'][:3])}`")
                    if packages_info.get('kernel'):
                        st.markdown(f"**Kernel Packages:** `{len(packages_info['kernel'])} installed`")
                
                # Filesystem/DF Section
                if df_info:
                    st.markdown("##### Filesystem Utilization (df)")
                    # Show high usage filesystems first
                    critical_fs = [fs for fs in df_info if fs.get('use_percent', 0) >= 80]
                    normal_fs = [fs for fs in df_info if fs.get('use_percent', 0) < 80]
                    
                    if critical_fs:
                        st.warning(f"âš ï¸ {len(critical_fs)} filesystem(s) at 80%+ utilization")
                    
                    # Create DataFrame for display
                    df_display = []
                    for fs in sorted(df_info, key=lambda x: x.get('use_percent', 0), reverse=True):
                        use_pct = fs.get('use_percent', 0)
                        status = "ðŸ”´" if use_pct >= 90 else "ðŸŸ¡" if use_pct >= 80 else "ðŸŸ¢"
                        df_display.append({
                            'Status': status,
                            'Mountpoint': fs.get('mountpoint', ''),
                            'Size': fs.get('size', 'N/A'),
                            'Used': fs.get('used', 'N/A'),
                            'Avail': fs.get('available', 'N/A'),
                            'Use%': f"{use_pct}%",
                            'Filesystem': fs.get('filesystem', '')[:30]
                        })
                    
                    if df_display:
                        st.dataframe(pd.DataFrame(df_display), use_container_width=True, hide_index=True)
                
                # Top Processes Section
                if top_processes and (top_processes.get('top_cpu') or top_processes.get('top_mem')):
                    st.markdown("##### Top Processes (at sosreport collection time)")
                    
                    proc_col1, proc_col2 = st.columns(2)
                    
                    with proc_col1:
                        st.markdown("**Top CPU Consumers**")
                        top_cpu = top_processes.get('top_cpu', [])
                        if top_cpu:
                            cpu_data = []
                            for p in top_cpu:
                                cpu_data.append({
                                    '%CPU': f"{p['cpu']:.1f}%",
                                    'PID': p['pid'],
                                    'User': p['user'][:12],
                                    'Command': p['command'][:40]
                                })
                            st.dataframe(pd.DataFrame(cpu_data), use_container_width=True, hide_index=True)
                        else:
                            st.write("No data available")
                    
                    with proc_col2:
                        st.markdown("**Top Memory Consumers**")
                        top_mem = top_processes.get('top_mem', [])
                        if top_mem:
                            mem_data = []
                            for p in top_mem:
                                mem_data.append({
                                    '%MEM': f"{p['mem']:.1f}%",
                                    'PID': p['pid'],
                                    'User': p['user'][:12],
                                    'Command': p['command'][:40]
                                })
                            st.dataframe(pd.DataFrame(mem_data), use_container_width=True, hide_index=True)
                        else:
                            st.write("No data available")
                else:
                    st.markdown("##### Top Processes")
                    st.info("â„¹ï¸ No process data found (ps aux output not available in this sosreport)")
                
                st.markdown("---")
                
                # ============= SAR ANOMALIES & PEAKS =============
                st.subheader("ðŸ“ˆ Performance Peaks & Anomalies")
                
                peak_col1, peak_col2, peak_col3, peak_col4 = st.columns(4)
                
                with peak_col1:
                    st.markdown("##### CPU")
                    if sar_anomalies['cpu']['samples'] > 0:
                        max_cpu = sar_anomalies['cpu']['max_usage']
                        avg_cpu = sar_anomalies['cpu']['avg_usage']
                        cpu_time = sar_anomalies['cpu']['max_time']
                        cpu_status = "ðŸ”´" if max_cpu >= 90 else "ðŸŸ¡" if max_cpu >= 70 else "ðŸŸ¢"
                        st.metric("Peak CPU Usage", f"{max_cpu}%", delta=f"avg: {avg_cpu}%")
                        if cpu_time:
                            st.caption(f"{cpu_status} Peak at: {cpu_time.strftime('%Y-%m-%d %H:%M')}")
                    else:
                        st.write("No CPU data")
                
                with peak_col2:
                    st.markdown("##### Memory")
                    if sar_anomalies['memory']['samples'] > 0:
                        max_mem = sar_anomalies['memory']['max_usage']
                        avg_mem = sar_anomalies['memory']['avg_usage']
                        mem_time = sar_anomalies['memory']['max_time']
                        mem_status = "ðŸ”´" if max_mem >= 90 else "ðŸŸ¡" if max_mem >= 80 else "ðŸŸ¢"
                        st.metric("Peak Memory Usage", f"{max_mem}%", delta=f"avg: {avg_mem}%")
                        if mem_time:
                            st.caption(f"{mem_status} Peak at: {mem_time.strftime('%Y-%m-%d %H:%M')}")
                    else:
                        st.write("No memory data")
                
                with peak_col3:
                    st.markdown("##### Disk I/O")
                    if sar_anomalies['disk']['samples'] > 0:
                        max_disk = sar_anomalies['disk']['max_util']
                        disk_time = sar_anomalies['disk']['max_time']
                        disk_dev = sar_anomalies['disk']['max_device']
                        disk_status = "ðŸ”´" if max_disk >= 90 else "ðŸŸ¡" if max_disk >= 70 else "ðŸŸ¢"
                        st.metric("Peak Disk Util", f"{max_disk}%", delta=f"dev: {disk_dev}")
                        if disk_time:
                            st.caption(f"{disk_status} Peak at: {disk_time.strftime('%Y-%m-%d %H:%M')}")
                    else:
                        st.write("No disk data")
                
                with peak_col4:
                    st.markdown("##### Load Average")
                    if sar_anomalies['load']['samples'] > 0:
                        max_load1 = sar_anomalies['load']['max_load1']
                        max_load5 = sar_anomalies['load']['max_load5']
                        max_load15 = sar_anomalies['load']['max_load15']
                        max_blocked = sar_anomalies['load']['max_blocked']
                        load_time = sar_anomalies['load']['max_time']
                        # Compare load to CPU count
                        cpu_count = cpu_info.get('cores', 1)
                        load_ratio = max_load1 / cpu_count if cpu_count else 0
                        load_status = "ðŸ”´" if load_ratio >= 2 else "ðŸŸ¡" if load_ratio >= 1 else "ðŸŸ¢"
                        st.metric("Peak Load (1/5/15)", f"{max_load1}/{max_load5}/{max_load15}")
                        if load_time:
                            st.caption(f"{load_status} Peak at: {load_time.strftime('%Y-%m-%d %H:%M')}")
                        if max_blocked > 0:
                            st.caption(f"âš ï¸ Max blocked processes: {max_blocked}")
                    else:
                        st.write("No load data")
                
                # Network peaks
                if sar_anomalies['network']['samples'] > 0:
                    net_col1, net_col2 = st.columns(2)
                    with net_col1:
                        max_rx = sar_anomalies['network']['max_rx']
                        max_tx = sar_anomalies['network']['max_tx']
                        net_iface = sar_anomalies['network']['max_interface']
                        net_time = sar_anomalies['network']['max_time']
                        st.markdown(f"##### Network Peak: RX={max_rx:.1f} KB/s | TX={max_tx:.1f} KB/s on `{net_iface}`")
                        if net_time:
                            st.caption(f"Peak at: {net_time.strftime('%Y-%m-%d %H:%M')}")
                
                st.markdown("---")
                
                # ============= DATA TOTALS =============
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
                
                with col3:
                    st.subheader("Log Entries")
                    # Show all log sources that have entries
                    log_source_labels = {
                        'messages': 'Messages', 'syslog': 'Syslog', 'secure': 'Secure',
                        'auth': 'Auth.log', 'audit': 'Audit', 'cron': 'Cron',
                        'dmesg': 'Dmesg', 'journal': 'Journalctl', 'kern': 'Kern.log',
                        'boot': 'Boot.log', 'maillog': 'Maillog', 'yum_dnf': 'Yum/DNF',
                    }
                    for key, label in log_source_labels.items():
                        count = log_parser.summary.get(key, 0)
                        if count > 0:
                            st.write(f"- {label}: {count:,}")
                    st.metric("Total Logs", f"{len(logs):,}")
                
                # Critical Events Summary
                if critical_events:
                    st.markdown("---")
                    st.header("ðŸš¨ Critical Events Detected")
                    
                    total_critical = len(critical_events)
                    st.error(f"âš ï¸ **{total_critical:,} critical events detected!**")
                    
                    # Group events by category for display
                    events_by_category = {}
                    for event in critical_events:
                        cat = event.get('category', 'Unknown')
                        if cat not in events_by_category:
                            events_by_category[cat] = []
                        events_by_category[cat].append(event)
                    
                    # Display each category with expandable event list
                    category_icons = {
                        "File System & Disk": "ðŸ’¾",
                        "Memory/OOM": "ðŸ§ ",
                        "CPU & Kernel Panic": "âš¡",
                        "Security & Antivirus": "ðŸ”’",
                        "Network Issues": "ðŸŒ"
                    }
                    
                    for category in LOG_PATTERNS.keys():
                        count = critical_summary.get(category, 0)
                        icon = category_icons.get(category, "âš ï¸")
                        
                        if count > 0:
                            with st.expander(f"{icon} {category} ({count:,} events)", expanded=False):
                                cat_events = events_by_category.get(category, [])
                                # Show all events for this category (limit to 100 for performance)
                                for event in cat_events[:100]:
                                    ts = event.get('timestamp', 'N/A')
                                    ts_str = ts.strftime('%Y-%m-%d %H:%M:%S') if ts else 'N/A'
                                    pattern = event.get('pattern', '')
                                    msg = event.get('message', '')[:300]
                                    st.code(f"[{ts_str}] [{pattern}] {msg}", language=None)
                                if len(cat_events) > 100:
                                    st.info(f"Showing first 100 of {len(cat_events):,} events")
                        else:
                            st.success(f"{icon} {category}: âœ… No issues detected")
                else:
                    st.markdown("---")
                    st.success("âœ… **No critical events detected** - System logs appear healthy!")
                
                # ============= PATCH COMPLIANCE (V5) =============
                st.markdown("---")
                st.header("ðŸ” Subscription & Patch Compliance")
                
                patch_compliance = detect_patch_compliance(
                    sosreport_path, packages_info, kernel_version, 
                    os_release, sys_date
                )
                
                # Show detected OS flavor
                detected_flavor = patch_compliance.get('os_flavor', 'unknown')
                flavor_labels = {
                    'oracle_linux': 'Oracle Linux', 'rhel': 'RHEL', 'centos': 'CentOS',
                    'rocky': 'Rocky Linux', 'alma': 'AlmaLinux', 'suse': 'SUSE', 'ubuntu': 'Ubuntu',
                    'unknown': 'Unknown'
                }
                flavor_label = flavor_labels.get(detected_flavor, detected_flavor)
                kernel_track = patch_compliance.get('kernel_type', 'standard').upper()
                st.caption(f"Detected OS: **{flavor_label}** | Kernel track: **{kernel_track}**")
                
                # Compliance Score Badge
                score = patch_compliance.get('compliance_score', 'Unknown')
                if score == 'Good':
                    st.success(f"âœ… Overall Compliance: **{score}**")
                elif score == 'Warning':
                    st.warning(f"âš ï¸ Overall Compliance: **{score}**")
                elif score == 'Critical':
                    st.error(f"ðŸ”´ Overall Compliance: **{score}**")
                else:
                    st.info(f"â„¹ï¸ Overall Compliance: **{score}**")
                
                comp_col1, comp_col2, comp_col3 = st.columns(3)
                
                with comp_col1:
                    st.markdown("**Subscription Status**")
                    sub_status = patch_compliance.get('subscription_status', 'Unknown')
                    if sub_status in ['Subscribed', 'RHUI Connected']:
                        st.markdown(f"ðŸŸ¢ {sub_status}")
                    elif sub_status == 'Not Subscribed':
                        st.markdown(f"ðŸ”´ {sub_status}")
                    else:
                        st.markdown(f"ðŸŸ¡ {sub_status}")
                    
                    if patch_compliance.get('subscription_details'):
                        for detail in patch_compliance['subscription_details'][:3]:
                            st.caption(f"  {detail}")
                
                with comp_col2:
                    st.markdown("**Kernel Status**")
                    k_status = patch_compliance.get('kernel_status', 'Unknown')
                    if k_status == 'Recent':
                        st.markdown(f"ðŸŸ¢ {k_status}")
                    elif k_status == 'Outdated':
                        st.markdown(f"ðŸŸ¡ {k_status}")
                    elif k_status == 'Very Outdated':
                        st.markdown(f"ðŸ”´ {k_status}")
                    else:
                        st.markdown(f"âšª {k_status}")
                    
                    st.caption(f"Running: `{kernel_version}`")
                    if patch_compliance.get('reboot_required'):
                        st.warning("âš ï¸ Reboot may be required")
                
                with comp_col3:
                    st.markdown("**Last Update Activity**")
                    st.markdown(f"`{patch_compliance.get('last_update_info', 'N/A')}`")
                    if patch_compliance.get('kernel_age_days'):
                        days = patch_compliance['kernel_age_days']
                        if days > 180:
                            st.error(f"ðŸ”´ {days} days since last update")
                        elif days > 90:
                            st.warning(f"ðŸŸ¡ {days} days since last update")
                        else:
                            st.success(f"ðŸŸ¢ {days} days since last update")
                
                # Findings
                if patch_compliance.get('findings'):
                    with st.expander(f"ðŸ“‹ Compliance Findings ({len(patch_compliance['findings'])})", expanded=False):
                        for finding in patch_compliance['findings']:
                            st.markdown(f"- âš ï¸ {finding}")
                
                # Installed Kernels
                if patch_compliance.get('installed_kernels'):
                    with st.expander("ðŸ“¦ Installed Kernel Packages", expanded=False):
                        for kpkg in patch_compliance['installed_kernels']:
                            st.code(kpkg, language=None)
                
                # Yum/DNF History
                history = patch_compliance.get('dnf_history') or patch_compliance.get('yum_history')
                if history:
                    pkg_mgr = "DNF" if patch_compliance.get('dnf_history') else "YUM"
                    with st.expander(f"ðŸ“œ Recent {pkg_mgr} History (last 10)", expanded=False):
                        hist_data = []
                        for h in history:
                            hist_data.append({
                                'ID': h.get('id', ''),
                                'Date': h.get('date', ''),
                                'Action': h.get('action', ''),
                                'Command': h.get('command', ''),
                                'Altered': h.get('altered', '')
                            })
                        if hist_data:
                            st.dataframe(pd.DataFrame(hist_data), use_container_width=True, hide_index=True)
                
                # ============= TIMESTAMP CORRELATION VIEW (V5) =============
                if critical_events and sar_metrics:
                    st.markdown("---")
                    st.header("ðŸ”— Timestamp Correlation View")
                    st.caption("Shows system resource usage at the time of each critical event")
                    
                    correlations = correlate_timestamps(sar_metrics, critical_events, window_minutes=5)
                    
                    if correlations:
                        # Summary stats
                        matched = sum(1 for c in correlations if c['sar_matched'])
                        st.info(f"ðŸ“Š **{len(correlations)}** unique critical events analyzed | **{matched}** matched with SAR data (Â±5 min window)")
                        
                        # Build correlation table
                        corr_data = []
                        for c in correlations:
                            row = {
                                'Time': c['event_time'].strftime('%Y-%m-%d %H:%M:%S'),
                                'Category': c['category'],
                                'Pattern': c['pattern'],
                            }
                            
                            if c['sar_matched']:
                                row['CPU%'] = f"{c['cpu_usage']}%" if c['cpu_usage'] is not None else '-'
                                row['IOWait%'] = f"{c['cpu_iowait']}%" if c['cpu_iowait'] is not None else '-'
                                row['MEM%'] = f"{c['mem_used_pct']}%" if c['mem_used_pct'] is not None else '-'
                                row['Load1'] = f"{c['load_1']}" if c['load_1'] is not None else '-'
                                row['Blocked'] = f"{int(c['blocked'])}" if c['blocked'] is not None else '-'
                                row['DiskUtil%'] = f"{c['disk_util']}%" if c['disk_util'] is not None else '-'
                            else:
                                row['CPU%'] = '-'
                                row['IOWait%'] = '-'
                                row['MEM%'] = '-'
                                row['Load1'] = '-'
                                row['Blocked'] = '-'
                                row['DiskUtil%'] = '-'
                            
                            row['Event'] = c['message'][:80]
                            corr_data.append(row)
                        
                        # Show as DataFrame
                        if corr_data:
                            st.dataframe(
                                pd.DataFrame(corr_data), 
                                use_container_width=True, 
                                hide_index=True,
                                height=min(400, len(corr_data) * 40 + 40)
                            )
                        
                        # Highlight correlated spikes
                        high_cpu_events = [c for c in correlations if c.get('cpu_usage') and c['cpu_usage'] >= 80]
                        high_mem_events = [c for c in correlations if c.get('mem_used_pct') and c['mem_used_pct'] >= 90]
                        high_load_events = [c for c in correlations if c.get('blocked') and c['blocked'] > 0]
                        
                        if high_cpu_events or high_mem_events or high_load_events:
                            st.markdown("##### âš¡ Notable Correlations")
                            if high_cpu_events:
                                st.warning(f"ðŸ”¥ **{len(high_cpu_events)}** critical events occurred during high CPU usage (â‰¥80%)")
                                for e in high_cpu_events[:3]:
                                    st.caption(f"  {e['event_time'].strftime('%H:%M')} - CPU {e['cpu_usage']}% - [{e['category']}] {e['pattern']}")
                            if high_mem_events:
                                st.warning(f"ðŸ§  **{len(high_mem_events)}** critical events occurred during high memory usage (â‰¥90%)")
                                for e in high_mem_events[:3]:
                                    st.caption(f"  {e['event_time'].strftime('%H:%M')} - MEM {e['mem_used_pct']}% - [{e['category']}] {e['pattern']}")
                            if high_load_events:
                                st.warning(f"â³ **{len(high_load_events)}** critical events occurred while processes were blocked")
                                for e in high_load_events[:3]:
                                    st.caption(f"  {e['event_time'].strftime('%H:%M')} - Blocked:{int(e['blocked'])} - [{e['category']}] {e['pattern']}")
                    else:
                        st.info("â„¹ï¸ No correlations found (events and SAR data may not overlap in time)")
                
                # ============= COPY-PASTE SUMMARY (V5) =============
                st.markdown("---")
                st.header("ðŸ“‹ Copy-Paste Summary")
                st.caption("Pre-formatted summary ready to paste into tickets, emails, or documentation")
                
                summary_text = generate_copy_paste_summary(
                    hostname=hostname,
                    system_info=system_info,
                    sar_anomalies=sar_anomalies,
                    critical_events=critical_events,
                    critical_summary=critical_summary,
                    sar_metrics_count=len(sar_metrics),
                    logs_count=len(logs),
                    patch_compliance=patch_compliance,
                    log_summary=log_parser.summary if log_parser else None
                )
                
                st.code(summary_text, language=None)
                
                st.download_button(
                    label="ðŸ“¥ Download Summary as Text File",
                    data=summary_text,
                    file_name=f"sosreport_summary_{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain",
                    use_container_width=True
                )
                
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
                    
                    # NOTE: Critical events are displayed in Streamlit main page only (skipped Loki push to reduce load)
                
                # Create dashboard with auto time range
                if create_dashboard:
                    progress_bar.progress(95, "Creating Grafana dashboard...")
                    status_text.text("ðŸ“Š Creating Grafana dashboard...")
                    
                    # Get time range from parsed data
                    time_from, time_to = get_time_range(sar_metrics, logs)
                    if time_from and time_to:
                        st.info(f"ðŸ“… Auto time range: {time_from.strftime('%Y-%m-%d %H:%M')} to {time_to.strftime('%Y-%m-%d %H:%M')}")
                    
                    dashboard_url = create_grafana_dashboard(hostname, time_from, time_to, 
                                                             system_info=system_info,
                                                             sar_anomalies=sar_anomalies)
                    
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
                    
                    # Check if using Azure Grafana (iframe embedding not supported due to Azure AD)
                    is_azure_grafana = 'grafana.azure.com' in GRAFANA_URL
                    
                    if is_azure_grafana:
                        # Azure Grafana doesn't support iframe embedding due to Azure AD auth
                        st.markdown(f"""
                        <div style="background-color: #e7f3ff; border: 2px solid #0078d4; border-radius: 10px; padding: 20px; margin: 20px 0; text-align: center;">
                            <h3 style="color: #0078d4; margin-bottom: 15px;">ðŸ”— Dashboard Ready on Azure Grafana</h3>
                            <p style="margin-bottom: 20px;">Azure Managed Grafana uses Azure AD authentication which doesn't support iframe embedding.</p>
                            <a href="{dashboard_url}" target="_blank" style="background-color: #0078d4; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-size: 16px; font-weight: bold;">
                                Open Dashboard in New Tab â†—
                            </a>
                            <p style="margin-top: 15px; color: #666; font-size: 12px;">ðŸ’¡ Tip: Right-click the button and select "Open in new tab" for best experience</p>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        # Self-hosted Grafana - can embed in iframe
                        # Add parameters for embedding (hide controls, no auto-refresh for historical data)
                        if '?' in dashboard_url:
                            embed_url = f"{dashboard_url}&kiosk=tv"
                        else:
                            embed_url = f"{dashboard_url}?kiosk=tv"
                        
                        st.markdown(f"""
                        <div style="margin-top: 1rem;">
                            <p>ðŸ’¡ <em>Dashboard shows historical SOSreport data. No auto-refresh needed.</em></p>
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
        "SOSreport Analyzer V6 | Powered by Streamlit, InfluxDB, Loki & Grafana | System Info + Anomaly Detection + Critical Events + Patch Compliance"
        "</div>",
        unsafe_allow_html=True
    )


if __name__ == "__main__":
    main()
