"""
SOSreport & Supportconfig Analyzer V8 - Streamlit Web Application
Upload SOSreport (RHEL/OL/CentOS) or Supportconfig (SUSE/SLES) archives and analyze
SAR metrics + Logs with automatic Grafana integration.

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
- OS Flavor Detection (RHEL/Oracle Linux/SUSE/etc.) with per-distro kernel analysis (V6)
- CPU Usage % stacked panel + Per-CPU breakdown in Grafana (V6)
- Expanded log sources: dmesg, journal, kern, boot, maillog, yum/dnf + mlx5/Azure patterns (V6)
- Cloud provider auto-detection (Azure/AWS/GCP/Oracle) with provider-specific metadata (NEW in V7)
- Additional SAR sections: hugepages, NFS, sockets, softnet, context switches (NEW in V7)
- CVE extraction from DNF/YUM security advisories (NEW in V7)
- Crash dump discovery with vmcore-dmesg analysis (NEW in V7)
- NetworkManager deep analysis (NEW in V7)
- System Health Checks — 30+ categorized checks (V7.1)
- SUSE Supportconfig archive support — auto-detect format, parse flat .txt files (V7.2)
- Multi-distro generalization: Ubuntu/Debian dpkg, apt, zypper support (V7.3)
- Executive TL;DR risk verdict at top of analysis (NEW in V8)
- Failed systemd services detection (current state at collection time) (NEW in V8)
- Inode exhaustion detection from df -i (NEW in V8)
- CPU %steal alerting for cloud VM noisy-neighbor / throttling (NEW in V8)
- Kernel taint flags decoding (proprietary modules, staging, etc.) (NEW in V8)
- NTP/Chrony time sync status check (NEW in V8)
"""

import streamlit as st
import streamlit.components.v1 as components
import os
import re
import json
import gzip
import logging
import requests
import tarfile
import tempfile
import shutil
import hashlib
import threading
import time as _time_mod
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import pandas as pd
from dotenv import load_dotenv
load_dotenv()  # Load .env file

# ============================================================================
# CONFIGURATION (loaded from .env file — see .env.example)
# ============================================================================
INFLUXDB_URL = os.environ.get("INFLUXDB_URL", "http://localhost:8086")
INFLUXDB_TOKEN = os.environ.get("INFLUXDB_TOKEN", "")
# Prefer INFLUXDB_ORG (name) for API calls; fall back to INFLUXDB_ORG_ID if set and not 'auto'
_org_id_raw = os.environ.get("INFLUXDB_ORG_ID", "")
INFLUXDB_ORG = os.environ.get("INFLUXDB_ORG", "") or ("" if _org_id_raw.lower() == "auto" else _org_id_raw)
INFLUXDB_BUCKET = os.environ.get("INFLUXDB_BUCKET", "sar_metrics")

LOKI_URL = os.environ.get("LOKI_URL", "http://localhost:3100")

GRAFANA_URL = os.environ.get("GRAFANA_URL", "http://localhost:3000")

# External URLs for links shown to the user's browser
# Inside Docker, service names (influxdb, loki, grafana) aren't reachable from the browser
_to_external = lambda u: u.replace("://influxdb:", "://localhost:").replace("://loki:", "://localhost:").replace("://grafana:", "://localhost:")
INFLUXDB_EXTERNAL_URL = os.environ.get("INFLUXDB_EXTERNAL_URL", "") or _to_external(INFLUXDB_URL)
LOKI_EXTERNAL_URL = os.environ.get("LOKI_EXTERNAL_URL", "") or _to_external(LOKI_URL)
GRAFANA_EXTERNAL_URL = os.environ.get("GRAFANA_EXTERNAL_URL", "") or _to_external(GRAFANA_URL)
GRAFANA_API_KEY = os.environ.get("GRAFANA_API_KEY", "")

# ── Auto-resolve InfluxDB org name when not configured ────────────────
def _resolve_influxdb_org(url, token, org_hint):
    """Resolve InfluxDB org name from the API if org_hint is empty or 'auto'."""
    if org_hint and org_hint.lower() != "auto":
        return org_hint
    try:
        resp = requests.get(
            f"{url}/api/v2/orgs",
            headers={"Authorization": f"Token {token}"},
            timeout=10,
        )
        if resp.status_code == 200:
            orgs = resp.json().get("orgs", [])
            if orgs:
                resolved = orgs[0]["name"]
                logging.info(f"Auto-resolved InfluxDB org: {resolved}")
                return resolved
    except Exception as e:
        logging.warning(f"Could not auto-resolve InfluxDB org: {e}")
    return org_hint

if not INFLUXDB_ORG or INFLUXDB_ORG.lower() == "auto":
    INFLUXDB_ORG = _resolve_influxdb_org(INFLUXDB_URL, INFLUXDB_TOKEN, INFLUXDB_ORG)

# ── Auto-provision Grafana API key (lazy — called on first use) ───────
def _auto_provision_grafana_key(url, admin_user="admin", admin_pass="sosreport2026"):
    """Create a Grafana service account + token using admin basic auth.
    Retries a few times in case Grafana is still starting up."""
    import time as _t
    for attempt in range(6):
        try:
            session = requests.Session()
            session.auth = (admin_user, admin_pass)

            health = session.get(f"{url}/api/health", timeout=5)
            if health.status_code != 200:
                _t.sleep(5)
                continue

            # Create or reuse service account
            sa_name = "sosreport-auto"
            resp = session.get(f"{url}/api/serviceaccounts/search?query={sa_name}", timeout=5)
            sa_id = None
            if resp.status_code == 200:
                for sa in resp.json().get("serviceAccounts", []):
                    if sa.get("name") == sa_name:
                        sa_id = sa["id"]
                        break

            if not sa_id:
                resp = session.post(
                    f"{url}/api/serviceaccounts",
                    json={"name": sa_name, "role": "Admin"},
                    timeout=5,
                )
                if resp.status_code in (200, 201):
                    sa_id = resp.json().get("id")
                else:
                    logging.warning(f"Grafana SA create failed: {resp.status_code} {resp.text[:200]}")
                    _t.sleep(5)
                    continue

            # Create token (delete existing ones first to avoid conflicts)
            resp = session.get(f"{url}/api/serviceaccounts/{sa_id}/tokens", timeout=5)
            if resp.status_code == 200:
                for tok in resp.json():
                    session.delete(f"{url}/api/serviceaccounts/{sa_id}/tokens/{tok['id']}", timeout=5)

            resp = session.post(
                f"{url}/api/serviceaccounts/{sa_id}/tokens",
                json={"name": "auto-token"},
                timeout=5,
            )
            if resp.status_code in (200, 201):
                key = resp.json().get("key", "")
                logging.info("Auto-provisioned Grafana API key")
                return key
            else:
                logging.warning(f"Grafana token create failed: {resp.status_code} {resp.text[:200]}")
        except requests.exceptions.ConnectionError:
            logging.info(f"Grafana not ready (attempt {attempt+1}/6), retrying in 5s...")
        except Exception as e:
            logging.warning(f"Grafana auto-provision error: {e}")
        _t.sleep(5)
    logging.error("Could not auto-provision Grafana API key after retries")
    return ""


def _get_grafana_api_key():
    """Lazy getter — provisions the key on first call, caches it globally."""
    global GRAFANA_API_KEY
    if not GRAFANA_API_KEY:
        GRAFANA_API_KEY = _auto_provision_grafana_key(GRAFANA_URL)
    return GRAFANA_API_KEY

# Performance Configuration
MAX_CONCURRENT_EXTRACTIONS = 3  # Limit concurrent heavy operations
MAX_LOG_LINES = 2000000  # Limit log lines (increased from 500K)
MAX_SAR_METRICS = 1000000  # Limit SAR metrics
EXTRACTION_TIMEOUT = 300  # 5 minute timeout for extraction

# ============================================================================
# SUPPORTCONFIG / SOSREPORT FORMAT HANDLING (V7.2)
# ============================================================================

# Supportconfig files use section delimiters like:
#   #==[ Command ]======#
#   # /usr/bin/hostname
#   <output lines>
#   #==[ Next Command ]======#
_SC_SECTION_RE = re.compile(r'^#==\[\s*(.*?)\s*\]=+#\s*$')
_SC_COMMAND_RE = re.compile(r'^#\s*(/\S+.*?)\s*$')

# Mapping: data need → supportconfig file → command/section to extract
# Each entry: (sc_filename, command_prefix_or_section)  — None means whole file
_SC_FILE_MAP = {
    # System basics
    'hostname':     ('basic-environment.txt', '/bin/hostname'),
    'uptime':       ('basic-environment.txt', '/usr/bin/uptime'),
    'uname':        ('basic-environment.txt', '/bin/uname'),
    'date':         ('basic-environment.txt', '/bin/date'),
    'lscpu':        ('hardware.txt',          '/usr/bin/lscpu'),
    'cpuinfo':      ('hardware.txt',          '/proc/cpuinfo'),
    'meminfo':      ('memory.txt',            '/proc/meminfo'),
    'free':         ('basic-environment.txt', '/usr/bin/free'),
    'df':           ('fs-diskio.txt',         '/bin/df'),
    'ps':           ('basic-environment.txt', '/bin/ps'),
    'last_reboot':  ('basic-environment.txt', '/usr/bin/last'),
    'sysctl':       ('env.txt',               '/sbin/sysctl'),
    'dmidecode':    ('hardware.txt',          '/usr/sbin/dmidecode'),
    'cmdline':      ('boot.txt',              '/proc/cmdline'),
    'os_release':   ('basic-environment.txt', '/etc/os-release'),
    'suse_release': ('basic-environment.txt', '/etc/SuSE-release'),
    'rpm_list':     ('rpm.txt',               None),   # whole file
    'sar_data':     ('sar.txt',               None),   # whole file
    # Logs
    'messages':     ('messages.txt',          None),
    'boot_log':     ('boot.txt',              None),
    'warn_log':     ('warn.txt',              None),
    'security':     ('security.txt',          None),
    # Network
    'ip_addr':      ('network.txt',           '/sbin/ip addr'),
    'ip_route':     ('network.txt',           '/sbin/ip route'),
    'resolv_conf':  ('network.txt',           '/etc/resolv.conf'),
    'firewall':     ('network.txt',           '/usr/bin/firewall-cmd'),
    'ethtool':      ('network.txt',           '/usr/sbin/ethtool'),
    # Kernel / Boot
    'dmesg':        ('boot.txt',              '/bin/dmesg'),
    'modules':      ('boot.txt',              '/sbin/lsmod'),
    'kdump':        ('crash.txt',             None),
    # Service mgmt
    'systemd':      ('systemd.txt',           None),
    'systemctl':    ('systemd.txt',           '/usr/bin/systemctl'),
    # Storage
    'lvm':          ('lvm.txt',               None),
    'lsblk':        ('fs-diskio.txt',         '/bin/lsblk'),
    'fstab':        ('fs-diskio.txt',         '/etc/fstab'),
    # HA / Cluster
    'ha_log':       ('ha.txt',                None),
    # Updates
    'updates':      ('updates.txt',           None),
    'zypper_log':   ('updates.txt',           '/usr/bin/zypper'),
    # THP
    'thp_enabled':  ('memory.txt',            '/sys/kernel/mm/transparent_hugepage/enabled'),
    'thp_defrag':   ('memory.txt',            '/sys/kernel/mm/transparent_hugepage/defrag'),
    # SELinux / AppArmor
    'apparmor':     ('security.txt',          '/usr/sbin/apparmor_status'),
    'sestatus':     ('security.txt',          '/usr/sbin/sestatus'),
    # SSH
    'sshd_config':  ('security.txt',          '/etc/ssh/sshd_config'),
    # Audit
    'auditd_conf':  ('security.txt',          '/etc/audit/auditd.conf'),
    'auditd_conf2': ('security-audit.txt',    '/etc/audit/auditd.conf'),
}


def detect_archive_format(root_path: str) -> str:
    """Detect if extracted archive is a sosreport or supportconfig.
    
    Returns: 'sosreport', 'supportconfig', or 'unknown'
    """
    # Supportconfig: flat directory with characteristic .txt files
    sc_markers = ['basic-environment.txt', 'hardware.txt', 'messages.txt', 'rpm.txt']
    if sum(1 for m in sc_markers if os.path.isfile(os.path.join(root_path, m))) >= 2:
        return 'supportconfig'
    
    # SOSreport: has sos_commands/ or var/log layout
    if os.path.isdir(os.path.join(root_path, 'sos_commands')):
        return 'sosreport'
    if os.path.isdir(os.path.join(root_path, 'var', 'log')):
        return 'sosreport'
    
    return 'unknown'


def sc_extract_section(filepath: str, command_prefix: str) -> str:
    """Extract a specific section from a supportconfig multi-section .txt file.
    
    Supportconfig files have sections delimited by:
        #==[ <Type> ]======#
        # /path/to/command [args]
        <output>
    
    This extracts the output block for the section whose command line starts with
    `command_prefix`.  Returns empty string if not found.
    """
    if not os.path.isfile(filepath):
        return ''
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return ''
    
    capturing = False
    result = []
    for i, line in enumerate(lines):
        # Check for section delimiter
        m = _SC_SECTION_RE.match(line)
        if m:
            if capturing:
                break  # end of our section
            # Next line(s) should have the command
            capturing = False
            # Look ahead for the command line
            for j in range(i + 1, min(i + 4, len(lines))):
                cmd_m = _SC_COMMAND_RE.match(lines[j])
                if cmd_m:
                    cmd = cmd_m.group(1)
                    if cmd.startswith(command_prefix) or command_prefix in cmd:
                        capturing = True
                    break
            continue
        
        if capturing:
            # Skip comment lines at the start of the section
            if line.startswith('#') and not result:
                continue
            result.append(line)
    
    return ''.join(result).strip()


def sc_read_file(root_path: str, data_key: str) -> str:
    """Read data from a supportconfig archive using the file map.
    
    Args:
        root_path: path to extracted supportconfig directory
        data_key: a key from _SC_FILE_MAP (e.g. 'hostname', 'meminfo', 'df')
    
    Returns the extracted text, or empty string if not found.
    """
    mapping = _SC_FILE_MAP.get(data_key)
    if not mapping:
        return ''
    
    sc_file, command = mapping
    filepath = os.path.join(root_path, sc_file)
    
    if not os.path.isfile(filepath):
        return ''
    
    if command is None:
        # Read entire file
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return ''
    else:
        return sc_extract_section(filepath, command)


def sc_find_file(root_path: str, filename: str) -> str:
    """Find a file in a supportconfig flat directory. Returns path or ''."""
    path = os.path.join(root_path, filename)
    return path if os.path.isfile(path) else ''


def sc_extract_log_sections(filepath: str, path_prefix: str) -> str:
    """Extract ALL log-file sections from a supportconfig .txt file matching a path.
    
    Gathers content from sections whose path starts with `path_prefix`.
    Handles all section types that contain file content:
      - '#==[ Log File ]======#'
      - '#==[ File ]======#'
      - '#==[ Configuration File ]======#'
    Plus also captures content from any section referencing the path_prefix.
    This handles rotated logs too (e.g. /var/log/messages, /var/log/messages-20260101).
    
    Returns concatenated log content (no section headers).
    """
    if not os.path.isfile(filepath):
        return ''
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return ''
    
    result = []
    capturing = False
    
    for i, line in enumerate(lines):
        m = _SC_SECTION_RE.match(line)
        if m:
            capturing = False
            # Look ahead for the file/command path
            for j in range(i + 1, min(i + 4, len(lines))):
                cmd_m = _SC_COMMAND_RE.match(lines[j])
                if cmd_m:
                    path = cmd_m.group(1)
                    if path.startswith(path_prefix) or path_prefix in path:
                        capturing = True
                    break
            continue
        
        if capturing:
            # Skip the comment line with the path itself (# /var/log/messages)
            if _SC_COMMAND_RE.match(line):
                continue
            result.append(line)
    
    return ''.join(result).strip()


# Refined Critical Events Log Patterns for V7
LOG_PATTERNS = {
    "File System & Disk": [
        r'FAT-fs.*Volume was not properly unmounted',  # Specific FAT corruption
        r'XFS\s\(dm-\d+\):\s(?!Ending\sclean\smount|Unmounting).*', # XFS but NOT clean mounts
        r'I/O\serror', r'Corruption\sdetected', r'xfs_force_shutdown',
        r'blk_update_request:\sI/O\serror', r'Read-only\sfile\ssystem',
        r'dm-.*taking\sa\slong\stime', r'LVM:\s.*failed',
        r'failed\sto\sidentify\sdevice', r'device\soffline'
    ],
    "Memory/OOM": [
        r'Out\sof\smemory:', r'oom-killer', r'invoked\soom-killer',
        r'page\sallocation\sfailure:\sorder:\d+', # Capture specific memory pressure
        r'SLUB:\sUnable\sto\sallocate', r'hugepages_total=0\shugepages_free=0'
    ],
    "CPU & Kernel Panic": [
        r'BUG:\ssoft\slockup', r'Kernel\spanic', r'Fatal\sexception',
        r'Watchdog\sdetected\shard\sLOCKUP', r'rcu_sched\sdetected\sstalls',
        r'blocked\sfor\smore\sthan\s\d+\sseconds', # Actual hung tasks
        r'general\sprotection\sfault', r'divide\serror'
        # Note: RIP and Call Trace are context, removed as primary triggers to reduce load
    ],
    "Network Issues": [
        r'NIC\sLink\sis\sDown', 
        r'NETDEV\sWATCHDOG',
        r'Connection\stimed\sout',
        r'martian\ssource',
        r'hv_netvsc.*(error|timeout|lost|failed)', 
        r'NetworkManager.*(failed|error|timeout|conflicting|terminated|fatal)' 
    ],
    "Security & Antivirus": [
        r'authentication\sfailure', r'FAILED\sLOGIN', r'AVC\sdenial',
        r'segfault\sat.*libcrypto', r'pam_unix.*authentication\sfailure',
        # Ubuntu AppArmor denials (equivalent to SELinux AVC denials)
        r'apparmor="DENIED"', r'apparmor=DENIED',
        r'audit.*apparmor=.?DENIED',
        # Ubuntu UFW firewall blocks
        r'\[UFW\s+BLOCK\]', r'\[UFW\s+AUDIT\]',
    ],
    "Service & Systemd": [
        r'systemd:\sFailed\sto\sstart', r'Dependency\sfailed\sfor',
        r'service\sentered\sfailed\sstate',
        r'(?<!Found unit )(?<!systemd/)coredump(?!.*(socket|service|regular file|\.mount|Collecting))',
        r'dumped\score',
        r'Start\srequest\srepeated\stoo\squickly'
    ],
    "Hardware & IPMI": [
        r'Hardware\sError', r'MCE:\sMachine\sCheck', r'PCIe\sBus\sError',
        r'Uncorrected\serror', r'ACPI\sError', r'thermal\szone.*critical'
    ]
}

# ── Pre-compiled pattern accelerators ──────────────────────────────────────
# Instead of calling re.search() per-pattern per-log-line (40+ calls × 500K lines),
# we compile a single mega-regex for a fast "does this line match ANYTHING?" check,
# and per-category compiled regexes for the second pass.
import re as _re

# Pre-compile individual patterns per category (avoids re-compilation per line)
_COMPILED_LOG_PATTERNS: Dict[str, list] = {}
for _cat, _pats in LOG_PATTERNS.items():
    _COMPILED_LOG_PATTERNS[_cat] = [(_re.compile(p, _re.IGNORECASE), p) for p in _pats]

# Build a fast pre-filter: one single regex that matches if ANY pattern would match.
# This lets us skip 99%+ of log lines with a single re.search() call.
# For patterns with lookbehind/lookahead (coredump), we use a simplified keyword.
def _build_prefilter_keywords():
    """Extract simple keyword fragments from each pattern for a fast pre-screen."""
    keywords = set()
    # Manually curated keywords from LOG_PATTERNS — covers every pattern's
    # shortest distinctive substring.  This is O(1) per line vs O(40) regex calls.
    kw_list = [
        # File System & Disk
        'FAT-fs', 'XFS', 'I/O error', 'Corruption detected', 'xfs_force_shutdown',
        'blk_update_request', 'Read-only file system', 'taking a long time',
        'LVM:', 'failed to identify', 'device offline',
        # Memory/OOM
        'Out of memory', 'oom-killer', 'invoked oom-killer', 'page allocation failure',
        'SLUB:', 'hugepages_total',
        # CPU & Kernel Panic
        'soft lockup', 'Kernel panic', 'Fatal exception', 'hard LOCKUP',
        'rcu_sched', 'blocked for more than', 'general protection fault', 'divide error',
        # Network
        'NIC Link is Down', 'NETDEV WATCHDOG', 'Connection timed out',
        'martian source', 'hv_netvsc', 'NetworkManager',
        # Security
        'authentication failure', 'FAILED LOGIN', 'AVC denial',
        'segfault at', 'pam_unix',
        # Ubuntu AppArmor + UFW
        'apparmor=', '[UFW BLOCK]', '[UFW AUDIT]',
        # Service & Systemd
        'Failed to start', 'Dependency failed', 'failed state',
        'coredump', 'dumped core', 'repeated too quickly',
        # Hardware
        'Hardware Error', 'Machine Check', 'PCIe Bus Error',
        'Uncorrected error', 'ACPI Error', 'thermal zone',
    ]
    return kw_list

_PREFILTER_KEYWORDS = _build_prefilter_keywords()
# Build case-insensitive regex from keywords (escape special chars, join with |)
_PREFILTER_RE = _re.compile(
    '|'.join(_re.escape(kw) for kw in _PREFILTER_KEYWORDS),
    _re.IGNORECASE
)

# ── Multiprocessing helpers for Step 10 ────────────────────────────────────
# Minimum log count before we spawn worker processes (overhead of process
# creation + module import outweighs benefit for small sets).
_MP_CRITICAL_THRESHOLD = 80_000

def _detect_critical_chunk(logs_chunk):
    """Multiprocessing worker: scan a chunk of logs for critical event patterns.

    Runs in a **separate process** so regex CPU work bypasses the GIL.
    Each worker process imports this module and gets its own copy of
    _PREFILTER_RE / _COMPILED_LOG_PATTERNS (compiled at import time).

    Returns (events_list, category_counts_dict, severity_counts_dict).
    """
    events = []
    category_counts = {cat: 0 for cat in LOG_PATTERNS}
    severity_counts = {'critical': 0, 'warning': 0, 'info': 0}

    prefilter = _PREFILTER_RE
    compiled_patterns = _COMPILED_LOG_PATTERNS

    for log in logs_chunk:
        message = log.get('message', '')
        if not message:
            continue
        # Fast pre-filter: single regex rejects 99%+ of lines
        if not prefilter.search(message):
            continue
        for category, compiled_list in compiled_patterns.items():
            for compiled_re, original_pattern in compiled_list:
                if compiled_re.search(message):
                    severity = classify_event_severity(message, original_pattern)
                    events.append({
                        'timestamp': log.get('timestamp'),
                        'source': log.get('source'),
                        'program': log.get('program'),
                        'message': message,
                        'category': category,
                        'pattern': original_pattern,
                        'severity': severity,
                    })
                    category_counts[category] += 1
                    severity_counts[severity] += 1
                    break  # one match per category per line
    return events, category_counts, severity_counts


_SEVERITY_RULES = [
    # ── INFORMATIONAL: routine server lifecycle / reboot / login ──────────
    # Shutdown & reboot unmount sequence
    (_re.compile(r'\bUMOUNT\b', _re.I), 'info'),
    (_re.compile(r'\bSKIP\b.*\bunmount\b', _re.I), 'info'),
    (_re.compile(r'Stopping\s+\S+', _re.I), 'info'),
    (_re.compile(r'Stopped\s+\S+', _re.I), 'info'),
    (_re.compile(r'Starting\s+\S+', _re.I), 'info'),
    (_re.compile(r'Started\s+\S+', _re.I), 'info'),
    (_re.compile(r'Reached target.*(Shutdown|Reboot|Final|Power)', _re.I), 'info'),
    (_re.compile(r'Shutting down\b', _re.I), 'info'),
    (_re.compile(r'Power.Off', _re.I), 'info'),
    (_re.compile(r'Deactivating swap', _re.I), 'info'),
    (_re.compile(r'Unmounting\s', _re.I), 'info'),
    # Normal filesystem mount / remount
    (_re.compile(r'Mounting V\d', _re.I), 'info'),
    (_re.compile(r'Ending clean mount', _re.I), 'info'),
    (_re.compile(r'mounted filesystem', _re.I), 'info'),
    (_re.compile(r'\bre-?mounted\b', _re.I), 'info'),
    (_re.compile(r'clean,\s+\d+.*files', _re.I), 'info'),
    # LVM / device-mapper housekeeping
    (_re.compile(r'\blvmetad\b', _re.I), 'info'),
    # Normal authentication
    (_re.compile(r'Accepted (publickey|password|keyboard)', _re.I), 'info'),
    (_re.compile(r'session (opened|closed) for user', _re.I), 'info'),
    (_re.compile(r'New session \d+', _re.I), 'info'),
    (_re.compile(r'Removed session', _re.I), 'info'),
    (_re.compile(r'pam_unix.*session (opened|closed)', _re.I), 'info'),
    # NetworkManager / firewalld routine state changes
    # NM uses <info>/<warn>/<error> prefixes; <info> lines are never actionable
    (_re.compile(r'<info>\s*\[\d', _re.I), 'info'),
    (_re.compile(r'Read config:', _re.I), 'info'),
    (_re.compile(r'NetworkManager.*state change', _re.I), 'info'),
    (_re.compile(r'NetworkManager.*(connection|device).*(activated|deactivated|managed|disconnected)', _re.I), 'info'),
    (_re.compile(r'NetworkManager.*terminated', _re.I), 'info'),
    (_re.compile(r'firewalld.*(RELOAD|start)', _re.I), 'info'),
    # SSH / NTP / app-level timeouts — noisy, not infrastructure issues
    (_re.compile(r'sshd?\b.*Connection timed out', _re.I), 'info'),
    (_re.compile(r'\b(ntpd?|chronyd?)\b.*Connection timed out', _re.I), 'info'),
    # Hyper-V / Azure routine messages (no error keyword)
    (_re.compile(r'hv_vmbus.*channel\s+(opened|closed|offer)', _re.I), 'info'),

    # ── WARNING: notable but not immediately critical ─────────────────────
    # Martian packets – noisy on cloud/multi-NIC VMs, never truly critical
    (_re.compile(r'martian\s+source', _re.I), 'warning'),
    (_re.compile(r'Corrected error', _re.I), 'warning'),
    (_re.compile(r'ACPI Warning', _re.I), 'warning'),
    (_re.compile(r'NIC Link is Down', _re.I), 'warning'),
    (_re.compile(r'(link is not ready|carrier lost|no carrier)', _re.I), 'warning'),
    (_re.compile(r'link status.*(up|down|changed)', _re.I), 'warning'),
    (_re.compile(r'\bhv_balloon\b', _re.I), 'warning'),
    (_re.compile(r'\bauthentication failure\b', _re.I), 'warning'),
    (_re.compile(r'Failed password', _re.I), 'warning'),
    (_re.compile(r'FAILED LOGIN', _re.I), 'warning'),
    (_re.compile(r'Invalid user', _re.I), 'warning'),
    (_re.compile(r'Connection closed by authenticating', _re.I), 'warning'),
    # Thermal events (warnings unless critical threshold)
    (_re.compile(r'thermal', _re.I), 'warning'),
]

# Broad patterns that match too many benign messages.  If the matched pattern
# is one of these AND the message has no problem-indicator keywords, demote
# to 'info'.
# With the refined regex patterns in V7, broad-pattern demotion is no longer
# needed — every pattern is already specific.  Keep the mechanism so it can be
# re-populated if needed in the future.
_BROAD_PATTERNS = frozenset()
_PROBLEM_INDICATORS = _re.compile(
    r'error|fail|block|timeout|hung|panic|crash|corrupt|stall|'
    r'denied|oom|kill|segfault|oops|bug:|'
    r'I/O|read.only|reset|offline|broken|'
    r'force_shutdown|unable|exception|fault|overflow|full',
    _re.I
)


def classify_event_severity(message: str, matched_pattern: str) -> str:
    """Classify an event as 'critical', 'warning', or 'info'.

    Applies _SEVERITY_RULES first (first match wins).
    Then checks broad-pattern demotion.
    Default is 'critical'.
    """
    # Explicit rules – first match wins
    for rule_re, sev in _SEVERITY_RULES:
        if rule_re.search(message):
            return sev

    # Broad-pattern catch-all: if the matched LOG_PATTERNS entry is a very
    # generic string and the actual message has no problem indicators, treat
    # it as informational rather than critical.
    if matched_pattern in _BROAD_PATTERNS:
        if not _PROBLEM_INDICATORS.search(message):
            return 'info'

    return 'critical'

# ============================================================================

# Thread pool for extraction (shared across sessions but limited)
_extraction_semaphore = threading.Semaphore(MAX_CONCURRENT_EXTRACTIONS)

# Track active processing sessions across all Streamlit threads
_active_sessions_lock = threading.Lock()
_active_sessions = {}  # session_id -> {hostname, start_time, phase}

st.set_page_config(
    page_title="SOSreport & Supportconfig Analyzer V8",
    
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
    /* Force primary buttons to consistent color */
    .stButton > button[kind="primary"],
    .stButton > button[data-testid="stBaseButton-primary"] {
        background-color: #ff4b4b !important;
        border-color: #ff4b4b !important;
        color: white !important;
    }
    .stButton > button[kind="primary"]:hover,
    .stButton > button[data-testid="stBaseButton-primary"]:hover {
        background-color: #ff2b2b !important;
        border-color: #ff2b2b !important;
    }
    .stButton > button[kind="primary"]:focus,
    .stButton > button[data-testid="stBaseButton-primary"]:focus {
        background-color: #ff4b4b !important;
        border-color: #ff4b4b !important;
        box-shadow: 0 0 0 0.2rem rgba(255,75,75,.5) !important;
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
    """Extract uploaded sosreport or supportconfig to temp directory with concurrency control.
    
    Supports:
      - SOSreport (.tar.gz/.tar.xz) from RHEL/OL/CentOS/Rocky/Alma
      - Supportconfig (.tar.gz/.tar.xz/.txz) from SUSE/SLES
    
    Returns (temp_dir, root_dir) where root_dir is the extracted content root.
    """
    
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
        fname = uploaded_file.name.lower()
        if fname.endswith('.tar.xz') or fname.endswith('.txz'):
            mode = 'r:xz'
        elif fname.endswith(('.tar.gz', '.tgz')):
            mode = 'r:gz'
        elif fname.endswith('.tar.bz2'):
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
                
                # Quick-detect if this is a supportconfig archive
                _is_supportconfig = any(
                    m.name.endswith('basic-environment.txt') or
                    m.name.endswith('hardware.txt') or
                    m.name.endswith('messages.txt')
                    for m in members[:50]
                )
                
                if _is_supportconfig:
                    # Supportconfig: extract ALL .txt files, sar/ data, and any var/log/
                    files_to_extract = []
                    for member in members:
                        name = member.name
                        if member.isdir():
                            files_to_extract.append(member)
                        elif name.endswith('.txt') or name.endswith('.log') or name.endswith('.xml'):
                            if len(os.path.join(temp_dir, name)) < 250:
                                files_to_extract.append(member)
                        elif '/sar/' in name or name.endswith('/sar'):
                            # Extract SAR data files (sar20250409, sa20250408, etc.)
                            if len(os.path.join(temp_dir, name)) < 250:
                                files_to_extract.append(member)
                        elif '/var/log/' in name or '/var/crash/' in name or '/etc/' in name:
                            if len(os.path.join(temp_dir, name)) < 250:
                                files_to_extract.append(member)
                        elif '/public_cloud/' in name or '/docker/' in name:
                            if len(os.path.join(temp_dir, name)) < 250:
                                files_to_extract.append(member)
                else:
                    # SOSreport: selective extraction (original logic)
                    files_to_extract = []
                    for member in members:
                        name = member.name
                        if any(p in name for p in [
                            '/var/log/sa/',
                            '/var/log/sysstat/',
                            '/sos_commands/sar/',
                            '/sos_commands/logs/',
                            '/sos_commands/auditd/',
                            '/sos_commands/date/',
                            '/sos_commands/general/',
                            '/sos_commands/host/',
                            '/sos_commands/kernel/',
                            '/sos_commands/filesys/',
                            '/sos_commands/process/',
                            '/sos_commands/rpm/',
                            '/sos_commands/hardware/',
                            '/sos_commands/memory/',
                            '/sos_commands/processor/',
                            '/sos_commands/subscription_manager/',
                            '/sos_commands/yum/',
                            '/sos_commands/dnf/',
                            '/sos_commands/kdump/',
                            '/sos_commands/systemd/',
                            '/sos_commands/azure/',
                            '/sos_commands/networking/',
                            '/sos_commands/selinux/',
                            '/sos_commands/firewalld/',
                            '/sos_commands/networkmanager/',
                            '/sos_commands/pacemaker/',
                            '/sos_commands/cluster/',
                            '/sos_commands/cloud/',
                            '/sos_commands/cloud_init/',
                            # Ubuntu/Debian-specific sos_commands
                            '/sos_commands/apt/',
                            '/sos_commands/dpkg/',
                            '/sos_commands/apparmor/',
                            '/sos_commands/block/',
                            '/sos_commands/ubuntu/',
                            # SUSE-specific sos_commands
                            '/sos_commands/zypper/',
                            '/sos_commands/registration/',
                            # V8: NTP/chrony and kernel taint
                            '/sos_commands/chrony/',
                            '/sos_commands/ntp/',
                            '/proc/sys/kernel/tainted',
                            '/etc/kdump.conf',
                            '/var/crash/',
                            '/proc/cmdline',
                            '/proc/cpuinfo',
                            '/proc/meminfo',
                            '/etc/hostname',
                            '/etc/redhat-release',
                            '/etc/centos-release',
                            '/etc/system-release',
                            '/etc/os-release',
                            '/etc/oracle-release',
                            '/etc/SuSE-release',
                            # Ubuntu/Debian release files
                            '/etc/lsb-release',
                            '/etc/debian_version',
                            '/etc/fstab',
                            '/etc/ssh/sshd_config',
                            '/etc/audit/auditd.conf',
                            '/etc/waagent.conf',
                            '/etc/cloud/',
                            '/etc/netplan/',
                            '/etc/sysconfig/network-scripts/',
                            '/etc/network/interfaces',
                            '/etc/NetworkManager/',
                            # Ubuntu/Debian package lists
                            '/installed-debs',
                            '/installed-snaps',
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
                        elif '/var/log/' in name and not member.isdir():
                            if len(os.path.join(temp_dir, name)) < 250:
                                files_to_extract.append(member)
                        elif member.isdir() and any(p in name for p in [
                            '/var/log/sa', '/var/log/sysstat', '/var/log/audit', '/var/log', '/var',
                            '/sos_commands/sar', '/sos_commands/logs', '/sos_commands',
                            '/sos_commands/date', '/sos_commands/general', '/sos_commands/host',
                            '/sos_commands/process',
                            '/sos_commands/subscription_manager', '/sos_commands/yum', '/sos_commands/dnf',
                            '/sos_commands/kdump', '/sos_commands/systemd',
                            '/sos_commands/azure',
                            '/sos_commands/apt', '/sos_commands/dpkg',
                            '/sos_commands/apparmor', '/sos_commands/block',
                            '/sos_commands/zypper', '/sos_commands/registration',
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
                
                for i, member in enumerate(files_to_extract):
                    try:
                        tar.extract(member, temp_dir, filter='data')
                    except TypeError:
                        tar.extract(member, temp_dir)
                    except Exception:
                        pass
                    if i % 50 == 0:
                        pct = 40 + int((i / max(len(files_to_extract), 1)) * 20)
                        progress_bar.progress(pct, f"Extracting file {i+1}/{len(files_to_extract)}...")
        
        finally:
            # Remove the archive to free disk space
            try:
                os.remove(temp_archive)
            except:
                pass
        
        sosreport_dir = os.path.join(temp_dir, top_dir) if top_dir else temp_dir
        
        # Detect format and materialize paths for supportconfig
        _fmt = detect_archive_format(sosreport_dir)
        if _fmt == 'supportconfig':
            _materialize_supportconfig_paths(sosreport_dir)
        
        return temp_dir, sosreport_dir


def _materialize_supportconfig_paths(sc_root: str):
    """For supportconfig archives, extract sections from flat .txt files and write
    them to the paths that the existing detect_* functions expect.
    
    This bridge function lets ALL existing sosreport detection logic work unchanged
    with supportconfig archives.
    """
    _materialized = []  # Track what was created for debugging
    
    def _write(relpath: str, content: str):
        if not content:
            return
        dest = os.path.join(sc_root, relpath)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        try:
            with open(dest, 'w', encoding='utf-8') as f:
                f.write(content)
            _materialized.append(f"{relpath} ({len(content)} bytes)")
        except Exception as e:
            _materialized.append(f"{relpath} (FAILED: {e})")
    
    # Log which .txt files exist in the supportconfig root
    sc_txt_files = [f for f in os.listdir(sc_root) if f.endswith('.txt')]
    logging.info(f"Supportconfig root: {sc_root}")
    logging.info(f"Supportconfig .txt files found: {sc_txt_files}")

    # ── System basics ───────────────────────────────────────
    hostname_val = sc_read_file(sc_root, 'hostname')
    if not hostname_val:
        # Fallback: extract hostname from uname output
        uname_out = sc_read_file(sc_root, 'uname')
        if uname_out:
            parts = uname_out.strip().split()
            if len(parts) >= 2 and parts[0] == 'Linux':
                hostname_val = parts[1]
        # Fallback: directory name (scc_hostname_YYMMDD)
        if not hostname_val:
            dirname = os.path.basename(sc_root)
            if dirname.startswith(('nts_', 'scc_')):
                d_parts = dirname.split('_')
                if len(d_parts) >= 2:
                    hostname_val = d_parts[1]
    _write('etc/hostname', hostname_val or '')
    _write('uptime',
           sc_read_file(sc_root, 'uptime'))
    _write('date',
           sc_read_file(sc_root, 'date'))

    # OS release
    os_release = sc_read_file(sc_root, 'os_release')
    if os_release:
        _write('etc/os-release', os_release)
    suse_release = sc_read_file(sc_root, 'suse_release')
    if suse_release:
        _write('etc/SuSE-release', suse_release)

    # Kernel
    uname = sc_read_file(sc_root, 'uname')
    if uname:
        _write('sos_commands/kernel/uname_-a', uname)
        _write('uname', uname)
    cmdline = sc_read_file(sc_root, 'cmdline')
    if cmdline:
        _write('proc/cmdline', cmdline.strip().splitlines()[0] if cmdline.strip() else '')

    # CPU
    lscpu = sc_read_file(sc_root, 'lscpu')
    if lscpu:
        _write('sos_commands/processor/lscpu', lscpu)
        _write('lscpu', lscpu)
    cpuinfo = sc_read_file(sc_root, 'cpuinfo')
    if cpuinfo:
        _write('proc/cpuinfo', cpuinfo)

    # Memory
    meminfo = sc_read_file(sc_root, 'meminfo')
    if meminfo:
        _write('proc/meminfo', meminfo)
    free_out = sc_read_file(sc_root, 'free')
    if free_out:
        _write('free', free_out)
    thp_e = sc_read_file(sc_root, 'thp_enabled')
    if thp_e:
        _write('sys/kernel/mm/transparent_hugepage/enabled', thp_e)
    thp_d = sc_read_file(sc_root, 'thp_defrag')
    if thp_d:
        _write('sys/kernel/mm/transparent_hugepage/defrag', thp_d)

    # Sysctl
    sysctl = sc_read_file(sc_root, 'sysctl')
    if sysctl:
        _write('sos_commands/kernel/sysctl_-a', sysctl)

    # Filesystem
    df_out = sc_read_file(sc_root, 'df')
    if df_out:
        _write('sos_commands/filesys/df_-h', df_out)
        _write('df', df_out)
    fstab = sc_read_file(sc_root, 'fstab')
    if fstab:
        _write('etc/fstab', fstab)
    lsblk = sc_read_file(sc_root, 'lsblk')
    if lsblk:
        _write('sos_commands/block/lsblk', lsblk)

    # Packages
    rpm_list = sc_read_file(sc_root, 'rpm_list')
    if rpm_list:
        _write('installed-rpms', rpm_list)

    # Processes
    ps_out = sc_read_file(sc_root, 'ps')
    if ps_out:
        _write('ps', ps_out)

    # dmidecode
    dmi = sc_read_file(sc_root, 'dmidecode')
    if dmi:
        _write('dmidecode', dmi)
        _write('sos_commands/hardware/dmidecode', dmi)

    # Dmesg
    dmesg = sc_read_file(sc_root, 'dmesg')
    if dmesg:
        _write('sos_commands/kernel/dmesg', dmesg)

    # Modules
    lsmod = sc_read_file(sc_root, 'modules')
    if lsmod:
        _write('sos_commands/kernel/lsmod', lsmod)

    # Network
    ip_addr = sc_read_file(sc_root, 'ip_addr')
    if ip_addr:
        _write('sos_commands/networking/ip_-d_address', ip_addr)
    ip_route = sc_read_file(sc_root, 'ip_route')
    if ip_route:
        _write('sos_commands/networking/ip_route', ip_route)
    resolv = sc_read_file(sc_root, 'resolv_conf')
    if resolv:
        _write('etc/resolv.conf', resolv)

    # Kdump / crash
    kdump = sc_read_file(sc_root, 'kdump')
    if kdump:
        _write('sos_commands/kdump/kdumpctl_status', kdump)

    # Systemd
    systemctl = sc_read_file(sc_root, 'systemctl')
    if systemctl:
        _write('sos_commands/systemd/systemctl_list-units', systemctl)
    systemd_full = sc_read_file(sc_root, 'systemd')
    if systemd_full:
        _write('sos_commands/systemd/systemd_info.txt', systemd_full)

    # Security / SSH / Audit
    sshd = sc_read_file(sc_root, 'sshd_config')
    if not sshd:
        # Try ssh.txt (SUSE separates SSH config into its own file)
        ssh_txt = os.path.join(sc_root, 'ssh.txt')
        if os.path.isfile(ssh_txt):
            sshd = sc_extract_section(ssh_txt, '/etc/ssh/sshd_config')
    if sshd:
        _write('etc/ssh/sshd_config', sshd)
    auditd = sc_read_file(sc_root, 'auditd_conf')
    if not auditd:
        auditd = sc_read_file(sc_root, 'auditd_conf2')
    if auditd:
        _write('etc/audit/auditd.conf', auditd)
    sestatus = sc_read_file(sc_root, 'sestatus')
    if sestatus:
        _write('sos_commands/selinux/sestatus', sestatus)
    apparmor = sc_read_file(sc_root, 'apparmor')
    if not apparmor:
        # Try security-apparmor.txt
        apparmor_txt = os.path.join(sc_root, 'security-apparmor.txt')
        if os.path.isfile(apparmor_txt):
            apparmor = sc_extract_section(apparmor_txt, '/usr/sbin/apparmor_status')
            if not apparmor:
                apparmor = sc_extract_section(apparmor_txt, 'apparmor_status')
    if apparmor:
        _write('sos_commands/apparmor/apparmor_status', apparmor)

    # SAR data — supportconfig stores SAR in two places:
    #   1. sar.txt — usually just verification/copy commands, rarely has actual data
    #   2. sar/ subdirectory — contains actual text sar files (sar20250409) and binary sa files
    sar_subdir = os.path.join(sc_root, 'sar')
    sar_dest = os.path.join(sc_root, 'var', 'log', 'sa')
    
    if os.path.isdir(sar_subdir):
        # Copy sar/ files to var/log/sa/ where the SAR parser looks
        os.makedirs(sar_dest, exist_ok=True)
        try:
            for fname in os.listdir(sar_subdir):
                src_file = os.path.join(sar_subdir, fname)
                if os.path.isfile(src_file):
                    shutil.copy2(src_file, os.path.join(sar_dest, fname))
                    _materialized.append(f"var/log/sa/{fname} ({os.path.getsize(src_file)} bytes)")
        except Exception as e:
            _materialized.append(f"var/log/sa/ copy (FAILED: {e})")
    
    # Also check sar.txt for inline SAR output (some supportconfigs embed sar -A output)
    sar_txt = sc_find_file(sc_root, 'sar.txt')
    if sar_txt:
        try:
            with open(sar_txt, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            # Try section-based extraction (get sar command output)
            sar_content = sc_extract_log_sections(sar_txt, '/usr/bin/sar')
            if not sar_content:
                sar_content = sc_extract_log_sections(sar_txt, '/usr/sbin/sar')
            if not sar_content:
                # Check if there's actual SAR data after stripping headers
                clean_lines = []
                for line in content.splitlines():
                    if _SC_SECTION_RE.match(line):
                        continue
                    if _SC_COMMAND_RE.match(line):
                        continue
                    clean_lines.append(line)
                candidate = '\n'.join(clean_lines).strip()
                if candidate and 'Linux' in candidate[:200]:
                    sar_content = candidate
            
            if sar_content and 'Linux' in sar_content[:200]:
                sar_content = sar_content.lstrip('\n\r ')
                os.makedirs(os.path.join(sc_root, 'sos_commands', 'sar'), exist_ok=True)
                dest = os.path.join(sc_root, 'sos_commands', 'sar', 'sar.txt')
                with open(dest, 'w', encoding='utf-8') as f:
                    f.write(sar_content)
                _materialized.append(f"sos_commands/sar/sar.txt ({len(sar_content)} bytes)")
        except Exception as e:
            _materialized.append(f"sos_commands/sar/sar.txt (FAILED: {e})")

    # Logs — messages.txt, warn.txt map to var/log equivalents
    # Use section-based extraction to get only actual log content
    for sc_file, var_log_path_prefix, var_log_name in [
        ('messages.txt', '/var/log/messages', 'var/log/messages'),
        ('warn.txt', '/var/log/warn', 'var/log/warn'),
    ]:
        src = sc_find_file(sc_root, sc_file)
        if src:
            # Try section-based extraction first (proper supportconfig with headers)
            log_content = sc_extract_log_sections(src, var_log_path_prefix)
            
            if not log_content:
                # Fallback: file might be raw log content with minimal headers
                # Just strip section headers and keep everything else
                try:
                    with open(src, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    log_lines = []
                    for line in content.splitlines():
                        if _SC_SECTION_RE.match(line):
                            continue
                        if _SC_COMMAND_RE.match(line):
                            continue
                        log_lines.append(line)
                    log_content = '\n'.join(log_lines)
                except Exception:
                    log_content = ''
            
            if log_content.strip():
                dest_path = os.path.join(sc_root, var_log_name)
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                try:
                    with open(dest_path, 'w', encoding='utf-8') as f:
                        f.write(log_content)
                    _materialized.append(f"{var_log_name} ({len(log_content)} bytes)")
                except Exception as e:
                    _materialized.append(f"{var_log_name} (FAILED: {e})")

    # Rotated messages files (messages-20250415.txt, etc.) — raw syslog, no headers
    import glob as _glob
    for rotated_file in _glob.glob(os.path.join(sc_root, 'messages-*.txt')):
        basename = os.path.basename(rotated_file)  # e.g. messages-20250415.txt
        # Map to var/log/messages-20250415
        dest_name = basename.replace('.txt', '')
        dest_path = os.path.join(sc_root, 'var', 'log', dest_name)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        try:
            shutil.copy2(rotated_file, dest_path)
            sz = os.path.getsize(rotated_file)
            _materialized.append(f"var/log/{dest_name} ({sz} bytes)")
        except Exception as e:
            _materialized.append(f"var/log/{dest_name} (FAILED: {e})")

    # boot.txt — extract only the boot.log / boot.msg section (not dmesg/lsmod/etc.)
    boot_src = sc_find_file(sc_root, 'boot.txt')
    if boot_src:
        boot_log = sc_extract_log_sections(boot_src, '/var/log/boot')
        if boot_log:
            _write('var/log/boot.log', boot_log)

    # security-audit.txt — SUSE splits security into separate files
    # Handle both old-style security.txt and new-style security-*.txt
    security_src = sc_find_file(sc_root, 'security.txt')
    audit_src = sc_find_file(sc_root, 'security-audit.txt')
    
    # Audit log extraction
    if audit_src:
        audit_log = sc_extract_log_sections(audit_src, '/var/log/audit')
        if audit_log:
            _write('var/log/audit/audit.log', audit_log)
    elif security_src:
        audit_log = sc_extract_log_sections(security_src, '/var/log/audit')
        if audit_log:
            _write('var/log/audit/audit.log', audit_log)
    
    # Secure/auth log extraction
    if security_src:
        secure_log = sc_extract_log_sections(security_src, '/var/log/secure')
        if not secure_log:
            secure_log = sc_extract_log_sections(security_src, '/var/log/auth')
        if secure_log:
            _write('var/log/secure', secure_log)
    
    # Firewall log
    if security_src:
        fw_log = sc_extract_log_sections(security_src, '/var/log/firewall')
        if fw_log:
            _write('var/log/firewall', fw_log)

    # journalctl.txt — newer SUSE supportconfigs include journal output
    journal_src = sc_find_file(sc_root, 'journalctl.txt')
    if journal_src:
        os.makedirs(os.path.join(sc_root, 'sos_commands', 'logs'), exist_ok=True)
        try:
            with open(journal_src, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            # Strip section headers
            log_lines = []
            for line in content.splitlines():
                if not _SC_SECTION_RE.match(line) and not _SC_COMMAND_RE.match(line):
                    log_lines.append(line)
            with open(os.path.join(sc_root, 'sos_commands', 'logs', 'journalctl_--no-pager'), 'w', encoding='utf-8') as f:
                f.write('\n'.join(log_lines))
        except Exception:
            pass

    # cron.txt — extract cron log entries
    cron_src = sc_find_file(sc_root, 'cron.txt')
    if cron_src:
        try:
            with open(cron_src, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            log_lines = []
            for line in content.splitlines():
                if not _SC_SECTION_RE.match(line) and not _SC_COMMAND_RE.match(line):
                    log_lines.append(line)
            if log_lines:
                _write('var/log/cron', '\n'.join(log_lines))
        except Exception:
            pass

    # HA / Pacemaker
    ha_src = sc_find_file(sc_root, 'ha.txt')
    if ha_src:
        os.makedirs(os.path.join(sc_root, 'sos_commands', 'pacemaker'), exist_ok=True)
        try:
            shutil.copy2(ha_src, os.path.join(sc_root, 'sos_commands', 'pacemaker', 'ha.txt'))
        except Exception:
            pass

    # Updates / zypper
    updates_src = sc_find_file(sc_root, 'updates.txt')
    if updates_src:
        os.makedirs(os.path.join(sc_root, 'sos_commands', 'dnf'), exist_ok=True)
        # Extract zypper patches info
        zypper_patches = sc_extract_section(updates_src, '/usr/bin/zypper')
        if zypper_patches:
            _write('sos_commands/dnf/zypper_patches', zypper_patches)

    # last reboot
    last_out = sc_read_file(sc_root, 'last_reboot')
    if last_out:
        _write('sos_commands/general/last_reboot', last_out)
        _write('last', last_out)

    # Log materialization summary
    logging.info(f"Supportconfig materialization: {len(_materialized)} files created")
    for item in _materialized:
        logging.info(f"  Materialized: {item}")
    
    # Also list what's now in var/log
    var_log = os.path.join(sc_root, 'var', 'log')
    if os.path.isdir(var_log):
        for root, dirs, files in os.walk(var_log):
            for f in files:
                full = os.path.join(root, f)
                sz = os.path.getsize(full) if os.path.isfile(full) else 0
                rel = os.path.relpath(full, sc_root)
                logging.info(f"  var/log contents: {rel} ({sz} bytes)")


def detect_hostname(sosreport_path: str, archive_format: str = 'sosreport') -> str:
    """Detect hostname from sosreport or supportconfig"""
    # Supportconfig: parse from basic-environment.txt
    if archive_format == 'supportconfig':
        sc_hostname = sc_read_file(sosreport_path, 'hostname')
        if sc_hostname:
            return sc_hostname.strip().splitlines()[0].strip()
        # Fallback: extract from uname output (Linux <hostname> ...)
        uname_out = sc_read_file(sosreport_path, 'uname')
        if uname_out:
            parts = uname_out.strip().split()
            if len(parts) >= 2 and parts[0] == 'Linux':
                return parts[1]
        # Try directory name pattern (nts_hostname_YYMMDD or scc_hostname_YYMMDD)
        dirname = os.path.basename(sosreport_path)
        if dirname.startswith(('nts_', 'scc_')):
            parts = dirname.split('_')
            if len(parts) >= 2:
                return parts[1]
    
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


def detect_uptime(sosreport_path: str, archive_format: str = 'sosreport') -> str:
    """Detect uptime from sosreport or supportconfig"""
    if archive_format == 'supportconfig':
        sc_uptime = sc_read_file(sosreport_path, 'uptime')
        if sc_uptime:
            for line in sc_uptime.splitlines():
                if 'load average' in line or 'up' in line:
                    return line.strip()
    
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


def detect_kernel_cmdline(sosreport_path: str, archive_format: str = 'sosreport') -> dict:
    """Read /proc/cmdline — the kernel boot parameters for the running kernel.
    
    Returns dict with:
      'raw': full cmdline string
      'params': dict of key=value pairs and standalone flags
      'boot_image': the BOOT_IMAGE value (kernel path)
      'notable': list of interesting/non-default parameters worth highlighting
    """
    cmdline_paths = [
        os.path.join(sosreport_path, "proc", "cmdline"),
        os.path.join(sosreport_path, "sos_commands", "kernel", "cat_.proc.cmdline"),
    ]
    
    # Supportconfig: /proc/cmdline is embedded in boot.txt
    if archive_format == 'supportconfig':
        sc_cmdline = sc_read_file(sosreport_path, 'cmdline')
        if sc_cmdline:
            # Write to temp path so the rest of the function works
            raw = sc_cmdline.strip().splitlines()[0].strip() if sc_cmdline.strip() else ''
            if raw:
                cmdline_paths = []  # skip file search
                # Fall through to parsing below with raw already set
    
    raw = ''
    for p in cmdline_paths:
        if os.path.isfile(p):
            try:
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    raw = f.read().strip()
                    if raw:
                        break
            except Exception:
                continue
    
    if not raw:
        return {'raw': '', 'params': {}, 'boot_image': '', 'notable': []}
    
    # Parse into key=value dict + flags
    params = {}
    for token in raw.split():
        if '=' in token:
            key, _, val = token.partition('=')
            params[key] = val
        else:
            params[token] = True  # standalone flag
    
    boot_image = params.get('BOOT_IMAGE', '')
    
    # Highlight notable / performance-relevant parameters
    notable_keys = [
        'crashkernel', 'hugepages', 'hugepagesz', 'default_hugepagesz',
        'transparent_hugepage', 'numa_balancing', 'isolcpus', 'nohz_full',
        'rcu_nocbs', 'intel_iommu', 'iommu', 'selinux', 'enforcing',
        'elevator', 'scsi_mod.use_blk_mq', 'rd.lvm.lv', 'root',
        'console', 'biosdevname', 'net.ifnames', 'nofb', 'nomodeset',
        'processor.max_cstate', 'intel_idle.max_cstate', 'idle',
        'audit', 'nmi_watchdog', 'mitigations', 'spectre_v2',
        'tsx', 'mds', 'nosmt', 'mem', 'memmap',
    ]
    notable = []
    for key in notable_keys:
        if key in params:
            val = params[key]
            if val is True:
                notable.append(key)
            else:
                notable.append(f"{key}={val}")
    
    return {
        'raw': raw,
        'params': params,
        'boot_image': boot_image,
        'notable': notable
    }


def detect_sysctl_tuning(sosreport_path: str, archive_format: str = 'sosreport') -> dict:
    """Extract performance-relevant sysctl parameters from sos_commands/kernel/sysctl_-a.

    Returns dict with categorized key parameters that impact performance tuning,
    especially for Oracle/SAP/database workloads.
    """
    sysctl = {}

    sysctl_files = [
        os.path.join(sosreport_path, "sos_commands", "kernel", "sysctl_-a"),
        os.path.join(sosreport_path, "sos_commands", "kernel", "sysctl"),
        os.path.join(sosreport_path, "proc", "sys"),  # fallback — individual files
    ]

    # Supportconfig: sysctl -a output is in env.txt
    if archive_format == 'supportconfig':
        sc_sysctl = sc_read_file(sosreport_path, 'sysctl')
        if sc_sysctl:
            # Write to temp file so the existing parsing logic works
            _tmp_sysctl = os.path.join(sosreport_path, '_sysctl_tmp.txt')
            try:
                with open(_tmp_sysctl, 'w') as f:
                    f.write(sc_sysctl)
                sysctl_files.insert(0, _tmp_sysctl)
            except Exception:
                pass

    # Key parameters to extract, grouped for display
    WANTED = {
        # VM / Memory
        'vm.swappiness', 'vm.dirty_ratio', 'vm.dirty_background_ratio',
        'vm.dirty_expire_centisecs', 'vm.dirty_writeback_centisecs',
        'vm.overcommit_memory', 'vm.overcommit_ratio',
        'vm.nr_hugepages', 'vm.hugetlb_shm_group',
        'vm.min_free_kbytes', 'vm.vfs_cache_pressure',
        'vm.zone_reclaim_mode', 'vm.max_map_count',
        # Kernel / IPC (Oracle semaphores, shared memory)
        'kernel.shmmax', 'kernel.shmall', 'kernel.shmmni',
        'kernel.sem', 'kernel.msgmax', 'kernel.msgmni', 'kernel.msgmnb',
        'kernel.panic', 'kernel.panic_on_oops',
        'kernel.sched_min_granularity_ns', 'kernel.sched_migration_cost_ns',
        'kernel.numa_balancing',
        # Network
        'net.core.somaxconn', 'net.core.rmem_max', 'net.core.wmem_max',
        'net.core.rmem_default', 'net.core.wmem_default',
        'net.core.netdev_max_backlog',
        'net.ipv4.tcp_rmem', 'net.ipv4.tcp_wmem',
        'net.ipv4.tcp_max_syn_backlog', 'net.ipv4.tcp_fin_timeout',
        'net.ipv4.tcp_keepalive_time', 'net.ipv4.tcp_tw_reuse',
        'net.ipv4.ip_local_port_range',
        # FS
        'fs.file-max', 'fs.aio-max-nr', 'fs.file-nr',
    }

    for sf in sysctl_files:
        if os.path.isfile(sf):
            try:
                with open(sf, 'r', errors='replace') as f:
                    for line in f:
                        line = line.strip()
                        if '=' in line:
                            key, _, val = line.partition('=')
                            key = key.strip()
                            val = val.strip()
                            if key in WANTED:
                                sysctl[key] = val
                if sysctl:
                    break
            except Exception:
                continue

    # Categorize for display
    categories = {
        'Memory & VM': {},
        'Kernel & IPC': {},
        'Network': {},
        'Filesystem': {},
    }
    for key, val in sorted(sysctl.items()):
        if key.startswith('vm.'):
            categories['Memory & VM'][key] = val
        elif key.startswith('kernel.'):
            categories['Kernel & IPC'][key] = val
        elif key.startswith('net.'):
            categories['Network'][key] = val
        elif key.startswith('fs.'):
            categories['Filesystem'][key] = val

    # Build highlights — flag non-default or notable values
    highlights = []
    swap = sysctl.get('vm.swappiness')
    if swap is not None:
        s = int(swap) if swap.isdigit() else -1
        if s == 0:
            highlights.append(('vm.swappiness', swap, '🟢', 'Swapping disabled — good for DB'))
        elif s <= 10:
            highlights.append(('vm.swappiness', swap, '🟢', 'Low swappiness — good for DB'))
        elif s >= 60:
            highlights.append(('vm.swappiness', swap, '🟡', 'Default/high — consider lowering for DB'))
        else:
            highlights.append(('vm.swappiness', swap, '🟢', ''))

    dirty = sysctl.get('vm.dirty_ratio')
    if dirty and dirty.isdigit():
        d = int(dirty)
        if d >= 40:
            highlights.append(('vm.dirty_ratio', dirty, '🟡', 'High — may cause I/O bursts'))
        else:
            highlights.append(('vm.dirty_ratio', dirty, '🟢', ''))

    overcommit = sysctl.get('vm.overcommit_memory')
    if overcommit:
        labels = {'0': 'heuristic (default)', '1': 'always overcommit', '2': 'no overcommit'}
        highlights.append(('vm.overcommit_memory', overcommit, '🟢' if overcommit == '2' else '🟡',
                          labels.get(overcommit, '')))

    nr_hp = sysctl.get('vm.nr_hugepages')
    if nr_hp and nr_hp != '0':
        highlights.append(('vm.nr_hugepages', nr_hp, '🟢', ''))

    panic = sysctl.get('kernel.panic')
    if panic and panic != '0':
        highlights.append(('kernel.panic', panic, '🟢', f'Auto-reboot after {panic}s on panic'))

    return {
        'all': sysctl,
        'categories': categories,
        'highlights': highlights,
    }


def detect_reboot_history(sosreport_path: str, report_year: int = None, archive_format: str = 'sosreport') -> list:
    """Detect reboot timestamps by grepping BOOT_IMAGE from messages/dmesg files.
    
    Each BOOT_IMAGE line in /var/log/messages marks a kernel boot, so it shows
    every time the server was (re)started.  Also checks 'last reboot' output.
    
    Returns list of dicts: [{'timestamp': datetime, 'kernel': str, 'source': str}, ...]
    sorted most-recent first.
    """
    import re as _re
    reboots = []
    seen = set()  # deduplicate by minute
    
    if report_year is None:
        report_year = datetime.now().year
    
    # ── 1. Scan /var/log/messages* and /var/log/syslog* for BOOT_IMAGE ──
    var_log = os.path.join(sosreport_path, 'var', 'log')
    msg_files = []
    if os.path.isdir(var_log):
        for fname in sorted(os.listdir(var_log)):
            # RHEL/OL/CentOS/SUSE use messages, Ubuntu/Debian use syslog
            if fname.startswith('messages') or fname.startswith('syslog'):
                msg_files.append(os.path.join(var_log, fname))
    
    # Patterns:  "Nov 29 13:39:20 hostname kernel: ... BOOT_IMAGE=..."
    boot_re = _re.compile(
        r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+\S+\s+kernel.*BOOT_IMAGE=(\S+)',
        _re.IGNORECASE
    )
    month_map = {'jan':1,'feb':2,'mar':3,'apr':4,'may':5,'jun':6,
                 'jul':7,'aug':8,'sep':9,'oct':10,'nov':11,'dec':12}
    
    for mf in msg_files:
        try:
            with open(mf, 'r', errors='replace') as fh:
                for line in fh:
                    m = boot_re.search(line)
                    if m:
                        mon_str, day_str, time_str, kernel_path = m.groups()
                        mon = month_map.get(mon_str.lower())
                        if not mon:
                            continue
                        day = int(day_str)
                        h, mi, s = (int(x) for x in time_str.split(':'))
                        # Determine year: if month > current sosreport month, it's previous year
                        yr = report_year
                        try:
                            ts = datetime(yr, mon, day, h, mi, s)
                        except ValueError:
                            continue
                        key = ts.strftime('%Y-%m-%d %H:%M')
                        if key not in seen:
                            seen.add(key)
                            # Extract just the kernel version from path
                            kernel_ver = kernel_path.split('/')[-1].replace('vmlinuz-', '')
                            reboots.append({
                                'timestamp': ts,
                                'kernel': kernel_ver,
                                'source': 'messages'
                            })
        except Exception:
            continue
    
    # ── 2. Check 'last reboot' output ────────────────────────────────────
    last_reboot_paths = [
        os.path.join(sosreport_path, 'sos_commands', 'last', 'last_reboot'),
        os.path.join(sosreport_path, 'sos_commands', 'general', 'last_reboot'),
        os.path.join(sosreport_path, 'last'),
    ]
    last_re = _re.compile(
        r'reboot\s+system boot\s+(\S+)\s+(\w{3})\s+(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2})'
    )
    for lf in last_reboot_paths:
        if os.path.isfile(lf):
            try:
                with open(lf, 'r', errors='replace') as fh:
                    for line in fh:
                        m = last_re.search(line)
                        if m:
                            kernel_ver, _dow, mon_str, day_str, time_str = m.groups()
                            mon = month_map.get(mon_str.lower())
                            if not mon:
                                continue
                            day = int(day_str)
                            h, mi = (int(x) for x in time_str.split(':'))
                            yr = report_year
                            try:
                                ts = datetime(yr, mon, day, h, mi, 0)
                            except ValueError:
                                continue
                            key = ts.strftime('%Y-%m-%d %H:%M')
                            if key not in seen:
                                seen.add(key)
                                reboots.append({
                                    'timestamp': ts,
                                    'kernel': kernel_ver,
                                    'source': 'last reboot'
                                })
            except Exception:
                continue
            break  # Only use first found
    
    # Sort most recent first
    reboots.sort(key=lambda r: r['timestamp'], reverse=True)
    return reboots


def detect_date(sosreport_path: str, archive_format: str = 'sosreport') -> str:
    """Detect date command output from sosreport or supportconfig"""
    if archive_format == 'supportconfig':
        sc_date = sc_read_file(sosreport_path, 'date')
        if sc_date:
            first_line = sc_date.strip().splitlines()[0].strip()
            if first_line and not first_line.startswith('Local time:'):
                return first_line
    
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


def detect_os_release(sosreport_path: str, archive_format: str = 'sosreport') -> str:
    """Detect OS release version from sosreport or supportconfig"""
    if archive_format == 'supportconfig':
        # Try /etc/os-release first
        sc_os = sc_read_file(sosreport_path, 'os_release')
        if sc_os:
            for line in sc_os.splitlines():
                if line.startswith('PRETTY_NAME='):
                    return line.split('=', 1)[1].strip('"\'')
        # Try /etc/SuSE-release
        sc_suse = sc_read_file(sosreport_path, 'suse_release')
        if sc_suse:
            return sc_suse.strip().splitlines()[0].strip()
    
    release_files = [
        os.path.join(sosreport_path, "etc", "redhat-release"),
        os.path.join(sosreport_path, "etc", "system-release"),
        os.path.join(sosreport_path, "etc", "os-release"),
        os.path.join(sosreport_path, "etc", "oracle-release"),
        os.path.join(sosreport_path, "etc", "SuSE-release"),
        # Ubuntu/Debian
        os.path.join(sosreport_path, "etc", "lsb-release"),
        os.path.join(sosreport_path, "etc", "debian_version"),
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
                        # For lsb-release, extract DISTRIB_DESCRIPTION
                        elif 'lsb-release' in rf:
                            for line in content.split('\n'):
                                if line.startswith('DISTRIB_DESCRIPTION='):
                                    return line.split('=', 1)[1].strip('"\'')
                            # Fallback: DISTRIB_ID + DISTRIB_RELEASE
                            distrib_id = ''
                            distrib_release = ''
                            for line in content.split('\n'):
                                if line.startswith('DISTRIB_ID='):
                                    distrib_id = line.split('=', 1)[1].strip('"\'')
                                elif line.startswith('DISTRIB_RELEASE='):
                                    distrib_release = line.split('=', 1)[1].strip('"\'')
                            if distrib_id:
                                return f"{distrib_id} {distrib_release}".strip()
                        # For debian_version, return "Debian X.Y"
                        elif 'debian_version' in rf:
                            return f"Debian {content.split(chr(10))[0]}"
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
      'debian'       - Debian
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
    elif 'suse' in os_lower or 'sles' in os_lower or 'sled' in os_lower or 'opensuse' in os_lower:
        return 'suse'
    elif 'ubuntu' in os_lower:
        return 'ubuntu'
    elif 'debian' in os_lower:
        return 'debian'
    else:
        return 'unknown'


# ─── OS-flavor-specific configuration ────────────────────────────────────────
# Each flavor defines:
#   base_kernel_prefix : prefix(es) for the BASE kernel package (not sub-pkgs)
#   kernel_type_tag    : string present in kernel name to identify this track
#   staleness_thresholds : (outdated_min, very_outdated_min) on the "major_update" number
#                          from version string  e.g. 5.14.0-<major_update>.x.y
#   subscription_methods : typical subscription mechanisms for this distro
#
# To add a new distro:  add an entry here + any special logic in detect_patch_compliance.
# ─────────────────────────────────────────────────────────────────────────────
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
    'ubuntu': {
        'base_kernel_prefixes': ['linux-image-'],
        'kernel_type_from_version': lambda kver: (
            'azure' if 'azure' in kver.lower() else
            'aws' if 'aws' in kver.lower() else
            'gcp' if 'gcp' in kver.lower() else
            'generic' if 'generic' in kver.lower() else
            'lowlatency' if 'lowlatency' in kver.lower() else
            'standard'
        ),
        'staleness_thresholds': {
            'generic':    {'outdated': 70, 'very_outdated': 40},
            'azure':      {'outdated': 70, 'very_outdated': 40},
            'aws':        {'outdated': 70, 'very_outdated': 40},
            'gcp':        {'outdated': 70, 'very_outdated': 40},
            'lowlatency': {'outdated': 70, 'very_outdated': 40},
            'standard':   {'outdated': 70, 'very_outdated': 40},
        },
        'subscription_methods': ['apt', 'Ubuntu Pro', 'unattended-upgrades'],
    },
    'debian': {
        'base_kernel_prefixes': ['linux-image-'],
        'kernel_type_from_version': lambda kver: (
            'cloud' if 'cloud' in kver.lower() else
            'rt' if 'rt' in kver.lower() else
            'standard'
        ),
        'staleness_thresholds': {
            'standard': {'outdated': 70, 'very_outdated': 40},
            'cloud':    {'outdated': 70, 'very_outdated': 40},
            'rt':       {'outdated': 70, 'very_outdated': 40},
        },
        'subscription_methods': ['apt'],
    },
}
# Fallback for unrecognized distros
OS_FLAVOR_CONFIG['unknown'] = OS_FLAVOR_CONFIG['rhel']


def detect_cpu_info(sosreport_path: str, archive_format: str = 'sosreport') -> dict:
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


def detect_memory_info(sosreport_path: str, archive_format: str = 'sosreport') -> dict:
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
        'hugepage_size_kb': 0,
        'thp_enabled': 'N/A',    # Transparent HugePages status
        'thp_defrag': 'N/A',
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
                        break  # Found meminfo, now read THP below
            except:
                continue
    
    # Read Transparent HugePages status
    thp_paths = [
        os.path.join(sosreport_path, "sys", "kernel", "mm", "transparent_hugepage", "enabled"),
        os.path.join(sosreport_path, "sos_commands", "memory", "cat_.sys.kernel.mm.transparent_hugepage.enabled"),
    ]
    for tp in thp_paths:
        if os.path.isfile(tp):
            try:
                with open(tp, 'r', errors='ignore') as f:
                    content = f.read().strip()
                    # Format: "always madvise [never]" — bracketed value is active
                    bracket_match = re.search(r'\[(\w+)\]', content)
                    if bracket_match:
                        mem_info['thp_enabled'] = bracket_match.group(1)
                    elif content:
                        mem_info['thp_enabled'] = content
                    break
            except Exception:
                continue
    
    thp_defrag_paths = [
        os.path.join(sosreport_path, "sys", "kernel", "mm", "transparent_hugepage", "defrag"),
        os.path.join(sosreport_path, "sos_commands", "memory", "cat_.sys.kernel.mm.transparent_hugepage.defrag"),
    ]
    for dp in thp_defrag_paths:
        if os.path.isfile(dp):
            try:
                with open(dp, 'r', errors='ignore') as f:
                    content = f.read().strip()
                    bracket_match = re.search(r'\[(\w+)\]', content)
                    if bracket_match:
                        mem_info['thp_defrag'] = bracket_match.group(1)
                    elif content:
                        mem_info['thp_defrag'] = content
                    break
            except Exception:
                continue
    
    if mem_info['total_kb'] > 0:
        return mem_info
    
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


def detect_kernel_version(sosreport_path: str, archive_format: str = 'sosreport') -> str:
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


def detect_df_info(sosreport_path: str, archive_format: str = 'sosreport') -> List[dict]:
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


def detect_installed_packages(sosreport_path: str, archive_format: str = 'sosreport') -> dict:
    """Detect important installed packages from sosreport (RPM or DPKG based)"""
    packages = {
        'rhui': [],
        'kernel': [],
        'python': [],
        'java': [],
        'total_count': 0,
        'all_packages': []
    }
    
    # ── RPM-based distros (RHEL, OL, CentOS, Rocky, Alma, SUSE) ────────
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
                        packages['all_packages'].append(pkg_name)
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
    
    # ── DPKG-based distros (Ubuntu, Debian) ────────────────────────────
    dpkg_files = []
    
    # Priority 1: installed-debs at sosreport root
    installed_debs = os.path.join(sosreport_path, "installed-debs")
    if os.path.isfile(installed_debs):
        dpkg_files.append(installed_debs)
    
    # Priority 2: sos_commands/dpkg/ directory
    dpkg_dir = os.path.join(sosreport_path, "sos_commands", "dpkg")
    if os.path.isdir(dpkg_dir):
        for f in os.listdir(dpkg_dir):
            f_lower = f.lower()
            if 'dpkg' in f_lower and ('list' in f_lower or 'get-selections' in f_lower):
                dpkg_files.append(os.path.join(dpkg_dir, f))
    
    for dpkg_file in dpkg_files:
        if os.path.isfile(dpkg_file):
            try:
                with open(dpkg_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        
                        # dpkg -l format: "ii  package-name  version  arch  description"
                        # dpkg --get-selections format: "package-name\tinstall"
                        parts = line.split()
                        if len(parts) >= 2:
                            # Skip header lines (lines starting with |, +, Desired=, etc.)
                            if parts[0] in ('Desired=', '||/', '|', '+') or line.startswith('|') or line.startswith('+'):
                                continue
                            
                            # dpkg -l format: status (ii/rc/etc.) is first column
                            if len(parts[0]) <= 3 and parts[0].replace('i', '').replace('r', '').replace('c', '').replace('u', '').replace('h', '').replace('n', '').replace('p', '') == '':
                                pkg_name = parts[1]
                                # Only count installed packages (status starts with 'i')
                                if not parts[0].startswith('i'):
                                    continue
                            else:
                                # dpkg --get-selections format
                                pkg_name = parts[0]
                                if len(parts) > 1 and parts[-1] == 'deinstall':
                                    continue
                            
                            packages['total_count'] += 1
                            # Strip :arch suffix (e.g. "linux-image-5.15.0-91-generic:amd64")
                            pkg_name_clean = pkg_name.split(':')[0]
                            packages['all_packages'].append(pkg_name_clean)
                            pkg_lower = pkg_name_clean.lower()
                            
                            # Ubuntu/Debian kernel packages start with linux-image-
                            if pkg_lower.startswith('linux-image-') or pkg_lower.startswith('linux-headers-'):
                                packages['kernel'].append(pkg_name_clean)
                            elif 'python' in pkg_lower and len(packages['python']) < 5:
                                packages['python'].append(pkg_name_clean)
                            elif 'java' in pkg_lower and len(packages['java']) < 5:
                                packages['java'].append(pkg_name_clean)
                    
                    if packages['total_count'] > 0:
                        return packages
            except:
                continue
    
    return packages


def detect_selinux_status(sosreport_path: str, archive_format: str = 'sosreport') -> str:
    """Detect SELinux or AppArmor status from sosreport/supportconfig"""
    # For SUSE — check AppArmor instead of SELinux
    apparmor_file = os.path.join(sosreport_path, 'sos_commands', 'apparmor', 'apparmor_status')
    if os.path.isfile(apparmor_file):
        try:
            with open(apparmor_file, 'r', errors='ignore') as f:
                content = f.read()
                if 'profiles are loaded' in content or 'profiles are in' in content:
                    return f"AppArmor (active)"
                return "AppArmor (unknown state)"
        except Exception:
            pass
    
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


def detect_kdump_status(sosreport_path: str, archive_format: str = 'sosreport') -> dict:
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


def detect_top_processes(sosreport_path: str, archive_format: str = 'sosreport') -> dict:
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


# ============================================================================
# V7 NEW DETECTION FUNCTIONS
# ============================================================================

def detect_cloud_provider(sosreport_path: str, archive_format: str = 'sosreport') -> dict:
    """Auto-detect cloud provider (Azure/AWS/GCP/Oracle) and collect provider-specific metadata.
    
    Detection order:
    1. DMI/BIOS via dmidecode
    2. Cloud-specific log files (waagent, guest-agent, etc.)
    3. Cloud-init presence
    4. Virtualization type (virt-what, systemd-detect-virt)
    
    Returns dict with 'provider', 'details', and 'cloud_init' keys.
    """
    cloud_info = {
        'provider': None,
        'provider_label': 'Unknown',
        'details': {},
        'cloud_init': {},
        'virtualization': {},
    }
    
    # --- Step 1: DMI/BIOS detection via dmidecode ---
    dmi_paths = [
        os.path.join(sosreport_path, 'dmidecode'),
        os.path.join(sosreport_path, 'sos_commands', 'hardware', 'dmidecode'),
    ]
    for dmi_path in dmi_paths:
        if os.path.isfile(dmi_path):
            try:
                with open(dmi_path, 'r', errors='ignore') as f:
                    content = f.read().lower()
                
                if 'amazon' in content or 'amazon ec2' in content:
                    cloud_info['provider'] = 'aws'
                    cloud_info['provider_label'] = 'Amazon Web Services (AWS)'
                elif 'microsoft corporation' in content and ('virtual machine' in content or 'azure' in content):
                    cloud_info['provider'] = 'azure'
                    cloud_info['provider_label'] = 'Microsoft Azure'
                elif 'google' in content and 'compute engine' in content:
                    cloud_info['provider'] = 'gcp'
                    cloud_info['provider_label'] = 'Google Cloud Platform (GCP)'
                elif 'oraclecloud' in content or 'oracle cloud' in content:
                    cloud_info['provider'] = 'oracle'
                    cloud_info['provider_label'] = 'Oracle Cloud Infrastructure (OCI)'
            except:
                pass
            break
    
    # --- Step 2: Cloud-specific files as fallback ---
    if not cloud_info['provider']:
        waagent_log = os.path.join(sosreport_path, 'var', 'log', 'waagent.log')
        if os.path.isfile(waagent_log):
            cloud_info['provider'] = 'azure'
            cloud_info['provider_label'] = 'Microsoft Azure'
        
        gcp_agent = os.path.join(sosreport_path, 'var', 'log', 'google-guest-agent.log')
        if not cloud_info['provider'] and os.path.isfile(gcp_agent):
            cloud_info['provider'] = 'gcp'
            cloud_info['provider_label'] = 'Google Cloud Platform (GCP)'
        
        hypervisor_uuid = os.path.join(sosreport_path, 'sys', 'hypervisor', 'uuid')
        if not cloud_info['provider'] and os.path.isfile(hypervisor_uuid):
            try:
                with open(hypervisor_uuid, 'r') as f:
                    if f.read().strip().startswith('ec2'):
                        cloud_info['provider'] = 'aws'
                        cloud_info['provider_label'] = 'Amazon Web Services (AWS)'
            except:
                pass
        
        # Fallback: sos_commands/azure/ directory with instance_metadata.json
        if not cloud_info['provider']:
            _azure_dir = os.path.join(sosreport_path, 'sos_commands', 'azure')
            if os.path.isdir(_azure_dir):
                cloud_info['provider'] = 'azure'
                cloud_info['provider_label'] = 'Microsoft Azure'
    
    # --- Step 3: Virtualization detection ---
    virt_what = os.path.join(sosreport_path, 'sos_commands', 'general', 'virt-what')
    if os.path.isfile(virt_what):
        try:
            with open(virt_what, 'r', errors='ignore') as f:
                cloud_info['virtualization']['virt_what'] = f.read().strip()
        except:
            pass
    
    systemd_virt = os.path.join(sosreport_path, 'sos_commands', 'general', 'systemd-detect-virt')
    if os.path.isfile(systemd_virt):
        try:
            with open(systemd_virt, 'r', errors='ignore') as f:
                cloud_info['virtualization']['systemd_detect'] = f.read().strip()
        except:
            pass
    
    product_name = os.path.join(sosreport_path, 'sys', 'class', 'dmi', 'id', 'product_name')
    if os.path.isfile(product_name):
        try:
            with open(product_name, 'r', errors='ignore') as f:
                cloud_info['virtualization']['product_name'] = f.read().strip()
        except:
            pass
    
    # --- Step 4: Provider-specific metadata ---
    provider = cloud_info['provider']
    
    if provider == 'azure':
        # WALinuxAgent config
        waagent_conf = os.path.join(sosreport_path, 'etc', 'waagent.conf')
        if os.path.isfile(waagent_conf):
            try:
                with open(waagent_conf, 'r', errors='ignore') as f:
                    cloud_info['details']['waagent_conf'] = f.read()
            except:
                pass
        
        # Azure VM extensions
        waagent_dir = os.path.join(sosreport_path, 'var', 'lib', 'waagent')
        if os.path.isdir(waagent_dir):
            extensions = []
            try:
                for item in os.listdir(waagent_dir):
                    if 'Microsoft' in item:
                        extensions.append(item)
            except:
                pass
            if extensions:
                cloud_info['details']['extensions'] = sorted(extensions)
        
        # waagent log (last 50 lines)
        waagent_log = os.path.join(sosreport_path, 'var', 'log', 'waagent.log')
        if os.path.isfile(waagent_log):
            try:
                with open(waagent_log, 'r', errors='ignore') as f:
                    lines = f.readlines()
                    cloud_info['details']['waagent_log_tail'] = ''.join(lines[-50:])
            except:
                pass
        
        # ovf-env.xml
        ovf_env = os.path.join(sosreport_path, 'var', 'lib', 'waagent', 'ovf-env.xml')
        if os.path.isfile(ovf_env):
            try:
                with open(ovf_env, 'r', errors='ignore') as f:
                    cloud_info['details']['ovf_env'] = f.read()
            except:
                pass
    
    elif provider == 'aws':
        sos_cloud_dir = os.path.join(sosreport_path, 'sos_commands', 'cloud')
        if os.path.isdir(sos_cloud_dir):
            for fname in os.listdir(sos_cloud_dir):
                fpath = os.path.join(sos_cloud_dir, fname)
                if 'instance-id' in fname:
                    try:
                        with open(fpath, 'r') as f:
                            cloud_info['details']['instance_id'] = f.read().strip()
                    except:
                        pass
                elif 'instance-type' in fname:
                    try:
                        with open(fpath, 'r') as f:
                            cloud_info['details']['instance_type'] = f.read().strip()
                    except:
                        pass
                elif 'availability-zone' in fname:
                    try:
                        with open(fpath, 'r') as f:
                            cloud_info['details']['availability_zone'] = f.read().strip()
                    except:
                        pass
        
        # ENA driver
        ena_info = os.path.join(sosreport_path, 'sos_commands', 'kernel', 'modinfo_ena')
        if os.path.isfile(ena_info):
            try:
                with open(ena_info, 'r', errors='ignore') as f:
                    cloud_info['details']['ena_driver'] = f.read()
            except:
                pass
    
    elif provider == 'gcp':
        gcp_agent = os.path.join(sosreport_path, 'var', 'log', 'google-guest-agent.log')
        if os.path.isfile(gcp_agent):
            try:
                with open(gcp_agent, 'r', errors='ignore') as f:
                    lines = f.readlines()
                    cloud_info['details']['guest_agent_tail'] = ''.join(lines[-50:])
            except:
                pass
    
    # --- Step 4b: Azure instance metadata (provider-agnostic location) ---
    # Runs for ANY Azure-detected provider, regardless of detection method.
    # Also searches sos_commands/azure/ which newer sos plugins use.
    if cloud_info['provider'] == 'azure' and 'instance_metadata' not in cloud_info.get('details', {}):
        _metadata_raw = None
        _metadata_search_dirs = [
            ('cloud', os.path.join(sosreport_path, 'sos_commands', 'cloud')),
            ('azure', os.path.join(sosreport_path, 'sos_commands', 'azure')),
        ]
        for _mdlabel, _mddir in _metadata_search_dirs:
            if not os.path.isdir(_mddir):
                continue
            for fname in os.listdir(_mddir):
                _is_match = False
                if _mdlabel == 'cloud' and '169.254.169.254' in fname and 'metadata' in fname.lower():
                    _is_match = True
                elif _mdlabel == 'azure' and 'instance_metadata' in fname.lower() and fname.endswith('.json'):
                    _is_match = True
                # Also match any .json file in sos_commands/azure/ as a fallback
                elif _mdlabel == 'azure' and fname.endswith('.json'):
                    _is_match = True
                if _is_match:
                    try:
                        with open(os.path.join(_mddir, fname), 'r', errors='ignore') as f:
                            _metadata_raw = f.read()
                            cloud_info['details']['instance_metadata'] = _metadata_raw
                    except:
                        pass
                    break
            if _metadata_raw:
                break

        # Parse structured fields from instance metadata JSON
        if _metadata_raw:
            try:
                import json as _json
                _md = _json.loads(_metadata_raw)
                _compute = _md.get('compute', {})
                if _compute:
                    cloud_info['details']['vm_size'] = _compute.get('vmSize', '')
                    cloud_info['details']['location'] = _compute.get('location', '')
                    cloud_info['details']['sku'] = _compute.get('sku', '')
                    cloud_info['details']['offer'] = _compute.get('offer', '')
                    cloud_info['details']['publisher'] = _compute.get('publisher', '')
                    cloud_info['details']['os_type'] = _compute.get('osType', '')
                    cloud_info['details']['vm_name'] = _compute.get('name', '')
                    cloud_info['details']['vm_id'] = _compute.get('vmId', '')
                    cloud_info['details']['resource_group'] = _compute.get('resourceGroupName', '')
                    cloud_info['details']['version'] = _compute.get('version', '')
                    cloud_info['details']['fault_domain'] = _compute.get('platformFaultDomain', '')
                    cloud_info['details']['update_domain'] = _compute.get('platformUpdateDomain', '')
                    cloud_info['details']['tags_raw'] = _compute.get('tags', '')
                _network = _md.get('network', {})
                if _network:
                    _ifaces = _network.get('interface', [])
                    if _ifaces:
                        _ips = []
                        for _iface in _ifaces:
                            for _addr in _iface.get('ipv4', {}).get('ipAddress', []):
                                _pip = _addr.get('privateIpAddress', '')
                                if _pip:
                                    _ips.append(_pip)
                        cloud_info['details']['private_ips'] = _ips
            except Exception:
                pass

    # --- Step 5: Cloud-init (provider-agnostic) ---
    cloud_cfg = os.path.join(sosreport_path, 'etc', 'cloud', 'cloud.cfg')
    if os.path.isfile(cloud_cfg):
        try:
            with open(cloud_cfg, 'r', errors='ignore') as f:
                cloud_info['cloud_init']['config'] = f.read()
        except:
            pass
    
    cloud_init_log = os.path.join(sosreport_path, 'var', 'log', 'cloud-init.log')
    if os.path.isfile(cloud_init_log):
        try:
            with open(cloud_init_log, 'r', errors='ignore') as f:
                lines = f.readlines()
                cloud_info['cloud_init']['log_tail'] = ''.join(lines[-100:])
        except:
            pass
    
    cloud_status = os.path.join(sosreport_path, 'sos_commands', 'cloud_init', 'cloud-init_status_--long')
    if os.path.isfile(cloud_status):
        try:
            with open(cloud_status, 'r', errors='ignore') as f:
                cloud_info['cloud_init']['status'] = f.read()
        except:
            pass
    
    return cloud_info


def detect_azure_metadata(sosreport_path: str, archive_format: str = 'sosreport') -> dict:
    """Directly find and parse Azure instance_metadata.json from sosreport.
    
    Searches ALL directories under sos_commands/ for any JSON file with a
    compute.vmSize field.  This is independent of detect_cloud_provider()
    so it works even if that function fails to identify the cloud.
    
    Returns dict with vm_size, location, sku, offer, resource_group, etc.
    Empty dict if not found.
    """
    import json
    import glob as _glob_mod
    
    result = {}
    
    # Strategy: search broadly for any JSON containing Azure metadata
    # 1. Direct known paths
    candidate_files = [
        os.path.join(sosreport_path, 'sos_commands', 'azure', 'instance_metadata.json'),
    ]
    
    # 2. Scan all subdirs under sos_commands/ for .json files
    sos_cmds = os.path.join(sosreport_path, 'sos_commands')
    if os.path.isdir(sos_cmds):
        for dirpath, dirnames, filenames in os.walk(sos_cmds):
            for fname in filenames:
                if fname.endswith('.json') or 'metadata' in fname.lower():
                    full = os.path.join(dirpath, fname)
                    if full not in candidate_files:
                        candidate_files.append(full)
    
    # 3. Also check files that contain the IMDS IP (169.254.169.254) in their name
    #    These are curl output files that sos captures, sometimes without .json extension
    if os.path.isdir(sos_cmds):
        for dirpath, dirnames, filenames in os.walk(sos_cmds):
            for fname in filenames:
                if '169.254.169.254' in fname:
                    full = os.path.join(dirpath, fname)
                    if full not in candidate_files:
                        candidate_files.append(full)
    
    _debug_tried = []
    for fpath in candidate_files:
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, 'r', errors='ignore') as f:
                raw = f.read().strip()
            
            if not raw:
                continue
            
            # Try to find JSON — some files have headers/text before the JSON
            # Look for the first '{' character
            json_start = raw.find('{')
            if json_start < 0:
                continue
            
            data = json.loads(raw[json_start:])
            
            # Handle both formats:
            # Format 1 (older): {"compute": {"vmSize": "...", "location": "..."}, "network": {...}}
            # Format 2 (newer): {"vmSize": "...", "location": "...", ...}  (flat, no compute wrapper)
            compute = data.get('compute', {})
            if compute and compute.get('vmSize'):
                src = compute
                network = data.get('network', {})
            elif data.get('vmSize'):
                src = data
                network = {}
            else:
                _debug_tried.append(f"  no vmSize in {os.path.basename(fpath)}")
                continue
            
            result['vm_name'] = src.get('name', '')
            result['vm_size'] = src.get('vmSize', '')
            result['location'] = src.get('location', '')
            result['sku'] = src.get('sku', '')
            result['offer'] = src.get('offer', '')
            result['publisher'] = src.get('publisher', '')
            result['os_type'] = src.get('osType', '')
            result['vm_id'] = src.get('vmId', '')
            result['resource_group'] = src.get('resourceGroupName', '')
            result['version'] = src.get('version', '')
            result['fault_domain'] = src.get('platformFaultDomain', '')
            result['update_domain'] = src.get('platformUpdateDomain', '')
            result['tags_raw'] = src.get('tags', '')
            
            # Network
            ips = []
            for iface in network.get('interface', []):
                for addr in iface.get('ipv4', {}).get('ipAddress', []):
                    pip = addr.get('privateIpAddress', '')
                    if pip:
                        ips.append(pip)
            result['private_ips'] = ips
            result['_source_file'] = os.path.basename(fpath)
            
            break  # Found valid metadata
        except Exception:
            continue
    
    # Store debug info so we can see what happened if metadata is empty
    if not result:
        # List what directories actually exist under sos_commands/
        sos_dirs = []
        if os.path.isdir(sos_cmds):
            sos_dirs = sorted(os.listdir(sos_cmds))
        result['_debug'] = (
            f"Searched {len(candidate_files)} candidate files. "
            f"sos_commands/ subdirs: {', '.join(sos_dirs[:30]) if sos_dirs else 'NONE (dir missing)'}. "
            f"{'; '.join(_debug_tried[:5])}"
        )
    
    return result


def detect_crash_dumps(sosreport_path: str, archive_format: str = 'sosreport') -> dict:
    """Discover crash dump directories and extract vmcore-dmesg content.
    
    Goes deeper than detect_kdump_status() — actually reads vmcore-dmesg.txt
    and kexec-dmesg.log to show what caused each crash.
    
    Returns dict with 'dumps' list (each with directory, files, dmesg content).
    """
    crash_info = {
        'dumps': [],
        'total_count': 0,
    }
    
    # Search locations for crash dumps
    crash_dirs = [
        os.path.join(sosreport_path, 'var', 'crash'),
        os.path.join(sosreport_path, 'var', 'spool', 'abrt'),
    ]
    
    interesting_files = [
        'vmcore-dmesg.txt', 'vmcore-dmesg', 'kexec-dmesg.log',
        'vmcore', 'backtrace', 'last_occurrence', 'reason',
        'crash_function', 'type', 'exception_type',
    ]
    
    for crash_base in crash_dirs:
        if not os.path.isdir(crash_base):
            continue
        
        try:
            for item in sorted(os.listdir(crash_base)):
                item_path = os.path.join(crash_base, item)
                if not os.path.isdir(item_path):
                    continue
                
                dump = {
                    'directory': item,
                    'full_path': item_path,
                    'files': [],
                    'vmcore_dmesg': None,
                    'kexec_dmesg': None,
                    'has_vmcore': False,
                    'crash_reason': None,
                }
                
                for fname in os.listdir(item_path):
                    fpath = os.path.join(item_path, fname)
                    if os.path.isfile(fpath):
                        dump['files'].append(fname)
                        
                        if fname == 'vmcore':
                            dump['has_vmcore'] = True
                        
                        # Read vmcore-dmesg.txt (the kernel log at crash time)
                        if fname in ('vmcore-dmesg.txt', 'vmcore-dmesg'):
                            try:
                                with open(fpath, 'r', errors='ignore') as f:
                                    content = f.read()
                                    # Keep last 200 lines (the crash part)
                                    lines = content.strip().split('\n')
                                    dump['vmcore_dmesg'] = '\n'.join(lines[-200:])
                            except:
                                pass
                        
                        # Read kexec-dmesg.log
                        if fname == 'kexec-dmesg.log':
                            try:
                                with open(fpath, 'r', errors='ignore') as f:
                                    content = f.read()
                                    lines = content.strip().split('\n')
                                    dump['kexec_dmesg'] = '\n'.join(lines[-100:])
                            except:
                                pass
                        
                        # ABRT crash reason
                        if fname in ('reason', 'crash_function', 'backtrace'):
                            try:
                                with open(fpath, 'r', errors='ignore') as f:
                                    content = f.read().strip()[:500]
                                    if fname == 'reason':
                                        dump['crash_reason'] = content
                                    elif fname == 'crash_function':
                                        dump['crash_reason'] = (dump.get('crash_reason') or '') + f" [{content}]"
                            except:
                                pass
                
                if dump['files']:
                    crash_info['dumps'].append(dump)
        except:
            pass
    
    crash_info['total_count'] = len(crash_info['dumps'])
    return crash_info


def detect_network_config(sosreport_path: str, archive_format: str = 'sosreport') -> dict:
    """Collect detailed network configuration from sosreport.
    
    Covers: interfaces (ip addr), routing, DNS (resolv.conf), firewall,
    NetworkManager connections, bonding, and ethtool info.
    """
    net_info = {
        'interfaces': None,
        'ip_link': None,
        'routing': None,
        'dns': {},
        'firewall': {},
        'networkmanager': {},
        'bonding': {},
        'ethtool': {},
    }
    
    net_dir = os.path.join(sosreport_path, 'sos_commands', 'networking')
    
    def safe_read(path, max_lines=None):
        if not os.path.isfile(path):
            return None
        try:
            with open(path, 'r', errors='ignore') as f:
                if max_lines:
                    return ''.join(f.readlines()[:max_lines])
                return f.read()
        except:
            return None
    
    # --- Interfaces ---
    for fname in ['ip_-d_address', 'ip_address_show', 'ip_addr']:
        content = safe_read(os.path.join(net_dir, fname))
        if content:
            net_info['interfaces'] = content
            break
    
    # IP link stats
    net_info['ip_link'] = safe_read(os.path.join(net_dir, 'ip_-s_-d_link'))
    
    # --- Routing ---
    for fname in ['ip_route_show_table_all', 'ip_route', 'route_-n']:
        content = safe_read(os.path.join(net_dir, fname))
        if content:
            net_info['routing'] = content
            break
    
    # --- DNS ---
    net_info['dns']['resolv_conf'] = safe_read(os.path.join(sosreport_path, 'etc', 'resolv.conf'))
    net_info['dns']['nsswitch'] = safe_read(os.path.join(sosreport_path, 'etc', 'nsswitch.conf'))
    net_info['dns']['hosts'] = safe_read(os.path.join(sosreport_path, 'etc', 'hosts'))
    
    # --- Firewall ---
    firewalld_dir = os.path.join(sosreport_path, 'sos_commands', 'firewalld')
    if os.path.isdir(firewalld_dir):
        for fname in os.listdir(firewalld_dir):
            if 'list-all' in fname or 'state' in fname:
                content = safe_read(os.path.join(firewalld_dir, fname))
                if content:
                    net_info['firewall'][fname] = content
    
    iptables = safe_read(os.path.join(net_dir, 'iptables_-t_filter_-nvL'))
    if iptables:
        net_info['firewall']['iptables'] = iptables
    
    # --- NetworkManager ---
    nm_dir = os.path.join(sosreport_path, 'sos_commands', 'networkmanager')
    if os.path.isdir(nm_dir):
        nm_files = {
            'nmcli_general_status': ['nmcli_general_status', 'nmcli_gen'],
            'nmcli_connection_show': ['nmcli_connection_show', 'nmcli_con_show'],
            'nmcli_device_show': ['nmcli_device_show', 'nmcli_dev_show'],
            'nmcli_device_status': ['nmcli_device_status', 'nmcli_dev_status'],
        }
        for key, fnames in nm_files.items():
            for fname in fnames:
                content = safe_read(os.path.join(nm_dir, fname))
                if content:
                    net_info['networkmanager'][key] = content
                    break
    
    # NetworkManager conf
    nm_conf = safe_read(os.path.join(sosreport_path, 'etc', 'NetworkManager', 'NetworkManager.conf'))
    if nm_conf:
        net_info['networkmanager']['config'] = nm_conf
    
    # --- Bonding ---
    bond_dir = os.path.join(sosreport_path, 'proc', 'net', 'bonding')
    if os.path.isdir(bond_dir):
        for fname in os.listdir(bond_dir):
            content = safe_read(os.path.join(bond_dir, fname))
            if content:
                net_info['bonding'][fname] = content
    
    # --- Ethtool (top interface info) ---
    if os.path.isdir(net_dir):
        for fname in sorted(os.listdir(net_dir)):
            if fname.startswith('ethtool_') and not fname.startswith('ethtool_-'):
                # Basic ethtool (speed/duplex/link)
                content = safe_read(os.path.join(net_dir, fname), max_lines=30)
                if content:
                    iface = fname.replace('ethtool_', '')
                    net_info['ethtool'][iface] = content
            if len(net_info['ethtool']) >= 10:  # Limit to 10 interfaces
                break
    
    return net_info


def detect_cve_advisories(sosreport_path: str, archive_format: str = 'sosreport') -> dict:
    """Extract CVE information from DNF/YUM security advisories.
    
    Parses sos_commands/dnf/dnf_updateinfo* and sos_commands/yum/yum_updateinfo*
    to extract pending CVEs, severity, and advisory counts.
    
    Returns dict with 'cves', 'advisories', 'update_summary'.
    """
    cve_info = {
        'package_manager': None,
        'cves': [],
        'cve_count': 0,
        'advisories': [],
        'update_summary': {
            'total': 0,
            'security': 0,
            'bugfix': 0,
            'enhancement': 0,
            'important': 0,
            'moderate': 0,
            'low': 0,
            'critical': 0,
        },
        'repolist': None,
        'history_tail': None,
    }
    
    # --- DNF (RHEL 8+) ---
    dnf_dir = os.path.join(sosreport_path, 'sos_commands', 'dnf')
    yum_dir = os.path.join(sosreport_path, 'sos_commands', 'yum')
    
    def safe_read(path):
        if not os.path.isfile(path):
            return None
        try:
            with open(path, 'r', errors='ignore') as f:
                return f.read()
        except:
            return None
    
    def find_file(directory, pattern):
        """Find file matching pattern (exact or glob)"""
        if not os.path.isdir(directory):
            return None
        exact = os.path.join(directory, pattern)
        if os.path.isfile(exact):
            return exact
        import glob
        matches = glob.glob(os.path.join(directory, f'{pattern}*'))
        return matches[0] if matches else None
    
    # Try DNF first, then YUM
    pkg_dir = None
    if os.path.isdir(dnf_dir):
        pkg_dir = dnf_dir
        cve_info['package_manager'] = 'dnf'
    elif os.path.isdir(yum_dir):
        pkg_dir = yum_dir
        cve_info['package_manager'] = 'yum'
    
    if not pkg_dir:
        # ── Ubuntu/Debian: check APT for security updates ──
        apt_dir = os.path.join(sosreport_path, 'sos_commands', 'apt')
        if os.path.isdir(apt_dir):
            cve_info['package_manager'] = 'apt'
            # Look for apt list --upgradable output
            for fname in os.listdir(apt_dir):
                fpath = os.path.join(apt_dir, fname)
                if 'upgradable' in fname.lower() or 'list' in fname.lower():
                    content = safe_read(fpath)
                    if content:
                        for line in content.split('\n'):
                            line = line.strip()
                            if not line or line.startswith('Listing'):
                                continue
                            cve_info['update_summary']['total'] += 1
                            if 'security' in line.lower():
                                cve_info['update_summary']['security'] += 1
            
            # Check for update-notifier info
            update_avail = os.path.join(sosreport_path, 'var', 'lib', 'update-notifier', 'updates-available')
            if os.path.isfile(update_avail):
                content = safe_read(update_avail)
                if content:
                    # Format: "X updates can be applied immediately." / "Y of these are security updates."
                    total_match = re.search(r'(\d+)\s+updates?\s+can\s+be', content)
                    sec_match = re.search(r'(\d+)\s+of\s+these\s+.*security', content, re.IGNORECASE)
                    if total_match:
                        cve_info['update_summary']['total'] = max(
                            cve_info['update_summary']['total'], int(total_match.group(1)))
                    if sec_match:
                        cve_info['update_summary']['security'] = max(
                            cve_info['update_summary']['security'], int(sec_match.group(1)))
            
            # Extract CVE IDs from apt changelogs or security notices
            apt_history = os.path.join(sosreport_path, 'var', 'log', 'apt', 'history.log')
            if os.path.isfile(apt_history):
                content = safe_read(apt_history)
                if content:
                    cves = set()
                    cve_matches = re.findall(r'CVE-\d{4}-\d{4,}', content)
                    cves.update(cve_matches)
                    cve_info['cves'] = sorted(list(cves))
                    cve_info['cve_count'] = len(cves)
            
            return cve_info
        
        # ── SUSE: check zypper for patches ──
        zypper_dir = os.path.join(sosreport_path, 'sos_commands', 'zypper')
        if os.path.isdir(zypper_dir):
            cve_info['package_manager'] = 'zypper'
            for fname in os.listdir(zypper_dir):
                fpath = os.path.join(zypper_dir, fname)
                if 'patches' in fname.lower() or 'list-patches' in fname.lower():
                    content = safe_read(fpath)
                    if content:
                        for line in content.split('\n'):
                            line = line.strip()
                            if not line or '|' not in line:
                                continue
                            parts = [p.strip() for p in line.split('|')]
                            if len(parts) >= 3:
                                cve_info['update_summary']['total'] += 1
                                cat = parts[1].lower() if len(parts) > 1 else ''
                                sev = parts[2].lower() if len(parts) > 2 else ''
                                if 'security' in cat:
                                    cve_info['update_summary']['security'] += 1
                                if 'critical' in sev:
                                    cve_info['update_summary']['critical'] += 1
                                elif 'important' in sev:
                                    cve_info['update_summary']['important'] += 1
                                elif 'moderate' in sev:
                                    cve_info['update_summary']['moderate'] += 1
                        # Extract CVEs
                        cves = set(re.findall(r'CVE-\d{4}-\d{4,}', content))
                        cve_info['cves'] = sorted(list(cves))
                        cve_info['cve_count'] = len(cves)
                        break
            return cve_info
        
        return cve_info
    
    # --- Parse available updates list ---
    prefix = cve_info['package_manager']
    updateinfo_list = find_file(pkg_dir, f'{prefix}_updateinfo_list_--available')
    if not updateinfo_list:
        updateinfo_list = find_file(pkg_dir, f'{prefix}_updateinfo_list')
    if not updateinfo_list:
        updateinfo_list = find_file(pkg_dir, f'{prefix}_updateinfo')
    
    if updateinfo_list:
        content = safe_read(updateinfo_list)
        if content:
            seen_packages = set()
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('Last metadata'):
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    advisory = parts[0]
                    severity_type = parts[1].lower()
                    package = parts[2]
                    
                    if package not in seen_packages:
                        seen_packages.add(package)
                        cve_info['update_summary']['total'] += 1
                        
                        if 'sec' in severity_type:
                            cve_info['update_summary']['security'] += 1
                        elif 'bugfix' in severity_type:
                            cve_info['update_summary']['bugfix'] += 1
                        elif 'enhancement' in severity_type:
                            cve_info['update_summary']['enhancement'] += 1
                        
                        if 'critical' in severity_type:
                            cve_info['update_summary']['critical'] += 1
                        elif 'important' in severity_type:
                            cve_info['update_summary']['important'] += 1
                        elif 'moderate' in severity_type:
                            cve_info['update_summary']['moderate'] += 1
                        elif 'low' in severity_type:
                            cve_info['update_summary']['low'] += 1
    
    # --- Parse security advisories for CVEs ---
    security_info = find_file(pkg_dir, f'{prefix}_updateinfo_info_security')
    if not security_info:
        security_info = find_file(pkg_dir, f'{prefix}_updateinfo_info')
    
    if security_info:
        content = safe_read(security_info)
        if content:
            cves = set()
            current_advisory = None
            
            for line in content.split('\n'):
                line = line.strip()
                
                if line.startswith('Update ID:') or line.startswith('Update ID :'):
                    if current_advisory:
                        cve_info['advisories'].append(current_advisory)
                    current_advisory = {
                        'id': line.split(':', 1)[1].strip(),
                        'type': '',
                        'severity': '',
                        'cves': [],
                        'description': '',
                    }
                elif current_advisory:
                    if line.startswith('Type:') or line.startswith('Type :'):
                        current_advisory['type'] = line.split(':', 1)[1].strip()
                    elif line.startswith('Severity:') or line.startswith('Severity :'):
                        current_advisory['severity'] = line.split(':', 1)[1].strip()
                    elif line.startswith('Description:') or line.startswith('Description :'):
                        current_advisory['description'] = line.split(':', 1)[1].strip()[:200]
                    
                    # Extract CVE IDs from anywhere in the line
                    cve_matches = re.findall(r'CVE-\d{4}-\d{4,}', line)
                    for cve_id in cve_matches:
                        if cve_id not in cves:
                            cves.add(cve_id)
                            if current_advisory:
                                current_advisory['cves'].append(cve_id)
            
            if current_advisory:
                cve_info['advisories'].append(current_advisory)
            
            cve_info['cves'] = sorted(list(cves))
            cve_info['cve_count'] = len(cves)
    
    # --- Repo list ---
    repolist = find_file(pkg_dir, f'{prefix}_-C_repolist')
    if not repolist:
        repolist = find_file(pkg_dir, f'{prefix}_repolist')
    if repolist:
        cve_info['repolist'] = safe_read(repolist)
    
    # --- History (last 30 lines) ---
    history = find_file(pkg_dir, f'{prefix}_history')
    if history:
        content = safe_read(history)
        if content:
            lines = content.strip().split('\n')
            cve_info['history_tail'] = '\n'.join(lines[:30])
    
    return cve_info


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
    # ── Identify OS flavor once; every section below can branch on it ──
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
    
    # ── SUSE subscription check (SUSEConnect / RMT) ──
    if os_flavor == 'suse' and compliance['subscription_status'] == 'Unknown':
        suse_sub_files = [
            os.path.join(sosreport_path, "sos_commands", "registration", "SUSEConnect_--status"),
            os.path.join(sosreport_path, "sos_commands", "registration", "SUSEConnect_-s"),
        ]
        for sf in suse_sub_files:
            if os.path.isfile(sf):
                try:
                    with open(sf, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if '"status":"Registered"' in content or '"Registered"' in content:
                            compliance['subscription_status'] = 'Registered (SUSEConnect)'
                        elif '"status":"Not Registered"' in content:
                            compliance['subscription_status'] = 'Not Registered'
                            compliance['findings'].append('SUSE system is not registered')
                        elif content.strip():
                            compliance['subscription_status'] = 'SUSEConnect configured'
                except:
                    pass
                break
        # Check zypper repos as fallback
        if compliance['subscription_status'] == 'Unknown':
            zypper_repo_files = [
                os.path.join(sosreport_path, "sos_commands", "zypper", "zypper_repos"),
                os.path.join(sosreport_path, "sos_commands", "dnf", "zypper_patches"),
            ]
            for zf in zypper_repo_files:
                if os.path.isfile(zf):
                    try:
                        with open(zf, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            repo_count = sum(1 for line in content.split('\n') if line.strip() and '|' in line)
                            if repo_count > 0:
                                compliance['subscription_status'] = 'Repos configured'
                                compliance['subscription_details'].append(f"{repo_count} zypper repos found")
                    except:
                        pass
                    break
    
    # ── Ubuntu/Debian subscription check (Ubuntu Pro / apt repos) ──
    if os_flavor in ('ubuntu', 'debian') and compliance['subscription_status'] == 'Unknown':
        # Check for Ubuntu Pro (ubuntu-advantage-tools)
        ua_status = os.path.join(sosreport_path, "sos_commands", "ubuntu", "pro_status")
        if not os.path.isfile(ua_status):
            ua_status = os.path.join(sosreport_path, "sos_commands", "ubuntu", "ua_status")
        if os.path.isfile(ua_status):
            try:
                with open(ua_status, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if 'attached' in content.lower():
                        compliance['subscription_status'] = 'Ubuntu Pro (attached)'
                    elif 'not attached' in content.lower() or 'disabled' in content.lower():
                        compliance['subscription_status'] = 'Ubuntu Pro (not attached)'
            except:
                pass
        
        # Check apt sources as fallback
        if compliance['subscription_status'] == 'Unknown':
            apt_sources = os.path.join(sosreport_path, "etc", "apt", "sources.list")
            if os.path.isfile(apt_sources):
                try:
                    with open(apt_sources, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        repo_count = sum(1 for line in content.split('\n') 
                                        if line.strip() and not line.strip().startswith('#') and 'deb' in line)
                        if repo_count > 0:
                            compliance['subscription_status'] = 'APT repos configured'
                            compliance['subscription_details'].append(f"{repo_count} apt source(s) enabled")
                except:
                    pass
    
    # 2. Check kernel age and reboot status  (OS-flavor-aware)
    kernel_packages = packages_info.get('kernel', [])
    compliance['installed_kernels'] = kernel_packages[:10]
    
    if kernel_version and kernel_version != 'N/A' and kernel_packages:
        # ── Step A: isolate BASE kernel packages for the SAME kernel track ──
        # Use flavor config prefixes to find the right prefix for the running kernel type.
        # E.g. Oracle Linux UEK → prefix "kernel-uek-", RHEL standard → "kernel-"
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
        
        # ── Step B: check if running kernel is installed ──
        running_kernel_found = any(kernel_version in kpkg for kpkg in base_kernel_pkgs)
        if not running_kernel_found:
            # Fallback: check ALL kernel packages (sub-packages might still reference it)
            running_kernel_found = any(kernel_version in kpkg for kpkg in kernel_packages)
        
        # ── Step C: compare against latest installed base kernel ──
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
    
    # ── Step D: kernel staleness heuristic (flavor-aware thresholds) ──
    if kernel_version and kernel_version != 'N/A':
        # RHEL/OL/CentOS/SUSE: 5.14.0-427.13.1 → major_update = 427
        kernel_match = re.search(r'(\d+\.\d+\.\d+)-(\d+)\.(\d+)\.(\d+)', kernel_version)
        if not kernel_match:
            # Ubuntu/Debian: 5.15.0-91-generic or 6.5.0-14-generic → major_update = 91 or 14
            kernel_match = re.search(r'(\d+\.\d+\.\d+)-(\d+)', kernel_version)
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
    
    # ── 3b. APT history for Ubuntu/Debian ──
    if os_flavor in ('ubuntu', 'debian') and compliance['last_update_info'] == 'N/A':
        apt_history_files = [
            os.path.join(sosreport_path, "var", "log", "apt", "history.log"),
        ]
        # Also check rotated apt history
        apt_log_dir = os.path.join(sosreport_path, "var", "log", "apt")
        if os.path.isdir(apt_log_dir):
            import glob as _apt_glob
            apt_history_files.extend(sorted(
                _apt_glob.glob(os.path.join(apt_log_dir, "history.log.*")),
                reverse=True
            ))
        
        for ahf in apt_history_files:
            if not os.path.isfile(ahf):
                continue
            try:
                # Handle .gz compressed rotated logs
                if ahf.endswith('.gz'):
                    with gzip.open(ahf, 'rt', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                else:
                    with open(ahf, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                
                # APT history format:
                #   Start-Date: 2026-01-15  10:30:45
                #   Commandline: apt-get upgrade -y
                #   Install: linux-image-5.15.0-91-generic:amd64 (...)
                #   End-Date: 2026-01-15  10:35:12
                apt_dates = re.findall(r'Start-Date:\s*(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})', content)
                if apt_dates:
                    # Most recent is last entry in the file
                    last_date_str = apt_dates[-1][0]
                    compliance['last_update_info'] = f"{last_date_str} (apt)"
                    
                    try:
                        last_update = datetime.strptime(last_date_str, '%Y-%m-%d')
                        report_date = None
                        if report_date_str and report_date_str != 'N/A':
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
                        if not report_date:
                            report_date = datetime.now()
                        days_since = (report_date - last_update).days
                        if days_since < 0:
                            days_since = 0
                        compliance['kernel_age_days'] = days_since
                        if days_since > 180:
                            compliance['findings'].append(f'Last apt update was {days_since} days before sosreport collection')
                        elif days_since > 90:
                            compliance['findings'].append(f'Last apt update was {days_since} days before sosreport - consider more frequent patching')
                    except:
                        pass
                    break  # Found history, stop looking
            except:
                continue
    
    # ── 3c. Zypper history for SUSE ──
    if os_flavor == 'suse' and compliance['last_update_info'] == 'N/A':
        zypper_history_files = [
            os.path.join(sosreport_path, "var", "log", "zypp", "history"),
            os.path.join(sosreport_path, "var", "log", "zypper.log"),
        ]
        for zhf in zypper_history_files:
            if not os.path.isfile(zhf):
                continue
            try:
                with open(zhf, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                # Zypper history format: "2026-01-15 10:30|install|..."
                zypper_dates = []
                for line in lines:
                    dm = re.match(r'^(\d{4}-\d{2}-\d{2})', line)
                    if dm:
                        zypper_dates.append(dm.group(1))
                if zypper_dates:
                    last_date_str = zypper_dates[-1]
                    compliance['last_update_info'] = f"{last_date_str} (zypper)"
                    try:
                        last_update = datetime.strptime(last_date_str, '%Y-%m-%d')
                        report_date = None
                        if report_date_str and report_date_str != 'N/A':
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
                        if not report_date:
                            report_date = datetime.now()
                        days_since = (report_date - last_update).days
                        if days_since < 0:
                            days_since = 0
                        compliance['kernel_age_days'] = days_since
                        if days_since > 180:
                            compliance['findings'].append(f'Last zypper update was {days_since} days before sosreport collection')
                        elif days_since > 90:
                            compliance['findings'].append(f'Last zypper update was {days_since} days before sosreport - consider more frequent patching')
                    except:
                        pass
                    break
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


# ═══════════════════════════════════════════════════════════════════════
#  SYSTEM HEALTH CHECKS — Categorized findings (V7.1)
#  Modeled after colleague's tool: Azure Extensions, Serial Console,
#  Filesystem, General Errors, Network, Pacemaker, Performance,
#  Repository Errors, SLES, System Config, Results
# ═══════════════════════════════════════════════════════════════════════

def run_system_health_checks(sosreport_path: str, system_info: dict,
                             critical_events: list = None,
                             patch_compliance: dict = None) -> dict:
    """Run comprehensive system health checks and return categorized findings.
    
    Returns dict of:
      { category_name: [ {name, severity, details}, ... ] }
    Severities: 'critical', 'warning', 'info'
    """
    findings = {}

    def add(category: str, name: str, severity: str, details: str = ""):
        findings.setdefault(category, []).append({
            'name': name, 'severity': severity, 'details': details,
        })

    cloud = system_info.get('cloud', {})
    cloud_details = cloud.get('details', {})
    is_azure = cloud.get('provider') == 'azure'

    # Helper: safe file reader
    def _read(path, tail=0):
        try:
            if os.path.isfile(path):
                with open(path, 'r', errors='ignore') as f:
                    if tail:
                        lines = f.readlines()
                        return ''.join(lines[-tail:])
                    return f.read()
        except Exception:
            pass
        return ""

    # ── Azure Extensions ──────────────────────────────────────────────
    if is_azure:
        waagent_log = _read(os.path.join(sosreport_path, 'var', 'log', 'waagent.log'))
        waagent_log_tail = cloud_details.get('waagent_log_tail', '') or waagent_log[-80_000:] if waagent_log else ''

        # 1. Automatic Guest patching errors
        patch_err_pats = [
            re.compile(r'(auto.?update|patch).*(fail|error|exception)', re.I),
            re.compile(r'PatchInstall.*(fail|error)', re.I),
        ]
        patch_errs = [l for l in waagent_log_tail.splitlines() if any(p.search(l) for p in patch_err_pats)]
        if patch_errs:
            add("Azure Extensions", "Automatic Guest patching errors", "warning",
                f"{len(patch_errs)} patching error(s) in waagent.log")
        else:
            add("Azure Extensions", "Automatic Guest patching errors", "info", "No patching errors found")

        # 2. VM Extension Failure
        ext_fail_re = re.compile(r'extension.*(fail|error|not\s+ready)', re.I)
        ext_fails = [l for l in waagent_log_tail.splitlines() if ext_fail_re.search(l)]
        if ext_fails:
            add("Azure Extensions", "VM Extension Failure", "critical" if len(ext_fails) > 5 else "info",
                f"{len(ext_fails)} extension error(s) detected")
        else:
            add("Azure Extensions", "VM Extension Failure", "info", "No extension failures")

        # 3. Azure Extension Timeout Errors
        timeout_re = re.compile(r'(extension|handler).*(timeout|timed?\s*out)', re.I)
        timeouts = [l for l in waagent_log_tail.splitlines() if timeout_re.search(l)]
        if timeouts:
            add("Azure Extensions", "Azure Extension Timeout Errors", "critical",
                f"{len(timeouts)} timeout(s) detected")
        else:
            add("Azure Extensions", "Azure Extension Timeout Errors", "info", "No timeout errors")

        # 4. OVF Environment Missing (Specialized Disk)
        ovf_env = cloud_details.get('ovf_env', '')
        ovf_path = os.path.join(sosreport_path, 'var', 'lib', 'waagent', 'ovf-env.xml')
        if not ovf_env and not os.path.isfile(ovf_path):
            add("Azure Extensions", "OVF Environment Missing (Specialized Disk)", "critical",
                "ovf-env.xml not found — VM may be from a specialized disk")
        else:
            add("Azure Extensions", "OVF Environment Missing (Specialized Disk)", "info",
                "ovf-env.xml present")

        # 5. Agent Extension Handler Launch Failure
        handler_fail_re = re.compile(r'(handler|ExtHandler).*(launch|start).*(fail|error|exception)', re.I)
        handler_fails = [l for l in waagent_log_tail.splitlines() if handler_fail_re.search(l)]
        if handler_fails:
            add("Azure Extensions", "Agent Extension Handler Launch Failure", "critical",
                f"{len(handler_fails)} handler launch failure(s)")
        else:
            add("Azure Extensions", "Agent Extension Handler Launch Failure", "info",
                "No handler launch failures")

        # 6. WALinuxAgent Python Missing Module
        py_missing_re = re.compile(r'(ImportError|ModuleNotFoundError|No module named)', re.I)
        py_errs = [l for l in waagent_log_tail.splitlines() if py_missing_re.search(l)]
        if py_errs:
            add("Azure Extensions", "WALinuxAgent Python Missing Module", "info",
                f"{len(py_errs)} Python import error(s) in waagent.log")
        else:
            add("Azure Extensions", "WALinuxAgent Python Missing Module", "info",
                "No Python module errors")

        # 7. Wireserver Connectivity
        wire_re = re.compile(r'(wire\s*server|168\.63\.129\.16).*(fail|error|timeout|unreachable|refused)', re.I)
        wire_errs = [l for l in waagent_log_tail.splitlines() if wire_re.search(l)]
        if wire_errs:
            add("Azure Extensions", "Wireserver Connectivity", "critical",
                f"{len(wire_errs)} wireserver connectivity issue(s)")
        else:
            add("Azure Extensions", "Wireserver Connectivity", "info", "No wireserver issues")

    # ── Serial Console / Boot ─────────────────────────────────────────
    # Check dmesg, journal, boot.log, messages for boot problems
    boot_sources = []
    for src in ['var/log/boot.log', 'var/log/messages']:
        content = _read(os.path.join(sosreport_path, src))
        if content:
            boot_sources.append(content)
    # dmesg
    for dpath in ['sos_commands/kernel/dmesg', 'var/log/dmesg']:
        content = _read(os.path.join(sosreport_path, dpath))
        if content:
            boot_sources.append(content)
            break
    # journal
    jdir = os.path.join(sosreport_path, 'sos_commands', 'logs')
    if os.path.isdir(jdir):
        for fn in os.listdir(jdir):
            if 'journalctl' in fn and not fn.endswith('.gz'):
                content = _read(os.path.join(jdir, fn))
                if content:
                    boot_sources.append(content[:500_000])
                    break
    all_boot = '\n'.join(boot_sources)

    # 1. Dracut Initqueue Timeout
    dracut_timeout_re = re.compile(r'dracut.*(initqueue|timeout).*?(could\s*not\s*boot|timeout|Warning)', re.I)
    if dracut_timeout_re.search(all_boot):
        add("Serial Console", "Dracut Initqueue Timeout - Could Not Boot", "critical",
            "dracut initqueue timeout detected — system may have failed to boot")
    
    # 2. Dracut Warning Would Not Boot
    dracut_warn_re = re.compile(r'dracut.*Warning.*(?:not boot|unable|fail)', re.I)
    if dracut_warn_re.search(all_boot):
        add("Serial Console", "Dracut Warning Would Not Boot", "critical",
            "dracut warning: system may not have booted correctly")

    # 3. Emergency Mode
    emergency_re = re.compile(r'(Entering emergency mode|emergency\.target|emergency\.service.*start)', re.I)
    if emergency_re.search(all_boot):
        add("Serial Console", "Emergency Mode", "critical",
            "System entered emergency mode")

    # 4. Unable To Boot Grub Rescue Error
    grub_re = re.compile(r'(grub\s*rescue|error:\s*no such (device|partition)|GRUB.*error)', re.I)
    if grub_re.search(all_boot):
        add("Serial Console", "Unable To Boot Grub Rescue Error", "critical",
            "GRUB rescue/boot error detected")

    # 5. Kernel NULL Pointer Dereference
    nullptr_re = re.compile(r'BUG:\s*kernel\s*NULL\s*pointer\s*dereference', re.I)
    if nullptr_re.search(all_boot):
        add("Serial Console", "Kernel NULL Pointer Dereference", "critical",
            "Kernel NULL pointer dereference detected")

    # 6. Kernel Panic
    kpanic_re = re.compile(r'Kernel\s*panic\s*-\s*not\s*syncing', re.I)
    if kpanic_re.search(all_boot):
        add("Serial Console", "Kernel Panic Detected", "critical",
            "Kernel panic detected in logs")

    # 7. Kernel Softlockup / Hung Tasks
    hung_re = re.compile(r'(soft\s*lockup|hung_task_timeout|task\s+\S+\s+blocked\s+for\s+more\s+than)', re.I)
    if hung_re.search(all_boot):
        add("Serial Console", "Kernel Softlockup - Hung Tasks", "critical",
            "Kernel soft lockup or hung task detected")

    # If nothing found, mark section clean
    if "Serial Console" not in findings:
        add("Serial Console", "No boot issues detected", "info", "All boot checks passed")

    # ── Filesystem ────────────────────────────────────────────────────
    # 1. Mount failures during boot
    mount_fail_re = re.compile(r'(mount|systemd).*(?:fail|error|unable).*mount', re.I)
    mount_fails = mount_fail_re.findall(all_boot)
    if mount_fails:
        add("Filesystem", "Mount failures detected during boot", "critical",
            f"{len(mount_fails)} mount failure(s) found in boot/system logs")

    # 2. NFSv3 fstab mounts conflict with cloud-init
    fstab_content = _read(os.path.join(sosreport_path, 'etc', 'fstab'))
    nfs_fstab = [l for l in fstab_content.splitlines()
                 if l.strip() and not l.strip().startswith('#') and 'nfs' in l.lower()]
    cloud_init_cfg = _read(os.path.join(sosreport_path, 'etc', 'cloud', 'cloud.cfg'))
    if nfs_fstab and ('mounts' in cloud_init_cfg or 'mount' in cloud_init_cfg.lower()):
        add("Filesystem", "NFSv3 fstab mounts conflict with cloud-init", "critical",
            f"{len(nfs_fstab)} NFS mount(s) in fstab; cloud-init also manages mounts")
    elif nfs_fstab:
        add("Filesystem", "NFSv3 fstab mounts conflict with cloud-init", "info",
            f"{len(nfs_fstab)} NFS mount(s) in fstab; no cloud-init conflict detected")

    # 3. XFS filesystem issues
    xfs_err_re = re.compile(r'(XFS.*error|xfs_force_shutdown|XFS.*corruption|xfs_log_force)', re.I)
    xfs_errs = xfs_err_re.findall(all_boot)
    if xfs_errs:
        add("Filesystem", "XFS filesystem issues detection", "critical",
            f"{len(xfs_errs)} XFS error(s) detected")

    # ── General Errors ────────────────────────────────────────────────
    # 1. Auto Power Off by Audit Daemon
    audit_poweroff_re = re.compile(r'(audit.*power.?off|auditd.*halt|audit.*action.*halt|disk_full_action\s*=\s*halt)', re.I)
    if audit_poweroff_re.search(all_boot):
        add("General Errors", "Auto Power Off by Audit Daemon", "critical",
            "System may have been powered off by audit daemon (disk full action = halt)")
    else:
        # Also check auditd.conf
        auditd_conf = _read(os.path.join(sosreport_path, 'etc', 'audit', 'auditd.conf'))
        if re.search(r'disk_full_action\s*=\s*(halt|HALT)', auditd_conf):
            add("General Errors", "Auto Power Off by Audit Daemon", "critical",
                "auditd.conf: disk_full_action = halt — auditd will shut down the system when disk is full")
        elif re.search(r'disk_full_action\s*=\s*(suspend|SUSPEND)', auditd_conf):
            add("General Errors", "Auto Power Off by Audit Daemon", "warning",
                "auditd.conf: disk_full_action = suspend")

    # 2. System Boot Analysis
    boot_fail_re = re.compile(r'(Failed to start|Dependency failed|Job .* failed)', re.I)
    boot_failures = boot_fail_re.findall(all_boot[:200_000])
    if boot_failures:
        add("General Errors", "System Boot Analysis", "critical",
            f"{len(boot_failures)} service startup failure(s) during boot")
    else:
        add("General Errors", "System Boot Analysis", "info", "No boot startup failures detected")

    # 3. Disk Space Exhaustion
    df_info = system_info.get('df_info', [])
    exhausted = [fs for fs in df_info if fs.get('use_percent', 0) >= 95]
    high = [fs for fs in df_info if 90 <= fs.get('use_percent', 0) < 95]
    if exhausted:
        mounts = ', '.join(fs.get('mountpoint', '?') for fs in exhausted)
        add("General Errors", "Disk Space Exhaustion", "critical",
            f"Disk ≥95% full: {mounts}")
    elif high:
        mounts = ', '.join(fs.get('mountpoint', '?') for fs in high)
        add("General Errors", "Disk Space Exhaustion", "warning",
            f"Disk ≥90% full: {mounts}")

    # 4. Filesystem Issues Analysis (from critical events)
    if critical_events:
        fs_events = [e for e in critical_events
                     if e.get('category') == 'File System & Disk' and e.get('severity') == 'critical']
        if fs_events:
            add("General Errors", "Filesystem Issues Analysis", "critical",
                f"{len(fs_events)} critical filesystem event(s) in logs")

        # 5. Kernel Issues Analysis
        kern_events = [e for e in critical_events
                       if e.get('category') == 'CPU & Kernel Panic' and e.get('severity') == 'critical']
        if kern_events:
            add("General Errors", "Kernel Issues Analysis", "critical",
                f"{len(kern_events)} critical kernel event(s)")

        # 6. Network Connectivity Analysis
        net_events = [e for e in critical_events if e.get('category') == 'Network Issues']
        if net_events:
            crit_net = [e for e in net_events if e.get('severity') == 'critical']
            add("General Errors", "Network Connectivity Analysis",
                "critical" if crit_net else "info",
                f"{len(net_events)} network event(s), {len(crit_net)} critical")
        else:
            add("General Errors", "Network Connectivity Analysis", "info", "No network issues in logs")

        # 7. Security Issues Analysis
        sec_events = [e for e in critical_events if e.get('category') == 'Security & Antivirus']
        if sec_events:
            crit_sec = [e for e in sec_events if e.get('severity') == 'critical']
            add("General Errors", "Security Issues Analysis",
                "critical" if crit_sec else "info",
                f"{len(sec_events)} security event(s), {len(crit_sec)} critical")
        else:
            add("General Errors", "Security Issues Analysis", "info", "No security issues in logs")

        # 8. Segmentation Faults Analysis
        segfault_re = re.compile(r'segfault|SIGSEGV|segmentation fault', re.I)
        segfaults = [e for e in critical_events if segfault_re.search(e.get('message', ''))]
        if segfaults:
            add("General Errors", "Segmentation Faults Analysis", "info",
                f"{len(segfaults)} segfault(s) detected")

        # 9. System Service Analysis
        svc_events = [e for e in critical_events if e.get('category') == 'Service & Systemd']
        if svc_events:
            crit_svc = [e for e in svc_events if e.get('severity') == 'critical']
            add("General Errors", "System Service Analysis",
                "critical" if crit_svc else "info",
                f"{len(svc_events)} service event(s), {len(crit_svc)} critical")
        else:
            add("General Errors", "System Service Analysis", "info", "No service failures in logs")

    # ── Network ───────────────────────────────────────────────────────

    # 1. DHCP request/lease failures (Linux.network.dhcp_failures)
    #    Inspects: var/log/syslog, var/log/messages
    _dhcp_failure_patterns = [
        re.compile(r'No DHCPOFFERS received', re.I),
        re.compile(r'No working leases in persistent database\s*-\s*sleeping', re.I),
        re.compile(r'DHCPREQUEST[^"\n]*no answer', re.I),
        re.compile(r'DHCPDISCOVER[^"\n]*no answer', re.I),
        re.compile(r'Failed to (?:acquire|obtain) DHCP (?:lease|address)', re.I),
        re.compile(r'DHCPv4.*timed out', re.I),
        re.compile(r'dhclient:.*timed out waiting for a valid offer', re.I),
    ]
    # Read the exact files specified in the signature
    _dhcp_log_content = ""
    for _dhcp_log in ['var/log/syslog', 'var/log/messages']:
        _dhcp_log_content += _read(os.path.join(sosreport_path, _dhcp_log))
    _dhcp_hits = []
    for _pat in _dhcp_failure_patterns:
        _dhcp_hits.extend(_pat.findall(_dhcp_log_content))
    if _dhcp_hits:
        _recommendations = (
            "Verify NIC/subnet allows DHCP and no NSG/firewall blocks UDP 67/68; "
            "Check DHCP server/relay availability; renew with 'dhclient -v'; "
            "Ensure predictable interface naming and correct MAC/NIC mapping; "
            "Review systemd-networkd/NetworkManager status and journal logs; "
            "As workaround, assign a temporary static IP for troubleshooting"
        )
        add("Network", "DHCP request/lease failures detected", "critical",
            f"{len(_dhcp_hits)} DHCP negotiation failure(s) — VM may not receive IP. {_recommendations}")
    else:
        add("Network", "DHCP request/lease failures detected", "info",
            "No DHCP negotiation failures found in syslog/messages")

    # 2. Network DHCP Configuration Check (Linux.network.dhcp)
    #    Inspects: netplan, ifcfg-*, /etc/network/interfaces
    _dhcp_config_issues = []

    # Check netplan (Ubuntu/cloud-init)
    _netplan_dir = os.path.join(sosreport_path, 'etc', 'netplan')
    if os.path.isdir(_netplan_dir):
        for _np_fn in os.listdir(_netplan_dir):
            _np_content = _read(os.path.join(_netplan_dir, _np_fn))
            if re.search(r'dhcp4:\s*false', _np_content, re.I):
                _dhcp_config_issues.append(f"Netplan {_np_fn}: dhcp4 is disabled (static IP)")

    # Check ifcfg (RHEL/CentOS/Oracle Linux)
    _ifcfg_dir = os.path.join(sosreport_path, 'etc', 'sysconfig', 'network-scripts')
    if os.path.isdir(_ifcfg_dir):
        for _ifcfg_fn in os.listdir(_ifcfg_dir):
            if _ifcfg_fn.startswith('ifcfg-') and _ifcfg_fn != 'ifcfg-lo':
                _ifcfg_content = _read(os.path.join(_ifcfg_dir, _ifcfg_fn))
                if re.search(r'BOOTPROTO\s*=\s*["\']?static', _ifcfg_content, re.I):
                    _dhcp_config_issues.append(f"{_ifcfg_fn}: BOOTPROTO=static (not DHCP)")

    # Check /etc/network/interfaces (Debian/Ubuntu classic)
    _eni_content = _read(os.path.join(sosreport_path, 'etc', 'network', 'interfaces'))
    if re.search(r'iface\s+\S+\s+inet\s+static', _eni_content, re.I):
        _static_ifaces = re.findall(r'iface\s+(\S+)\s+inet\s+static', _eni_content, re.I)
        for _si in _static_ifaces:
            _dhcp_config_issues.append(f"/etc/network/interfaces: {_si} configured as static")

    if _dhcp_config_issues:
        _dhcp_reco = (
            "For Azure VMs, DHCP is recommended for network interfaces; "
            "If using static IP, ensure it matches Azure portal config; "
            "Check cloud-init network configuration is enabled; "
            "Verify network interface is detected and network service is running"
        )
        add("Network", "Network DHCP Configuration Check", "warning",
            f"{len(_dhcp_config_issues)} interface(s) not using DHCP: "
            + '; '.join(_dhcp_config_issues) + f". {_dhcp_reco}")
    else:
        add("Network", "Network DHCP Configuration Check", "info",
            "All detected interfaces are using DHCP (recommended for Azure VMs)")

    # ── Pacemaker ──────────────────────────────────────────────────────
    pcs_dir = os.path.join(sosreport_path, 'sos_commands', 'pacemaker')
    crm_dir = os.path.join(sosreport_path, 'sos_commands', 'cluster')
    pcs_content = ""
    for d in [pcs_dir, crm_dir]:
        if os.path.isdir(d):
            for fn in os.listdir(d):
                pcs_content += _read(os.path.join(d, fn), tail=500)
    corosync_log = _read(os.path.join(sosreport_path, 'var', 'log', 'cluster', 'corosync.log'), tail=500)
    pacemaker_log = _read(os.path.join(sosreport_path, 'var', 'log', 'pacemaker', 'pacemaker.log'), tail=500)
    # Also check messages for pacemaker/corosync
    pcs_all = pcs_content + corosync_log + pacemaker_log
    if pcs_all:
        pcs_recovery_re = re.compile(r'(fenc|stonith|recover|fail.?over|reboot.*node|resource.*(fail|stop|restart|migrate))', re.I)
        pcs_issues = pcs_recovery_re.findall(pcs_all)
        if pcs_issues:
            add("Pacemaker", "Pacemaker cluster recovery issues", "info",
                f"{len(pcs_issues)} cluster event(s) (failover/fencing/recovery)")
        else:
            add("Pacemaker", "Pacemaker cluster recovery issues", "info",
                "Pacemaker present, no recovery events detected")

    # ── Performance ───────────────────────────────────────────────────
    # 1. OOM Kill Analysis
    if critical_events:
        oom_events = [e for e in critical_events
                      if e.get('category') == 'Memory/OOM' and e.get('severity') == 'critical']
        if oom_events:
            add("Performance", "OOM Kill Analysis", "critical",
                f"{len(oom_events)} OOM kill event(s) detected")

    # 2. System Performance Analysis (from SAR anomalies - will be enriched in UI)
    add("Performance", "System Performance Analysis", "info", "See Performance Peaks section for details")

    # 3. System Resource Exhaustion
    resource_exhaust_re = re.compile(r'(out of memory|cannot allocate|ENOMEM|no space left on device|too many open files|file-max limit)', re.I)
    resource_issues = resource_exhaust_re.findall(all_boot)
    if resource_issues:
        add("Performance", "System Resource Exhaustion Analysis", "critical" if len(resource_issues) > 5 else "info",
            f"{len(resource_issues)} resource exhaustion event(s)")
    else:
        add("Performance", "System Resource Exhaustion Analysis", "info", "No resource exhaustion")

    # ── V8: Inode Exhaustion ──────────────────────────────────────────
    inode_info = system_info.get('inode_usage', [])
    inode_critical = [i for i in inode_info if i.get('inode_used_pct', 0) >= 90]
    if inode_critical:
        mounts = ', '.join(f"{i['mountpoint']} ({i['inode_used_pct']}%)" for i in inode_critical)
        add("Filesystem", "Inode Exhaustion", "critical" if any(i['inode_used_pct'] >= 95 for i in inode_critical) else "warning",
            f"Inode usage ≥90%: {mounts}")
    else:
        add("Filesystem", "Inode Exhaustion", "info", "Inode usage normal")

    # ── V8: Failed Systemd Services ───────────────────────────────────
    failed_svc = system_info.get('failed_services', {})
    if failed_svc.get('total_failed', 0) > 0:
        svc_list = ', '.join(failed_svc['failed_units'][:5])
        more = f" +{failed_svc['total_failed'] - 5} more" if failed_svc['total_failed'] > 5 else ""
        add("General Errors", "Failed Systemd Services (current state)", "critical",
            f"{failed_svc['total_failed']} service(s) in failed state: {svc_list}{more}")
    else:
        add("General Errors", "Failed Systemd Services (current state)", "info",
            "No failed services detected")

    # ── V8: Kernel Taint ──────────────────────────────────────────────
    taint = system_info.get('kernel_taint', {})
    if taint.get('tainted'):
        add("System Config", "Kernel Taint Flags", "warning",
            f"Kernel tainted (value={taint['value']}, flags={taint['flag_letters']}): {'; '.join(taint['flags'][:3])}")
    else:
        add("System Config", "Kernel Taint Flags", "info", "Kernel not tainted")

    # ── V8: NTP/Chrony Time Sync ──────────────────────────────────────
    time_sync = system_info.get('time_sync', {})
    if time_sync.get('service'):
        if time_sync.get('synced') is False:
            add("System Config", "NTP/Chrony Time Sync", "warning",
                f"{time_sync['service']}: NOT synchronized — {time_sync.get('details', 'clock drift risk')}")
        elif time_sync.get('offset_ms') is not None and time_sync['offset_ms'] > 500:
            add("System Config", "NTP/Chrony Time Sync", "warning",
                f"{time_sync['service']}: offset {time_sync['offset_ms']:.1f}ms (>500ms threshold)")
        elif time_sync.get('synced') is True:
            offset_str = f", offset {time_sync['offset_ms']:.3f}ms" if time_sync.get('offset_ms') is not None else ""
            add("System Config", "NTP/Chrony Time Sync", "info",
                f"{time_sync['service']}: synchronized{offset_str}")
        else:
            add("System Config", "NTP/Chrony Time Sync", "info",
                f"{time_sync['service']}: status unknown")
    else:
        add("System Config", "NTP/Chrony Time Sync", "warning",
            "No NTP/chrony/timedatectl data found — time sync status unknown")

    # ── Repository Errors ─────────────────────────────────────────────
    # 1. RHUI Connectivity
    rhui_log = _read(os.path.join(sosreport_path, 'var', 'log', 'rhui', 'rhui.log'))
    yum_log = _read(os.path.join(sosreport_path, 'var', 'log', 'yum.log'))
    dnf_log = _read(os.path.join(sosreport_path, 'var', 'log', 'dnf.log'))
    repo_content = rhui_log + yum_log + dnf_log
    # Also check sos_commands/yum or dnf
    for sos_sub in ['sos_commands/yum', 'sos_commands/dnf']:
        sos_sub_path = os.path.join(sosreport_path, sos_sub)
        if os.path.isdir(sos_sub_path):
            for fn in os.listdir(sos_sub_path):
                if 'repolist' in fn.lower() or 'repoinfo' in fn.lower():
                    repo_content += _read(os.path.join(sos_sub_path, fn))

    rhui_err_re = re.compile(r'(RHUI|rhui).*(fail|error|timeout|unreachable|Cannot)', re.I)
    rhui_errs = rhui_err_re.findall(repo_content)
    if rhui_errs:
        add("Repository Errors", "RHUI Connectivity", "warning",
            f"{len(rhui_errs)} RHUI connectivity issue(s)")
    else:
        add("Repository Errors", "RHUI Connectivity", "info", "No RHUI issues detected")

    # 2. RHUI Server IP issues
    rhui_ip_re = re.compile(r'(rhui|repo).*(cannot resolve|Name or service not known|No route to host|Connection refused)', re.I)
    rhui_ip_errs = rhui_ip_re.findall(repo_content)
    if rhui_ip_errs:
        add("Repository Errors", "RHUI Server IP issues", "warning",
            f"{len(rhui_ip_errs)} RHUI DNS/IP issue(s)")
    else:
        add("Repository Errors", "RHUI Server IP issues", "info", "No RHUI server IP issues")

    # ── Results (3rd party checks) ────────────────────────────────────
    # 1. CrowdStrike presence
    packages = system_info.get('packages', {})
    all_pkgs = packages.get('all', []) if isinstance(packages.get('all'), list) else []
    pkg_names_str = ' '.join(str(p) for p in all_pkgs).lower()
    cs_installed = 'falcon-sensor' in pkg_names_str or 'crowdstrike' in pkg_names_str
    cs_service_re = re.compile(r'falcon-sensor|crowdstrike', re.I)
    cs_in_logs = cs_service_re.search(all_boot)
    if cs_installed or cs_in_logs:
        add("Results", "Check for CrowdStrike presence", "warning",
            "CrowdStrike Falcon sensor detected")
    else:
        add("Results", "Check for CrowdStrike presence", "info", "CrowdStrike not found")

    # 2. Custom Or 3rd Party Image Analysis
    os_release = system_info.get('os_release', '')
    cloud_init_log = _read(os.path.join(sosreport_path, 'var', 'log', 'cloud-init.log'))
    custom_image_hints = re.compile(r'(custom.?image|marketplace|plan.*info|BillingTag|third.?party)', re.I)
    is_custom = custom_image_hints.search(cloud_init_log + str(cloud_details))
    if is_custom:
        add("Results", "Custom Or 3rd Party Image Analysis", "warning",
            "Custom or 3rd party image indicators detected")
    else:
        add("Results", "Custom Or 3rd Party Image Analysis", "info",
            "Standard marketplace image")

    # 3. Qualys presence
    qualys_re = re.compile(r'qualys', re.I)
    qualys_found = qualys_re.search(pkg_names_str) or qualys_re.search(all_boot[:200_000])
    if qualys_found:
        add("Results", "Check for Qualys presence", "warning", "Qualys agent detected")
    else:
        add("Results", "Check for Qualys presence", "info", "Qualys not found")

    # ── SLES ──────────────────────────────────────────────────────────
    # Use normalized os_flavor from detect_os_flavor() for reliable matching
    _detected_flavor = detect_os_flavor(system_info.get('os_release', ''), system_info.get('kernel', ''))
    if _detected_flavor == 'suse':
        rmt_re = re.compile(r'(RMT|SUSEConnect|registration).*(fail|error|timeout|refused)', re.I)
        suseconnect_log = _read(os.path.join(sosreport_path, 'var', 'log', 'YaST2', 'registration.log'))
        zypper_log = _read(os.path.join(sosreport_path, 'var', 'log', 'zypper.log'), tail=500)
        sles_content = suseconnect_log + zypper_log + repo_content
        rmt_errs = rmt_re.findall(sles_content)
        if rmt_errs:
            add("SLES", "RMT Connectivity", "warning",
                f"{len(rmt_errs)} RMT/registration connectivity issue(s)")
        else:
            add("SLES", "RMT Connectivity", "info", "RMT connectivity OK or not applicable")

    # ── Ubuntu/Debian ─────────────────────────────────────────────────
    if _detected_flavor in ('ubuntu', 'debian'):
        # Check APT repo errors
        apt_log_content = _read(os.path.join(sosreport_path, 'var', 'log', 'apt', 'term.log'), tail=500)
        apt_history = _read(os.path.join(sosreport_path, 'var', 'log', 'apt', 'history.log'), tail=200)
        apt_content = apt_log_content + apt_history
        apt_err_re = re.compile(r'(apt|dpkg).*(fail|error|broken|unmet|Hash Sum mismatch|Could not)', re.I)
        apt_errs = apt_err_re.findall(apt_content)
        if apt_errs:
            add("Ubuntu/Debian", "APT Package Errors", "warning",
                f"{len(apt_errs)} APT/dpkg error(s) detected")
        else:
            add("Ubuntu/Debian", "APT Package Errors", "info", "No APT errors detected")
        
        # Check unattended-upgrades
        unatt_log = _read(os.path.join(sosreport_path, 'var', 'log', 'unattended-upgrades', 'unattended-upgrades.log'), tail=100)
        if unatt_log:
            unatt_errs = re.findall(r'(WARNING|ERROR|failed)', unatt_log, re.I)
            if unatt_errs:
                add("Ubuntu/Debian", "Unattended Upgrades", "warning",
                    f"{len(unatt_errs)} unattended-upgrades issue(s)")
            else:
                add("Ubuntu/Debian", "Unattended Upgrades", "info", "Unattended upgrades operational")

    # ── System Config ─────────────────────────────────────────────────
    # 1. Repositories Analysis
    # Include APT and zypper errors alongside yum/dnf
    apt_repo_content = _read(os.path.join(sosreport_path, 'var', 'log', 'apt', 'term.log'), tail=300)
    zypper_repo_content = _read(os.path.join(sosreport_path, 'var', 'log', 'zypper.log'), tail=300)
    all_repo_content = repo_content + (apt_repo_content or '') + (zypper_repo_content or '')
    repo_errors = re.compile(r'(repo.*error|Cannot find|Errors during downloading|status code: (404|403|500)|Hash Sum mismatch|Failed to fetch)', re.I)
    repo_errs = repo_errors.findall(all_repo_content)
    if repo_errs:
        add("System Config", "Repositories Analysis", "warning",
            f"{len(repo_errs)} repository error(s) detected")
    else:
        add("System Config", "Repositories Analysis", "info", "No repository errors")

    # 2. FSTAB mount analysis
    if fstab_content:
        fstab_lines = [l.strip() for l in fstab_content.splitlines()
                       if l.strip() and not l.strip().startswith('#')]
        # Check for device paths (not UUID/LABEL) which are risky
        dev_mounts = [l for l in fstab_lines if l.startswith('/dev/sd')]
        nofail_missing = [l for l in fstab_lines
                          if not l.startswith('#') and 'nofail' not in l
                          and not any(l.startswith(x) for x in ['proc', 'sysfs', 'devpts', 'tmpfs', 'devtmpfs'])]
        issues = []
        if dev_mounts:
            issues.append(f"{len(dev_mounts)} mount(s) use /dev/sd* (not UUID — risky after reboot)")
        if issues:
            add("System Config", "FSTAB mount analysis", "critical", '; '.join(issues))
        else:
            add("System Config", "FSTAB mount analysis", "info", "FSTAB looks healthy")

    # 3. Detect hostname change
    hostname = system_info.get('hostname', '')
    hostname_re = re.compile(r'hostname.*changed|set-hostname|hostnamectl.*set', re.I)
    hostname_changes = hostname_re.findall(all_boot)
    if hostname_changes:
        add("System Config", "Detect hostname change", "info",
            f"Hostname change detected ({len(hostname_changes)} occurrence(s))")
    else:
        add("System Config", "Detect hostname change", "info", f"Hostname stable: {hostname}")

    # 4. Network DHCP Configuration
    net_config = system_info.get('network_config', {})
    nm_conns = net_config.get('nm_connections', '')
    ifcfg_dir = os.path.join(sosreport_path, 'etc', 'sysconfig', 'network-scripts')
    dhcp_configured = False
    if os.path.isdir(ifcfg_dir):
        for fn in os.listdir(ifcfg_dir):
            if fn.startswith('ifcfg-'):
                content = _read(os.path.join(ifcfg_dir, fn))
                if re.search(r'BOOTPROTO\s*=\s*["\']?dhcp', content, re.I):
                    dhcp_configured = True
                    break
    if not dhcp_configured and nm_conns:
        dhcp_configured = 'auto' in nm_conns.lower() or 'dhcp' in nm_conns.lower()
    if dhcp_configured:
        add("System Config", "Network DHCP Configuration", "warning",
            "DHCP is configured for at least one interface")
    else:
        add("System Config", "Network DHCP Configuration", "info", "Static IP or no DHCP detected")

    # 5. NVMe presence
    lsblk_content = ""
    for fn_cand in ['sos_commands/block/lsblk', 'sos_commands/block/lsblk_-o_NAME.KNAME.MAJ_MIN.FSTYPE.MOUNTPOINT.LABEL.UUID.RA.MODEL.SIZE.STATE.OWNER.GROUP.MODE.ALIGNMENT.MIN-IO.OPT-IO.PHY-SEC.LOG-SEC.ROTA.SCHED.RQ-SIZE.DISC-ALN.DISC-GRAN.DISC-MAX.DISC-ZERO.TYPE.HCTL.TRAN.REV.VENDOR']:
        content = _read(os.path.join(sosreport_path, fn_cand))
        if content:
            lsblk_content = content
            break
    nvme_re = re.compile(r'nvme', re.I)
    if nvme_re.search(lsblk_content) or nvme_re.search(all_boot[:200_000]):
        add("System Config", "Check for NVMe presence", "info",
            "NVMe device(s) detected")
    else:
        add("System Config", "Check for NVMe presence", "info", "No NVMe devices")

    # 6. SSH Security Analysis
    sshd_config = _read(os.path.join(sosreport_path, 'etc', 'ssh', 'sshd_config'))
    ssh_issues = []
    if re.search(r'^\s*PermitRootLogin\s+(yes|without-password)', sshd_config, re.M | re.I):
        ssh_issues.append("PermitRootLogin is enabled")
    if re.search(r'^\s*PasswordAuthentication\s+yes', sshd_config, re.M | re.I):
        ssh_issues.append("PasswordAuthentication is enabled")
    if re.search(r'^\s*PermitEmptyPasswords\s+yes', sshd_config, re.M | re.I):
        ssh_issues.append("PermitEmptyPasswords is enabled")
    if ssh_issues:
        add("System Config", "SSH Security Analysis", "warning", '; '.join(ssh_issues))
    else:
        add("System Config", "SSH Security Analysis", "info", "SSH configuration looks secure")

    # Sort categories and findings by severity
    severity_order = {'critical': 0, 'warning': 1, 'info': 2}
    for cat in findings:
        findings[cat].sort(key=lambda f: severity_order.get(f['severity'], 3))

    return findings


def generate_copy_paste_summary(hostname: str, system_info: dict, sar_anomalies: dict,
                                critical_events: list, critical_summary: dict,
                                sar_metrics_count: int, logs_count: int,
                                patch_compliance: dict = None,
                                log_summary: dict = None,
                                health_checks: dict = None) -> str:
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
    # HugePages & THP
    hp_total = memory_info.get('hugepages_total', 0)
    hp_free = memory_info.get('hugepages_free', 0)
    hp_size_kb = memory_info.get('hugepage_size_kb', 0)
    thp_status = memory_info.get('thp_enabled', 'N/A')
    if hp_total > 0:
        hp_size_mb = hp_size_kb / 1024 if hp_size_kb else 2
        hp_used = hp_total - hp_free
        hp_total_gb = (hp_total * hp_size_kb) / 1024 / 1024
        lines.append(f"  HugePages:    {hp_total:,} x {hp_size_mb:.0f}MB = {hp_total_gb:.1f}GB (used: {hp_used:,}, free: {hp_free:,})")
    lines.append(f"  THP:          {thp_status} (Transparent HugePages)")
    # Sysctl key tuning values
    sysctl_data = system_info.get('sysctl', {})
    sysctl_all = sysctl_data.get('all', {})
    if sysctl_all:
        lines.append(f"  --- Key sysctl ---")
        key_params = [
            'vm.swappiness', 'vm.dirty_ratio', 'vm.dirty_background_ratio',
            'vm.overcommit_memory', 'vm.nr_hugepages', 'kernel.sem',
            'kernel.shmmax', 'kernel.panic', 'net.core.somaxconn',
            'fs.file-max',
        ]
        for p in key_params:
            if p in sysctl_all:
                lines.append(f"  {p:<35} = {sysctl_all[p]}")
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
    reboot_hist = system_info.get('reboot_history', [])
    if reboot_hist:
        last_rb = reboot_hist[0]
        lines.append(f"  Last Reboot:  {last_rb['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}  (kernel: {last_rb['kernel']})")
        if len(reboot_hist) > 1:
            lines.append(f"  Reboots:      {len(reboot_hist)} boot(s) detected in logs")
            for rb in reboot_hist[1:5]:
                lines.append(f"                {rb['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}  (kernel: {rb['kernel']})")
            if len(reboot_hist) > 5:
                lines.append(f"                ... and {len(reboot_hist) - 5} more")
    else:
        lines.append(f"  Last Reboot:  N/A (no BOOT_IMAGE in messages)")
    kcmd = system_info.get('kernel_cmdline', {})
    if kcmd.get('raw'):
        lines.append(f"  Boot Params:  {kcmd['raw'][:200]}")
        notable = kcmd.get('notable', [])
        if notable:
            lines.append(f"  Notable:      {', '.join(notable)}")
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
    
    # Critical Events (with severity breakdown)
    lines.append("--- LOG EVENTS ANALYSIS ---")
    if critical_events:
        sev_c = sum(1 for e in critical_events if e.get('severity') == 'critical')
        sev_w = sum(1 for e in critical_events if e.get('severity') == 'warning')
        sev_i = sum(1 for e in critical_events if e.get('severity') == 'info')
        lines.append(f"  Total: {len(critical_events)} events  (Critical: {sev_c} | Warning: {sev_w} | Info: {sev_i})")
        for category, count in critical_summary.items():
            if count > 0:
                # Show severity breakdown per category
                cat_events = [e for e in critical_events if e.get('category') == category]
                cc = sum(1 for e in cat_events if e.get('severity') == 'critical')
                cw = sum(1 for e in cat_events if e.get('severity') == 'warning')
                ci = sum(1 for e in cat_events if e.get('severity') == 'info')
                sev_str = ", ".join(filter(None, [f"{cc} critical" if cc else "", f"{cw} warning" if cw else "", f"{ci} info" if ci else ""]))
                lines.append(f"  - {category}: {count} events ({sev_str})")
        if sev_c == 0:
            lines.append("  >>> No critical events — only warnings/informational. System appears stable.")
    else:
        lines.append("  No events detected - system logs appear healthy.")
    lines.append("")
    
    # Patch Compliance (if available)
    if patch_compliance:
        lines.append("--- PATCH COMPLIANCE ---")
        flavor_labels = {
            'oracle_linux': 'Oracle Linux', 'rhel': 'RHEL', 'centos': 'CentOS',
            'rocky': 'Rocky Linux', 'alma': 'AlmaLinux', 'suse': 'SUSE', 'ubuntu': 'Ubuntu',
            'debian': 'Debian',
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
    
    # Cloud Provider (V7)
    cloud = system_info.get('cloud', {})
    if cloud.get('provider'):
        lines.append("--- CLOUD PROVIDER ---")
        lines.append(f"  Provider:      {cloud.get('provider_label', cloud['provider'])}")
        virt = cloud.get('virtualization', {})
        if virt.get('product_name'):
            lines.append(f"  VM Type:       {virt['product_name']}")
        if virt.get('virt_what'):
            lines.append(f"  virt-what:     {virt['virt_what']}")
        details = cloud.get('details', {})
        if cloud['provider'] == 'azure' and details.get('extensions'):
            lines.append(f"  Extensions:    {len(details['extensions'])} installed")
        elif cloud['provider'] == 'aws':
            if details.get('instance_type'):
                lines.append(f"  Instance Type: {details['instance_type']}")
            if details.get('availability_zone'):
                lines.append(f"  AZ:            {details['availability_zone']}")
        lines.append("")
    
    # CVE / Security Advisories (V7)
    cve = system_info.get('cve_advisories', {})
    update_sum = cve.get('update_summary', {})
    if update_sum.get('total', 0) > 0 or cve.get('cve_count', 0) > 0:
        lines.append("--- SECURITY ADVISORIES ---")
        lines.append(f"  Pending Updates:  {update_sum.get('total', 0)}")
        lines.append(f"  Security:         {update_sum.get('security', 0)}")
        lines.append(f"  Critical+Important: {update_sum.get('critical', 0) + update_sum.get('important', 0)}")
        lines.append(f"  Unique CVEs:      {cve.get('cve_count', 0)}")
        if cve.get('cves'):
            lines.append(f"  Top CVEs:")
            for cve_id in cve['cves'][:10]:
                lines.append(f"    - {cve_id}")
            if len(cve['cves']) > 10:
                lines.append(f"    ... and {len(cve['cves']) - 10} more")
        lines.append("")
    
    # Crash Dumps (V7)
    crash_dumps = system_info.get('crash_dumps', {})
    if crash_dumps.get('total_count', 0) > 0:
        lines.append("--- CRASH DUMPS ---")
        lines.append(f"  Total:         {crash_dumps['total_count']} crash dump(s) found!")
        for dump in crash_dumps['dumps'][:5]:
            reason = dump.get('crash_reason', 'Unknown')
            lines.append(f"  - {dump['directory']}: {reason}")
        lines.append("")
    
    # System Health Checks (V7.1)
    if health_checks:
        lines.append("--- SYSTEM HEALTH CHECKS ---")
        _sev_icon = {'critical': '[CRITICAL]', 'warning': '[WARNING]', 'info': '[INFO]'}
        for cat_name, cat_findings in sorted(health_checks.items()):
            cat_crit = sum(1 for f in cat_findings if f['severity'] == 'critical')
            cat_warn = sum(1 for f in cat_findings if f['severity'] == 'warning')
            if cat_crit > 0 or cat_warn > 0:
                lines.append(f"  {cat_name} ({len(cat_findings)} checks):")
                for f in cat_findings:
                    if f['severity'] in ('critical', 'warning'):
                        lines.append(f"    {_sev_icon[f['severity']]} {f['name']}: {f.get('details', '')}")
        hc_crit = sum(1 for c in health_checks.values() for f in c if f['severity'] == 'critical')
        hc_warn = sum(1 for c in health_checks.values() for f in c if f['severity'] == 'warning')
        if hc_crit == 0 and hc_warn == 0:
            lines.append("  All health checks passed (no critical/warning findings)")
        lines.append("")
    
    # Data Summary
    lines.append("--- DATA SUMMARY ---")
    lines.append(f"  SAR Metrics:   {sar_metrics_count:,}")
    lines.append(f"  Log Entries:   {logs_count:,}")
    if log_summary:
        source_labels = {
            'messages': 'Messages', 'syslog': 'Syslog', 'warn': 'Warn (SUSE)',
            'secure': 'Secure', 'auth': 'Auth.log', 'audit': 'Audit', 'cron': 'Cron',
            'dmesg': 'Dmesg', 'journal': 'Journalctl', 'kern': 'Kern.log',
            'boot': 'Boot.log', 'maillog': 'Maillog', 'yum_dnf': 'Yum/DNF',
        }
        for key, label in source_labels.items():
            count = log_summary.get(key, 0)
            if count > 0:
                lines.append(f"    {label + ':':<15} {count:,}")
    lines.append("")
    lines.append("=" * 70)
    lines.append(f"  Generated by SOSreport & Supportconfig Analyzer V8")
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
            'severity': event.get('severity', 'critical'),
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


# ── Correlation relevance scoring & grouping ──────────────────────────────
# These helpers enrich the raw correlations so the "Timestamp Correlation View"
# shows grouped, de-noised, actionable insight instead of raw log lines.

# Patterns that are NOISE in a correlation context — they fire frequently but
# don't explain *why* the system was busy at that moment.
_CORRELATION_NOISE_PATTERNS = _re.compile(
    r'martian\s+source|'
    r'Connection\s+timed\s+out|'
    r'authentication\s+failure|'
    r'Failed\s+password|'
    r'FAILED\s+LOGIN|'
    r'Invalid\s+user|'
    r'session\s+(opened|closed)|'
    r'pam_unix.*session|'
    r'Accepted\s+(publickey|password)|'
    r'Connection\s+closed\s+by\s+authenticating|'
    r'hv_balloon|'
    r'ACPI\s+Warning',
    _re.I
)

# Extract a human-readable "what happened" summary from an event.
_SUMMARY_EXTRACTORS = [
    # OOM: extract killed process name
    (_re.compile(r'Out\s+of\s+memory.*Killed\s+process\s+\d+\s*\(([^)]+)\)', _re.I),
     lambda m: f"OOM killed **{m.group(1)}**"),
    (_re.compile(r'oom-killer.*\(([^)]+)\)', _re.I),
     lambda m: f"OOM killed **{m.group(1)}**"),
    (_re.compile(r'invoked\s+oom-killer', _re.I),
     lambda m: "OOM killer invoked"),
    # Kernel panic / lockup
    (_re.compile(r'Kernel\s+panic', _re.I),
     lambda m: "**Kernel panic**"),
    (_re.compile(r'BUG:\s+soft\s+lockup.*CPU#(\d+)', _re.I),
     lambda m: f"Soft lockup on CPU#{m.group(1)}"),
    (_re.compile(r'Watchdog\s+detected\s+hard\s+LOCKUP.*CPU#?(\d+)', _re.I),
     lambda m: f"Hard lockup on CPU#{m.group(1)}"),
    (_re.compile(r'rcu_sched\s+detected\s+stalls', _re.I),
     lambda m: "RCU stall detected"),
    (_re.compile(r'blocked\s+for\s+more\s+than\s+(\d+)\s+seconds', _re.I),
     lambda m: f"Task hung >{m.group(1)}s"),
    # Disk / I/O
    (_re.compile(r'I/O\s+error.*dev\s+(\S+)', _re.I),
     lambda m: f"I/O error on **{m.group(1)}**"),
    (_re.compile(r'I/O\s+error', _re.I),
     lambda m: "I/O error"),
    (_re.compile(r'xfs_force_shutdown', _re.I),
     lambda m: "XFS force shutdown"),
    (_re.compile(r'Read-only\s+file\s+system', _re.I),
     lambda m: "Filesystem went **read-only**"),
    (_re.compile(r'XFS\s+\((\S+)\):', _re.I),
     lambda m: f"XFS error on **{m.group(1)}**"),
    (_re.compile(r'Corruption\s+detected', _re.I),
     lambda m: "**Data corruption** detected"),
    # Service / systemd
    (_re.compile(r'Failed\s+to\s+start\s+(.+?)\.?$', _re.I),
     lambda m: f"Service failed: **{m.group(1).strip()[:60]}**"),
    (_re.compile(r'Dependency\s+failed\s+for\s+(.+?)\.?$', _re.I),
     lambda m: f"Dependency failed: **{m.group(1).strip()[:60]}**"),
    (_re.compile(r'(\S+)\s+entered\s+failed\s+state', _re.I),
     lambda m: f"**{m.group(1)}** entered failed state"),
    (_re.compile(r'coredump', _re.I),
     lambda m: "Process **core dumped**"),
    (_re.compile(r'dumped\s+core', _re.I),
     lambda m: "Process **core dumped**"),
    (_re.compile(r'Start\s+request\s+repeated\s+too\s+quickly', _re.I),
     lambda m: "Service restart loop"),
    # Network
    (_re.compile(r'NIC\s+Link\s+is\s+Down', _re.I),
     lambda m: "NIC link **down**"),
    (_re.compile(r'NETDEV\s+WATCHDOG', _re.I),
     lambda m: "Network device watchdog timeout"),
    (_re.compile(r'hv_netvsc.*(error|timeout|lost|failed)', _re.I),
     lambda m: f"Hyper-V NIC {m.group(1)}"),
    # Hardware
    (_re.compile(r'Hardware\s+Error', _re.I),
     lambda m: "**Hardware error**"),
    (_re.compile(r'MCE:\s+Machine\s+Check', _re.I),
     lambda m: "Machine check exception"),
    (_re.compile(r'PCIe\s+Bus\s+Error', _re.I),
     lambda m: "PCIe bus error"),
    (_re.compile(r'Uncorrected\s+error', _re.I),
     lambda m: "Uncorrected hardware error"),
    (_re.compile(r'segfault\s+at', _re.I),
     lambda m: "Segfault"),
    (_re.compile(r'general\s+protection\s+fault', _re.I),
     lambda m: "General protection fault"),
    # Memory
    (_re.compile(r'page\s+allocation\s+failure', _re.I),
     lambda m: "Page allocation failure"),
    (_re.compile(r'SLUB:\s+Unable\s+to\s+allocate', _re.I),
     lambda m: "SLUB allocation failure"),
]


def _summarize_event(message: str) -> str:
    """Turn a raw log line into a short, human-readable 'What Happened' string."""
    for pattern, formatter in _SUMMARY_EXTRACTORS:
        m = pattern.search(message)
        if m:
            return formatter(m)
    # Fallback: first 80 chars of message
    return message[:80]


def _extract_daemon(event: dict) -> str:
    """Extract the daemon / service name from an event's program field or message."""
    prog = (event.get('program') or '').strip()
    # Strip PID suffix: "sshd[12345]" -> "sshd"
    prog = _re.sub(r'\[\d+\]$', '', prog).strip()
    if prog and prog.lower() not in ('kernel', '-', '', 'unknown'):
        return prog
    # Try to extract from systemd-style messages
    msg = event.get('message', '')
    m = _re.search(r'(?:Failed to start|Dependency failed for)\s+(\S+)', msg)
    if m:
        return m.group(1).strip('.')
    m = _re.search(r'(\S+\.service)', msg)
    if m:
        return m.group(1)
    return 'kernel'


def enrich_correlations(correlations: list) -> list:
    """Enrich raw correlations: filter noise, add summary, extract daemon.

    Returns a NEW list of enriched dicts — only events worth showing.
    """
    enriched = []
    for c in correlations:
        if not c.get('sar_matched'):
            continue
        msg = c.get('message', '')
        # Skip noisy events that don't explain system behavior
        if _CORRELATION_NOISE_PATTERNS.search(msg):
            continue
        c_copy = dict(c)
        c_copy['summary'] = _summarize_event(msg)
        c_copy['daemon'] = _extract_daemon(c)
        enriched.append(c_copy)
    return enriched


def group_correlations(enriched: list) -> list:
    """Group enriched correlations by (minute, category, summary).

    Returns a list of group dicts:
      {minute, category, daemon, summary, count, severity, cpu%, mem%, ...}
    Sorted by time, then severity (critical first).
    """
    from collections import OrderedDict

    groups: dict = OrderedDict()
    for c in enriched:
        minute = c['event_time'].strftime('%Y-%m-%d %H:%M')
        key = (minute, c['category'], c['summary'])
        if key not in groups:
            groups[key] = {
                'minute': minute,
                'event_time': c['event_time'],
                'category': c['category'],
                'summary': c['summary'],
                'daemon': c.get('daemon', ''),
                'severity': c['severity'],
                'count': 0,
                # SAR — keep worst values across the group
                'cpu_usage': c.get('cpu_usage'),
                'cpu_iowait': c.get('cpu_iowait'),
                'mem_used_pct': c.get('mem_used_pct'),
                'load_1': c.get('load_1'),
                'blocked': c.get('blocked'),
                'disk_util': c.get('disk_util'),
                'disk_device': c.get('disk_device'),
                'messages': [],
            }
        g = groups[key]
        g['count'] += 1
        if c['severity'] == 'critical':
            g['severity'] = 'critical'  # escalate group to critical
        # Keep highest resource values
        for metric in ('cpu_usage', 'cpu_iowait', 'mem_used_pct', 'load_1', 'blocked', 'disk_util'):
            if c.get(metric) is not None:
                if g[metric] is None or c[metric] > g[metric]:
                    g[metric] = c[metric]
        if len(g['messages']) < 3:  # keep up to 3 example messages
            g['messages'].append(c['message'][:120])

    result = list(groups.values())
    sev_order = {'critical': 0, 'warning': 1, 'info': 2}
    result.sort(key=lambda g: (g['event_time'], sev_order.get(g['severity'], 9)))
    return result


# ============================================================================
# V8 NEW DETECTION FUNCTIONS
# ============================================================================

def detect_failed_services(sosreport_path: str, archive_format: str = 'sosreport') -> dict:
    """Detect systemd services currently in failed state at collection time.
    
    Parses systemctl list-units --all output to find units in 'failed' state.
    This shows what's broken NOW, not just what failed in the past (logs).
    
    Returns dict with 'failed_units' list and 'total_failed' count.
    """
    result = {'failed_units': [], 'total_failed': 0}
    
    systemctl_files = [
        os.path.join(sosreport_path, "sos_commands", "systemd", "systemctl_list-units_--all"),
        os.path.join(sosreport_path, "sos_commands", "systemd", "systemctl_list-units"),
        os.path.join(sosreport_path, "sos_commands", "systemd", "systemctl_--failed"),
    ]
    
    for sf in systemctl_files:
        if not os.path.isfile(sf):
            continue
        try:
            with open(sf, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_stripped = line.strip()
                    if not line_stripped:
                        continue
                    # systemctl output: "● unit.service  loaded failed failed  Description"
                    # or:               "  unit.service  loaded active running Description"
                    if 'failed' in line_stripped.lower():
                        parts = line_stripped.split()
                        if len(parts) >= 4:
                            # Unit name might be preceded by ● or ✗
                            unit_name = parts[0] if not parts[0].startswith(('●', '✗', '*')) else parts[1] if len(parts) > 1 else parts[0]
                            # Clean up: strip bullet chars
                            unit_name = unit_name.lstrip('●✗* ')
                            # Verify it's actually a failed unit (not just a line mentioning "failed")
                            if any(p.lower() == 'failed' for p in parts[1:5]):
                                if unit_name.endswith(('.service', '.socket', '.mount', '.timer', '.target', '.path', '.scope', '.slice')):
                                    result['failed_units'].append(unit_name)
            if result['failed_units']:
                break
        except Exception:
            continue
    
    # Deduplicate
    result['failed_units'] = sorted(set(result['failed_units']))
    result['total_failed'] = len(result['failed_units'])
    return result


def detect_inode_usage(sosreport_path: str, archive_format: str = 'sosreport') -> list:
    """Detect inode usage from df -i output.
    
    Inode exhaustion (100% inodes used with free space remaining) is a common
    root cause of "No space left on device" errors that disk % alone misses.
    
    Returns list of dicts with filesystem, inode_used_pct, mountpoint.
    """
    inode_info = []
    
    df_i_files = [
        os.path.join(sosreport_path, "sos_commands", "filesys", "df_-ali"),
        os.path.join(sosreport_path, "sos_commands", "filesys", "df_-i"),
        os.path.join(sosreport_path, "sos_commands", "filesys", "df_-ih"),
    ]
    
    for df_file in df_i_files:
        if not os.path.isfile(df_file):
            continue
        try:
            with open(df_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line in lines[1:]:  # Skip header
                parts = line.split()
                if len(parts) < 6:
                    continue
                try:
                    filesystem = parts[0]
                    use_pct_str = parts[4].rstrip('%')
                    mountpoint = parts[5]
                    
                    # Skip virtual/pseudo filesystems
                    skip_fs = ['tmpfs', 'devtmpfs', 'overlay', 'sysfs', 'proc', 'cgroup', 'devpts']
                    if any(fs in filesystem.lower() for fs in skip_fs):
                        continue
                    skip_mounts = ['/sys', '/proc', '/dev/', '/run/']
                    if any(mountpoint.startswith(mp) for mp in skip_mounts):
                        continue
                    if mountpoint in ['/dev', '/run', '/sys', '/proc']:
                        continue
                    
                    if use_pct_str == '-' or not use_pct_str:
                        continue
                    
                    inode_pct = int(use_pct_str)
                    if inode_pct > 0:  # Only track filesystems with inode usage
                        inode_info.append({
                            'filesystem': filesystem,
                            'inodes_total': parts[1],
                            'inodes_used': parts[2],
                            'inodes_free': parts[3],
                            'inode_used_pct': inode_pct,
                            'mountpoint': mountpoint,
                        })
                except (ValueError, IndexError):
                    continue
            
            if inode_info:
                return inode_info
        except Exception:
            continue
    
    return inode_info


def detect_kernel_taint(sosreport_path: str, archive_format: str = 'sosreport') -> dict:
    """Decode kernel taint flags from /proc/sys/kernel/tainted.
    
    A non-zero taint value means the kernel has loaded out-of-tree or
    proprietary modules, which may cause vendors to decline support for crashes.
    
    Returns dict with 'value' (int), 'tainted' (bool), 'flags' (list of strings).
    """
    TAINT_FLAGS = {
        0:  'Proprietary module loaded (P)',
        1:  'Module force loaded (F)',
        2:  'Kernel running on out-of-spec system (S)',
        3:  'Module force unloaded (R)',
        4:  'Processor reported MCE (M)',
        5:  'Bad page referenced (B)',
        6:  'User requested taint (U)',
        7:  'ACPI table overridden by user (A)',
        8:  'Kernel issued warning (W)',
        9:  'Staging driver loaded (C)',
        10: 'Workaround for platform firmware bug applied (I)',
        11: 'Externally-built out-of-tree module loaded (O)',
        12: 'Unsigned module loaded (E)',
        13: 'Soft lockup occurred (L)',
        14: 'Kernel live-patched (K)',
        15: 'Auxiliary taint (X)',
        16: 'Struct randomization plugin in use (T)',
        17: 'In-kernel test used (N)',
    }
    
    result = {'value': 0, 'tainted': False, 'flags': [], 'flag_letters': ''}
    
    taint_files = [
        os.path.join(sosreport_path, 'proc', 'sys', 'kernel', 'tainted'),
        os.path.join(sosreport_path, 'sos_commands', 'kernel', 'cat_.proc.sys.kernel.tainted'),
    ]
    
    for tf in taint_files:
        if not os.path.isfile(tf):
            continue
        try:
            with open(tf, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().strip()
            if content and content.isdigit():
                taint_val = int(content)
                result['value'] = taint_val
                result['tainted'] = taint_val != 0
                
                if taint_val != 0:
                    flags = []
                    letters = []
                    letter_map = {0:'P', 1:'F', 2:'S', 3:'R', 4:'M', 5:'B', 6:'U', 7:'A',
                                  8:'W', 9:'C', 10:'I', 11:'O', 12:'E', 13:'L', 14:'K',
                                  15:'X', 16:'T', 17:'N'}
                    for bit, description in TAINT_FLAGS.items():
                        if taint_val & (1 << bit):
                            flags.append(description)
                            letters.append(letter_map.get(bit, '?'))
                    result['flags'] = flags
                    result['flag_letters'] = ''.join(letters)
                break
        except Exception:
            continue
    
    return result


def detect_time_sync(sosreport_path: str, archive_format: str = 'sosreport') -> dict:
    """Detect NTP/Chrony time synchronization status.
    
    Clock drift causes Kerberos failures, DB replication issues, cluster split-brain,
    and certificate validation errors. This checks chronyc/ntpstat output.
    
    Returns dict with 'service', 'synced', 'offset_ms', 'source', 'details'.
    """
    result = {
        'service': None,
        'synced': None,
        'offset_ms': None,
        'source': None,
        'stratum': None,
        'details': '',
    }
    
    # ── Check chrony (modern distros) ──
    chrony_files = [
        os.path.join(sosreport_path, 'sos_commands', 'chrony', 'chronyc_tracking'),
        os.path.join(sosreport_path, 'sos_commands', 'chrony', 'chronyc_sources'),
    ]
    
    for cf in chrony_files:
        if not os.path.isfile(cf):
            continue
        try:
            with open(cf, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            result['service'] = 'chrony'
            
            if 'tracking' in cf.lower():
                for line in content.splitlines():
                    line_lower = line.lower().strip()
                    if line_lower.startswith('reference id'):
                        ref = line.split(':', 1)[1].strip() if ':' in line else ''
                        result['source'] = ref
                        if '127.127.1.1' in ref or 'local' in ref.lower():
                            result['synced'] = False
                            result['details'] = 'Synced to LOCAL clock only (no external source)'
                    elif line_lower.startswith('stratum'):
                        try:
                            result['stratum'] = int(line.split(':', 1)[1].strip())
                        except (ValueError, IndexError):
                            pass
                    elif 'system time' in line_lower and 'offset' in line_lower:
                        # "System time     : 0.000001234 seconds slow of NTP time"
                        try:
                            offset_match = re.search(r'([\d.]+)\s+seconds', line)
                            if offset_match:
                                offset_sec = float(offset_match.group(1))
                                result['offset_ms'] = round(offset_sec * 1000, 3)
                                if result['synced'] is None:
                                    result['synced'] = True
                        except (ValueError, IndexError):
                            pass
                    elif 'last offset' in line_lower:
                        try:
                            offset_match = re.search(r'([+-]?[\d.]+)', line.split(':', 1)[1])
                            if offset_match:
                                offset_sec = abs(float(offset_match.group(1)))
                                if result['offset_ms'] is None:
                                    result['offset_ms'] = round(offset_sec * 1000, 3)
                        except (ValueError, IndexError):
                            pass
                
                if result['stratum'] and result['stratum'] >= 16:
                    result['synced'] = False
                    result['details'] = 'Stratum 16 — not synchronized'
                elif result['synced'] is None and result['source']:
                    result['synced'] = True
            break
        except Exception:
            continue
    
    # ── Check NTP (legacy) ──
    if result['service'] is None:
        ntp_files = [
            os.path.join(sosreport_path, 'sos_commands', 'ntp', 'ntpstat'),
            os.path.join(sosreport_path, 'sos_commands', 'ntp', 'ntpq_-pn'),
        ]
        for nf in ntp_files:
            if not os.path.isfile(nf):
                continue
            try:
                with open(nf, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                result['service'] = 'ntp'
                
                if 'ntpstat' in nf.lower():
                    if 'synchronised' in content.lower() or 'synchronized' in content.lower():
                        result['synced'] = True
                        # Extract offset
                        offset_match = re.search(r'time correct to within (\d+)\s*ms', content)
                        if offset_match:
                            result['offset_ms'] = float(offset_match.group(1))
                    elif 'unsynchronised' in content.lower() or 'unsynchronized' in content.lower():
                        result['synced'] = False
                        result['details'] = 'NTP unsynchronized'
                    
                    stratum_match = re.search(r'stratum\s+(\d+)', content)
                    if stratum_match:
                        result['stratum'] = int(stratum_match.group(1))
                break
            except Exception:
                continue
    
    # ── Check timedatectl (systemd) as fallback ──
    if result['service'] is None:
        timedatectl_files = [
            os.path.join(sosreport_path, 'sos_commands', 'date', 'timedatectl'),
            os.path.join(sosreport_path, 'sos_commands', 'general', 'timedatectl'),
        ]
        for tf in timedatectl_files:
            if not os.path.isfile(tf):
                continue
            try:
                with open(tf, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                for line in content.splitlines():
                    line_lower = line.lower().strip()
                    if 'ntp synchronized' in line_lower or 'system clock synchronized' in line_lower:
                        if 'yes' in line_lower:
                            result['synced'] = True
                            result['service'] = 'systemd-timesyncd'
                        elif 'no' in line_lower:
                            result['synced'] = False
                            result['service'] = 'systemd-timesyncd'
                            result['details'] = 'NTP not synchronized (timedatectl)'
                    elif 'ntp service' in line_lower or 'ntp enabled' in line_lower:
                        if 'inactive' in line_lower or 'no' in line_lower:
                            result['details'] = 'NTP service not active'
                break
            except Exception:
                continue
    
    return result


def generate_executive_summary(system_info: dict, sar_anomalies: dict,
                               critical_events: list, health_checks: dict,
                               patch_compliance: dict) -> dict:
    """Generate a 3-5 bullet executive TL;DR with overall risk level.
    
    Returns dict with 'risk_level' (GREEN/YELLOW/RED), 'bullets' (list of strings),
    and 'risk_score' (0-10).
    """
    bullets = []
    risk_score = 0  # 0=pristine, 10=on fire
    
    # ── Critical events ──
    if critical_events:
        crit_count = sum(1 for e in critical_events if e.get('severity') == 'critical')
        if crit_count > 0:
            # Find top category
            cat_counts = {}
            for e in critical_events:
                if e.get('severity') == 'critical':
                    cat = e.get('category', 'Unknown')
                    cat_counts[cat] = cat_counts.get(cat, 0) + 1
            top_cat = max(cat_counts, key=cat_counts.get) if cat_counts else 'Unknown'
            bullets.append(f"🔴 {crit_count} critical event(s) detected — top category: {top_cat}")
            risk_score += min(crit_count, 4)  # Cap at 4
        
        oom_count = sum(1 for e in critical_events 
                       if e.get('category') == 'Memory/OOM' and e.get('severity') == 'critical')
        if oom_count > 0:
            bullets.append(f"🧠 {oom_count} OOM kill(s) — system ran out of memory")
            risk_score += 2
    
    # ── Disk space ──
    df_info = system_info.get('df_info', [])
    exhausted = [fs for fs in df_info if fs.get('use_percent', 0) >= 95]
    if exhausted:
        mounts = ', '.join(fs.get('mountpoint', '?') for fs in exhausted)
        bullets.append(f"💾 Disk ≥95% full: {mounts}")
        risk_score += 2
    
    # ── Inode exhaustion ──
    inode_info = system_info.get('inode_usage', [])
    inode_critical = [i for i in inode_info if i.get('inode_used_pct', 0) >= 95]
    if inode_critical:
        mounts = ', '.join(i.get('mountpoint', '?') for i in inode_critical)
        bullets.append(f"📁 Inode exhaustion ≥95%: {mounts}")
        risk_score += 2
    
    # ── Crash dumps ──
    crash_count = system_info.get('crash_dumps', {}).get('total_count', 0)
    if crash_count > 0:
        bullets.append(f"💥 {crash_count} crash dump(s) found — kernel crashed")
        risk_score += 3
    
    # ── Kernel taint ──
    taint = system_info.get('kernel_taint', {})
    if taint.get('tainted'):
        bullets.append(f"⚠️ Kernel tainted ({taint.get('flag_letters', '?')}) — out-of-tree/proprietary modules loaded")
        risk_score += 1
    
    # ── Patch compliance ──
    if patch_compliance:
        if patch_compliance.get('kernel_status') == 'Very Outdated':
            bullets.append(f"📦 Kernel very outdated — {patch_compliance.get('kernel_type', '').upper()} update level below threshold")
            risk_score += 2
        if patch_compliance.get('reboot_required'):
            bullets.append(f"🔄 Reboot required — running kernel is not the latest installed")
            risk_score += 1
    
    # ── CPU steal (cloud VMs) ──
    steal_info = sar_anomalies.get('steal', {})
    if steal_info.get('avg_steal', 0) > 2:
        bullets.append(f"☁️ CPU steal avg {steal_info['avg_steal']}% (peak {steal_info['max_steal']}%) — noisy neighbor or throttling")
        risk_score += 2
    
    # ── Time sync ──
    time_sync = system_info.get('time_sync', {})
    if time_sync.get('synced') is False:
        bullets.append(f"🕐 NTP not synchronized — clock drift risk ({time_sync.get('details', '')})")
        risk_score += 1
    
    # ── Failed services ──
    failed_svc = system_info.get('failed_services', {})
    if failed_svc.get('total_failed', 0) > 0:
        top_3 = ', '.join(failed_svc['failed_units'][:3])
        more = f" +{failed_svc['total_failed'] - 3} more" if failed_svc['total_failed'] > 3 else ""
        bullets.append(f"🔧 {failed_svc['total_failed']} failed service(s): {top_3}{more}")
        risk_score += 1
    
    # ── Health check critical count ──
    if health_checks:
        hc_crit = sum(1 for cat in health_checks.values() for f in cat if f['severity'] == 'critical')
        if hc_crit > 5 and not any('critical event' in b for b in bullets):
            bullets.append(f"🔍 {hc_crit} critical health check findings")
    
    # If nothing bad found
    if not bullets:
        bullets.append("✅ No critical issues detected — system appears healthy")
    
    # Determine risk level
    risk_score = min(risk_score, 10)
    if risk_score >= 5:
        risk_level = 'RED'
    elif risk_score >= 2:
        risk_level = 'YELLOW'
    else:
        risk_level = 'GREEN'
    
    return {
        'risk_level': risk_level,
        'risk_score': risk_score,
        'bullets': bullets[:8],  # Cap at 8 bullets
    }


def get_system_info(sosreport_path: str, archive_format: str = 'sosreport') -> dict:
    """Get all system information from sosreport or supportconfig (like xsos)"""
    _af = archive_format
    return {
        'hostname': detect_hostname(sosreport_path, _af),
        'uptime': detect_uptime(sosreport_path, _af),
        'date': detect_date(sosreport_path, _af),
        'os_release': detect_os_release(sosreport_path, _af),
        'kernel': detect_kernel_version(sosreport_path, _af),
        'cpu_info': detect_cpu_info(sosreport_path, _af),
        'memory_info': detect_memory_info(sosreport_path, _af),
        'df_info': detect_df_info(sosreport_path, _af),
        'packages': detect_installed_packages(sosreport_path, _af),
        'selinux': detect_selinux_status(sosreport_path, _af),
        'top_processes': detect_top_processes(sosreport_path, _af),
        'kdump': detect_kdump_status(sosreport_path, _af),
        # V7 additions
        'cloud': detect_cloud_provider(sosreport_path, _af),
        'azure_metadata': detect_azure_metadata(sosreport_path, _af),
        'crash_dumps': detect_crash_dumps(sosreport_path, _af),
        'network_config': detect_network_config(sosreport_path, _af),
        'cve_advisories': detect_cve_advisories(sosreport_path, _af),
        'reboot_history': detect_reboot_history(sosreport_path, archive_format=_af),
        'kernel_cmdline': detect_kernel_cmdline(sosreport_path, _af),
        'sysctl': detect_sysctl_tuning(sosreport_path, _af),
        # V8 additions
        'failed_services': detect_failed_services(sosreport_path, _af),
        'inode_usage': detect_inode_usage(sosreport_path, _af),
        'kernel_taint': detect_kernel_taint(sosreport_path, _af),
        'time_sync': detect_time_sync(sosreport_path, _af),
        '_archive_format': archive_format,
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
        'load': {'max_load1': 0, 'max_load5': 0, 'max_load15': 0, 'max_time': None, 'max_blocked': 0, 'samples': 0},
        'steal': {'max_steal': 0, 'avg_steal': 0, 'max_time': None, 'samples': 0},  # V8
    }
    
    cpu_totals = []
    mem_totals = []
    steal_totals = []  # V8: track steal for cloud VM alerting
    
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
                
                # V8: Track steal time for cloud VM alerting
                steal = fields.get('pct_steal', 0)
                if steal > 0:
                    steal_totals.append(steal)
                    anomalies['steal']['samples'] += 1
                    if steal > anomalies['steal']['max_steal']:
                        anomalies['steal']['max_steal'] = round(steal, 2)
                        anomalies['steal']['max_time'] = ts
        
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
    if steal_totals:
        anomalies['steal']['avg_steal'] = round(sum(steal_totals) / len(steal_totals), 2)
    
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
    
    Uses SAR metric timestamps as the PRIMARY range (covers the sar collection
    window, typically a few days).  Log timestamps are only used as a fallback
    when no SAR data is available, because logs (dmesg, messages, journal) can
    span the entire server uptime (months) and would make the default Grafana
    time window far too wide.
    """
    sar_timestamps = []
    log_timestamps = []
    
    # Collect timestamps from SAR metrics
    for m in sar_metrics:
        ts = m.get('timestamp')
        if ts and isinstance(ts, datetime):
            sar_timestamps.append(ts)
    
    # Collect timestamps from logs (fallback only)
    for log in logs:
        ts = log.get('timestamp')
        if ts and isinstance(ts, datetime):
            log_timestamps.append(ts)
    
    # Prefer SAR range; fall back to logs if no SAR data
    timestamps = sar_timestamps if sar_timestamps else log_timestamps
    
    if not timestamps:
        return None, None
    
    min_ts = min(timestamps)
    max_ts = max(timestamps)
    
    # Add a small buffer (1 hour before and after) for better visibility
    min_ts = min_ts - timedelta(hours=1)
    max_ts = max_ts + timedelta(hours=1)
    
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
            'cpu': 0,
            # V7 additions
            'swap': 0,
            'hugepages': 0,
            'paging': 0,
            'context': 0,
            'socket': 0,
        }
    
    @staticmethod
    def _extract_data_columns(header_line: str, anchor_keyword: str) -> List[str]:
        """Extract data column names from a SAR header line, stripping timestamp/AM-PM.
        
        SAR headers look like:
          12:00:01 AM  kbmemfree kbmemused  %memused ...   (12-hour)
          00:00:01     kbmemfree kbmemused  %memused ...   (24-hour)
          12:00:01 AM  DEV       tps  rd_sec/s ...          (disk)
          12:00:01 AM  CPU    %user  %nice  %system ...     (cpu)
        
        This finds anchor_keyword in the parts and returns that column + everything after it.
        For memory: anchor='kbmemfree' → ['kbmemfree', 'kbmemused', '%memused', ...]
        For disk:   anchor='DEV'       → ['DEV', 'tps', 'rd_sec/s', ...]
        For CPU:    anchor='CPU'       → ['CPU', '%user', '%nice', ...]
        """
        parts = header_line.split()
        anchor_lower = anchor_keyword.lower()
        for i, p in enumerate(parts):
            if p.lower() == anchor_lower or anchor_lower in p.lower():
                return parts[i:]
        # Fallback: skip timestamp + optional AM/PM
        if len(parts) > 2 and parts[1] in ('AM', 'PM'):
            return parts[2:]
        elif len(parts) > 1:
            return parts[1:]
        return parts
    
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
        
        Strategy (handles RHEL 7 sysstat 10.x where XML only has CPU):
          1. Collect XML files from sos_commands/sar/ (may be CPU-only on old sysstat)
          2. Collect text sar* files from var/log/sa/ (always have full data)
          3. Collect text SAR outputs from sos_commands/sar/ (e.g. sar -A output)
          4. Return ALL valid files — parse_all() will merge & deduplicate measurements
        """
        import glob
        
        def _is_binary_sa_file(filepath: str) -> bool:
            """Detect binary sa* files (sysstat data collector format).
            Binary sa files start with sysstat magic bytes, not readable text."""
            try:
                with open(filepath, 'rb') as f:
                    header = f.read(16)
                    # sysstat binary files: first bytes are typically 0xd5 0x96 or contain
                    # non-printable chars.  Quick heuristic: if >30% non-ASCII in first 16 bytes → binary
                    if not header:
                        return True
                    non_ascii = sum(1 for b in header if b > 127 or (b < 32 and b not in (9, 10, 13)))
                    return non_ascii > 4  # >25% non-printable → binary
            except:
                return True
        
        def filter_sar_files(files: List[str], allow_xml=True) -> List[str]:
            """Filter for valid SAR files (text or XML, not binary sa* data files)"""
            result = []
            for f in files:
                if not os.path.isfile(f):
                    continue
                if f.endswith('.bin'):
                    continue
                    
                basename = os.path.basename(f)
                
                # XML files from sadf -x command
                if f.endswith('.xml') and allow_xml:
                    result.append(f)
                    continue
                
                # Skip binary sa* files (sa01, sa02, etc.) — these need sadf to decode
                # Text files are named sar01, sar02, etc.
                if re.match(r'^sa\d+$', basename):
                    # This is likely a binary data collector file — verify
                    if _is_binary_sa_file(f):
                        continue
                
                # Check if it's a text file by reading first lines
                try:
                    with open(f, 'r', encoding='utf-8', errors='ignore') as file:
                        # Read first 10 lines — supportconfig SAR may have blank leading lines
                        for _line_num in range(10):
                            first_line = file.readline()
                            if not first_line:
                                break
                            first_line = first_line.strip()
                            if not first_line:
                                continue  # skip blank lines
                            # SAR text files start with "Linux" header or have timestamps
                            if 'Linux' in first_line or '<?xml' in first_line or any(c.isdigit() for c in first_line[:20]):
                                result.append(f)
                                break
                except:
                    pass
            return result
        
        all_files = []
        sources_used = []
        
        # Source 1: sos_commands/sar/ (XML + text outputs)
        sos_sar_path = os.path.join(self.sosreport_path, "sos_commands", "sar", "*")
        sos_sar_files = glob.glob(sos_sar_path)
        sos_sar_files = filter_sar_files(sos_sar_files, allow_xml=True)
        if sos_sar_files:
            all_files.extend(sos_sar_files)
            sources_used.append("sos_commands/sar/")
        
        # Source 2: var/log/sa/ — text sar* files (sar01, sar02, etc.)
        # These are critical for RHEL 7 where XML may only have CPU stats
        var_sa_text = glob.glob(os.path.join(self.sosreport_path, "var", "log", "sa", "sar*"))
        var_sa_text = filter_sar_files(var_sa_text, allow_xml=False)
        
        # Also check for any other readable files in var/log/sa/ that aren't binary
        var_sa_other = glob.glob(os.path.join(self.sosreport_path, "var", "log", "sa", "sa[0-9]*"))
        var_sa_other = filter_sar_files(var_sa_other, allow_xml=True)
        
        var_sa_all = list(set(var_sa_text + var_sa_other))  # dedupe
        if var_sa_all:
            # Don't add duplicates (same basename from different paths)
            existing_basenames = {os.path.basename(f) for f in all_files}
            new_files = [f for f in var_sa_all if os.path.basename(f) not in existing_basenames]
            if new_files:
                all_files.extend(new_files)
                sources_used.append("var/log/sa/")
        
        # Source 3: var/log/sysstat/ — Ubuntu/Debian sysstat default path
        # Ubuntu/Debian use /var/log/sysstat/ instead of /var/log/sa/
        var_sysstat_text = glob.glob(os.path.join(self.sosreport_path, "var", "log", "sysstat", "sar*"))
        var_sysstat_text = filter_sar_files(var_sysstat_text, allow_xml=False)
        
        var_sysstat_other = glob.glob(os.path.join(self.sosreport_path, "var", "log", "sysstat", "sa[0-9]*"))
        var_sysstat_other = filter_sar_files(var_sysstat_other, allow_xml=True)
        
        var_sysstat_all = list(set(var_sysstat_text + var_sysstat_other))
        if var_sysstat_all:
            existing_basenames = {os.path.basename(f) for f in all_files}
            new_files = [f for f in var_sysstat_all if os.path.basename(f) not in existing_basenames]
            if new_files:
                all_files.extend(new_files)
                sources_used.append("var/log/sysstat/")
        
        if sources_used:
            self.sar_source = " + ".join(sources_used)
        else:
            self.sar_source = "none"
        
        return all_files
    
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
                header_found = False  # Section boundary
                continue
            
            # Skip Average: lines (end-of-section summary)
            if line.startswith('Average:'):
                header_found = False
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
        """Parse memory metrics — handles 12-hour (AM/PM) and 24-hour timestamp formats."""
        metrics = []
        header_found = False
        data_columns = []
        
        for line in lines:
            line = line.strip()
            if not line:
                header_found = False  # Section boundary
                continue
            
            if line.startswith('Average:'):
                header_found = False
                continue
            
            if 'kbmemfree' in line:
                header_found = True
                data_columns = self._extract_data_columns(line, 'kbmemfree')
                continue
            
            if header_found and data_columns:
                match = re.match(self.TIMESTAMP_PATTERN, line)
                if match:
                    parts = line.split()
                    am_pm = parts[1] if len(parts) > 1 and parts[1] in ['AM', 'PM'] else None
                    offset = 2 if am_pm else 1
                    
                    timestamp = self.parse_timestamp(parts[0], am_pm)
                    if timestamp and len(parts) > offset:
                        fields = {}
                        for i, col in enumerate(data_columns):
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
        """Parse disk I/O metrics — handles 12-hour (AM/PM) and 24-hour formats."""
        metrics = []
        header_found = False
        data_columns = []
        
        for line in lines:
            line = line.strip()
            if not line:
                header_found = False  # Section boundary
                continue
            
            if line.startswith('Average:'):
                header_found = False
                continue
            
            if 'DEV' in line and ('tps' in line or 'rd_sec' in line or 'rkB' in line):
                header_found = True
                data_columns = self._extract_data_columns(line, 'DEV')
                continue
            
            if header_found and data_columns:
                match = re.match(self.TIMESTAMP_PATTERN, line)
                if match:
                    parts = line.split()
                    am_pm = parts[1] if len(parts) > 1 and parts[1] in ['AM', 'PM'] else None
                    offset = 2 if am_pm else 1
                    
                    timestamp = self.parse_timestamp(parts[0], am_pm)
                    if timestamp and len(parts) > offset:
                        device = parts[offset]  # First data column = DEV value
                        fields = {'DEV': device}
                        
                        # data_columns = ['DEV', 'tps', 'rd_sec/s', '%util', ...]
                        # Normalize: %util→pct_util, rd_sec/s→rd_sec_s, avgrq-sz→avgrq_sz
                        for i, col in enumerate(data_columns[1:]):
                            idx = offset + 1 + i
                            if idx < len(parts):
                                try:
                                    field_name = col.replace('%', 'pct_').replace('/', '_').replace('-', '_')
                                    fields[field_name] = float(parts[idx])
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
        """Parse network metrics — handles 12-hour (AM/PM) and 24-hour formats."""
        metrics = []
        header_found = False
        data_columns = []
        
        for line in lines:
            line = line.strip()
            if not line:
                header_found = False  # Section boundary
                continue
            
            if line.startswith('Average:'):
                header_found = False
                continue
            
            if 'IFACE' in line and ('rxpck' in line or 'rxkB' in line):
                header_found = True
                data_columns = self._extract_data_columns(line, 'IFACE')
                continue
            
            if header_found and data_columns:
                match = re.match(self.TIMESTAMP_PATTERN, line)
                if match:
                    parts = line.split()
                    am_pm = parts[1] if len(parts) > 1 and parts[1] in ['AM', 'PM'] else None
                    offset = 2 if am_pm else 1
                    
                    timestamp = self.parse_timestamp(parts[0], am_pm)
                    if timestamp and len(parts) > offset:
                        interface = parts[offset]  # First data column = IFACE value
                        fields = {'IFACE': interface}
                        
                        # data_columns = ['IFACE', 'rxpck/s', 'txpck/s', ...]
                        for i, col in enumerate(data_columns[1:]):
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
        """Parse CPU utilization metrics — handles 12-hour (AM/PM) and 24-hour formats."""
        metrics = []
        header_found = False
        data_columns = []
        
        for line in lines:
            line = line.strip()
            if not line:
                header_found = False  # Section boundary
                continue
            
            if line.startswith('Average:'):
                header_found = False
                continue
            
            # Match both RHEL (%user/%system) and Oracle Linux/UEK (%usr/%sys) formats
            if ('CPU' in line) and ('%usr' in line or '%user' in line) and ('%sys' in line or '%system' in line):
                header_found = True
                data_columns = self._extract_data_columns(line, 'CPU')
                continue
            
            if header_found and data_columns:
                match = re.match(self.TIMESTAMP_PATTERN, line)
                if match:
                    parts = line.split()
                    am_pm = parts[1] if len(parts) > 1 and parts[1] in ['AM', 'PM'] else None
                    offset = 2 if am_pm else 1
                    
                    timestamp = self.parse_timestamp(parts[0], am_pm)
                    if timestamp and len(parts) > offset:
                        cpu_id = parts[offset]  # First data column = CPU value
                        fields = {'cpu': cpu_id}
                        
                        # Normalize field names: %usr→pct_user, %sys→pct_system
                        # so all downstream code (anomaly, Grafana) works consistently
                        FIELD_NORMALIZE = {
                            'pct_usr': 'pct_user', 'pct_sys': 'pct_system',
                            'pct_irq': 'pct_irq', 'pct_soft': 'pct_soft',
                            'pct_guest': 'pct_guest', 'pct_gnice': 'pct_gnice',
                        }
                        # data_columns = ['CPU', '%usr', '%nice', '%sys', ...]
                        for i, col in enumerate(data_columns[1:]):
                            idx = offset + 1 + i
                            if idx < len(parts):
                                try:
                                    col_name = col.replace('%', 'pct_')
                                    col_name = FIELD_NORMALIZE.get(col_name, col_name)
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
    
    def parse_swap_metrics(self, lines: List[str]) -> List[dict]:
        """Parse swap utilization metrics (V7 — kbswpfree, kbswpused, %swpused, etc.)"""
        metrics = []
        header_found = False
        data_columns = []
        
        for line in lines:
            line = line.strip()
            if not line:
                header_found = False  # Section boundary
                continue
            
            if line.startswith('Average:'):
                header_found = False
                continue
            
            if 'kbswpfree' in line:
                header_found = True
                data_columns = self._extract_data_columns(line, 'kbswpfree')
                continue
            
            if header_found and data_columns:
                match = re.match(self.TIMESTAMP_PATTERN, line)
                if match:
                    parts = line.split()
                    am_pm = parts[1] if len(parts) > 1 and parts[1] in ['AM', 'PM'] else None
                    offset = 2 if am_pm else 1
                    
                    timestamp = self.parse_timestamp(parts[0], am_pm)
                    if timestamp and len(parts) > offset:
                        fields = {}
                        for i, col in enumerate(data_columns):
                            idx = offset + i
                            if idx < len(parts):
                                try:
                                    col_name = col.replace('%', 'pct_').replace('-', '_')
                                    fields[col_name] = float(parts[idx])
                                except ValueError:
                                    pass
                        
                        if fields:
                            metrics.append({
                                'measurement': 'sar_swap',
                                'timestamp': timestamp,
                                'fields': fields
                            })
                            self.summary['swap'] += 1
        return metrics
    
    def parse_hugepages_metrics(self, lines: List[str]) -> List[dict]:
        """Parse hugepages metrics (V7 — kbhugfree, kbhugused, %hugused)"""
        metrics = []
        header_found = False
        data_columns = []
        
        for line in lines:
            line = line.strip()
            if not line:
                header_found = False  # Section boundary
                continue
            
            if line.startswith('Average:'):
                header_found = False
                continue
            
            if 'kbhugfree' in line or 'hugfree' in line:
                header_found = True
                anchor = 'kbhugfree' if 'kbhugfree' in line else 'hugfree'
                data_columns = self._extract_data_columns(line, anchor)
                continue
            
            if header_found and data_columns:
                match = re.match(self.TIMESTAMP_PATTERN, line)
                if match:
                    parts = line.split()
                    am_pm = parts[1] if len(parts) > 1 and parts[1] in ['AM', 'PM'] else None
                    offset = 2 if am_pm else 1
                    
                    timestamp = self.parse_timestamp(parts[0], am_pm)
                    if timestamp and len(parts) > offset:
                        fields = {}
                        for i, col in enumerate(data_columns):
                            idx = offset + i
                            if idx < len(parts):
                                try:
                                    col_name = col.replace('%', 'pct_').replace('-', '_')
                                    fields[col_name] = float(parts[idx])
                                except ValueError:
                                    pass
                        
                        if fields:
                            metrics.append({
                                'measurement': 'sar_hugepages',
                                'timestamp': timestamp,
                                'fields': fields
                            })
                            self.summary['hugepages'] += 1
        return metrics
    
    def parse_paging_metrics(self, lines: List[str]) -> List[dict]:
        """Parse paging/swapping activity metrics (V7 — pgpgin/s, pgpgout/s, fault/s, majflt/s, etc.)"""
        metrics = []
        header_found = False
        data_columns = []
        
        for line in lines:
            line = line.strip()
            if not line:
                header_found = False  # Section boundary
                continue
            
            if line.startswith('Average:'):
                header_found = False
                continue
            
            if 'pgpgin' in line and 'pgpgout' in line:
                header_found = True
                data_columns = self._extract_data_columns(line, 'pgpgin')
                continue
            
            if header_found and data_columns:
                match = re.match(self.TIMESTAMP_PATTERN, line)
                if match:
                    parts = line.split()
                    am_pm = parts[1] if len(parts) > 1 and parts[1] in ['AM', 'PM'] else None
                    offset = 2 if am_pm else 1
                    
                    timestamp = self.parse_timestamp(parts[0], am_pm)
                    if timestamp and len(parts) > offset:
                        fields = {}
                        for i, col in enumerate(data_columns):
                            idx = offset + i
                            if idx < len(parts):
                                try:
                                    fields[col.replace('/', '_')] = float(parts[idx])
                                except ValueError:
                                    pass
                        
                        if fields:
                            metrics.append({
                                'measurement': 'sar_paging',
                                'timestamp': timestamp,
                                'fields': fields
                            })
                            self.summary['paging'] += 1
        return metrics
    
    def parse_context_switch_metrics(self, lines: List[str]) -> List[dict]:
        """Parse task creation & context switching (V7 — proc/s, cswch/s)"""
        metrics = []
        header_found = False
        data_columns = []
        
        for line in lines:
            line = line.strip()
            if not line:
                header_found = False  # Section boundary
                continue
            
            if line.startswith('Average:'):
                header_found = False
                continue
            
            if 'cswch' in line and 'proc' in line:
                header_found = True
                data_columns = self._extract_data_columns(line, 'proc')
                continue
            
            if header_found and data_columns:
                match = re.match(self.TIMESTAMP_PATTERN, line)
                if match:
                    parts = line.split()
                    am_pm = parts[1] if len(parts) > 1 and parts[1] in ['AM', 'PM'] else None
                    offset = 2 if am_pm else 1
                    
                    timestamp = self.parse_timestamp(parts[0], am_pm)
                    if timestamp and len(parts) > offset:
                        fields = {}
                        for i, col in enumerate(data_columns):
                            idx = offset + i
                            if idx < len(parts):
                                try:
                                    fields[col.replace('/', '_')] = float(parts[idx])
                                except ValueError:
                                    pass
                        
                        if fields:
                            metrics.append({
                                'measurement': 'sar_context',
                                'timestamp': timestamp,
                                'fields': fields
                            })
                            self.summary['context'] += 1
        return metrics
    
    def parse_socket_metrics(self, lines: List[str]) -> List[dict]:
        """Parse socket statistics (V7 — totsck, tcpsck, udpsck, rawsck, ip-frag, tcp-tw)"""
        metrics = []
        header_found = False
        data_columns = []
        
        for line in lines:
            line = line.strip()
            if not line:
                header_found = False  # Section boundary
                continue
            
            if line.startswith('Average:'):
                header_found = False
                continue
            
            if 'totsck' in line and 'tcpsck' in line:
                header_found = True
                data_columns = self._extract_data_columns(line, 'totsck')
                continue
            
            if header_found and data_columns:
                match = re.match(self.TIMESTAMP_PATTERN, line)
                if match:
                    parts = line.split()
                    am_pm = parts[1] if len(parts) > 1 and parts[1] in ['AM', 'PM'] else None
                    offset = 2 if am_pm else 1
                    
                    timestamp = self.parse_timestamp(parts[0], am_pm)
                    if timestamp and len(parts) > offset:
                        fields = {}
                        for i, col in enumerate(data_columns):
                            idx = offset + i
                            if idx < len(parts):
                                try:
                                    fields[col.replace('-', '_')] = float(parts[idx])
                                except ValueError:
                                    pass
                        
                        if fields:
                            metrics.append({
                                'measurement': 'sar_socket',
                                'timestamp': timestamp,
                                'fields': fields
                            })
                            self.summary['socket'] += 1
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
        
        def categorize_children(parent):
            """Single-pass categorization of ALL descendant elements by tag name.
            Returns dict[local_tag_name] -> list of elements.
            Much faster than calling find_elements() repeatedly."""
            by_tag = {}
            for elem in parent.iter():
                tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                if tag not in by_tag:
                    by_tag[tag] = []
                by_tag[tag].append(elem)
            return by_tag
        
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
            
            # PERFORMANCE: single-pass categorization instead of repeated find_elements()
            ts_children = categorize_children(timestamp_elem)
            
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
            cpu_elements = ts_children.get('cpu', [])
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
            queue_elements = ts_children.get('queue', [])
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
            memory_elements = ts_children.get('memory', [])
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
            disk_elements = list(ts_children.get('disk', []))
            # Also try disk-device directly
            disk_device_elements = ts_children.get('disk-device', [])
            # Also try inside io element (disks inside io are already in ts_children)
            # No need to re-search — categorize_children already found all descendants
            
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
            net_elements = ts_children.get('net-dev', [])
            if not net_elements:
                net_elements = ts_children.get('net', [])
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
        
            # V7: Parse hugepages in XML
            hugepages_elements = ts_children.get('hugepages', [])
            for hp in hugepages_elements:
                fields = {}
                hp_map = {
                    'hugfree': 'kbhugfree', 'hugused': 'kbhugused',
                    'hugused-percent': 'pct_hugused', 'hugrsv': 'kbhugrsv',
                    'hugsurp': 'kbhugsurp',
                }
                for child in hp:
                    child_tag = local_tag(child)
                    if child_tag in hp_map and child.text:
                        try:
                            fields[hp_map[child_tag]] = float(child.text.strip())
                        except:
                            pass
                if not fields:
                    for attr, field_name in hp_map.items():
                        val = hp.get(attr)
                        if val:
                            try:
                                fields[field_name] = float(val)
                            except:
                                pass
                if fields:
                    metrics.append({
                        'measurement': 'sar_hugepages', 'timestamp': ts, 'fields': fields
                    })
                    self.summary['hugepages'] += 1
            
            # V7: Parse paging in XML (pgpgin, pgpgout, fault, majflt)
            paging_elements = ts_children.get('paging', [])
            for pg in paging_elements:
                fields = {}
                pg_map = {
                    'pgpgin': 'pgpgin_s', 'pgpgout': 'pgpgout_s',
                    'fault': 'fault_s', 'majflt': 'majflt_s',
                    'pgfree': 'pgfree_s', 'pgscank': 'pgscank_s',
                    'pgscand': 'pgscand_s', 'pgsteal': 'pgsteal_s',
                    'vmeff-percent': 'pct_vmeff',
                }
                for child in pg:
                    child_tag = local_tag(child)
                    if child_tag in pg_map and child.text:
                        try:
                            fields[pg_map[child_tag]] = float(child.text.strip())
                        except:
                            pass
                if not fields:
                    for attr, field_name in pg_map.items():
                        val = pg.get(attr)
                        if val:
                            try:
                                fields[field_name] = float(val)
                            except:
                                pass
                if fields:
                    metrics.append({
                        'measurement': 'sar_paging', 'timestamp': ts, 'fields': fields
                    })
                    self.summary['paging'] += 1
            
            # V7: Parse process-and-context-switch in XML
            proc_elements = ts_children.get('process-and-context-switch', [])
            for proc in proc_elements:
                fields = {}
                proc_map = {
                    'proc': 'proc_s', 'cswch': 'cswch_s',
                }
                for child in proc:
                    child_tag = local_tag(child)
                    if child_tag in proc_map and child.text:
                        try:
                            fields[proc_map[child_tag]] = float(child.text.strip())
                        except:
                            pass
                if not fields:
                    for attr, field_name in proc_map.items():
                        val = proc.get(attr)
                        if val:
                            try:
                                fields[field_name] = float(val)
                            except:
                                pass
                if fields:
                    metrics.append({
                        'measurement': 'sar_context', 'timestamp': ts, 'fields': fields
                    })
                    self.summary['context'] += 1
            
            # V7: Parse socket stats in XML
            # 'sock' elements are already categorized (they're descendants of 'network')
            sock_childs = ts_children.get('sock', [])
            for s in sock_childs:
                fields = {}
                sock_map = {
                    'totsck': 'totsck', 'tcpsck': 'tcpsck',
                    'udpsck': 'udpsck', 'rawsck': 'rawsck',
                    'ip-frag': 'ip_frag', 'tcp-tw': 'tcp_tw',
                }
                for child in s:
                    child_tag = local_tag(child)
                    if child_tag in sock_map and child.text:
                        try:
                            fields[sock_map[child_tag]] = float(child.text.strip())
                        except:
                            pass
                if not fields:
                    for attr, field_name in sock_map.items():
                        val = s.get(attr)
                        if val:
                            try:
                                fields[field_name] = float(val)
                            except:
                                pass
                if fields:
                    metrics.append({
                        'measurement': 'sar_socket', 'timestamp': ts, 'fields': fields
                    })
                    self.summary['socket'] += 1
        
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
        # V7 additional SAR sections
        metrics.extend(self.parse_swap_metrics(lines))
        metrics.extend(self.parse_hugepages_metrics(lines))
        metrics.extend(self.parse_paging_metrics(lines))
        metrics.extend(self.parse_context_switch_metrics(lines))
        metrics.extend(self.parse_socket_metrics(lines))
        
        return metrics
    
    def parse_all(self, progress_callback=None) -> List[dict]:
        """Parse all SAR files.
        
        Handles deduplication when both XML (CPU-only on old sysstat) and text sar*
        files exist for the same date. Text files win for measurements they cover,
        XML data is kept for any measurements not in the text files.
        
        Args:
            progress_callback: Optional callable(current, total, filename) for UI progress
        """
        sar_files = self.find_sar_files()
        
        # Separate XML and text files
        xml_files = [f for f in sar_files if f.endswith('.xml') or self._is_xml_content(f)]
        text_files = [f for f in sar_files if f not in xml_files]
        
        total_files = len(text_files) + len(xml_files)
        files_done = 0
        
        # Track which (date, measurement) combos we've seen from text files
        # Text files are authoritative — they have ALL metrics on RHEL 7
        text_keys = set()  # (date_str, measurement)
        text_dates = set()  # dates covered by text SAR files
        
        # Parse text files first (higher priority — contain all metrics)
        for filepath in text_files:
            if progress_callback:
                progress_callback(files_done, total_files, os.path.basename(filepath))
            file_metrics = self.parse_file(filepath)
            for m in file_metrics:
                ts = m.get('timestamp')
                if ts:
                    date_str = ts.strftime('%Y-%m-%d')
                    text_keys.add((date_str, m['measurement']))
                    text_dates.add(date_str)
            self.metrics.extend(file_metrics)
            files_done += 1
        
        # Determine date window from text files (if available)
        # XML sa??.xml files cycle monthly by day-of-month — sa25-sa30 may
        # belong to the PREVIOUS month.  Only accept XML data whose dates
        # fall within (or adjacent to) the text file date range.
        if text_dates:
            min_text_date = min(text_dates)
            max_text_date = max(text_dates)
        else:
            min_text_date = None
            max_text_date = None
        
        # Parse XML files — only keep metrics NOT already covered by text files
        # AND within the text-file date window
        # OPTIMIZATION: peek at <file-date> in XML header to skip files outside
        # the text date range entirely (avoids parsing hundreds of KB per file)
        xml_skipped_dates = set()
        xml_skipped_files = 0
        for filepath in xml_files:
            fname = os.path.basename(filepath)
            if progress_callback:
                progress_callback(files_done, total_files, fname)
            
            # Quick date check — read first 1KB to extract file-date without
            # full XML parsing.  Skip the entire file if outside text range.
            if min_text_date or max_text_date:
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
                        header = fh.read(1024)
                    import re as _re
                    dm = _re.search(r'<file-date>(\d{4}-\d{2}-\d{2})</file-date>', header)
                    if not dm:
                        dm = _re.search(r'date="(\d{4}-\d{2}-\d{2})"', header)
                    if dm:
                        xml_file_date = dm.group(1)
                        if (min_text_date and xml_file_date < min_text_date) or \
                           (max_text_date and xml_file_date > max_text_date):
                            xml_skipped_dates.add(xml_file_date)
                            xml_skipped_files += 1
                            files_done += 1
                            continue
                except Exception:
                    pass  # If peek fails, parse normally
            
            file_metrics = self.parse_file(filepath)
            deduped = []
            for m in file_metrics:
                ts = m.get('timestamp')
                if ts:
                    date_str = ts.strftime('%Y-%m-%d')
                    
                    # Skip XML data outside the text-file date range
                    if min_text_date and date_str < min_text_date:
                        xml_skipped_dates.add(date_str)
                        continue
                    if max_text_date and date_str > max_text_date:
                        xml_skipped_dates.add(date_str)
                        continue
                    
                    key = (date_str, m['measurement'])
                    if key not in text_keys:
                        deduped.append(m)
                        text_keys.add(key)
                else:
                    deduped.append(m)
            self.metrics.extend(deduped)
            files_done += 1
        
        if xml_skipped_dates:
            logging.info(f"Skipped {xml_skipped_files} XML files with dates outside text SAR range: {sorted(xml_skipped_dates)}")
        
        # Calculate metrics by date for debugging
        self.metrics_by_date = {}
        for m in self.metrics:
            ts = m.get('timestamp')
            if ts:
                date_str = ts.strftime('%Y-%m-%d')
                if date_str not in self.metrics_by_date:
                    self.metrics_by_date[date_str] = 0
                self.metrics_by_date[date_str] += 1
        
        # Debug: log measurement types found per source
        if not hasattr(self, 'debug_measurements_by_source'):
            self.debug_measurements_by_source = {}
        for filepath in sar_files:
            basename = os.path.basename(filepath)
            # Count will be populated after parsing
            self.debug_measurements_by_source[basename] = "parsed"
        
        return self.metrics
    
    def _is_xml_content(self, filepath: str) -> bool:
        """Check if file content is XML"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline()
                return '<?xml' in first_line or '<sysstat' in first_line
        except:
            return False


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
            'warn': 0,
        }
        self.critical_summary = {}  # Summary by category
        self._boot_time = None  # Calculated lazily by _get_boot_time()
    
    def _get_boot_time(self) -> Optional[datetime]:
        """Calculate system boot time from /proc/uptime + sosreport date.
        
        boot_time = sosreport_date - uptime_seconds
        This lets us convert dmesg [seconds.usec] to real timestamps.
        """
        if self._boot_time is not None:
            return self._boot_time if self._boot_time else None
        
        # Read /proc/uptime → "12345.67 99999.99" (seconds since boot)
        uptime_seconds = None
        proc_uptime = os.path.join(self.sosreport_path, 'proc', 'uptime')
        if os.path.isfile(proc_uptime):
            try:
                with open(proc_uptime, 'r') as f:
                    content = f.read().strip()
                    uptime_seconds = float(content.split()[0])
            except (ValueError, IndexError, IOError):
                pass
        
        if uptime_seconds is None:
            self._boot_time = False  # Sentinel: we tried and failed
            return None
        
        # Get sosreport generation time from the 'date' file
        sosreport_time = None
        date_files = [
            os.path.join(self.sosreport_path, 'date'),
            os.path.join(self.sosreport_path, 'sos_commands', 'date', 'date'),
            os.path.join(self.sosreport_path, 'sos_commands', 'general', 'date'),
        ]
        for df in date_files:
            if os.path.isfile(df):
                try:
                    with open(df, 'r') as f:
                        date_str = f.read().strip()
                    # Try common formats: "Thu Feb  6 10:30:45 UTC 2026"
                    for fmt in ["%a %b %d %H:%M:%S %Z %Y", "%a %b %d %H:%M:%S %Y",
                                 "%Y-%m-%d %H:%M:%S", "%a %b  %d %H:%M:%S %Z %Y"]:
                        try:
                            sosreport_time = datetime.strptime(date_str.strip(), fmt)
                            break
                        except ValueError:
                            continue
                    # Fallback: use dateutil-style parsing
                    if not sosreport_time:
                        # Try to extract with regex: "... HH:MM:SS ... YYYY"
                        m = re.match(r'.*?(\d{4})[-/](\d{1,2})[-/](\d{1,2})\s+(\d{2}:\d{2}:\d{2})', date_str)
                        if m:
                            sosreport_time = datetime.strptime(f"{m.group(1)}-{m.group(2)}-{m.group(3)} {m.group(4)}", "%Y-%m-%d %H:%M:%S")
                    if sosreport_time:
                        break
                except (IOError, OSError):
                    continue
        
        # Fallback: use file mtime of proc/uptime itself
        if not sosreport_time:
            try:
                mtime = os.path.getmtime(proc_uptime)
                sosreport_time = datetime.fromtimestamp(mtime)
            except OSError:
                pass
        
        if not sosreport_time:
            self._boot_time = False
            return None
        
        from datetime import timedelta
        self._boot_time = sosreport_time - timedelta(seconds=uptime_seconds)
        return self._boot_time
    
    def read_file(self, filepath: str):
        """Read log file line-by-line as a **generator** (Step 8 — streaming mode).

        Yields lines one at a time instead of loading the entire file into memory.
        For a 50 MB log file this avoids ~50 MB of temporary string allocation.
        Supports plain text, gzip, xz, and bz2 compressed files.
        """
        try:
            if filepath.endswith('.gz'):
                fh = gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore')
            elif filepath.endswith('.xz'):
                import lzma
                fh = lzma.open(filepath, 'rt', encoding='utf-8', errors='ignore')
            elif filepath.endswith('.bz2'):
                import bz2
                fh = bz2.open(filepath, 'rt', encoding='utf-8', errors='ignore')
            else:
                fh = open(filepath, 'r', encoding='utf-8', errors='ignore')
            with fh:
                for line in fh:
                    yield line
        except Exception:
            return
    
    def parse_syslog_line(self, line: str) -> Tuple[Optional[datetime], str, str]:
        """Parse syslog format line with smart year detection
        
        Supports:
          - BSD syslog:  "Jan 15 10:30:01 host prog[pid]: msg"
          - ISO 8601 (SUSE/rsyslog): "2026-01-15T10:30:01.123456+00:00 host prog[pid]: msg"
          - ISO 8601 short: "2026-01-15T10:30:01+00:00 host prog[pid]: msg"
        
        If log month > report month, the log is from the previous year (BSD format only).
        """
        # ── ISO 8601 timestamp (SUSE/SLES supportconfig format) ──
        iso_pattern = r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s*(.*)$'
        iso_match = re.match(iso_pattern, line)
        if iso_match:
            ts_str, hostname, program, message = iso_match.groups()
            try:
                timestamp = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")
                return timestamp, program, message
            except ValueError:
                pass

        # ── BSD syslog timestamp (RHEL/OL/CentOS format) ──
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
                dmesg, journalctl, maillog, yum/dnf logs, warn (SUSE).
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
            'warn': [],
        }
        
        var_log = os.path.join(self.sosreport_path, 'var', 'log')
        sos_cmds = os.path.join(self.sosreport_path, 'sos_commands')
        
        # ── messages (RHEL/OL primary system log) ──
        found_files['messages'] = self._glob_log_variants(
            var_log, 'messages',
            [os.path.join(sos_cmds, 'logs', '*messages*')]
        )
        
        # ── syslog (Debian/Ubuntu primary system log) ──
        found_files['syslog'] = self._glob_log_variants(
            var_log, 'syslog',
            [os.path.join(sos_cmds, 'logs', '*syslog*')]
        )
        
        # ── warn (SUSE/SLES warning log — equivalent of messages for warnings) ──
        found_files['warn'] = self._glob_log_variants(
            var_log, 'warn'
        )
        
        # ── secure (RHEL/OL auth log) ──
        found_files['secure'] = self._glob_log_variants(
            var_log, 'secure',
            [os.path.join(sos_cmds, 'logs', '*secure*')]
        )
        
        # ── auth.log (Debian/Ubuntu auth log) ──
        found_files['auth'] = self._glob_log_variants(
            var_log, 'auth.log'
        )
        
        # ── audit ──
        audit_dir = os.path.join(var_log, 'audit')
        found_files['audit'] = self._glob_log_variants(
            audit_dir, 'audit.log',
            [os.path.join(sos_cmds, 'auditd', '*')]
        )
        
        # ── cron ──
        found_files['cron'] = self._glob_log_variants(
            var_log, 'cron',
            [os.path.join(sos_cmds, 'logs', '*cron*')]
        )
        
        # ── dmesg (kernel ring buffer — critical for hardware/driver errors) ──
        dmesg_paths = [
            os.path.join(sos_cmds, 'kernel', 'dmesg'),
            os.path.join(sos_cmds, 'kernel', 'dmesg_-T'),  # dmesg with human timestamps
            os.path.join(var_log, 'dmesg'),
            os.path.join(var_log, 'dmesg.old'),
        ]
        found_files['dmesg'] = [f for f in dmesg_paths if os.path.isfile(f)]
        
        # ── journalctl (systemd journal — primary on Debian/Ubuntu, useful everywhere) ──
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
        
        # ── kern.log (Debian/Ubuntu kernel log) ──
        found_files['kern'] = self._glob_log_variants(var_log, 'kern.log')
        
        # ── boot.log ──
        boot_path = os.path.join(var_log, 'boot.log')
        if os.path.isfile(boot_path):
            found_files['boot'] = [boot_path]
        
        # ── maillog ──
        found_files['maillog'] = self._glob_log_variants(var_log, 'maillog')
        # Also check mail.log (Debian)
        found_files['maillog'].extend(self._glob_log_variants(var_log, 'mail.log'))
        
        # ── yum/dnf logs (package management activity) ──
        yum_path = os.path.join(var_log, 'yum.log')
        dnf_path = os.path.join(var_log, 'dnf.log')
        dnf_rpm_path = os.path.join(var_log, 'dnf.rpm.log')
        for p in [yum_path, dnf_path, dnf_rpm_path]:
            if os.path.isfile(p):
                found_files['yum_dnf'].append(p)
        # Also rotated variants
        found_files['yum_dnf'].extend(self._glob_log_variants(var_log, 'yum.log'))
        found_files['yum_dnf'].extend(self._glob_log_variants(var_log, 'dnf.log'))
        
        # ── apt logs (Ubuntu/Debian package management) ──
        apt_log_dir = os.path.join(var_log, 'apt')
        if os.path.isdir(apt_log_dir):
            found_files['yum_dnf'].extend(self._glob_log_variants(apt_log_dir, 'history.log'))
            found_files['yum_dnf'].extend(self._glob_log_variants(apt_log_dir, 'term.log'))
        
        # ── zypper logs (SUSE package management) ──
        zypper_log = os.path.join(var_log, 'zypper.log')
        if os.path.isfile(zypper_log):
            found_files['yum_dnf'].append(zypper_log)
        zypp_history = os.path.join(var_log, 'zypp', 'history')
        if os.path.isfile(zypp_history):
            found_files['yum_dnf'].append(zypp_history)
        
        # ── ufw (Ubuntu firewall) — log into kern/syslog category since UFW writes to kern.log ──
        # UFW also has its own /var/log/ufw.log on some setups
        found_files['kern'].extend(self._glob_log_variants(var_log, 'ufw.log'))
        
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
        """Parse dmesg output — handles epoch timestamps, [seconds.usec], and dmesg -T formats.
        
        For [seconds.usec] format, derives real timestamps using boot_time from /proc/uptime.
        Entries without any derivable timestamp are skipped (they can't be pushed to Loki).
        """
        entries = []
        lines = self.read_file(filepath)
        boot_time = self._get_boot_time()  # May be None if /proc/uptime unavailable
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            timestamp = None
            message = line
            program = 'kernel'
            
            # Format 1: [epoch timestamp] like dmesg -T → [Mon Dec 23 10:15:32 2025]
            dt_match = re.match(r'^\[([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+\d{4})\]\s*(.*)', line)
            if dt_match:
                try:
                    timestamp = datetime.strptime(dt_match.group(1), '%a %b %d %H:%M:%S %Y')
                    message = dt_match.group(2)
                except ValueError:
                    pass
            
            # Format 2: [seconds.usec] like standard dmesg → derive from boot_time
            if not timestamp:
                sec_match = re.match(r'^\[\s*([\d.]+)\]\s*(.*)', line)
                if sec_match:
                    message = sec_match.group(2)
                    if boot_time:
                        try:
                            from datetime import timedelta
                            seconds = float(sec_match.group(1))
                            timestamp = boot_time + timedelta(seconds=seconds)
                        except (ValueError, OverflowError):
                            pass
            
            # Only add entries with a valid timestamp (no-timestamp entries can't be pushed to Loki)
            if timestamp:
                entries.append({
                    'timestamp': timestamp,
                    'source': 'dmesg',
                    'program': program,
                    'message': message
                })
        
        return entries
    
    def parse_journal(self, filepath: str) -> List[dict]:
        """Parse journalctl output — handles systemd journal format"""
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
            
            # Only add entries with a valid timestamp
            if ts:
                entries.append({
                    'timestamp': ts,
                    'source': 'journal',
                    'program': program if program else 'journal',
                    'message': message
                })
        
        return entries
    
    def parse_all(self) -> List[dict]:
        """Parse all log files — parallelized with ThreadPoolExecutor.
        
        File I/O (especially gzip/xz decompression) is the bottleneck, so we
        parse multiple files concurrently.  Each file gets its own parser call;
        results are merged at the end.
        """
        import time as _perf_time
        _t_start = _perf_time.perf_counter()

        log_files = self.find_log_files()

        # Build a flat list of (log_type, filepath) tasks
        tasks = []
        for log_type, filepaths in log_files.items():
            for filepath in filepaths:
                tasks.append((log_type, filepath))

        # Parse files in parallel — I/O bound, so threads work well
        MAX_PARSE_WORKERS = min(8, max(1, len(tasks)))
        all_results = []   # list of (log_type, entries)

        def _parse_one(task):
            log_type, filepath = task
            if log_type == 'audit':
                entries = self.parse_audit(filepath)
            elif log_type == 'dmesg':
                entries = self.parse_dmesg(filepath)
            elif log_type == 'journal':
                entries = self.parse_journal(filepath)
            else:
                entries = self.parse_messages(filepath, log_type)
            return log_type, entries

        with ThreadPoolExecutor(max_workers=MAX_PARSE_WORKERS) as executor:
            futures = [executor.submit(_parse_one, t) for t in tasks]
            for future in as_completed(futures):
                try:
                    log_type, entries = future.result()
                    self.logs.extend(entries)
                    self.summary[log_type] += len(entries)
                except Exception as e:
                    logging.warning(f"Log parse worker failed: {e}")

        _t_io = _perf_time.perf_counter() - _t_start

        # Store found files for debugging
        self.found_files = log_files
        
        # Deduplicate entries — on Windows, tar symlinks get extracted as full copies,
        # causing the same log content to be parsed twice (e.g. messages + messages-20251224
        # when messages was a symlink). Dedup by (timestamp, source, message).
        seen = set()
        unique_logs = []
        for log in self.logs:
            key = (log.get('timestamp'), log.get('source', ''), log.get('message', ''))
            if key not in seen:
                seen.add(key)
                unique_logs.append(log)
        dupes_removed = len(self.logs) - len(unique_logs)
        if dupes_removed > 0:
            logging.info(f"Deduplicated {dupes_removed:,} duplicate log entries (likely from symlink copies)")
        self.logs = unique_logs
        
        # Calculate log entries by date for debugging
        self.logs_by_date = {}
        for log in self.logs:
            ts = log.get('timestamp')
            if ts:
                date_str = ts.strftime('%Y-%m-%d')
                if date_str not in self.logs_by_date:
                    self.logs_by_date[date_str] = 0
                self.logs_by_date[date_str] += 1
        
        # Detect critical events (uses pre-compiled patterns + prefilter)
        _t_ce = _perf_time.perf_counter()
        n_logs = len(self.logs)
        self.detect_critical_events()
        _t_ce_done = _perf_time.perf_counter() - _t_ce

        _mp_mode = "multiprocessing" if n_logs >= _MP_CRITICAL_THRESHOLD and (os.cpu_count() or 4) >= 2 else "single-thread"
        _t_total = _perf_time.perf_counter() - _t_start
        logging.info(
            f"Log parsing: {len(self.logs):,} entries from {len(tasks)} files "
            f"in {_t_total:.1f}s (I/O: {_t_io:.1f}s, critical scan: {_t_ce_done:.1f}s [{_mp_mode}]) | "
            f"{MAX_PARSE_WORKERS} I/O workers"
        )
        
        return self.logs
    
    def detect_critical_events(self):
        """Scan all logs for critical event patterns.

        Two execution paths (chosen automatically):
        ┌─────────────────────────────────────────────────────────────────────┐
        │  Small sets (<80 K entries)  → single-threaded prefilter scan      │
        │  Large sets (≥80 K entries)  → ProcessPoolExecutor (Step 10)       │
        │      Splits logs into N chunks (N = cpu_count), each process runs  │
        │      prefilter + category matching — bypasses the GIL entirely.    │
        └─────────────────────────────────────────────────────────────────────┘

        Both paths use:
        - _PREFILTER_RE   → single regex rejects 99 %+ of lines instantly
        - _COMPILED_LOG_PATTERNS → per-category compiled regexes (Step 9)
        """
        self.critical_events = []
        self.critical_summary = {category: 0 for category in LOG_PATTERNS.keys()}
        self.severity_counts = {'critical': 0, 'warning': 0, 'info': 0}

        n_logs = len(self.logs)
        n_cpus = os.cpu_count() or 4

        # ── Multiprocessing path (Step 9 + 10) ──────────────────────────────
        if n_logs >= _MP_CRITICAL_THRESHOLD and n_cpus >= 2:
            n_workers = min(n_cpus, 8)
            chunk_size = max(1, n_logs // n_workers)
            chunks = [self.logs[i:i + chunk_size] for i in range(0, n_logs, chunk_size)]

            logging.info(
                f"Critical-event scan: multiprocessing with {len(chunks)} chunks "
                f"across {n_workers} workers ({n_logs:,} logs)"
            )

            try:
                with ProcessPoolExecutor(max_workers=n_workers) as pool:
                    futures = [pool.submit(_detect_critical_chunk, chunk) for chunk in chunks]
                    for fut in as_completed(futures):
                        events, cat_counts, sev_counts = fut.result()
                        self.critical_events.extend(events)
                        for k, v in cat_counts.items():
                            self.critical_summary[k] += v
                        for k, v in sev_counts.items():
                            self.severity_counts[k] += v
                return  # done
            except Exception as e:
                # Fall back to single-threaded on any multiprocessing error
                logging.warning(f"Multiprocessing critical scan failed ({e}), falling back to single-thread")
                self.critical_events = []
                self.critical_summary = {cat: 0 for cat in LOG_PATTERNS}
                self.severity_counts = {'critical': 0, 'warning': 0, 'info': 0}

        # ── Single-threaded path (small sets or fallback) ────────────────────
        prefilter = _PREFILTER_RE
        compiled_patterns = _COMPILED_LOG_PATTERNS

        for log in self.logs:
            message = log.get('message', '')
            if not message:
                continue

            # FAST PRE-FILTER: single regex check — skips 99%+ of lines instantly
            if not prefilter.search(message):
                continue
            
            # Only lines that pass prefilter get the full per-category scan
            for category, compiled_list in compiled_patterns.items():
                for compiled_re, original_pattern in compiled_list:
                    if compiled_re.search(message):
                        severity = classify_event_severity(message, original_pattern)
                        self.critical_events.append({
                            'timestamp': log.get('timestamp'),
                            'source': log.get('source'),
                            'program': log.get('program'),
                            'message': message,
                            'category': category,
                            'pattern': original_pattern,
                            'severity': severity
                        })
                        self.critical_summary[category] += 1
                        self.severity_counts[severity] += 1
                        break  # Only count once per category per log line


# ============================================================================
# DATA PUSHERS
# ============================================================================

def delete_influxdb_host_data(hostname: str) -> Tuple[bool, str]:
    """Delete ALL existing data for a hostname from InfluxDB before re-uploading.
    
    This prevents stale data from previous uploads from contaminating the
    Grafana time range (e.g., old Nov 25 CPU data mixed with new Dec 20-24 data).
    Uses InfluxDB v2 /api/v2/delete endpoint.
    """
    url = f"{INFLUXDB_URL}/api/v2/delete?org={INFLUXDB_ORG}&bucket={INFLUXDB_BUCKET}"
    headers = {
        "Authorization": f"Token {INFLUXDB_TOKEN}",
        "Content-Type": "application/json"
    }
    safe_hostname = hostname.replace(' ', '_').replace(',', '_')
    payload = {
        "start": "1970-01-01T00:00:00Z",
        "stop": "2099-12-31T23:59:59Z",
        "predicate": f'host="{safe_hostname}"'
    }
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=120)
        if resp.status_code == 204:
            return True, ""
        else:
            return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return False, str(e)[:200]


def delete_loki_host_data(hostname: str) -> Tuple[bool, str]:
    """Delete log data for a hostname from Loki.
    
    Uses Loki's /loki/api/v1/delete endpoint (requires compactor or
    deletion API enabled). Falls back gracefully if not supported.
    """
    safe_hostname = hostname.replace(' ', '_').replace(',', '_')
    # Loki delete API uses LogQL matchers and a time range
    # end must not be in the future — Loki rejects future deletes
    now_utc = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    params = {
        "query": f'{{host="{safe_hostname}"}}',
        "start": "1970-01-01T00:00:00Z",
        "end": now_utc
    }
    try:
        resp = requests.post(
            f"{LOKI_URL}/loki/api/v1/delete",
            params=params,
            timeout=120
        )
        if resp.status_code in (200, 204):
            return True, ""
        elif resp.status_code == 404:
            return False, "Loki delete API not enabled (requires compactor config)"
        else:
            return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return False, str(e)[:200]


def delete_grafana_dashboard(hostname: str) -> Tuple[bool, str]:
    """Delete the Grafana dashboard for a hostname."""
    safe_host = re.sub(r'[^a-zA-Z0-9_-]', '-', hostname)[:36]
    uid = f"web-{safe_host}"
    try:
        resp = requests.delete(
            f"{GRAFANA_URL}/api/dashboards/uid/{uid}",
            headers={"Authorization": f"Bearer {_get_grafana_api_key()}"},
            timeout=15
        )
        if resp.status_code == 200:
            return True, ""
        elif resp.status_code == 404:
            return True, "Dashboard not found (already deleted)"
        else:
            return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return False, str(e)[:200]


def cleanup_all_host_data(hostname: str) -> dict:
    """Delete ALL customer data for a hostname from all backends.
    
    Returns dict with status for each service.
    Used for data privacy compliance — removes all traces of customer data.
    """
    results = {}
    
    # 1. Delete from InfluxDB
    ok, err = delete_influxdb_host_data(hostname)
    results['influxdb'] = {'ok': ok, 'error': err}
    
    # 2. Delete from Loki
    ok, err = delete_loki_host_data(hostname)
    results['loki'] = {'ok': ok, 'error': err}
    
    # 3. Delete Grafana dashboard
    ok, err = delete_grafana_dashboard(hostname)
    results['grafana'] = {'ok': ok, 'error': err}
    
    return results


def cleanup_stale_temp_dirs(max_age_hours: int = 4):
    """Remove stale sosreport_web_* temp directories left by crashed sessions.
    
    Called on app startup to prevent disk space leaks.
    """
    import glob
    import time as _t
    temp_base = tempfile.gettempdir()
    pattern = os.path.join(temp_base, 'sosreport_web_*')
    now = _t.time()
    cleaned = 0
    for path in glob.glob(pattern):
        try:
            mtime = os.path.getmtime(path)
            age_hours = (now - mtime) / 3600
            if age_hours > max_age_hours:
                shutil.rmtree(path, ignore_errors=True)
                cleaned += 1
        except Exception:
            pass
    if cleaned > 0:
        logging.info(f"Cleaned up {cleaned} stale temp directories (>{max_age_hours}h old)")
    return cleaned


def _create_resilient_session(token: str = None, content_type: str = "text/plain") -> requests.Session:
    """Create a requests.Session with connection pooling and automatic retry.

    - Connection pooling: keeps TCP connections alive across batches (no re-handshake).
    - Retry on 429 / 500-503 with exponential backoff (0.5s, 1s, 2s).
    - Pool size 10 = up to 10 parallel connections to the same host.
    """
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=0.5,           # 0.5s → 1s → 2s
        status_forcelist=[429, 500, 502, 503],
        allowed_methods=["POST", "GET", "DELETE"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=10,
        pool_maxsize=10,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    headers = {"Content-Type": content_type}
    if token:
        headers["Authorization"] = f"Token {token}"
    session.headers.update(headers)
    return session


def push_sar_to_influxdb(metrics: List[dict], hostname: str, progress_callback=None) -> Tuple[int, str]:
    """Push SAR metrics to InfluxDB — enterprise-grade with session pooling,
    10k batches, gzip, ThreadPoolExecutor, retry+backoff, and throughput metrics.

    Returns: (pushed_count, error_message)
    """
    if not metrics:
        return 0, "No metrics to push"

    t_start = _time_mod.perf_counter()

    url = f"{INFLUXDB_URL}/api/v2/write?org={INFLUXDB_ORG}&bucket={INFLUXDB_BUCKET}&precision=s"

    BATCH_SIZE = 10_000      # InfluxDB optimal: 5k-10k lines per write
    MAX_WORKERS = 4          # parallel HTTP connections
    TIMEOUT = 45             # seconds per request
    GZIP_THRESHOLD = 1024    # compress anything > 1KB

    # ---- 1. Build all line-protocol strings (CPU-bound, fast) ----
    all_lines = []
    for m in metrics:
        measurement = m['measurement']

        # Build fields string - only numeric values
        fields_list = []
        for k, v in m['fields'].items():
            if isinstance(v, (int, float)) and k not in ['DEV', 'IFACE', 'cpu']:
                field_name = k.replace(' ', '_').replace('/', '_').replace('%', 'pct_')
                fields_list.append(f'{field_name}={v}')

        if not fields_list:
            continue

        fields = ','.join(fields_list)

        # Build tags
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
            except Exception:
                pass

        if ts_unix:
            all_lines.append(f"{measurement},{tags} {fields} {ts_unix}")

    if not all_lines:
        return 0, "No valid metrics to push"

    # ---- 2. Split into 10k-line batches ----
    batches = [all_lines[i:i + BATCH_SIZE] for i in range(0, len(all_lines), BATCH_SIZE)]

    # ---- 3. Push concurrently with pooled session + gzip + retry ----
    session = _create_resilient_session(token=INFLUXDB_TOKEN, content_type="text/plain")

    pushed = 0
    errors = []
    _lock = threading.Lock()

    def _send_batch(idx_batch):
        idx, lines = idx_batch
        data = '\n'.join(lines).encode('utf-8')
        raw_size = len(data)

        # Gzip compress if > threshold
        headers = {}
        if raw_size > GZIP_THRESHOLD:
            data = gzip.compress(data, compresslevel=6)
            headers["Content-Encoding"] = "gzip"

        try:
            resp = session.post(url, data=data, headers=headers, timeout=TIMEOUT)
            if resp.status_code == 204:
                return len(lines), None, raw_size, len(data)
            elif resp.status_code == 429:
                # Rate limited — wait and retry once manually
                retry_after = int(resp.headers.get('Retry-After', '2'))
                _time_mod.sleep(retry_after)
                resp2 = session.post(url, data=data, headers=headers, timeout=TIMEOUT)
                if resp2.status_code == 204:
                    return len(lines), None, raw_size, len(data)
                return 0, f"Batch {idx}: HTTP {resp2.status_code} (after 429 retry)", raw_size, len(data)
            else:
                return 0, f"Batch {idx}: HTTP {resp.status_code} - {resp.text[:100]}", raw_size, len(data)
        except requests.exceptions.Timeout:
            return 0, f"Batch {idx}: Timeout after {TIMEOUT}s", raw_size, len(data)
        except Exception as e:
            return 0, f"Batch {idx}: {str(e)[:100]}", raw_size, 0

    total_raw = 0
    total_compressed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(_send_batch, (i, b)): i for i, b in enumerate(batches)}
        for future in as_completed(futures):
            count, err, raw, comp = future.result()
            with _lock:
                pushed += count
                total_raw += raw
                total_compressed += comp
                if err:
                    errors.append(err)

    session.close()

    # ---- 4. Throughput metrics ----
    elapsed = _time_mod.perf_counter() - t_start
    rate = pushed / elapsed if elapsed > 0 else 0
    compress_ratio = (1 - total_compressed / total_raw) * 100 if total_raw > 0 else 0

    logging.info(
        f"InfluxDB push: {pushed:,}/{len(all_lines):,} metrics in {elapsed:.2f}s "
        f"({rate:,.0f} metrics/sec) | {len(batches)} batches × {MAX_WORKERS} workers | "
        f"gzip {compress_ratio:.0f}% reduction ({total_raw/1024:.0f}KB → {total_compressed/1024:.0f}KB)"
    )

    error_msg = "; ".join(errors[:5]) if errors else ""
    if pushed > 0 and not error_msg:
        error_msg = ""  # clean success
    return pushed, error_msg


def push_logs_to_loki(logs: List[dict], hostname: str, progress_callback=None) -> Tuple[int, str, str]:
    """Push logs to Loki — enterprise-grade with session pooling, gzip,
    retry+backoff, ns dedup, and throughput metrics.

    Loki requires strictly monotonic timestamps per stream, so each stream's
    batches are sent sequentially.  Different streams are pushed in parallel
    via ThreadPoolExecutor (safe because Loki orders per-stream, not globally).

    Returns: (pushed_count, error_message, info_message)
    """
    if not logs:
        return 0, "No logs to push", ""

    import json as _json
    t_start = _time_mod.perf_counter()

    url = f"{LOKI_URL}/loki/api/v1/push"
    BATCH_SIZE = 5000
    TIMEOUT = 45
    GZIP_THRESHOLD = 1024
    MAX_STREAM_WORKERS = 3   # parallel streams (each stream still sequential internally)

    # ---- 1. Group by source, skip entries without timestamps ----
    streams: Dict[str, list] = {}
    skipped = 0
    for log in logs:
        if not log.get('timestamp'):
            skipped += 1
            continue
        source = log['source']
        if source not in streams:
            streams[source] = []
        ts_ns = str(int(log['timestamp'].timestamp() * 1e9))
        msg = f"[{log['program']}] {log['message']}"
        streams[source].append([ts_ns, msg])

    if not streams:
        return 0, f"No timestamped logs to push ({skipped} skipped)", ""

    # Sort + deduplicate timestamps per stream (ns offsets for same-second entries)
    for source in streams:
        streams[source].sort(key=lambda x: x[0])
        deduped = []
        prev_ts = None
        offset = 0
        for ts_ns, msg in streams[source]:
            if ts_ns == prev_ts:
                offset += 1
                deduped.append([str(int(ts_ns) + offset), msg])
            else:
                prev_ts = ts_ns
                offset = 0
                deduped.append([ts_ns, msg])
        streams[source] = deduped

    # Filter entries too old for Loki ingester
    LOKI_MAX_AGE_HOURS = 720
    age_filtered = 0
    max_ts_ns = 0
    for source_vals in streams.values():
        if source_vals:
            max_ts_ns = max(max_ts_ns, int(source_vals[-1][0]))

    if max_ts_ns > 0:
        cutoff_ns = max_ts_ns - (LOKI_MAX_AGE_HOURS * 3600 * 10**9)
        for source in list(streams.keys()):
            original_len = len(streams[source])
            streams[source] = [v for v in streams[source] if int(v[0]) >= cutoff_ns]
            age_filtered += original_len - len(streams[source])
        if age_filtered > 0:
            logging.warning(f"Loki: filtered {age_filtered:,} entries older than {LOKI_MAX_AGE_HOURS}h")

    # ---- 2. Push streams in parallel, batches within each stream sequentially ----
    session = _create_resilient_session(content_type="application/json")
    total_raw = 0
    total_compressed = 0

    def _push_stream(source: str, values: list) -> Tuple[int, list, int, int]:
        """Push one stream's batches sequentially. Returns (count, errors, raw, compressed)."""
        stream_pushed = 0
        stream_errors = []
        stream_raw = 0
        stream_comp = 0

        for batch_start in range(0, len(values), BATCH_SIZE):
            batch = values[batch_start:batch_start + BATCH_SIZE]
            payload = {
                "streams": [{
                    "stream": {"host": hostname, "source": source, "job": "sosreport"},
                    "values": batch
                }]
            }

            data = _json.dumps(payload).encode('utf-8')
            raw_size = len(data)
            stream_raw += raw_size

            headers = {}
            if raw_size > GZIP_THRESHOLD:
                data = gzip.compress(data, compresslevel=6)
                headers["Content-Encoding"] = "gzip"
                headers["Content-Type"] = "application/json"
            stream_comp += len(data)

            try:
                resp = session.post(url, data=data, headers=headers, timeout=TIMEOUT)
                if resp.status_code == 204:
                    stream_pushed += len(batch)
                elif resp.status_code == 429:
                    retry_after = int(resp.headers.get('Retry-After', '2'))
                    _time_mod.sleep(retry_after)
                    resp2 = session.post(url, data=data, headers=headers, timeout=TIMEOUT)
                    if resp2.status_code == 204:
                        stream_pushed += len(batch)
                    else:
                        stream_errors.append(f"{source} batch {batch_start//BATCH_SIZE}: HTTP {resp2.status_code} (after 429)")
                else:
                    stream_errors.append(f"{source} batch {batch_start//BATCH_SIZE}: HTTP {resp.status_code} - {resp.text[:100]}")
            except requests.exceptions.Timeout:
                stream_errors.append(f"{source} batch {batch_start//BATCH_SIZE}: Timeout {TIMEOUT}s")
            except Exception as e:
                stream_errors.append(f"{source} batch {batch_start//BATCH_SIZE}: {str(e)[:80]}")

        return stream_pushed, stream_errors, stream_raw, stream_comp

    pushed = 0
    errors = []

    # Parallel across streams (each stream is independent in Loki)
    with ThreadPoolExecutor(max_workers=MAX_STREAM_WORKERS) as executor:
        futures = {executor.submit(_push_stream, src, vals): src for src, vals in streams.items()}
        for future in as_completed(futures):
            count, errs, raw, comp = future.result()
            pushed += count
            errors.extend(errs)
            total_raw += raw
            total_compressed += comp

    session.close()

    # ---- 3. Throughput metrics ----
    elapsed = _time_mod.perf_counter() - t_start
    rate = pushed / elapsed if elapsed > 0 else 0
    compress_ratio = (1 - total_compressed / total_raw) * 100 if total_raw > 0 else 0
    total_entries = sum(len(v) for v in streams.values())

    logging.info(
        f"Loki push: {pushed:,}/{total_entries:,} logs in {elapsed:.2f}s "
        f"({rate:,.0f} entries/sec) | {len(streams)} streams × {MAX_STREAM_WORKERS} workers | "
        f"gzip {compress_ratio:.0f}% reduction ({total_raw/1024:.0f}KB → {total_compressed/1024:.0f}KB)"
    )

    error_msg = "; ".join(errors[:5]) if errors else ""
    if skipped > 0:
        skip_note = f"({skipped} entries without timestamp skipped)"
        error_msg = f"{error_msg}; {skip_note}" if error_msg else skip_note
    info_msg = ""
    if age_filtered > 0:
        info_msg = f"{age_filtered:,} old log entries filtered (older than {LOKI_MAX_AGE_HOURS}h before newest log — Loki would reject these)"
    return pushed, error_msg, info_msg


def push_critical_events_to_loki(critical_events: List[dict], hostname: str, progress_callback=None) -> Tuple[int, str]:
    """Push critical events to Loki with category labels.
    Uses session pooling, gzip, retry+backoff, and ns dedup.

    Returns: (pushed_count, error_message)
    """
    if not critical_events:
        return 0, ""

    import json as _json
    t_start = _time_mod.perf_counter()

    url = f"{LOKI_URL}/loki/api/v1/push"
    BATCH_SIZE = 2000
    TIMEOUT = 30
    GZIP_THRESHOLD = 1024

    # Group by category
    streams_by_category: Dict[str, list] = {}
    for event in critical_events:
        category = event.get('category', 'Unknown')
        if category not in streams_by_category:
            streams_by_category[category] = []
        ts = event.get('timestamp')
        if ts:
            ts_ns = str(int(ts.timestamp() * 1e9))
            msg = f"[{event.get('program', '')}] {event.get('message', '')}"
            streams_by_category[category].append([ts_ns, msg])

    session = _create_resilient_session(content_type="application/json")
    pushed = 0
    errors = []

    for category, values in streams_by_category.items():
        # Sort + deduplicate ns timestamps
        values.sort(key=lambda x: x[0])
        deduped = []
        prev_ts = None
        offset = 0
        for ts_ns, msg in values:
            if ts_ns == prev_ts:
                offset += 1
                deduped.append([str(int(ts_ns) + offset), msg])
            else:
                prev_ts = ts_ns
                offset = 0
                deduped.append([ts_ns, msg])
        values = deduped

        for i in range(0, len(values), BATCH_SIZE):
            batch = values[i:i + BATCH_SIZE]
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

            data = _json.dumps(payload).encode('utf-8')
            headers = {}
            if len(data) > GZIP_THRESHOLD:
                data = gzip.compress(data, compresslevel=6)
                headers["Content-Encoding"] = "gzip"
                headers["Content-Type"] = "application/json"

            try:
                resp = session.post(url, data=data, headers=headers, timeout=TIMEOUT)
                if resp.status_code == 204:
                    pushed += len(batch)
                elif resp.status_code == 429:
                    _time_mod.sleep(int(resp.headers.get('Retry-After', '2')))
                    resp2 = session.post(url, data=data, headers=headers, timeout=TIMEOUT)
                    if resp2.status_code == 204:
                        pushed += len(batch)
                    else:
                        errors.append(f"{category}: HTTP {resp2.status_code} (after 429)")
                else:
                    errors.append(f"{category}: HTTP {resp.status_code}")
            except Exception as e:
                errors.append(f"{category}: {str(e)[:50]}")

        if progress_callback:
            progress_callback(pushed, len(critical_events))

    session.close()

    elapsed = _time_mod.perf_counter() - t_start
    total_events = sum(len(v) for v in streams_by_category.values())
    logging.info(f"Loki critical push: {pushed:,}/{total_events:,} events in {elapsed:.2f}s")

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
    api_key = _get_grafana_api_key()
    if not api_key:
        logging.error("Grafana API key is empty — cannot create dashboard")
        return None
    session.headers['Authorization'] = f'Bearer {api_key}'
    
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
    else:
        logging.error(f"Grafana datasources API returned {response.status_code}: {response.text[:200]}")
    
    if not influx_uid or not loki_uid:
        logging.error(f"Missing datasource UIDs: influx={influx_uid}, loki={loki_uid}")
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

    # Per-CPU Usage % — uses pct_user (simple, always available, works with 96+ CPUs)
    # For many-CPU systems, aggregateWindow reduces data points enough to stay under Grafana limits
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "custom": {"lineWidth": 1, "fillOpacity": 5}, "unit": "percent", "max": 100, "min": 0}},
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": y_pos},
        "id": panel_id,
        "maxDataPoints": 200,
        "options": {"legend": {"displayMode": "table", "placement": "right", "calcs": ["mean", "max"]}, "tooltip": {"mode": "multi", "sort": "desc"}},
        "targets": [
            {"datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'from(bucket: "{INFLUXDB_BUCKET}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r["_measurement"] == "sar_cpu") |> filter(fn: (r) => r["host"] == "{hostname}") |> filter(fn: (r) => r["cpu"] != "all") |> filter(fn: (r) => r["_field"] == "pct_idle") |> map(fn: (r) => ({{r with _value: 100.0 - r._value}})) |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)',
            "refId": "A"}
        ],
        "title": "Per-CPU Usage % (100 - idle)",
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
    
    # Disk I/O — read + write throughput per device
    # Uses aggregateWindow to reduce data points; no device filter (dev252-0 etc. are valid names)
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "custom": {"lineWidth": 2, "fillOpacity": 10}, "unit": "KBs"},
                        "overrides": []},
        "gridPos": {"h": 6, "w": 12, "x": 0, "y": y_pos},
        "id": panel_id,
        "maxDataPoints": 500,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        "targets": [
            {"datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'from(bucket: "{INFLUXDB_BUCKET}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r["_measurement"] == "sar_disk") |> filter(fn: (r) => r["host"] == "{hostname}") |> filter(fn: (r) => r["_field"] == "rkB_s" or r["_field"] == "wkB_s" or r["_field"] == "rd_sec_s" or r["_field"] == "wr_sec_s") |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)',
            "refId": "A"}],
        "title": "Disk I/O (KB/s or sectors/s)",
        "type": "timeseries"
    })
    panel_id += 1
    
    # Disk Utilization % per device
    panels.append({
        "datasource": {"type": "influxdb", "uid": influx_uid},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "custom": {"lineWidth": 2, "fillOpacity": 10}, "unit": "percent", "max": 100}},
        "gridPos": {"h": 6, "w": 12, "x": 12, "y": y_pos},
        "id": panel_id,
        "maxDataPoints": 500,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        "targets": [{"datasource": {"type": "influxdb", "uid": influx_uid},
            "query": f'from(bucket: "{INFLUXDB_BUCKET}") |> range(start: v.timeRangeStart, stop: v.timeRangeStop) |> filter(fn: (r) => r["_measurement"] == "sar_disk") |> filter(fn: (r) => r["host"] == "{hostname}") |> filter(fn: (r) => r["_field"] == "pct_util") |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)',
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
        "title": "📋 Log Analysis",
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
        "title": "📄 System Messages (/var/log/messages)",
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
        "title": "🔐 Security/Auth Logs (/var/log/secure)",
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
        "title": "🛡️ Audit Logs (/var/log/audit/audit.log)",
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
        "title": "⏰ Cron Logs (/var/log/cron)",
        "type": "logs"
    })
    panel_id += 1
    y_pos += 6
    
    # NOTE: Critical Events are displayed in Streamlit main page only (removed from Grafana to reduce load)
    
    # Build dashboard with auto time range
    # Use provided timestamps or fallback to last year
    if time_from and time_to:
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
        # Use external URL for browser-facing links (GRAFANA_URL may be internal Docker hostname)
        return f"{GRAFANA_EXTERNAL_URL}{result.get('url', '')}"
    
    logging.error(f"Grafana dashboard creation failed: {response.status_code} {response.text[:300]}")
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
        headers = {"Authorization": f"Bearer {_get_grafana_api_key()}"}
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
    # Startup: clean stale temp dirs from crashed sessions
    if 'startup_cleanup_done' not in st.session_state:
        cleaned = cleanup_stale_temp_dirs(max_age_hours=4)
        st.session_state.startup_cleanup_done = True
        if cleaned > 0:
            logging.info(f"Startup: cleaned {cleaned} stale temp dirs")
    
    st.markdown('<h1 class="main-header">📊 SOSreport & Supportconfig Analyzer V8</h1>', unsafe_allow_html=True)
    st.markdown("---")
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # Session Info
        st.subheader("📊 Session Info")
        import uuid
        if 'session_id' not in st.session_state:
            st.session_state.session_id = str(uuid.uuid4())[:8]
        st.text(f"Session: {st.session_state.session_id}")
        
        # Show active processing sessions (cross-session visibility)
        with _active_sessions_lock:
            active_count = len(_active_sessions)
            active_details = list(_active_sessions.values())
        st.text(f"Active sessions: {active_count}/{MAX_CONCURRENT_EXTRACTIONS}")
        if active_details:
            for detail in active_details:
                _host = detail.get('hostname', 'unknown')
                _phase = detail.get('phase', 'processing')
                st.caption(f"  ↳ {_host}: {_phase}")
        
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
        st.subheader("🔌 Service Connectivity")
        
        # Auto-check on first load (local Docker = fast), manual refresh via button
        if 'service_status' not in st.session_state:
            st.session_state.service_status = get_all_service_status()
            st.session_state.last_health_check = datetime.now()
        
        if st.button("🔄 Refresh Status", key="health_check"):
            with st.spinner("Checking backends..."):
                st.session_state.service_status = get_all_service_status()
                st.session_state.last_health_check = datetime.now()
                st.rerun()
        
        # Display status
        status = st.session_state.service_status
        
        # Display InfluxDB status
        influx_ok, influx_msg = status['influxdb']
        if influx_ok:
            st.markdown(f"🟢 **InfluxDB**: {influx_msg}")
        else:
            st.markdown(f"🔴 **InfluxDB**: {influx_msg}")
        st.caption(f"   {INFLUXDB_EXTERNAL_URL}")
        
        # Display Loki status
        loki_ok, loki_msg = status['loki']
        if loki_ok:
            st.markdown(f"🟢 **Loki**: {loki_msg}")
        else:
            st.markdown(f"🔴 **Loki**: {loki_msg}")
        st.caption(f"   {LOKI_EXTERNAL_URL}")
        
        # Display Grafana status
        grafana_ok, grafana_msg = status['grafana']
        if grafana_ok:
            st.markdown(f"🟢 **Grafana**: {grafana_msg}")
        else:
            st.markdown(f"🔴 **Grafana**: {grafana_msg}")
        st.caption(f"   {GRAFANA_EXTERNAL_URL}")
        
        # Show last check time
        if 'last_health_check' in st.session_state:
            st.caption(f"Last checked: {st.session_state.last_health_check.strftime('%H:%M:%S')}")
        
        # Show warning if any service is down
        all_ok = influx_ok and loki_ok and grafana_ok
        if not all_ok:
            st.warning("⚠️ Some services are down!")
        
        st.markdown("---")
        st.markdown("### 📖 Instructions")
        st.markdown("""
        1. Upload a SOSreport (.tar.xz, .tar.gz) or SUSE Supportconfig archive
        2. Wait for extraction and parsing
        3. Review the analysis summary
        4. Push data to InfluxDB/Loki
        5. View dashboard in Grafana
        """)
        
        st.markdown("---")
        st.subheader("🔒 Data Privacy")
        st.markdown("""
        **Local data**: Extracted files are automatically 
        deleted after processing (temp directory cleanup).
        
        **Remote data**: SAR metrics (InfluxDB), logs (Loki), 
        and dashboards (Grafana) persist until manually purged.
        
        Use **🗑️ Purge Host Data** below after your analysis 
        to remove all customer data from backends.
        """)
        
        # Data purge controls
        purge_hostname = st.text_input(
            "Hostname to purge", 
            value=st.session_state.get('last_hostname', ''),
            key="purge_host",
            help="Enter the hostname whose data you want to delete from all backends"
        )
        if st.button("🗑️ Purge Host Data", type="secondary", key="purge_btn"):
            if purge_hostname:
                st.session_state['purge_confirm'] = purge_hostname
            else:
                st.warning("Enter a hostname first")
        
        # Confirmation step
        if 'purge_confirm' in st.session_state:
            host_to_purge = st.session_state['purge_confirm']
            st.warning(f"⚠️ Delete ALL data for **{host_to_purge}**?")
            col_yes, col_no = st.columns(2)
            with col_yes:
                if st.button("✅ Confirm", key="purge_yes"):
                    with st.spinner(f"Purging {host_to_purge}..."):
                        results = cleanup_all_host_data(host_to_purge)
                    for svc, r in results.items():
                        if r['ok']:
                            st.success(f"✅ {svc}: purged")
                        else:
                            st.error(f"❌ {svc}: {r['error']}")
                    del st.session_state['purge_confirm']
            with col_no:
                if st.button("❌ Cancel", key="purge_no"):
                    del st.session_state['purge_confirm']
        
        st.markdown("---")
        st.caption(f"Max concurrent: {MAX_CONCURRENT_EXTRACTIONS}")
        st.caption(f"Max SAR metrics: {MAX_SAR_METRICS:,}")
        st.caption(f"Max log lines: {MAX_LOG_LINES:,}")
    
    # Main area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.header("📁 Upload SOSreport / Supportconfig")
        uploaded_file = st.file_uploader(
            "Choose a SOSreport file",
            type=['tar.xz', 'tar.gz', 'tgz', 'tar.bz2', 'tar', 'txz'],
            help="Upload a compressed SOSreport or SUSE Supportconfig archive"
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
        # Clear cached results when a different file is uploaded
        if st.session_state.get('_analysis_filename') != uploaded_file.name:
            st.session_state.pop('_analysis_data', None)
            st.session_state.pop('_processing', None)
            st.session_state['_analysis_filename'] = uploaded_file.name
        
        _is_processing = st.session_state.get('_processing', False)
        process_clicked = st.button(
            "⏳ Processing — please wait..." if _is_processing else " Process SOSreport",
            type="primary",
            use_container_width=True,
            disabled=_is_processing
        )
        
        # === PROCESSING (only on button click) ===
        if process_clicked:
            st.session_state['_processing'] = True
            st.rerun()
        
        if st.session_state.get('_processing', False):
            temp_dir = None
            
            try:
                _time = _time_mod  # use module-level import
                _timings = {}  # phase -> seconds
                _total_start = _time.time()
                
                # Register this session as active
                _sid = st.session_state.get('session_id', 'unknown')
                with _active_sessions_lock:
                    _active_sessions[_sid] = {'hostname': '...', 'start_time': _time.time(), 'phase': 'starting'}
                
                # Progress tracking
                progress_bar = st.progress(0, "Starting...")
                status_text = st.empty()
                
                # Show file info
                file_size_mb = uploaded_file.size / (1024 * 1024)
                
                # Extract with concurrency control
                with _active_sessions_lock:
                    if _sid in _active_sessions:
                        _active_sessions[_sid]['phase'] = 'extracting'
                status_text.text("📦 Extracting archive...")
                _t0 = _time.time()
                temp_dir, sosreport_path = extract_sosreport(uploaded_file, progress_bar, status_text)
                _timings['Extraction'] = _time.time() - _t0
                
                # Detect archive format (sosreport vs supportconfig)
                archive_format = detect_archive_format(sosreport_path)
                _format_label = "Supportconfig (SUSE)" if archive_format == 'supportconfig' else "SOSreport"
                st.info(f"📁 File: {uploaded_file.name} ({file_size_mb:.1f} MB) — Detected format: **{_format_label}**")
                
                # Detect system info
                _t0 = _time.time()
                system_info = get_system_info(sosreport_path, archive_format)
                hostname = system_info['hostname']
                st.session_state['last_hostname'] = hostname  # For data privacy purge
                with _active_sessions_lock:
                    if _sid in _active_sessions:
                        _active_sessions[_sid]['hostname'] = hostname
                        _active_sessions[_sid]['phase'] = 'analyzing'
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
                # V7 additions
                cloud_info = system_info.get('cloud', {})
                azure_meta = system_info.get('azure_metadata', {})
                crash_dumps = system_info.get('crash_dumps', {})
                network_config = system_info.get('network_config', {})
                cve_advisories = system_info.get('cve_advisories', {})
                
                _timings['System Info'] = _time.time() - _t0
                
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
                
                # ── Extract report month early (needed by LogParser) ─────────
                report_month = None
                if sys_date and sys_date != "N/A":
                    month_map = {'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
                                 'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12}
                    for month_name, month_num in month_map.items():
                        if month_name in sys_date.lower():
                            report_month = month_num
                            break
                
                # ── Step 7: Launch log parsing in a background thread ────────
                # SAR parsing (main thread) and log parsing (background)
                # run concurrently — they read different files and are independent.
                _log_parse_start = _time.time()
                log_parser = LogParser(sosreport_path, hostname, year, report_month=report_month)
                _log_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='log_parse')
                _log_future = _log_executor.submit(log_parser.parse_all)
                
                # ── SAR parsing in main thread (uses UI progress callback) ───
                _t0 = _time.time()
                sar_parser = SARParser(sosreport_path, hostname, report_year=year, report_date_str=sys_date)
                sar_files_found = sar_parser.find_sar_files()
                status_text.text(f" Found {len(sar_files_found)} SAR files (source: {sar_parser.sar_source})")
                
                def _sar_progress(current, total, filename):
                    pct = 50 + int((current / max(total, 1)) * 15)  # 50-65% range
                    progress_bar.progress(pct, f"Parsing SAR: {filename} ({current+1}/{total})")
                    status_text.text(f"📊 Parsing SAR file {current+1}/{total}: {filename} ({len(sar_parser.metrics):,} metrics so far)")
                
                with _active_sessions_lock:
                    if _sid in _active_sessions:
                        _active_sessions[_sid]['phase'] = 'parsing SAR + logs (parallel)'
                sar_metrics = sar_parser.parse_all(progress_callback=_sar_progress)
                _timings['SAR Parsing'] = _time.time() - _t0
                
                # Apply limits to prevent memory issues
                if len(sar_metrics) > MAX_SAR_METRICS:
                    st.warning(f" SAR metrics limited to {MAX_SAR_METRICS:,} (total: {len(sar_metrics):,})")
                    sar_metrics = sar_metrics[:MAX_SAR_METRICS]
                
                # Analyze SAR metrics for peaks and anomalies
                status_text.text(" Analyzing for peaks and anomalies...")
                _t0 = _time.time()
                sar_anomalies = analyze_sar_anomalies(sar_metrics)
                _timings['Anomaly Analysis'] = _time.time() - _t0
                
                # ── Wait for background log parsing to finish (Step 7) ───────
                status_text.text("⏳ Waiting for log parsing to finish...")
                progress_bar.progress(66, "Finishing log parsing...")
                logs = _log_future.result()          # blocks until done
                _log_executor.shutdown(wait=False)    # cleanup thread pool
                critical_events = log_parser.critical_events
                critical_summary = log_parser.critical_summary
                _timings['Log Parsing'] = _time.time() - _log_parse_start
                logging.info(
                    f"Step 7 parallel gain: SAR {_timings['SAR Parsing']:.1f}s + "
                    f"Logs {_timings['Log Parsing']:.1f}s → wall time "
                    f"{_time.time() - _log_parse_start:.1f}s"
                )
                
                # Apply log limits
                if len(logs) > MAX_LOG_LINES:
                    st.warning(f" Log entries limited to {MAX_LOG_LINES:,} (total: {len(logs):,})")
                    logs = logs[:MAX_LOG_LINES]
                
                # Debug: Show var/log contents
                var_log_path = os.path.join(sosreport_path, 'var', 'log')
                log_dir_contents = []
                if os.path.isdir(var_log_path):
                    log_dir_contents = os.listdir(var_log_path)
                
                # Supportconfig debug: show what files exist in the extracted root
                _sc_debug_info = {}
                if archive_format == 'supportconfig':
                    _sc_debug_info['sc_txt_files'] = [f for f in os.listdir(sosreport_path) if f.endswith('.txt')]
                    _sc_debug_info['var_log_contents'] = log_dir_contents
                    # Walk var/log for all files with sizes
                    _sc_debug_info['var_log_files'] = {}
                    if os.path.isdir(var_log_path):
                        for root_d, dirs, files in os.walk(var_log_path):
                            for f in files:
                                full = os.path.join(root_d, f)
                                rel = os.path.relpath(full, sosreport_path)
                                _sc_debug_info['var_log_files'][rel] = os.path.getsize(full)
                    # Check sos_commands/sar
                    sar_dir = os.path.join(sosreport_path, 'sos_commands', 'sar')
                    if os.path.isdir(sar_dir):
                        _sc_debug_info['sar_files'] = {f: os.path.getsize(os.path.join(sar_dir, f)) for f in os.listdir(sar_dir)}
                    else:
                        _sc_debug_info['sar_files'] = 'sos_commands/sar/ NOT FOUND'
                    # Check var/log/sa (where SAR data from sar/ gets copied)
                    sa_dir = os.path.join(sosreport_path, 'var', 'log', 'sa')
                    if os.path.isdir(sa_dir):
                        _sc_debug_info['var_log_sa_files'] = {f: os.path.getsize(os.path.join(sa_dir, f)) for f in os.listdir(sa_dir)}
                    else:
                        _sc_debug_info['var_log_sa_files'] = 'var/log/sa/ NOT FOUND'
                    # Log found files from parser
                    _lp_found = getattr(log_parser, 'found_files', {})
                    _sc_debug_info['log_parser_found'] = {k: [os.path.basename(f) for f in v] for k, v in _lp_found.items() if v}
                    _sc_debug_info['log_parser_summary'] = {k: v for k, v in log_parser.summary.items() if v > 0}
                    _sc_debug_info['sar_files_found'] = [os.path.basename(f) for f in sar_files_found]
                    _sc_debug_info['sar_metrics_count'] = len(sar_metrics)
                
                progress_bar.progress(70, "Data parsed!")
                
                
                # ---- Pre-compute patch compliance (needs sosreport_path) ----
                progress_bar.progress(72, "Analyzing compliance...")
                status_text.text(" Checking patch compliance...")
                _t0 = _time.time()
                patch_compliance = detect_patch_compliance(
                    sosreport_path, packages_info, kernel_version, os_release, sys_date
                )
                _timings['Patch Compliance'] = _time.time() - _t0
                
                # ---- Pre-compute timestamp correlations ----
                actionable_events = [e for e in critical_events if e.get('severity') in ('critical', 'warning')]
                correlations = correlate_timestamps(sar_metrics, actionable_events, window_minutes=5) if actionable_events and sar_metrics else []
                
                # ---- Run system health checks (V7.1) ----
                progress_bar.progress(74, "Running health checks...")
                status_text.text("🔍 Running system health checks...")
                _t0 = _time.time()
                health_checks = run_system_health_checks(
                    sosreport_path, system_info,
                    critical_events=critical_events,
                    patch_compliance=patch_compliance,
                )
                _timings['Health Checks'] = _time.time() - _t0
                
                # ---- Pre-compute SAR display metadata ----
                sar_files_display = []
                for _f in sar_files_found:
                    _bn = os.path.basename(_f)
                    _sfx = ' (XML)' if _f.endswith('.xml') else ' (text)'
                    sar_files_display.append(f'{_bn}{_sfx}')
                
                sar_meas_by_date = {}
                for _m in sar_parser.metrics:
                    _ts = _m.get('timestamp')
                    if _ts:
                        _d = _ts.strftime('%Y-%m-%d')
                        if _d not in sar_meas_by_date:
                            sar_meas_by_date[_d] = set()
                        sar_meas_by_date[_d].add(_m['measurement'])
                
                # ---- Generate copy-paste summary ----
                summary_text = generate_copy_paste_summary(
                    hostname=hostname, system_info=system_info,
                    sar_anomalies=sar_anomalies,
                    critical_events=critical_events, critical_summary=critical_summary,
                    sar_metrics_count=len(sar_metrics), logs_count=len(logs),
                    patch_compliance=patch_compliance,
                    log_summary=log_parser.summary,
                    health_checks=health_checks,
                )
                
                # ---- V8: Generate executive TL;DR ----
                exec_summary = generate_executive_summary(
                    system_info=system_info,
                    sar_anomalies=sar_anomalies,
                    critical_events=critical_events,
                    health_checks=health_checks,
                    patch_compliance=patch_compliance,
                )
                
                progress_bar.progress(75, "Analysis complete! Pushing data...")
                
                # ============= DATA UPLOAD =============
                results = {}
                
                if push_sar and sar_metrics:
                    with _active_sessions_lock:
                        if _sid in _active_sessions:
                            _active_sessions[_sid]['phase'] = 'pushing to InfluxDB'
                    # Clean old data for this host first to avoid stale series
                    progress_bar.progress(72, "Cleaning old InfluxDB data...")
                    status_text.text(f"🧹 Removing old data for {hostname} from InfluxDB...")
                    del_ok, del_err = delete_influxdb_host_data(hostname)
                    if del_ok:
                        st.info(f"🧹 Cleared old InfluxDB data for **{hostname}**")
                    elif del_err:
                        st.warning(f"⚠️ Could not clear old data: {del_err}")
                    
                    progress_bar.progress(75, "Pushing SAR to InfluxDB...")
                    status_text.text(f"📤 Pushing {len(sar_metrics):,} SAR metrics to InfluxDB...")
                    _t0 = _time.time()
                    pushed_sar, push_error = push_sar_to_influxdb(sar_metrics, hostname)
                    _influx_elapsed = _time.time() - _t0
                    _timings['InfluxDB Push'] = _influx_elapsed
                    results['sar'] = pushed_sar
                    if pushed_sar > 0:
                        _influx_rate = int(pushed_sar / _influx_elapsed) if _influx_elapsed > 0 else 0
                        st.success(f"✅ Pushed {pushed_sar:,} SAR metrics to InfluxDB in {_influx_elapsed:.1f}s ({_influx_rate:,} metrics/sec)")
                        
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
                                st.info(f"📊 **InfluxDB Verification:** Query for host='{hostname}' completed. Check Grafana with time range matching your data.")
                        except Exception as e:
                            st.warning(f"Could not verify InfluxDB data: {str(e)[:100]}")
                    else:
                        st.warning(f"⚠️ No SAR metrics pushed to InfluxDB")
                    if push_error:
                        st.error(f"❌ InfluxDB errors: {push_error}")
                
                if push_logs and logs:
                    with _active_sessions_lock:
                        if _sid in _active_sessions:
                            _active_sessions[_sid]['phase'] = 'pushing to Loki'
                    # Clean old Loki data for this host first to avoid 'entry too far behind' errors
                    progress_bar.progress(82, "Cleaning old Loki data...")
                    status_text.text(f"🧹 Removing old data for {hostname} from Loki...")
                    loki_del_ok, loki_del_err = delete_loki_host_data(hostname)
                    if loki_del_ok:
                        st.info(f"🧹 Cleared old Loki data for **{hostname}**")
                    elif loki_del_err:
                        st.warning(f"⚠️ Could not clear old Loki data: {loki_del_err}")
                    
                    progress_bar.progress(85, "Pushing Logs to Loki...")
                    status_text.text("📤 Pushing logs to Loki...")
                    _t0 = _time.time()
                    pushed_logs, loki_error, loki_info = push_logs_to_loki(logs, hostname)
                    _loki_elapsed = _time.time() - _t0
                    _timings['Loki Push'] = _loki_elapsed
                    results['logs'] = pushed_logs
                    if pushed_logs > 0:
                        _loki_rate = int(pushed_logs / _loki_elapsed) if _loki_elapsed > 0 else 0
                        st.success(f"✅ Pushed {pushed_logs:,} log entries to Loki in {_loki_elapsed:.1f}s ({_loki_rate:,} entries/sec)")
                        # Flush Loki to ensure old-timestamp data is written to TSDB store
                        try:
                            requests.post(f"{LOKI_URL}/flush", timeout=60)
                        except Exception:
                            pass
                    else:
                        st.warning(f"⚠️ No log entries pushed to Loki")
                    if loki_info:
                        st.info(f"ℹ️ {loki_info}")
                    if loki_error:
                        st.error(f"❌ Loki errors: {loki_error}")
                        st.info("💡 **Tip**: If you see 'out of order' errors, this means logs for this host with newer timestamps already exist in Loki. Try deleting previous data or using a different host label.")
                    
                    # NOTE: Critical events are displayed in Streamlit main page only (skipped Loki push to reduce load)
                
                # Create dashboard with auto time range
                if create_dashboard:
                    with _active_sessions_lock:
                        if _sid in _active_sessions:
                            _active_sessions[_sid]['phase'] = 'creating dashboard'
                    progress_bar.progress(95, "Creating Grafana dashboard...")
                    status_text.text("📊 Creating Grafana dashboard...")
                    
                    # Get time range from parsed data
                    time_from, time_to = get_time_range(sar_metrics, logs)
                    if time_from and time_to:
                        st.info(f"📅 Auto time range: {time_from.strftime('%Y-%m-%d %H:%M')} to {time_to.strftime('%Y-%m-%d %H:%M')}")
                    
                    _t0 = _time.time()
                    dashboard_url = create_grafana_dashboard(hostname, time_from, time_to, 
                                                             system_info=system_info,
                                                             sar_anomalies=sar_anomalies)
                    _timings['Grafana Dashboard'] = _time.time() - _t0
                    
                    if dashboard_url:
                        results['dashboard'] = dashboard_url
                        st.success(f"✅ Dashboard created!")
                        st.markdown(f"🔗 [Open Dashboard]({dashboard_url})")
                    else:
                        st.warning("⚠️ Dashboard creation failed — check Grafana connectivity and API key. "
                                   "View container logs: `docker compose -f docker-compose.all.yml logs app`")
                
                progress_bar.progress(100, "Complete!")
                _timings['_total'] = _time.time() - _total_start
                _total_time = _timings.pop('_total')
                status_text.text(f"✅ Processing complete! Total time: {_total_time:.1f}s")
                
                # ========== SAVE TO SESSION STATE (for persistence across reruns) ==========
                st.session_state['_analysis_data'] = {
                    'hostname': hostname,
                    'system_info': system_info,
                    'cpu_info': cpu_info,
                    'memory_info': memory_info,
                    'df_info': df_info,
                    'kernel_version': kernel_version,
                    'os_release': os_release,
                    'uptime': uptime,
                    'sys_date': sys_date,
                    'selinux_status': selinux_status,
                    'kdump_info': kdump_info,
                    'packages_info': packages_info,
                    'top_processes': top_processes,
                    'cloud_info': cloud_info,
                    'azure_metadata': azure_meta,
                    'crash_dumps': crash_dumps,
                    'network_config': network_config,
                    'cve_advisories': cve_advisories,
                    'sar_anomalies': sar_anomalies,
                    'sar_metrics_count': len(sar_metrics),
                    'logs_count': len(logs),
                    'sar_files_display': sar_files_display,
                    'sar_summary': dict(sar_parser.summary),
                    'sar_source': getattr(sar_parser, 'sar_source', ''),
                    'sar_meas_by_date': {d: sorted(v) for d, v in sar_meas_by_date.items()},
                    'log_summary': dict(log_parser.summary),
                    'critical_events': critical_events,
                    'critical_summary': critical_summary,
                    'correlations': correlations,
                    'patch_compliance': patch_compliance,
                    'health_checks': health_checks,
                    'summary_text': summary_text,
                    'exec_summary': exec_summary,
                    'push_results': results,
                    'timings': dict(_timings),
                    'total_time': _total_time,
                    'file_size_mb': file_size_mb,
                    'archive_format': archive_format,
                    'sc_debug_info': _sc_debug_info,
                }
                
            except Exception as e:
                st.error(f"❌ Error processing archive: {str(e)}")
            
            finally:
                # Unregister this session from active tracking
                _sid = st.session_state.get('session_id', 'unknown')
                with _active_sessions_lock:
                    _active_sessions.pop(_sid, None)
                # Cleanup
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
                # Re-enable the Process button
                st.session_state['_processing'] = False
        
        # === DISPLAY RESULTS (from session state — persists across radio/filter reruns) ===
        if '_analysis_data' in st.session_state:
            _ad = st.session_state['_analysis_data']
            # Unpack all variables for display
            hostname = _ad['hostname']
            system_info = _ad['system_info']
            cpu_info = _ad['cpu_info']
            memory_info = _ad['memory_info']
            df_info = _ad['df_info']
            kernel_version = _ad['kernel_version']
            os_release = _ad['os_release']
            uptime = _ad['uptime']
            sys_date = _ad['sys_date']
            selinux_status = _ad['selinux_status']
            kdump_info = _ad['kdump_info']
            packages_info = _ad['packages_info']
            top_processes = _ad['top_processes']
            cloud_info = _ad['cloud_info']
            azure_meta = _ad.get('azure_metadata', {})
            crash_dumps = _ad['crash_dumps']
            network_config = _ad['network_config']
            cve_advisories = _ad['cve_advisories']
            sar_anomalies = _ad['sar_anomalies']
            critical_events = _ad['critical_events']
            critical_summary = _ad['critical_summary']
            patch_compliance = _ad['patch_compliance']
            correlations = _ad['correlations']
            summary_text = _ad['summary_text']
            results = _ad.get('push_results', {})
            _timings = _ad.get('timings', {})
            _total_time = _ad.get('total_time', 0)
            file_size_mb = _ad.get('file_size_mb', 0)
            
            # Display summary
            st.markdown("---")
            _archive_format = _ad.get('archive_format', 'sosreport')
            _fmt_badge = "🟢 Supportconfig (SUSE)" if _archive_format == 'supportconfig' else "🔵 SOSreport"
            st.header(f" Analysis Summary — {_fmt_badge}")

            # ============= V8: EXECUTIVE TL;DR ========================
            _exec = _ad.get('exec_summary', {})
            if _exec:
                _risk = _exec.get('risk_level', 'GREEN')
                _risk_icons = {'RED': '🔴', 'YELLOW': '🟡', 'GREEN': '🟢'}
                _risk_colors = {'RED': '#f8d7da', 'YELLOW': '#fff3cd', 'GREEN': '#d4edda'}
                _risk_borders = {'RED': '#f5c6cb', 'YELLOW': '#ffc107', 'GREEN': '#c3e6cb'}
                _risk_icon = _risk_icons.get(_risk, '⚪')
                _bg = _risk_colors.get(_risk, '#f0f2f6')
                _border = _risk_borders.get(_risk, '#dee2e6')
                
                _bullets_html = ''.join(f'<div style="padding: 2px 0;">{b}</div>' for b in _exec.get('bullets', []))
                st.markdown(f"""
                <div style="background-color: {_bg}; border: 2px solid {_border}; border-radius: 8px; padding: 12px 16px; margin: 8px 0 16px 0;">
                    <div style="font-size: 1.1rem; font-weight: bold; margin-bottom: 8px;">
                        {_risk_icon} Risk Assessment: <strong>{_risk}</strong> (score: {_exec.get('risk_score', 0)}/10)
                    </div>
                    <div style="font-size: 0.95rem;">
                        {_bullets_html}
                    </div>
                </div>
                """, unsafe_allow_html=True)

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

            # Azure VM metadata — inline text format
            _vm_size = azure_meta.get('vm_size', 'N/A')
            _sku_display = azure_meta.get('sku', '')
            _offer = azure_meta.get('offer', '')
            if _offer and _sku_display:
                _sku_display = f"{_offer} {_sku_display}"
            _location = azure_meta.get('location', 'N/A')
            _rg = azure_meta.get('resource_group', 'N/A')
            st.markdown(
                f"**VM Size:** `{_vm_size}` &nbsp;&nbsp; "
                f"**SKU:** `{_sku_display or 'N/A'}` &nbsp;&nbsp; "
                f"**Location:** `{_location}` &nbsp;&nbsp; "
                f"**Resource Group:** `{_rg}`"
            )
            if azure_meta.get('_debug'):
                st.caption(f"ℹ️ {azure_meta['_debug']}")

            # Second row: More details — two columns side by side
            detail_col1, detail_col2 = st.columns(2)

            # ── LEFT COLUMN: Core System Info ──────────────────────────
            with detail_col1:
                st.markdown("##### System Details")
                st.markdown(f"**OS Release:** `{os_release}`")
                st.markdown(f"**Architecture:** `{cpu_info.get('architecture', 'N/A')}`")
                st.markdown(f"**CPU Model:** `{cpu_info.get('model', 'N/A')}`")
                if cpu_info.get('sockets'):
                    st.markdown(f"**Sockets/Threads:** `{cpu_info.get('sockets', 'N/A')} sockets, {cpu_info.get('threads_per_core', 'N/A')} threads/core`")
                st.markdown(f"**SELinux:** `{selinux_status}`")
                # V8: Kernel taint
                _taint = system_info.get('kernel_taint', {})
                if _taint.get('tainted'):
                    st.markdown(f"**Kernel Taint:** 🟡 `{_taint['flag_letters']}` — {', '.join(_taint['flags'][:2])}")
                else:
                    st.markdown(f"**Kernel Taint:** 🟢 `Clean (0)`")
                # V8: Time sync
                _ts = system_info.get('time_sync', {})
                if _ts.get('service'):
                    _ts_icon = "🟢" if _ts.get('synced') else "🔴" if _ts.get('synced') is False else "🟡"
                    _ts_detail = f"offset {_ts['offset_ms']:.1f}ms" if _ts.get('offset_ms') is not None else _ts.get('details', '')
                    st.markdown(f"**Time Sync:** {_ts_icon} `{_ts['service']}` {_ts_detail}")
                # V8: Failed services
                _fsvc = system_info.get('failed_services', {})
                if _fsvc.get('total_failed', 0) > 0:
                    st.markdown(f"**Failed Services:** 🔴 `{_fsvc['total_failed']}` — {', '.join(_fsvc['failed_units'][:3])}")
                # Kdump status - simple one-liner
                kdump_status = kdump_info.get('enabled', 'Unknown')
                kdump_icon = "🟢" if kdump_info.get('operational') else "🔴" if kdump_info.get('operational') is False else "⚪"
                kdump_text = f"{kdump_icon} `{kdump_status}`"
                if kdump_info.get('crashkernel'):
                    kdump_text += f" (crashkernel={kdump_info['crashkernel']})"
                if kdump_info.get('crash_dumps'):
                    kdump_text += f" | ⚠️ **{len(kdump_info['crash_dumps'])} crash dump(s) found!**"
                st.markdown(f"**Kdump:** {kdump_text}")
                if kdump_info.get('crash_dumps'):
                    for dump in kdump_info['crash_dumps']:
                        dump_details = f"📁 `{dump['directory']}`"
                        if dump.get('has_vmcore'):
                            dump_details += " (vmcore ✅)"
                        if dump.get('has_dmesg'):
                            dump_details += " (dmesg ✅)"
                        st.caption(dump_details)
                st.markdown(f"**Uptime:** `{uptime}`")
                st.markdown(f"**SOSreport Date:** `{sys_date}`")

                # Reboot history
                reboot_history = system_info.get('reboot_history', [])
                if reboot_history:
                    last_boot = reboot_history[0]
                    last_boot_str = last_boot['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                    st.markdown(f"**Last Reboot:** `{last_boot_str}` (kernel: `{last_boot['kernel']}`)") 
                    if len(reboot_history) > 1:
                        with st.expander(f"🔄 Full reboot history ({len(reboot_history)} boots detected)", expanded=False):
                            for i, rb in enumerate(reboot_history):
                                rb_ts = rb['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                                st.code(f"{rb_ts}  kernel: {rb['kernel']}  (source: {rb['source']})", language=None)
                else:
                    st.markdown("**Last Reboot:** `N/A` (no BOOT_IMAGE found in messages)")

                # Kernel boot parameters
                kcmd = system_info.get('kernel_cmdline', {})
                if kcmd.get('raw'):
                    notable = kcmd.get('notable', [])
                    if notable:
                        notable_str = ", ".join(f"`{p}`" for p in notable)
                        st.markdown(f"**Boot Parameters:** {notable_str}")
                    with st.expander("📋 Full /proc/cmdline", expanded=False):
                        st.code(kcmd['raw'], language=None)

                # Installed Packages
                st.markdown("---")
                st.markdown("##### Installed Packages")
                st.markdown(f"**Total Packages:** `{packages_info.get('total_count', 0):,}`")
                if packages_info.get('rhui'):
                    st.markdown(f"**RHUI Packages:** `{', '.join(packages_info['rhui'][:3])}`")
                if packages_info.get('kernel'):
                    st.markdown(f"**Kernel Packages:** `{len(packages_info['kernel'])} installed`")
                all_pkgs = packages_info.get('all_packages', [])
                if all_pkgs:
                    with st.expander(f"📦 View All Installed Packages ({len(all_pkgs):,})", expanded=False):
                        # Search filter
                        pkg_filter = st.text_input("🔍 Filter packages", key="pkg_filter", placeholder="Type to search (e.g. kernel, python, java)...")
                        filtered = [p for p in sorted(all_pkgs) if pkg_filter.lower() in p.lower()] if pkg_filter else sorted(all_pkgs)
                        st.caption(f"Showing {len(filtered):,} of {len(all_pkgs):,} packages")
                        # Display as a scrollable code block
                        st.code("\n".join(filtered), language=None)

            # ── RIGHT COLUMN: Memory, HugePages, Sysctl ──────────────
            with detail_col2:
                # Memory overview
                st.markdown("##### Memory Details")
                if memory_info.get('total_kb', 0) > 0:
                    total_mb = memory_info['total_kb'] / 1024
                    free_mb = memory_info.get('free_kb', 0) / 1024
                    avail_mb = memory_info.get('available_kb', 0) / 1024
                    swap_total = memory_info.get('swap_total_kb', 0) / 1024 / 1024
                    swap_free = memory_info.get('swap_free_kb', 0) / 1024 / 1024
                    st.markdown(f"**Total:** `{total_mb/1024:.1f} GB` &nbsp;|&nbsp; **Free:** `{free_mb/1024:.1f} GB` &nbsp;|&nbsp; **Available:** `{avail_mb/1024:.1f} GB`")
                    st.markdown(f"**Swap:** `{swap_total:.1f} GB total` &nbsp;|&nbsp; `{swap_free:.1f} GB free`")

                # HugePages & THP
                hp_total = memory_info.get('hugepages_total', 0)
                hp_free = memory_info.get('hugepages_free', 0)
                hp_size_kb = memory_info.get('hugepage_size_kb', 0)
                thp_status = memory_info.get('thp_enabled', 'N/A')
                thp_defrag = memory_info.get('thp_defrag', 'N/A')

                if hp_total > 0 or thp_status != 'N/A':
                    st.markdown("---")
                    st.markdown("##### HugePages Configuration")

                    if hp_total > 0:
                        hp_size_mb = hp_size_kb / 1024 if hp_size_kb else 2
                        hp_used = hp_total - hp_free
                        hp_total_gb = (hp_total * hp_size_kb) / 1024 / 1024
                        hp_pct = (hp_used / hp_total * 100) if hp_total else 0
                        hp_icon = "🟢" if hp_pct < 80 else "🟡" if hp_pct < 95 else "🔴"
                        st.markdown(
                            f"**Static HugePages:** `{hp_total:,}` × `{hp_size_mb:.0f} MB` = "
                            f"`{hp_total_gb:.1f} GB`"
                        )
                        st.markdown(
                            f"{hp_icon} Used: `{hp_used:,}` ({hp_pct:.0f}%) &nbsp; Free: `{hp_free:,}`"
                        )
                    else:
                        st.markdown("**Static HugePages:** `0` (none reserved)")

                    thp_icon = "🟢" if thp_status == 'never' else "🟡" if thp_status == 'madvise' else "🔴" if thp_status == 'always' else "⚪"
                    st.markdown(f"**THP:** {thp_icon} `{thp_status}` &nbsp;|&nbsp; Defrag: `{thp_defrag}`")
                    if thp_status == 'never':
                        st.caption("THP disabled — recommended for Oracle/SAP")
                    elif thp_status == 'always':
                        st.caption("⚠️ THP=always can cause latency spikes for DB workloads")

                # Sysctl Tuning parameters
                sysctl_info = system_info.get('sysctl', {})
                sysctl_all = sysctl_info.get('all', {})
                sysctl_highlights = sysctl_info.get('highlights', [])
                sysctl_categories = sysctl_info.get('categories', {})

                if sysctl_all:
                    st.markdown("---")
                    st.markdown("##### Kernel Tuning (sysctl)")

                    # Show highlights first
                    if sysctl_highlights:
                        for key, val, icon, note in sysctl_highlights:
                            note_str = f" — *{note}*" if note else ""
                            st.markdown(f"{icon} `{key}` = `{val}`{note_str}")

                    # Show all categories in expandable sections
                    for cat_name, cat_params in sysctl_categories.items():
                        if cat_params:
                            with st.expander(f"🔧 {cat_name} ({len(cat_params)} params)", expanded=False):
                                for k, v in sorted(cat_params.items()):
                                    st.code(f"{k} = {v}", language=None)

            # Filesystem/DF Section
            if df_info:
                st.markdown("##### Filesystem Utilization (df)")
                # Show high usage filesystems first
                critical_fs = [fs for fs in df_info if fs.get('use_percent', 0) >= 80]
                normal_fs = [fs for fs in df_info if fs.get('use_percent', 0) < 80]

                if critical_fs:
                    st.warning(f"⚠️ {len(critical_fs)} filesystem(s) at 80%+ utilization")

                # Create DataFrame for display
                df_display = []
                for fs in sorted(df_info, key=lambda x: x.get('use_percent', 0), reverse=True):
                    use_pct = fs.get('use_percent', 0)
                    status = "🔴" if use_pct >= 90 else "🟡" if use_pct >= 80 else "🟢"
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
                st.info("ℹ️ No process data found (ps aux output not available in this sosreport)")

            # ============= V7: CLOUD & INFRASTRUCTURE (NEW) =============
            v7_has_content = (
                cloud_info.get('provider') or 
                cve_advisories.get('cve_count', 0) > 0 or 
                cve_advisories.get('update_summary', {}).get('total', 0) > 0 or
                crash_dumps.get('total_count', 0) > 0 or
                network_config.get('interfaces')
            )

            if v7_has_content:
                st.markdown("---")

                # --- Cloud Provider Detection ---
                if cloud_info.get('provider'):
                    st.subheader("☁️ Cloud Provider")
                    cloud_col1, cloud_col2 = st.columns(2)

                    with cloud_col1:
                        provider = cloud_info['provider']
                        provider_icons = {'azure': '🔷', 'aws': '🟠', 'gcp': '🔵', 'oracle': '🔴'}
                        st.markdown(f"**Provider:** {provider_icons.get(provider, '☁️')} {cloud_info.get('provider_label', provider)}")

                        virt = cloud_info.get('virtualization', {})
                        if virt.get('product_name'):
                            st.markdown(f"**VM Type:** `{virt['product_name']}`")
                        if virt.get('virt_what'):
                            st.markdown(f"**virt-what:** `{virt['virt_what']}`")
                        if virt.get('systemd_detect'):
                            st.markdown(f"**systemd-detect-virt:** `{virt['systemd_detect']}`")

                    with cloud_col2:
                        details = cloud_info.get('details', {})
                        if provider == 'azure':
                            # Use azure_meta (direct JSON parse) for reliable display
                            _am = azure_meta if azure_meta else details
                            if _am.get('vm_size'):
                                st.markdown(f"**VM Size:** `{_am['vm_size']}`")
                            if _am.get('vm_id'):
                                st.markdown(f"**VM ID:** `{_am['vm_id']}`")
                            if _am.get('fault_domain') or _am.get('update_domain'):
                                st.markdown(f"**FD/UD:** `{_am.get('fault_domain', '?')} / {_am.get('update_domain', '?')}`")
                            if _am.get('private_ips'):
                                st.markdown(f"**Private IPs:** `{', '.join(_am['private_ips'])}`")
                            if _am.get('version'):
                                st.markdown(f"**Image Version:** `{_am['version']}`")
                            # Tags
                            tags_raw = _am.get('tags_raw', '')
                            if tags_raw:
                                with st.expander("Azure Tags"):
                                    for tag in tags_raw.split(';'):
                                        tag = tag.strip()
                                        if tag:
                                            st.caption(f"  • {tag}")
                            extensions = details.get('extensions', [])
                            if extensions:
                                st.markdown(f"**Azure VM Extensions ({len(extensions)}):**")
                                for ext in extensions[:10]:
                                    st.caption(f"  • {ext}")
                        elif provider == 'aws':
                            if details.get('instance_id'):
                                st.markdown(f"**Instance ID:** `{details['instance_id']}`")
                            if details.get('instance_type'):
                                st.markdown(f"**Instance Type:** `{details['instance_type']}`")
                            if details.get('availability_zone'):
                                st.markdown(f"**AZ:** `{details['availability_zone']}`")

                    # Cloud-init
                    cloud_init = cloud_info.get('cloud_init', {})
                    if cloud_init:
                        with st.expander("Cloud-Init Details"):
                            if cloud_init.get('status'):
                                st.code(cloud_init['status'], language=None)
                            if cloud_init.get('log_tail'):
                                st.markdown("**Cloud-init log (last 100 lines):**")
                                st.code(cloud_init['log_tail'][-3000:], language=None)

                # --- CVE / Security Advisories ---
                if cve_advisories.get('cve_count', 0) > 0 or cve_advisories.get('update_summary', {}).get('total', 0) > 0:
                    st.subheader("🛡️ Security Advisories & CVEs")

                    update_sum = cve_advisories.get('update_summary', {})
                    cve_col1, cve_col2, cve_col3, cve_col4 = st.columns(4)

                    with cve_col1:
                        total = update_sum.get('total', 0)
                        st.metric("Pending Updates", f"{total:,}")
                    with cve_col2:
                        sec = update_sum.get('security', 0)
                        st.metric("Security Updates", f"{sec:,}", 
                                  delta="⚠️ Action needed" if sec > 0 else None,
                                  delta_color="inverse" if sec > 0 else "off")
                    with cve_col3:
                        cve_count = cve_advisories.get('cve_count', 0)
                        st.metric("Unique CVEs", f"{cve_count:,}",
                                  delta="⚠️" if cve_count > 0 else None,
                                  delta_color="inverse" if cve_count > 0 else "off")
                    with cve_col4:
                        crit = update_sum.get('critical', 0) + update_sum.get('important', 0)
                        st.metric("Critical+Important", f"{crit:,}",
                                  delta="🔴 HIGH" if crit > 0 else "✅ None",
                                  delta_color="inverse" if crit > 0 else "off")

                    # Severity breakdown
                    if any(update_sum.get(k, 0) > 0 for k in ['bugfix', 'enhancement', 'moderate', 'low']):
                        with st.expander("Update Breakdown"):
                            breakdown_cols = st.columns(4)
                            with breakdown_cols[0]:
                                st.write(f"**Bugfix:** {update_sum.get('bugfix', 0)}")
                            with breakdown_cols[1]:
                                st.write(f"**Enhancement:** {update_sum.get('enhancement', 0)}")
                            with breakdown_cols[2]:
                                st.write(f"**Moderate:** {update_sum.get('moderate', 0)}")
                            with breakdown_cols[3]:
                                st.write(f"**Low:** {update_sum.get('low', 0)}")

                    # CVE list
                    if cve_advisories.get('cves'):
                        with st.expander(f"CVE List ({cve_count} unique CVEs)"):
                            # Show CVEs in columns
                            cves_per_col = max(1, len(cve_advisories['cves']) // 3 + 1)
                            cve_cols = st.columns(3)
                            for i, cve_id in enumerate(cve_advisories['cves'][:60]):
                                col_idx = i // cves_per_col
                                if col_idx < 3:
                                    with cve_cols[col_idx]:
                                        st.caption(cve_id)
                            if len(cve_advisories['cves']) > 60:
                                st.caption(f"... and {len(cve_advisories['cves']) - 60} more")

                    # Advisory details
                    if cve_advisories.get('advisories'):
                        with st.expander(f"Advisory Details ({len(cve_advisories['advisories'])} advisories)"):
                            for adv in cve_advisories['advisories'][:20]:
                                severity_icon = {
                                    'Critical': '🔴', 'Important': '🟠', 'Moderate': '🟡', 'Low': '🟢'
                                }.get(adv.get('severity', ''), '⚪')
                                st.markdown(f"{severity_icon} **{adv.get('id', 'N/A')}** — {adv.get('type', '')} ({adv.get('severity', 'N/A')})")
                                if adv.get('cves'):
                                    st.caption(f"  CVEs: {', '.join(adv['cves'][:5])}")
                            if len(cve_advisories['advisories']) > 20:
                                st.caption(f"... and {len(cve_advisories['advisories']) - 20} more advisories")

                    # Repo list
                    if cve_advisories.get('repolist'):
                        with st.expander("Repository List"):
                            st.code(cve_advisories['repolist'][:3000], language=None)

                # --- Crash Dumps ---
                if crash_dumps.get('total_count', 0) > 0:
                    st.subheader("💥 Crash Dumps")
                    st.error(f"⚠️ **{crash_dumps['total_count']} crash dump(s) found!**")

                    for i, dump in enumerate(crash_dumps['dumps']):
                        header = f"Crash #{i+1}: {dump['directory']}"
                        if dump.get('crash_reason'):
                            header += f" — {dump['crash_reason'][:80]}"

                        with st.expander(header):
                            st.markdown(f"**Directory:** `{dump['directory']}`")
                            st.markdown(f"**Files:** {', '.join(dump['files'][:10])}")
                            if dump.get('has_vmcore'):
                                st.markdown("**vmcore:** ✅ Present (kernel memory dump)")

                            if dump.get('vmcore_dmesg'):
                                st.markdown("**vmcore-dmesg.txt** (kernel log at crash time):")
                                st.code(dump['vmcore_dmesg'][-3000:], language=None)

                            if dump.get('kexec_dmesg'):
                                st.markdown("**kexec-dmesg.log** (kexec boot log):")
                                st.code(dump['kexec_dmesg'][-2000:], language=None)

                # --- Network Configuration ---
                if network_config.get('interfaces'):
                    with st.expander("🌐 Network Configuration (V7)", expanded=False):
                        net_tab1, net_tab2, net_tab3, net_tab4 = st.tabs(["Interfaces", "Routing & DNS", "Firewall", "NetworkManager"])

                        with net_tab1:
                            if network_config.get('interfaces'):
                                st.code(network_config['interfaces'][:5000], language=None)
                            if network_config.get('bonding'):
                                st.markdown("**Bond Interfaces:**")
                                for bond_name, bond_data in network_config['bonding'].items():
                                    st.markdown(f"**{bond_name}:**")
                                    st.code(bond_data[:2000], language=None)
                            if network_config.get('ethtool'):
                                st.markdown("**Ethtool (link speed/status):**")
                                for iface, data in list(network_config['ethtool'].items())[:5]:
                                    st.caption(f"**{iface}:**")
                                    st.code(data[:500], language=None)

                        with net_tab2:
                            if network_config.get('routing'):
                                st.markdown("**Routing Table:**")
                                st.code(network_config['routing'][:3000], language=None)
                            dns = network_config.get('dns', {})
                            if dns.get('resolv_conf'):
                                st.markdown("**resolv.conf:**")
                                st.code(dns['resolv_conf'], language=None)
                            if dns.get('hosts'):
                                st.markdown("**/etc/hosts:**")
                                st.code(dns['hosts'][:2000], language=None)

                        with net_tab3:
                            fw = network_config.get('firewall', {})
                            if fw:
                                for fw_name, fw_data in fw.items():
                                    st.markdown(f"**{fw_name}:**")
                                    st.code(fw_data[:3000], language=None)
                            else:
                                st.info("No firewall data found")

                        with net_tab4:
                            nm = network_config.get('networkmanager', {})
                            if nm:
                                for nm_key, nm_data in nm.items():
                                    st.markdown(f"**{nm_key}:**")
                                    st.code(nm_data[:3000], language=None)
                            else:
                                st.info("No NetworkManager data found")

            st.markdown("---")

            # ============= SAR ANOMALIES & PEAKS =============
            st.subheader("📈 Performance Peaks & Anomalies")

            peak_col1, peak_col2, peak_col3, peak_col4 = st.columns(4)

            with peak_col1:
                st.markdown("##### CPU")
                if sar_anomalies['cpu']['samples'] > 0:
                    max_cpu = sar_anomalies['cpu']['max_usage']
                    avg_cpu = sar_anomalies['cpu']['avg_usage']
                    cpu_time = sar_anomalies['cpu']['max_time']
                    cpu_status = "🔴" if max_cpu >= 90 else "🟡" if max_cpu >= 70 else "🟢"
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
                    mem_status = "🔴" if max_mem >= 90 else "🟡" if max_mem >= 80 else "🟢"
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
                    disk_status = "🔴" if max_disk >= 90 else "🟡" if max_disk >= 70 else "🟢"
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
                    load_status = "🔴" if load_ratio >= 2 else "🟡" if load_ratio >= 1 else "🟢"
                    st.metric("Peak Load (1/5/15)", f"{max_load1}/{max_load5}/{max_load15}")
                    if load_time:
                        st.caption(f"{load_status} Peak at: {load_time.strftime('%Y-%m-%d %H:%M')}")
                    if max_blocked > 0:
                        st.caption(f"⚠️ Max blocked processes: {max_blocked}")
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

            # V8: CPU Steal alert (cloud VMs)
            steal_info = sar_anomalies.get('steal', {})
            if steal_info.get('samples', 0) > 0 and steal_info.get('max_steal', 0) > 0:
                _steal_avg = steal_info.get('avg_steal', 0)
                _steal_max = steal_info.get('max_steal', 0)
                _steal_time = steal_info.get('max_time')
                _steal_icon = "🔴" if _steal_avg > 5 else "🟡" if _steal_avg > 2 else "🟢"
                st.markdown(f"##### {_steal_icon} CPU Steal: Avg={_steal_avg}% | Peak={_steal_max}%")
                if _steal_avg > 2:
                    _cloud = system_info.get('cloud', {})
                    _provider = _cloud.get('provider_label', 'Cloud') if _cloud.get('provider') else 'Host'
                    st.warning(f"⚠️ Sustained CPU steal >2% — indicates {_provider} host contention or VM throttling. Consider VM resize or migration.")
                if _steal_time:
                    st.caption(f"Peak steal at: {_steal_time.strftime('%Y-%m-%d %H:%M')}")

            st.markdown("---")

            # ============= DATA TOTALS =============
            col1, col2, col3 = st.columns(3)

            with col1:
                st.subheader("📊 Totals")
                _sar_count = _ad.get('sar_metrics_count', 0)
                _log_count = _ad.get('logs_count', 0)
                _sar_summary = _ad.get('sar_summary', {})
                _sar_source = _ad.get('sar_source', '')
                _sar_files_disp = _ad.get('sar_files_display', [])
                _sar_meas_dates = _ad.get('sar_meas_by_date', {})
                _log_summary = _ad.get('log_summary', {})
                st.metric("Total SAR Metrics", f"{_sar_count:,}")
                st.metric("Total Log Entries", f"{_log_count:,}")
                st.metric("SAR Files", len(_sar_files_disp))

            with col2:
                st.subheader("SAR Breakdown")
                st.write(f"- Load: {_sar_summary.get('load', 0):,}")
                st.write(f"- Memory: {_sar_summary.get('memory', 0):,}")
                st.write(f"- Disk: {_sar_summary.get('disk', 0):,}")
                st.write(f"- Network: {_sar_summary.get('network', 0):,}")
                st.write(f"- CPU: {_sar_summary.get('cpu', 0):,}")
                # V7 additional SAR sections
                v7_sar_sections = {
                    'swap': 'Swap', 'hugepages': 'HugePages', 'paging': 'Paging',
                    'context': 'Context Switch', 'socket': 'Sockets',
                }
                for key, label in v7_sar_sections.items():
                    count = _sar_summary.get(key, 0)
                    if count > 0:
                        st.write(f"- {label}: {count:,}")
                if _sar_files_disp:
                    with st.expander("Show SAR files"):
                        if _sar_source:
                            st.caption(f"📂 Source: {_sar_source}")
                        for _sf in _sar_files_disp:
                            st.text(_sf)
                        # Show measurement types per date (pre-computed)
                        if _sar_meas_dates:
                            st.caption("📊 Measurement types per date:")
                            for d in sorted(_sar_meas_dates.keys()):
                                st.text(f"  {d}: {', '.join(_sar_meas_dates[d])}")

            with col3:
                st.subheader("Log Entries")
                # Show all log sources that have entries
                log_source_labels = {
                    'messages': 'Messages', 'syslog': 'Syslog', 'warn': 'Warn (SUSE)',
                    'secure': 'Secure', 'auth': 'Auth.log', 'audit': 'Audit', 'cron': 'Cron',
                    'dmesg': 'Dmesg', 'journal': 'Journalctl', 'kern': 'Kern.log',
                    'boot': 'Boot.log', 'maillog': 'Maillog', 'yum_dnf': 'Yum/DNF',
                }
                for key, label in log_source_labels.items():
                    count = _log_summary.get(key, 0)
                    if count > 0:
                        st.write(f"- {label}: {count:,}")
                st.metric("Total Logs", f"{_log_count:,}")

            # ============= SYSTEM HEALTH CHECKS (V7.1) =============
            health_checks = _ad.get('health_checks', {})
            if health_checks:
                st.markdown("---")
                # Count totals per severity
                _hc_total = sum(len(v) for v in health_checks.values())
                _hc_crit = sum(1 for cat in health_checks.values() for f in cat if f['severity'] == 'critical')
                _hc_warn = sum(1 for cat in health_checks.values() for f in cat if f['severity'] == 'warning')
                _hc_info = sum(1 for cat in health_checks.values() for f in cat if f['severity'] == 'info')

                if _hc_crit > 0:
                    st.header("🔍 System Health Checks")
                    st.error(f"🔴 **{_hc_crit} critical** &nbsp;|&nbsp; 🟡 **{_hc_warn} warning** &nbsp;|&nbsp; 🔵 **{_hc_info} info** &nbsp;|&nbsp; **{len(health_checks)} categories**, **{_hc_total} checks**")
                elif _hc_warn > 0:
                    st.header("🔍 System Health Checks")
                    st.warning(f"🟡 **{_hc_warn} warning** &nbsp;|&nbsp; 🔵 **{_hc_info} info** &nbsp;|&nbsp; **{len(health_checks)} categories**, **{_hc_total} checks**")
                else:
                    st.header("🔍 System Health Checks")
                    st.success(f"🔵 **{_hc_info} info** &nbsp;|&nbsp; **{len(health_checks)} categories**, **{_hc_total} checks** — all clear")

                _sev_badge = {'critical': '🔴 Critical', 'warning': '🟡 Warning', 'info': '🔵 Info'}
                _sev_order = {'critical': 0, 'warning': 1, 'info': 2}

                # Sort categories: those with critical findings first
                _sorted_cats = sorted(health_checks.items(),
                                      key=lambda kv: (min(_sev_order.get(f['severity'], 3) for f in kv[1]), kv[0]))

                # Display as a two-column grid of categories (like the screenshot)
                _cat_items = list(_sorted_cats)
                _left_cats = _cat_items[:len(_cat_items)//2 + len(_cat_items) % 2]
                _right_cats = _cat_items[len(_cat_items)//2 + len(_cat_items) % 2:]

                _hc_col1, _hc_col2 = st.columns(2)

                def _render_health_category(container, cat_name, findings_list):
                    with container:
                        _cat_crit = sum(1 for f in findings_list if f['severity'] == 'critical')
                        _cat_warn = sum(1 for f in findings_list if f['severity'] == 'warning')
                        _cat_count = len(findings_list)
                        # Category header with count badge
                        _expand = _cat_crit > 0  # auto-expand if critical
                        with st.expander(f"▸ **{cat_name}** ({_cat_count})", expanded=_expand):
                            for finding in findings_list:
                                _badge = _sev_badge.get(finding['severity'], finding['severity'])
                                _name = finding['name']
                                _detail = finding.get('details', '')
                                if finding['severity'] == 'critical':
                                    st.markdown(f"&nbsp;&nbsp; {_badge} &nbsp; **{_name}**")
                                    if _detail:
                                        st.caption(f"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; {_detail}")
                                elif finding['severity'] == 'warning':
                                    st.markdown(f"&nbsp;&nbsp; {_badge} &nbsp; {_name}")
                                    if _detail:
                                        st.caption(f"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; {_detail}")
                                else:
                                    st.markdown(f"&nbsp;&nbsp; {_badge} &nbsp; {_name}")

                for cat_name, findings_list in _left_cats:
                    _render_health_category(_hc_col1, cat_name, findings_list)
                for cat_name, findings_list in _right_cats:
                    _render_health_category(_hc_col2, cat_name, findings_list)

            # Critical Events Summary (with severity classification)
            if critical_events:
                st.markdown("---")

                # Separate events by severity
                sev_counts = {'critical': 0, 'warning': 0, 'info': 0}
                for ev in critical_events:
                    sev_counts[ev.get('severity', 'critical')] += 1

                n_crit = sev_counts['critical']
                n_warn = sev_counts['warning']
                n_info = sev_counts['info']

                # Headline adapts to what was actually found
                if n_crit > 0:
                    st.header("🚨 Log Events Analysis")
                    st.error(f"🔴 **{n_crit:,} critical** &nbsp;|&nbsp; 🟡 **{n_warn:,} warning** &nbsp;|&nbsp; 🔵 **{n_info:,} informational** &nbsp;|&nbsp; Total: **{len(critical_events):,}**")
                elif n_warn > 0:
                    st.header("⚠️ Log Events Analysis")
                    st.warning(f"🟡 **{n_warn:,} warning** &nbsp;|&nbsp; 🔵 **{n_info:,} informational** &nbsp;|&nbsp; Total: **{len(critical_events):,}** &nbsp; (no critical events)")
                else:
                    st.header("ℹ️ Log Events Analysis")
                    st.info(f"🔵 **{n_info:,} informational** events detected &mdash; no critical or warning events")

                # Severity filter
                sev_filter = st.radio(
                    "Show severity:",
                    ["All", "🔴 Critical only", "🟡 Warning only", "🔵 Info only"],
                    horizontal=True,
                    index=0 if n_crit > 0 else 0
                )
                sev_map = {
                    "All": None,
                    "🔴 Critical only": "critical",
                    "🟡 Warning only": "warning",
                    "🔵 Info only": "info"
                }
                selected_sev = sev_map[sev_filter]

                # Group events by category for display
                events_by_category = {}
                for event in critical_events:
                    if selected_sev and event.get('severity') != selected_sev:
                        continue
                    cat = event.get('category', 'Unknown')
                    if cat not in events_by_category:
                        events_by_category[cat] = []
                    events_by_category[cat].append(event)

                # Category icons
                category_icons = {
                    "File System & Disk": "💾",
                    "Memory/OOM": "🧠",
                    "CPU & Kernel Panic": "⚡",
                    "Security & Antivirus": "🔒",
                    "Network Issues": "🌐",
                    "Service & Systemd": "🔧",
                    "Hardware & IPMI": "🖥️"
                }

                # Severity badges for display
                sev_badge = {'critical': '🔴', 'warning': '🟡', 'info': '🔵'}

                for category in LOG_PATTERNS.keys():
                    cat_events = events_by_category.get(category, [])
                    count = len(cat_events)
                    icon = category_icons.get(category, "⚠️")

                    # Count severities within this category
                    cat_crit = sum(1 for e in cat_events if e.get('severity') == 'critical')
                    cat_warn = sum(1 for e in cat_events if e.get('severity') == 'warning')
                    cat_info = sum(1 for e in cat_events if e.get('severity') == 'info')

                    if count > 0:
                        # Build severity breakdown string
                        sev_parts = []
                        if cat_crit: sev_parts.append(f"🔴 {cat_crit}")
                        if cat_warn: sev_parts.append(f"🟡 {cat_warn}")
                        if cat_info: sev_parts.append(f"🔵 {cat_info}")
                        sev_str = "  ".join(sev_parts)

                        with st.expander(f"{icon} {category} ({count:,} events) — {sev_str}", expanded=(cat_crit > 0)):
                            # Show critical events first, then warnings, then info
                            sorted_events = sorted(cat_events, key=lambda e: {'critical': 0, 'warning': 1, 'info': 2}.get(e.get('severity', 'critical'), 3))
                            for event in sorted_events[:150]:
                                ts = event.get('timestamp', 'N/A')
                                ts_str = ts.strftime('%Y-%m-%d %H:%M:%S') if ts else 'N/A'
                                msg = event.get('message', '')[:300]
                                badge = sev_badge.get(event.get('severity', 'critical'), '⚪')
                                st.code(f"{badge} [{ts_str}] {msg}", language=None)
                            if len(sorted_events) > 150:
                                st.info(f"Showing first 150 of {len(sorted_events):,} events")
                    else:
                        if not selected_sev:  # Only show "no issues" when viewing all
                            st.success(f"{icon} {category}: ✅ No issues detected")
            else:
                st.markdown("---")
                st.success("✅ **No critical events detected** - System logs appear healthy!")

            # ============= PATCH COMPLIANCE (V5) =============
            st.markdown("---")
            st.header("🔐 Subscription & Patch Compliance")


            # Show detected OS flavor
            detected_flavor = patch_compliance.get('os_flavor', 'unknown')
            flavor_labels = {
                'oracle_linux': 'Oracle Linux', 'rhel': 'RHEL', 'centos': 'CentOS',
                'rocky': 'Rocky Linux', 'alma': 'AlmaLinux', 'suse': 'SUSE', 'ubuntu': 'Ubuntu',
                'debian': 'Debian', 'unknown': 'Unknown'
            }
            flavor_label = flavor_labels.get(detected_flavor, detected_flavor)
            kernel_track = patch_compliance.get('kernel_type', 'standard').upper()
            st.caption(f"Detected OS: **{flavor_label}** | Kernel track: **{kernel_track}**")

            # Compliance Score Badge
            score = patch_compliance.get('compliance_score', 'Unknown')
            if score == 'Good':
                st.success(f"✅ Overall Compliance: **{score}**")
            elif score == 'Warning':
                st.warning(f"⚠️ Overall Compliance: **{score}**")
            elif score == 'Critical':
                st.error(f"🔴 Overall Compliance: **{score}**")
            else:
                st.info(f"ℹ️ Overall Compliance: **{score}**")

            comp_col1, comp_col2, comp_col3 = st.columns(3)

            with comp_col1:
                st.markdown("**Subscription Status**")
                sub_status = patch_compliance.get('subscription_status', 'Unknown')
                if sub_status in ['Subscribed', 'RHUI Connected']:
                    st.markdown(f"🟢 {sub_status}")
                elif sub_status == 'Not Subscribed':
                    st.markdown(f"🔴 {sub_status}")
                else:
                    st.markdown(f"🟡 {sub_status}")

                if patch_compliance.get('subscription_details'):
                    for detail in patch_compliance['subscription_details'][:3]:
                        st.caption(f"  {detail}")

            with comp_col2:
                st.markdown("**Kernel Status**")
                k_status = patch_compliance.get('kernel_status', 'Unknown')
                if k_status == 'Recent':
                    st.markdown(f"🟢 {k_status}")
                elif k_status == 'Outdated':
                    st.markdown(f"🟡 {k_status}")
                elif k_status == 'Very Outdated':
                    st.markdown(f"🔴 {k_status}")
                else:
                    st.markdown(f"⚪ {k_status}")

                st.caption(f"Running: `{kernel_version}`")
                if patch_compliance.get('reboot_required'):
                    st.warning("⚠️ Reboot may be required")

            with comp_col3:
                st.markdown("**Last Update Activity**")
                st.markdown(f"`{patch_compliance.get('last_update_info', 'N/A')}`")
                if patch_compliance.get('kernel_age_days'):
                    days = patch_compliance['kernel_age_days']
                    if days > 180:
                        st.error(f"🔴 {days} days since last update")
                    elif days > 90:
                        st.warning(f"🟡 {days} days since last update")
                    else:
                        st.success(f"🟢 {days} days since last update")

            # Findings
            if patch_compliance.get('findings'):
                with st.expander(f"📋 Compliance Findings ({len(patch_compliance['findings'])})", expanded=False):
                    for finding in patch_compliance['findings']:
                        st.markdown(f"- ⚠️ {finding}")

            # Installed Kernels
            if patch_compliance.get('installed_kernels'):
                with st.expander("📦 Installed Kernel Packages", expanded=False):
                    for kpkg in patch_compliance['installed_kernels']:
                        st.code(kpkg, language=None)

            # Yum/DNF History
            history = patch_compliance.get('dnf_history') or patch_compliance.get('yum_history')
            if history:
                pkg_mgr = "DNF" if patch_compliance.get('dnf_history') else "YUM"
                with st.expander(f"📜 Recent {pkg_mgr} History (last 10)", expanded=False):
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

            # ============= TIMESTAMP CORRELATION VIEW (V7 — enriched) =============
            # Enrich: filter noise, extract daemon/process, summarize, group duplicates.
            _actionable_events = [e for e in critical_events if e.get('severity') in ('critical', 'warning')]
            if _actionable_events and correlations:
                st.markdown("---")
                st.header("🔗 Timestamp Correlation View")
                st.caption("Infrastructure events correlated with system resource usage — noise filtered, grouped by minute")

                # Enrich + group
                _enriched = enrich_correlations(correlations)
                _grouped = group_correlations(_enriched)

                raw_matched = sum(1 for c in correlations if c['sar_matched'])
                noise_filtered = raw_matched - len(_enriched)

                if _grouped:
                    st.info(
                        f"📊 **{len(_grouped)}** event groups from **{len(_enriched)}** actionable events "
                        f"(±5 min SAR window)"
                        + (f" | {noise_filtered} routine/noise events hidden" if noise_filtered > 0 else "")
                    )

                    # ── Main grouped table ──
                    corr_rows = []
                    for g in _grouped:
                        sev_icon = {'critical': '🔴', 'warning': '🟡'}.get(g['severity'], '⚪')
                        row = {
                            'Sev': sev_icon,
                            'Time': g['minute'],
                            'Category': g['category'],
                            'Service': g['daemon'],
                            'What Happened': g['summary'] + (f"  (×{g['count']})" if g['count'] > 1 else ""),
                            'CPU%': f"{g['cpu_usage']}%" if g['cpu_usage'] is not None else '-',
                            'IOWait%': f"{g['cpu_iowait']}%" if g['cpu_iowait'] is not None else '-',
                            'MEM%': f"{g['mem_used_pct']}%" if g['mem_used_pct'] is not None else '-',
                            'Load1': f"{g['load_1']}" if g['load_1'] is not None else '-',
                            'Blocked': f"{int(g['blocked'])}" if g['blocked'] is not None else '-',
                            'DiskUtil%': f"{g['disk_util']}%" if g['disk_util'] is not None else '-',
                        }
                        corr_rows.append(row)

                    st.dataframe(
                        pd.DataFrame(corr_rows),
                        use_container_width=True,
                        hide_index=True,
                        height=min(500, len(corr_rows) * 40 + 40),
                    )

                    # ── Notable correlations: resource spikes + events ──
                    high_cpu = [g for g in _grouped if g.get('cpu_usage') and g['cpu_usage'] >= 80]
                    high_mem = [g for g in _grouped if g.get('mem_used_pct') and g['mem_used_pct'] >= 90]
                    high_io = [g for g in _grouped if g.get('cpu_iowait') and g['cpu_iowait'] >= 20]
                    blocked = [g for g in _grouped if g.get('blocked') and g['blocked'] > 0]

                    if high_cpu or high_mem or high_io or blocked:
                        st.markdown("##### ⚡ Notable Correlations")
                        if high_cpu:
                            st.warning(f"🔥 **{len(high_cpu)}** event group(s) during high CPU (≥80%)")
                            for g in high_cpu[:3]:
                                st.caption(f"  {g['minute']} — CPU {g['cpu_usage']}% — [{g['daemon']}] {g['summary']}")
                        if high_mem:
                            st.warning(f"🧠 **{len(high_mem)}** event group(s) during high memory (≥90%)")
                            for g in high_mem[:3]:
                                st.caption(f"  {g['minute']} — MEM {g['mem_used_pct']}% — [{g['daemon']}] {g['summary']}")
                        if high_io:
                            st.warning(f"💾 **{len(high_io)}** event group(s) during high IOWait (≥20%)")
                            for g in high_io[:3]:
                                st.caption(f"  {g['minute']} — IOWait {g['cpu_iowait']}% — [{g['daemon']}] {g['summary']}")
                        if blocked:
                            st.warning(f"⏳ **{len(blocked)}** event group(s) while processes were blocked")
                            for g in blocked[:3]:
                                st.caption(f"  {g['minute']} — Blocked:{int(g['blocked'])} — [{g['daemon']}] {g['summary']}")

                    # ── Expandable: raw event messages per group ──
                    with st.expander("🔍 Show raw event messages per group", expanded=False):
                        for g in _grouped:
                            sev_icon = {'critical': '🔴', 'warning': '🟡'}.get(g['severity'], '⚪')
                            st.markdown(f"**{sev_icon} {g['minute']} — [{g['category']}] {g['summary']}** ({g['count']}×)")
                            for msg in g['messages']:
                                st.caption(f"  └ {msg}")
                else:
                    if noise_filtered > 0:
                        st.info(f"ℹ️ All {noise_filtered} correlated events were routine/noise — no actionable events to display")
                    else:
                        st.info("ℹ️ No correlations found (events and SAR data may not overlap in time)")

            # ============= COPY-PASTE SUMMARY (V5) =============
            st.markdown("---")
            st.header("📋 Copy-Paste Summary")
            st.caption("Pre-formatted summary ready to paste into tickets, emails, or documentation")

            st.code(summary_text, language=None)

            st.download_button(
                label="📥 Download Summary as Text File",
                data=summary_text,
                file_name=f"sosreport_summary_{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain",
                use_container_width=True
            )

            # ============= PUSH RESULTS =============
            if results:
                st.markdown("---")
                st.header("📤 Data Upload Results")
                if results.get('sar', 0) > 0:
                    st.success(f"✅ SAR: {results['sar']:,} metrics pushed to InfluxDB")
                if results.get('logs', 0) > 0:
                    st.success(f"✅ Logs: {results['logs']:,} entries pushed to Loki")
                if results.get('dashboard'):
                    st.success(f"✅ Dashboard created")
                    st.markdown(f"🔗 [Open Dashboard]({results['dashboard']})")
            
            st.header("🎉 Results")

            st.markdown(f"""
            <div class="success-box">
                <h3>Processing Complete!</h3>
                <p><strong>Hostname:</strong> {hostname}</p>
                <p><strong>SAR Metrics Pushed:</strong> {results.get('sar', 0):,}</p>
                <p><strong>Log Entries Pushed:</strong> {results.get('logs', 0):,}</p>
                <p><strong>Dashboard:</strong> <a href="{results.get('dashboard', '#')}" target="_blank">Open in new tab ↗</a></p>
            </div>
            """, unsafe_allow_html=True)

            # ===== SUPPORTCONFIG DEBUG (if applicable) =====
            _sc_debug = _ad.get('sc_debug_info', {})
            if _sc_debug:
                st.markdown("---")
                with st.expander("🔧 Supportconfig Debug Info", expanded=False):
                    st.write("**Supportconfig .txt files in archive root:**")
                    st.code('\n'.join(_sc_debug.get('sc_txt_files', ['(none)'])))
                    
                    st.write("**Materialized var/log/ files:**")
                    vl_files = _sc_debug.get('var_log_files', {})
                    if vl_files:
                        for fname, sz in sorted(vl_files.items()):
                            st.text(f"  {fname}: {sz:,} bytes")
                    else:
                        st.warning("No files in var/log/ — materialization may have failed")
                    
                    st.write("**SAR files (sos_commands/sar/):**")
                    sar_info = _sc_debug.get('sar_files', {})
                    if isinstance(sar_info, dict):
                        for fname, sz in sorted(sar_info.items()):
                            st.text(f"  {fname}: {sz:,} bytes")
                    else:
                        st.warning(str(sar_info))
                    
                    st.write(f"**SAR files parsed:** {_sc_debug.get('sar_files_found', [])}")
                    st.write(f"**SAR metrics count:** {_sc_debug.get('sar_metrics_count', 0)}")
                    
                    st.write("**Log parser — found files:**")
                    for log_type, files in _sc_debug.get('log_parser_found', {}).items():
                        st.text(f"  {log_type}: {files}")
                    
                    st.write("**Log parser — parsed entry counts:**")
                    for log_type, count in _sc_debug.get('log_parser_summary', {}).items():
                        st.text(f"  {log_type}: {count:,}")

            # ===== PERFORMANCE TIMING BREAKDOWN =====
            st.markdown("---")
            st.subheader("⏱️ Processing Time Breakdown")

            # Build timing table
            timing_rows = []
            for phase, secs in _timings.items():
                if secs >= 60:
                    display = f"{int(secs // 60)}m {secs % 60:.1f}s"
                else:
                    display = f"{secs:.2f}s"
                pct = (secs / _total_time * 100) if _total_time > 0 else 0
                bar_len = int(pct / 2)  # max ~50 chars
                bar = '█' * bar_len + '░' * (50 - bar_len)
                timing_rows.append({'Phase': phase, 'Time': display, '%': f"{pct:.1f}%", 'Bar': bar})

            # Sort by time descending
            timing_rows.sort(key=lambda r: _timings.get(r['Phase'], 0), reverse=True)

            if timing_rows:
                st.dataframe(pd.DataFrame(timing_rows), use_container_width=True, hide_index=True)

            # Total time in a nice box
            if _total_time >= 60:
                total_display = f"{int(_total_time // 60)}m {_total_time % 60:.1f}s"
            else:
                total_display = f"{_total_time:.2f}s"
            st.info(f"⏱️ **Total Processing Time: {total_display}** | File size: {file_size_mb:.1f} MB | SAR metrics: {_ad['sar_metrics_count']:,} | Log entries: {_ad['logs_count']:,}")

            # Embed Grafana Dashboard
            if results.get('dashboard'):
                st.markdown("---")
                st.header("📊 Grafana Dashboard")

                # Convert dashboard URL to embed format
                dashboard_url = results.get('dashboard')

                # Check if using Azure Grafana (iframe embedding not supported due to Azure AD)
                is_azure_grafana = 'grafana.azure.com' in GRAFANA_URL

                if is_azure_grafana:
                    # Azure Grafana doesn't support iframe embedding due to Azure AD auth
                    st.markdown(f"""
                    <div style="background-color: #e7f3ff; border: 2px solid #0078d4; border-radius: 10px; padding: 20px; margin: 20px 0; text-align: center;">
                        <h3 style="color: #0078d4; margin-bottom: 15px;">🔗 Dashboard Ready on Azure Grafana</h3>
                        <p style="margin-bottom: 20px;">Azure Managed Grafana uses Azure AD authentication which doesn't support iframe embedding.</p>
                        <a href="{dashboard_url}" target="_blank" style="background-color: #0078d4; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-size: 16px; font-weight: bold;">
                            Open Dashboard in New Tab ↗
                        </a>
                        <p style="margin-top: 15px; color: #666; font-size: 12px;">💡 Tip: Right-click the button and select "Open in new tab" for best experience</p>
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
                        <p>💡 <em>Dashboard shows historical SOSreport data. No auto-refresh needed.</em></p>
                    </div>
                    """, unsafe_allow_html=True)

                    # Embed dashboard in iframe
                    components.iframe(
                        src=embed_url,
                        height=800,
                        scrolling=True
                    )

    
    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: gray;'>"
        "SOSreport & Supportconfig Analyzer V8 | Powered by Streamlit, InfluxDB, Loki & Grafana | System Info + Anomaly Detection + Critical Events + Patch Compliance + Cloud Detection"
        "</div>",
        unsafe_allow_html=True
    )


if __name__ == "__main__":
    main()
