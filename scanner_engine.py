#!/usr/bin/env python3
"""
Network Security Scanner v6.5
Bounded discovery, conservative findings, explicit online CVE lookup.
"""

import socket
import http.client
import math
from itertools import islice
from http.cookies import SimpleCookie
from html.parser import HTMLParser
import ssl
import ipaddress
import json
import re
import time
import urllib.request
import urllib.error
import concurrent.futures
import hashlib
import threading
import queue
import html as html_escape
import random
import os
import sqlite3
import struct
import subprocess
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any, Tuple, Set, Callable, Union
from enum import Enum
from urllib.parse import urlparse, urljoin

# =======================================================
#  ENUMS
# =======================================================

class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    NONE = "NONE"

class Confidence(Enum):
    HIGH = 0.95
    MEDIUM = 0.75
    LOW = 0.55
    NONE = 0.0

class FindingStatus(Enum):
    DETECTED = "DETECTED"
    EXPOSED = "EXPOSED"
    MISCONFIGURED = "MISCONFIGURED"
    POTENTIALLY_VULNERABLE = "POTENTIALLY_VULNERABLE"
    VULNERABLE = "VULNERABLE"
    CONFIRMED = "CONFIRMED"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    UNKNOWN = "UNKNOWN"

class ScanPhase(Enum):
    INIT = "init"
    RESOLVE = "resolve"
    DISCOVERY = "discovery"
    FINGERPRINT = "fingerprint"
    OS_DETECT = "os_detect"
    WEB = "web"
    TLS = "tls"
    CVE = "cve"
    CONFIG = "config"
    SCORING = "scoring"
    DONE = "done"

class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open_filtered"
    UNKNOWN = "unknown"

class ServiceProtocol(Enum):
    TCP = "tcp"
    UDP = "udp"

class ScanMode(Enum):
    SAFE = "safe"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"
    EXTENDED = "extended"
    KEENETIC = "keenetic"
    UNIVERSAL = "universal"

# =======================================================
#  MODELS
# =======================================================

@dataclass
class Evidence:
    source: str
    value: str
    confidence: float

@dataclass
class ResolvedAddress:
    address: str
    family: int
    is_ipv6: bool

@dataclass
class Target:
    original: str
    host: str
    port: int = 80
    scheme: str = "http"
    is_hostname: bool = False
    is_cidr: bool = False
    is_url: bool = False
    addresses: List[ResolvedAddress] = field(default_factory=list)

@dataclass
class Service:
    address: str
    port: int
    protocol: ServiceProtocol
    state: PortState
    service: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    confidence: float = 0.0
    evidence: List[Evidence] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

@dataclass
class WebService:
    address: str
    port: int
    protocol: str
    url: str
    server: str = ""
    powered_by: str = ""
    technologies: List[Dict[str, Any]] = field(default_factory=list)
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body_hash: str = ""
    body_preview: str = ""
    redirect_chain: List[str] = field(default_factory=list)
    is_https: bool = False
    findings: List['Vulnerability'] = field(default_factory=list)
    title: str = ''
    extra: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Vulnerability:
    id: str
    title: str
    description: str
    risk: RiskLevel
    confidence: Confidence
    status: FindingStatus
    service: Service
    evidence: List[Evidence] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DeviceProfile:
    address: str
    os_family: str = "unknown"      # linux, windows, macos, ios, android, network_device, unknown
    os_name: str = ""               # человеко-читаемое имя, напр. "Ubuntu", "Windows Server"
    os_version: str = ""
    device_type: str = ""           # server, workstation, mobile, router, iot, unknown
    confidence: float = 0.0
    evidence: List[Evidence] = field(default_factory=list)

@dataclass
class ScanResult:
    target: str
    resolved_addresses: List[str] = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    services: List[Service] = field(default_factory=list)
    web_services: List[WebService] = field(default_factory=list)
    devices: List[DeviceProfile] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    errors: List[Dict[str, str]] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    checks: List[Dict[str, Any]] = field(default_factory=list)

# =======================================================
#  EVENTS
# =======================================================

class ScannerEvent:
    def __init__(self, phase: ScanPhase, message: str, progress: float = 0.0, data: Any = None):
        self.phase = phase
        self.message = message
        self.progress = progress
        self.data = data
        self.timestamp = datetime.now().isoformat()

# =======================================================
#  NO REDIRECT HANDLER
# =======================================================

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

# =======================================================
#  CVE CACHE (SQLite)
# =======================================================

class CVECache:
    def __init__(self, db_path: str = "cve_cache.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS cve_cache (
                key TEXT PRIMARY KEY,
                data TEXT,
                timestamp REAL
            )
        ''')
        conn.commit()
        conn.close()
    
    def get(self, key: str) -> Optional[List[Dict]]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT data, timestamp FROM cve_cache WHERE key = ?', (key,))
        row = c.fetchone()
        conn.close()
        if row:
            data = json.loads(row[0])
            if time.time() - row[1] < 86400:
                return data
        return None
    
    def set(self, key: str, data: List[Dict]):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('REPLACE INTO cve_cache (key, data, timestamp) VALUES (?, ?, ?)',
                  (key, json.dumps(data), time.time()))
        conn.commit()
        conn.close()

# =======================================================
#  SCANNER ENGINE V6.2
# =======================================================

# Snapshot verified against https://keenetic.com/en/security on 2026-09-08.
# These are applicability rules, never exploit confirmations or a complete CVE inventory.
KEENETIC_ADVISORIES = [
    {'id':'CVE-2025-56007','title':'Keenetic Web API: CRLF','bound':'4.3.0','risk':'MEDIUM','condition':'Нужна активная сессия администратора и взаимодействие пользователя.'},
    {'id':'CVE-2025-56008','title':'Keenetic Wireless ISP: XSS','bound':'4.3.0','risk':'MEDIUM','condition':'Нужны близость к Wi-Fi и действие администратора в веб-интерфейсе.'},
    {'id':'CVE-2025-56009','title':'Keenetic Web API: CSRF','bound':'4.3.0','risk':'MEDIUM','condition':'Нужны активная сессия и действие пользователя.'},
    *[{'id':cve,'title':'MediaTek Wi-Fi driver','bound':'4.3.2','risk':'MEDIUM',
       'condition':'Требуется подтвердить чипсет MT7628/MT7603/MT7612/MT7613/MT7915/MT7916; радиопроверка не проводилась.'}
      for cve in ('CVE-2025-20674','CVE-2025-20685','CVE-2025-20686')],
    {'id':'CVE-2024-4021','title':'Раскрытие списка компонентов','bound':'4.1.2.15','inclusive':True,
     'risk':'LOW','models':['KN-1010','KN-1410','KN-1711','KN-1810','KN-1910'],
     'condition':'Это раскрытие названий компонентов, не доступ к управлению.'},
    {'id':'CVE-2024-4022','title':'Версия устройства: спорная CVE','bound':'4.1.2.15','inclusive':True,
     'risk':'INFO','models':['KN-1010','KN-1410','KN-1711','KN-1810','KN-1910'],
     'condition':'Производитель считает публикацию модели/версии штатным поведением.'},
    {'id':'KEN-PSA-2026-WP01','title':'Права пользователя read-only','bound':'5.0.4','risk':'HIGH',
     'condition':'Нужна учётная запись read-only. Для поддерживаемой ветки отдельно сверьте наличие backport-исправления.'},
]


class PageFacts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_title=False
        self.title=''
        self.password_input=False
        self.is_html=False

    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag in ('html','head','body','form','title'):
            self.is_html=True
        if tag=='title':self.in_title=True
        if tag=='input' and attrs.get('type','').lower()=='password':
            self.password_input=True

    def handle_endtag(self,tag):
        if tag=='title':self.in_title=False

    def handle_data(self,data):
        if self.in_title and len(self.title)<200:self.title+=data[:200]


class ScannerEngineV6:
    def __init__(self, target: str, mode: ScanMode = ScanMode.UNIVERSAL, 
                 timeout: float = 1.5, max_workers: int = 20,
                 event_callback: Optional[Callable] = None, *,
                 ports: str = "", max_hosts: int = 256, udp: bool = False,
                 cve_lookup: bool = False, cache_path: str = "cve_cache.db",
                 device_model: str = "", firmware: str = "", service_map: str = ""):
        if not math.isfinite(timeout) or not 0.1 <= timeout <= 30:
            raise ValueError("Timeout must be between 0.1 and 30 seconds")
        if not isinstance(max_workers, int) or not 1 <= max_workers <= 100:
            raise ValueError("Workers must be between 1 and 100")
        if not isinstance(max_hosts, int) or not 1 <= max_hosts <= 4096:
            raise ValueError("max_hosts must be between 1 and 4096")
        self.device_model = device_model.strip().upper()
        self.firmware_hint = firmware.strip()
        if self.device_model and not re.fullmatch(r'KN-[0-9]{4}', self.device_model):
            raise ValueError('Model must use KN-1234 format from the device label')
        if self.firmware_hint and not re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,3}', self.firmware_hint):
            raise ValueError('Firmware must be a numeric release, e.g. 4.2.1; prereleases are not mapped to stable releases')
        from protocol_checks import PROBES
        self.service_hints = {}
        for entry in service_map.split(',') if service_map else []:
            try:
                number, protocol = entry.strip().split('=')
                if not number.isdigit() or not 1 <= int(number) <= 65535 or protocol not in PROBES:
                    raise ValueError()
                self.service_hints[int(number)] = protocol
            except ValueError:
                raise ValueError('Service map: use 1884=mqtt,33389=rdp; see supported protocol names in README')
        self._web_cache = {}
        self._device_metadata = {}
        self.custom_ports = self.parse_ports(ports) if ports else None
        self.max_hosts = max_hosts
        self.udp_enabled = udp
        self.cve_lookup = cve_lookup
        self._last_api_call = 0.0
        self.target_str = target
        self.mode = mode
        self.timeout = timeout
        self.max_workers = max_workers
        self.event_callback = event_callback
        self._cancel_event = threading.Event()
        self._lock = threading.Lock()
        self._cve_cache = CVECache(cache_path) if cve_lookup else None
        self._target: Optional[Target] = None
        self._explicit_port = False
        self._api_call_count = 0
        self.result = ScanResult(
            target=target,
            start_time=datetime.now().isoformat()
        )
        
    def _emit(self, phase: ScanPhase, message: str, progress: float = 0.0, data: Any = None):
        if self.event_callback:
            try:
                self.event_callback(ScannerEvent(phase, message, progress, data))
            except Exception:
                pass
        print(f"[{phase.value}] {message}")
    
    def _record_error(self, module: str, message: str, details: Any = None):
        error = {"module": module, "message": message, "timestamp": datetime.now().isoformat()}
        if details:
            error["details"] = str(details)
        with self._lock:
            self.result.errors.append(error)
    
    def cancel(self):
        self._cancel_event.set()
        self._emit(ScanPhase.INIT, "Cancelling scan...")
    
    def scan(self) -> ScanResult:
        started = time.monotonic()
        self.result.start_time = datetime.now().isoformat()
        try:
            self._scan_impl()
        except Exception as exc:
            self._record_error("scan", str(exc))
        finally:
            self._score_and_deduplicate()
            self.result.end_time = datetime.now().isoformat()
            self.result.duration = time.monotonic() - started
            self.result.stats.update({
                "addresses": len(self.result.resolved_addresses),
                "services": len(self.result.services),
                "web_services": len(self.result.web_services),
                "findings": len(self.result.vulnerabilities),
                "errors": len(self.result.errors),
                "cancelled": self._cancel_event.is_set(),
                "status": "cancelled" if self._cancel_event.is_set() else
                          "completed_with_errors" if self.result.errors else "completed",
                "cve_lookup": self.cve_lookup,
                "keenetic_catalog_date": "2026-09-08",
                "mode": self.mode.value,
                "checks": len(self.result.checks),
                "unknown_checks": sum(c['status'] == 'UNKNOWN' for c in self.result.checks),
                "coverage_note": "No findings does not establish security. Authentication/data permissions, Wi-Fi attacks and SMBv1 are not tested; RDP is negotiation-only.",
                "protocol_modules": sorted({s.extra['protocol_audit'] for s in self.result.services if s.extra.get('protocol_audit')}),
            })
            self._emit(ScanPhase.DONE, self.result.stats["status"], 1.0)
        return self.result

    def _scan_impl(self) -> ScanResult:
        start_time = time.time()
        
        self._emit(ScanPhase.INIT, f"Starting scan for {self.target_str}")
        self._emit(ScanPhase.INIT, f"Mode: {self.mode.value}, Timeout: {self.timeout}s, Workers: {self.max_workers}")
        
        # 1. Resolve target
        self._emit(ScanPhase.RESOLVE, "Resolving target...")
        addresses = self._resolve_target(self.target_str)
        if not addresses:
            self.result.end_time = datetime.now().isoformat()
            return self.result
        
        if (self.device_model or self.firmware_hint) and len(addresses) != 1:
            raise ValueError('Manual model/firmware applies only to a single resolved device')
        self.result.resolved_addresses = [a.address for a in addresses]
        if self.device_model or self.firmware_hint:
            addr = addresses[0].address
            self._device_metadata[addr] = {'vendor': 'Keenetic', 'models': set(), 'versions': set(),
                'manual_model': self.device_model, 'manual_version': self.firmware_hint,
                'sources': ['user input (not verified by the scanner)']}
        self._emit(ScanPhase.RESOLVE, f"Resolved to {len(addresses)} addresses")
        
        # 2. Discovery
        if self._cancel_event.is_set():
            return self.result
        self._emit(ScanPhase.DISCOVERY, "TCP discovery...")
        services = self._discover(addresses)
        self.result.services = services
        self._emit(ScanPhase.DISCOVERY, f"Found {len(services)} services")
        
        # 3. Service fingerprint (с определением HTTPS)
        if self._cancel_event.is_set():
            return self.result
        self._emit(ScanPhase.FINGERPRINT, f"Fingerprinting {len(services)} services...")
        self._fingerprint_services()
        self._emit(ScanPhase.FINGERPRINT, f"Fingerprinted {len(self.result.services)} services")
        
        # 4. Web fingerprint (HTTP и HTTPS)
        web_candidates = [s for s in self.result.services if s.extra.get("identification") == "http_response"]
        if web_candidates and not self._cancel_event.is_set():
            self._emit(ScanPhase.WEB, f"Web fingerprint ({len(web_candidates)} services)...")
            self._fingerprint_web(web_candidates)
            self._emit(ScanPhase.WEB, f"Web fingerprint complete")
        
        if not self._cancel_event.is_set():
            self._probe_keenetic_web()

        # 4.5 OS / device fingerprint (Windows/Linux/macOS/iOS/Android)
        if not self._cancel_event.is_set():
            self._emit(ScanPhase.OS_DETECT, "Detecting device/OS types...")
            self._detect_devices()
            self._emit(ScanPhase.OS_DETECT, f"Identified {len(self.result.devices)} device(s)")
        
        # 5. TLS scanner (теперь работает, потому что есть service == "https")
        if not self._cancel_event.is_set():
            self._emit(ScanPhase.TLS, "TLS scanning...")
            self._scan_tls()
            self._emit(ScanPhase.TLS, "TLS scanning complete")
        
        if not self._cancel_event.is_set():
            self._check_keenetic_advisories()

        # 6. CVE correlation
        if not self._cancel_event.is_set():
            self._emit(ScanPhase.CVE, "CVE correlation...")
            self._correlate_cves()
            self._emit(ScanPhase.CVE, f"CVE correlation complete")
        
        # 7. Configuration checks
        if not self._cancel_event.is_set():
            self._emit(ScanPhase.CONFIG, "Configuration checks...")
            self._check_configuration()
            self._emit(ScanPhase.CONFIG, "Configuration checks complete")
        
        # 8. Scoring & deduplication
        if not self._cancel_event.is_set():
            self._emit(ScanPhase.SCORING, "Scoring & deduplication...")
            self._score_and_deduplicate()
            self._emit(ScanPhase.SCORING, f"Final findings: {len(self.result.vulnerabilities)}")
        
        self.result.end_time = datetime.now().isoformat()
        self.result.duration = time.time() - start_time
        self.result.stats.update({
            "addresses": len(self.result.resolved_addresses),
            "services": len(self.result.services),
            "web_services": len(self.result.web_services),
            "findings": len(self.result.vulnerabilities),
            "errors": len(self.result.errors)
        })
        
        
        return self.result
    
    # =======================================================
    #  TARGET RESOLVER
    # =======================================================
    
    @staticmethod
    def parse_ports(spec: str) -> List[int]:
        ports = set()
        for part in spec.split(','):
            part = part.strip()
            if not re.fullmatch(r"[0-9]+(?:-[0-9]+)?", part):
                raise ValueError("Ports: use 22,80,443 or 8000-8100")
            bounds = [int(x) for x in part.split('-')]
            lo, hi = bounds[0], bounds[-1]
            if not 1 <= lo <= hi <= 65535:
                raise ValueError("Ports must be in 1..65535; ranges must ascend")
            ports.update(range(lo, hi + 1))
        return sorted(ports)

    def _resolve_target(self, target_str: str) -> List[ResolvedAddress]:
        value = target_str.strip()
        if not value or any(ord(c) < 33 for c in value):
            raise ValueError("Target must be one IP, hostname, CIDR or HTTP(S) URL")
        if '/' in value and '://' not in value:
            network = ipaddress.ip_network(value, strict=False)
            self._target = Target(value, str(network), is_cidr=True)
            return self._resolve_cidr(network)
        try:
            ip = ipaddress.ip_address(value.strip('[]'))
        except ValueError:
            ip = None
        if ip is not None:
            self._target = Target(value, str(ip))
            return [ResolvedAddress(str(ip), socket.AF_INET6 if ip.version == 6 else socket.AF_INET, ip.version == 6)]
        parsed = urlparse(value if '://' in value else '//' + value)
        if parsed.scheme and parsed.scheme not in ('http', 'https'):
            raise ValueError("Only HTTP(S) URLs are supported")
        if not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError("Invalid target or embedded credentials")
        host = parsed.hostname.encode('idna').decode('ascii')
        scheme = parsed.scheme or ('https' if parsed.port == 443 else 'http')
        if parsed.port == 0:
            raise ValueError("Port must be between 1 and 65535")
        port = parsed.port or (443 if scheme == 'https' else 80)
        self._explicit_port = parsed.port is not None or bool(parsed.scheme)
        self._target = Target(value, host, port, scheme, is_hostname=True, is_url=bool(parsed.scheme))
        addresses = self._resolve_host(host)
        if len(addresses) > self.max_hosts:
            raise ValueError("Resolved addresses exceed max_hosts")
        self._target.addresses = addresses
        return addresses
    
    def _resolve_cidr(self, network) -> List[ResolvedAddress]:
        # Never silently truncate or sample an enormous IPv6 address space.
        count = network.num_addresses
        if network.version == 4 and network.prefixlen < 31:
            count -= 2
        elif network.version == 6 and network.prefixlen < 127:
            count -= 1
        if count > self.max_hosts:
            raise ValueError(f"Network contains {count} hosts; limit is {self.max_hosts}. Use a smaller subnet.")
        return [ResolvedAddress(str(h), socket.AF_INET6 if network.version == 6 else socket.AF_INET,
                                network.version == 6) for h in network.hosts()]

    def _server_name(self, address: str) -> str:
        return self._target.host if self._target and self._target.is_hostname else address

    def _http_request(self, address, port, scheme, path='/'):
        """Pin connection to discovered IP; preserve HTTP Host and TLS SNI. No redirects/proxies."""
        name = self._server_name(address)
        conn = http.client.HTTPConnection(address, port, timeout=self._application_timeout())
        try:
            conn.connect()
            if scheme == 'https':
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE  # Certificate trust is audited separately.
                conn.sock = ctx.wrap_socket(conn.sock, server_hostname=name)
            host = f'[{name}]' if ':' in name else name
            conn.request('GET', path, headers={'Host': f'{host}:{port}',
                         'User-Agent': 'NetworkSecurityScanner/6.5', 'Connection': 'close'})
            with conn.getresponse() as response:
                headers = {}
                for key, value in response.getheaders():
                    key = key.lower()
                    headers[key] = headers[key] + '\n' + value if key in headers else value
                return response.status, headers, response.read(65536)
        finally:
            conn.close()
    
    def _resolve_host(self, host: str) -> List[ResolvedAddress]:
        try:
            addrinfo = socket.getaddrinfo(host, 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
            addresses = []
            seen = set()
            for info in addrinfo:
                family = info[0]
                addr = info[4][0]
                if addr not in seen:
                    seen.add(addr)
                    addresses.append(ResolvedAddress(
                        address=addr,
                        family=family,
                        is_ipv6=family == socket.AF_INET6
                    ))
            return addresses
        except socket.gaierror as e:
            self._record_error("resolve", f"Failed to resolve {host}", e)
            return []
    
    def _build_url(self, address: str, port: int, scheme: str) -> str:
        if ':' in address:
            address = f"[{address}]"
        return f"{scheme}://{address}:{port}/"
    
    # =======================================================
    #  DISCOVERY
    # =======================================================
    
    def _discover(self, addresses: List[ResolvedAddress]) -> List[Service]:
        basic = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443]
        standard = basic + [5432,6379,9200,9300,5000,5001,8000,8001,8081,8088,9000,9001,9443,27017]
        extended = standard + [465,548,554,631,853,1883,2375,2376,3702,5357,5555,5671,5672,
                               5985,5986,7000,8008,8009,8883,8888,9100,10000,32400,62078]
        universal = extended + [2121,2222,587,4222,5901,5902,5903,8554,11211]
        presets = {ScanMode.SAFE: basic, ScanMode.STANDARD: standard,
                   ScanMode.EXTENDED: extended, ScanMode.KEENETIC: extended, ScanMode.UNIVERSAL: universal, ScanMode.AGGRESSIVE: list(range(1,1025)) + extended}
        ports = set(self.custom_ports if self.custom_ports is not None else presets[self.mode])
        if self._target and self._explicit_port:
            ports.add(self._target.port)
        ports.update(self.service_hints)
        ports = sorted(ports)
        udp_ports = [53,123] if self.udp_enabled else []
        total = len(addresses) * (len(ports) + len(udp_ports))
        self.result.stats.update({'tcp_ports': ports, 'udp_ports': udp_ports, 'discovery_jobs': total})
        jobs = ((a.address, p, proto) for a in addresses
                for proto, group in [('tcp',ports),('udp',udp_ports)] for p in group)
        services = []
        completed = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            while not self._cancel_event.is_set():
                batch = list(islice(jobs, self.max_workers))
                if not batch:
                    break
                futures = [pool.submit(self._probe_tcp if proto == 'tcp' else self._probe_udp, a, p)
                           for a,p,proto in batch]
                for future in concurrent.futures.as_completed(futures):
                    completed += 1
                    try:
                        service = future.result()
                        if service:
                            services.append(service)
                    except Exception as exc:
                        self._record_error('discovery', str(exc))
                self._emit(ScanPhase.DISCOVERY, f"Progress: {completed}/{total}", completed / total)
        self.result.stats['discovery_completed'] = completed
        return sorted(services, key=lambda x: (x.address, x.protocol.value, x.port))
    
    def _probe_tcp(self, address: str, port: int) -> Optional[Service]:
        if self._cancel_event.is_set():
            return None
        try:
            family = socket.AF_INET6 if ':' in address else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                if sock.connect_ex((address, port)) == 0:
                    return Service(
                        address=address,
                        port=port,
                        protocol=ServiceProtocol.TCP,
                        state=PortState.OPEN
                    )
        except Exception:
            pass
        return None
    
    def _probe_udp(self, address: str, port: int) -> Optional[Service]:
        if self._cancel_event.is_set():
            return None
        try:
            family = socket.AF_INET6 if ':' in address else socket.AF_INET
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((address, port))  # Kernel filters replies to this peer.
                if port == 53:
                    token = os.urandom(2)
                    packet = token + bytes.fromhex('01000001000000000000') + b'\x00\x00\x02\x00\x01'
                elif port == 123:
                    token = os.urandom(8)
                    packet = b'\x23' + bytes(39) + token
                else:
                    return None
                sock.send(packet)
                data = sock.recv(4096)
                valid = (len(data) >= 12 and data[:2] == token and data[2] & 0x80) if port == 53 else (
                    len(data) >= 48 and data[0] & 7 == 4 and data[24:32] == token)
                if valid:
                    return Service(address, port, ServiceProtocol.UDP, PortState.OPEN,
                                   service='dns' if port == 53 else 'ntp', confidence=0.9)
        except OSError:
            pass  # No reply is inconclusive, never evidence of an open port.
        return None
    
    def _fingerprint_services(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._fingerprint_single, svc): svc for svc in self.result.services}
            for future in concurrent.futures.as_completed(futures):
                if self._cancel_event.is_set():
                    break
                result = future.result()
                if result:
                    original = futures[future]
                    for i, svc in enumerate(self.result.services):
                        if (svc.address == original.address and 
                            svc.port == original.port and 
                            svc.protocol == original.protocol):
                            self.result.services[i] = result
                            break
    
    def _fingerprint_single(self, service: Service) -> Service:
        if service.protocol != ServiceProtocol.TCP or self._cancel_event.is_set():
            return service
        port = service.port
        guessed, product, _ = self._detect_service(port, '')
        service.service = 'unknown'
        service.extra.update(identification='port_hint', port_hint=guessed or 'unknown')
        if port == 23:
            return self._fingerprint_telnet(service)
        from protocol_checks import select_protocol
        protocol = self.service_hints.get(port)
        if not protocol and not (self._target and self._target.is_url and self._target.port == port):
            protocol = select_protocol(port)
        if protocol:
            return self._audit_protocol(service, protocol)
        web_ports = {80,443,5000,5001,8000,8001,8008,8080,8081,8088,8443,8888,9000,9001,9443,10000,32400}
        tls_ports = {443,465,636,853,993,995,2376,5671,5986,8443,8883,9443}
        if self._target and self._explicit_port:
            web_ports.add(self._target.port)
        if port in web_ports:
            # HTTP reply confirms both the application and (for HTTPS) the TLS handshake.
            first = 'https' if port in tls_ports else 'http'
            if self._target and self._target.port == port and self._target.is_url:
                first = self._target.scheme
            attempts = []
            for scheme in (first, 'http' if first == 'https' else 'https'):
                if self._cancel_event.is_set():
                    return service
                try:
                    response = self._http_request(service.address,port,scheme)
                    status, headers, _ = response
                    service.service = scheme
                    service.extra.update(tls=scheme == 'https', identification='http_response')
                    service.banner = f"HTTP {status} Server: {headers.get('server','')}"[:512]
                    _, service.product, service.version = self._detect_service(port,service.banner)
                    service.confidence = 0.95
                    with self._lock:
                        self._web_cache[(service.address,port,scheme)] = response
                    self._check_row('HTTP-DETECTION',service,'PASS',f'{scheme.upper()} response {status}')
                    return service
                except (OSError,http.client.HTTPException,ValueError) as exc:
                    attempts.append(f'{scheme}: {type(exc).__name__}: {exc}')
            # Failed HTTP requests can still leave a valid non-HTTP TLS endpoint.
            if self._check_tls(service.address,port):
                service.service = 'tls'
                service.extra.update(tls=True,identification='tls_handshake')
                service.confidence = 0.95
            self._check_row('HTTP-DETECTION',service,'UNKNOWN','; '.join(attempts))
            return service
        if port in tls_ports:
            tls = self._check_tls(service.address,port)
            service.extra['tls'] = tls
            if tls:
                service.service = guessed or 'tls'
                service.extra['identification'] = 'tls_handshake'
                service.confidence = 0.6 if guessed else 0.95
            return service
        try:
            with socket.create_connection((service.address,port),timeout=self.timeout) as sock:
                if port == 6379:
                    sock.sendall(b'*1\r\n$4\r\nPING\r\n')
                data = sock.recv(2048)
                if data:
                    banner = self._clean_banner(data.decode('utf-8',errors='replace'))
                    service.banner = banner[:512]
                    detected, service.product, service.version = self._detect_service(port,banner)
                    strong = banner.lower().startswith(('ssh-','http/','220','rfb ')) or banner.startswith('+PONG')
                    service.service = detected if strong else 'unknown'
                    service.confidence = 0.75 if strong else 0.25
                    service.extra['identification'] = 'banner' if strong else 'port_hint'
                    inferred = select_protocol(0, service.service, banner)
                    if inferred:
                        return self._audit_protocol(service,inferred)
                    if service.service == 'ssh' and banner.startswith(('SSH-1.3-','SSH-1.5-')):
                        self._add_finding('SSH-V1-BANNER',service,'Сервис объявляет устаревший SSHv1',
                            'Получен баннер SSH-1.x. Ключевой обмен и вход не выполнялись.',RiskLevel.HIGH,
                            remediation='Отключите SSHv1, обновите SSH-сервер и используйте SSHv2.')
        except OSError:
            pass
        return service

    def _audit_protocol(self, service, protocol):
        from protocol_checks import audit
        outcome = audit(protocol, service.address, service.port, self._application_timeout(),
                        self._cancel_event, self._server_name(service.address))
        service.extra['protocol_audit'] = protocol
        service.extra['protocol_metadata'] = outcome.metadata
        if outcome.confirmed:
            service.service = protocol
            service.confidence = 0.95
            service.extra['identification'] = 'protocol_response'
            if outcome.banner:
                service.banner = self._clean_banner(outcome.banner)[:512]
            service.product = outcome.product
            service.version = outcome.version
            if not service.product and service.banner:
                detected, product, version = self._detect_service(service.port,service.banner)
                if detected == protocol:
                    service.product, service.version = product, version
        if outcome.tls:
            service.extra['tls'] = True
        for check in outcome.checks:
            if check['risk']:
                status = FindingStatus.POTENTIALLY_VULNERABLE if check['status'] == 'POTENTIAL' else FindingStatus.MISCONFIGURED
                titles = {
                    'VNC-NONE-OFFERED':'VNC предлагает режим без аутентификации',
                    'SMB-SIGNING':'SMB не требует подпись сообщений',
                    'RDP-CREDSSP':'RDP согласовал TLS без CredSSP',
                    'MQTT-ANONYMOUS':'MQTT принял соединение без учётных данных',
                    'REDIS-METADATA':'Redis раскрывает служебные сведения без входа',
                    'FTP-AUTH-TLS':'FTP не поддержал AUTH TLS',
                    'SMTP-AUTH-PLAINTEXT':'SMTP рекламирует парольную аутентификацию до TLS',
                    'NATS-AUTH':'NATS сообщает об отключённой обязательной аутентификации',
                }
                self._add_finding(check['id'],service,titles.get(check['id'],check['id']),check['detail'],RiskLevel[check['risk']],
                                  status,check['remediation'],check['references'])
            self._check_row(check['id'],service,check['status'],check['detail'],check['references'])
        return service

    def _check_tls(self, address: str, port: int) -> bool:
        if self._cancel_event.is_set():
            return False
        try:
            with socket.create_connection((address,port),timeout=self._application_timeout()) as sock:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock,server_hostname=self._server_name(address)):
                    return True
        except OSError:
            return False

    def _detect_service(self, port: int, banner: str) -> Tuple[str, str, str]:
        banner_lower = banner.lower()
        
        port_map = {
            21: ("ftp", "FTP", ""), 22: ("ssh", "SSH", ""), 23: ("telnet", "Telnet", ""),
            25: ("smtp", "SMTP", ""), 53: ("dns", "DNS", ""), 80: ("http", "HTTP", ""),
            110: ("pop3", "POP3", ""), 135: ("rpc", "MS RPC", ""), 139: ("netbios", "NetBIOS", ""),
            143: ("imap", "IMAP", ""), 443: ("https", "HTTPS", ""), 445: ("smb", "SMB", ""),
            993: ("imaps", "IMAPS", ""), 995: ("pop3s", "POP3S", ""), 1723: ("pptp", "PPTP", ""),
            3306: ("mysql", "MySQL", ""), 3389: ("rdp", "RDP", ""), 5432: ("postgresql", "PostgreSQL", ""),
            5900: ("vnc", "VNC", ""), 6379: ("redis", "Redis", ""), 8080: ("http", "HTTP", ""),
            1883: ("mqtt", "MQTT", ""), 8883: ("mqtts", "MQTT", ""),
            554: ("rtsp", "RTSP", ""), 631: ("ipp", "IPP", ""), 9100: ("printing", "", ""),
            548: ("afp", "AFP", ""), 5555: ("adb", "", ""), 62078: ("lockdownd", "", ""),
            8443: ("https", "HTTPS", ""), 27017: ("mongodb", "MongoDB", ""),
        }
        
        service, product, version = port_map.get(port, ("", "", ""))
        
        if banner:
            if banner_lower.startswith("ssh-"):
                service, product = "ssh", "OpenSSH" if "openssh" in banner_lower else "Dropbear" if "dropbear" in banner_lower else "SSH"
                version = self._extract_version(banner, ["OpenSSH", "Dropbear"])
            elif banner_lower.startswith("220") and "ftp" in banner_lower:
                service, product = "ftp", "vsftpd" if "vsftpd" in banner_lower else "ProFTPD" if "proftpd" in banner_lower else "FTP"
                version = self._extract_version(banner, ["vsftpd", "ProFTPD"])
            elif banner_lower.startswith("http") or "nginx/" in banner_lower or "apache/" in banner_lower:
                service = "http"
                product = "HTTP"
                if "nginx" in banner_lower:
                    product = "nginx"
                    version = self._extract_version(banner, ["nginx"])
                elif "apache" in banner_lower:
                    product = "Apache"
                    version = self._extract_version(banner, ["Apache"])
                elif "iis" in banner_lower:
                    product = "IIS"
                    version = self._extract_version(banner, ["IIS"])
            elif "mysql" in banner_lower:
                service, product = "mysql", "MySQL"
                version = self._extract_version(banner, ["MySQL"])
            elif "redis" in banner_lower:
                service, product = "redis", "Redis"
                version = self._extract_version(banner, ["Redis"])
            elif "smb" in banner_lower:
                service, product = "smb", "SMB"
            elif "rdp" in banner_lower:
                service, product = "rdp", "RDP"
        
        return service, product, version
    
    def _extract_version(self, banner: str, keywords: List[str]) -> str:
        for keyword in keywords:
            match = re.search(re.escape(keyword) + r'[/_ -]([0-9]+(?:\.[0-9]+)+(?:p[0-9]+)?)', banner, re.I)
            if match:
                return match.group(1)
        return ""
    
    def _fingerprint_web(self, web_services: List[Service]):
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._fingerprint_web_single, svc): svc for svc in web_services}
            for future in concurrent.futures.as_completed(futures):
                if self._cancel_event.is_set():
                    break
                result = future.result()
                if result:
                    self.result.web_services.append(result)
    
    def _fingerprint_web_single(self, service: Service) -> Optional[WebService]:
        if self._cancel_event.is_set():
            return None
        proto = service.service
        try:
            cached = self._web_cache.pop((service.address,service.port,proto),None)
            status, headers, raw = cached if cached is not None else self._http_request(service.address,service.port,proto)
            body = raw.decode('utf-8',errors='replace')
            parser = PageFacts()
            parser.feed(body)
            safe_headers = {k:v for k,v in headers.items() if k in {
                'server','content-type','content-security-policy','x-frame-options','x-content-type-options',
                'strict-transport-security','referrer-policy','location','www-authenticate','x-powered-by',
                'x-ndm-product','x-ndm-version'}}
            # Don't store cookie values or authentication nonce values in reports.
            if 'www-authenticate' in safe_headers:
                safe_headers['www-authenticate'] = safe_headers['www-authenticate'].split(' ',1)[0]
            cookies = []
            for line in headers.get('set-cookie','').splitlines():
                jar = SimpleCookie()
                try:
                    jar.load(line)
                    for name, item in jar.items():
                        cookies.append({'name':name,'secure':bool(item['secure']),
                                        'httponly':bool(item['httponly']),'samesite':item['samesite'],
                                        'nonempty':bool(item.value)})
                except Exception:
                    pass
            web = WebService(service.address,service.port,proto,
                             self._build_url(service.address,service.port,proto),
                             status_code=status,headers=safe_headers,is_https=proto == 'https',
                             server=headers.get('server',''),powered_by=headers.get('x-powered-by',''),
                             body_hash=hashlib.sha256(raw).hexdigest(),body_preview='',
                             title=parser.title.strip()[:200],
                             extra={'password_form':parser.password_input,'cookies':cookies,
                                    'html':parser.is_html or 'text/html' in headers.get('content-type',''),
                                    'bytes_inspected':len(raw),'possibly_truncated':len(raw)==65536})
            web.technologies = self._detect_technologies(body,web.server,web.powered_by)
            self._observe_keenetic(service.address,body,headers,proto+' root page')
            if 300 <= status < 400:
                web.redirect_chain = [headers.get('location','')]
            return web
        except (OSError,http.client.HTTPException,ValueError) as exc:
            self._record_error('web',str(exc),service.address)
            self._check_row('WEB-PAGE',service,'UNKNOWN',str(exc))
        return None

    def _detect_technologies(self, html: str, server: str, powered_by: str) -> List[Dict[str, Any]]:
        html_lower = html.lower()
        technologies = []
        
        if 'wp-content' in html_lower or 'wp-includes' in html_lower:
            tech = {'tech': 'WordPress', 'confidence': 0.9}
            match = re.search(r'generator" content="WordPress ([0-9.]+)', html)
            if match:
                tech['version'] = match.group(1)
                tech['confidence'] = 0.95
            technologies.append(tech)
        
        if 'drupal' in html_lower or 'sites/default' in html_lower:
            tech = {'tech': 'Drupal', 'confidence': 0.85}
            match = re.search(r'Drupal ([0-9.]+)', html)
            if match:
                tech['version'] = match.group(1)
                tech['confidence'] = 0.95
            technologies.append(tech)
        
        if 'joomla' in html_lower or 'media/system/js' in html_lower:
            technologies.append({'tech': 'Joomla', 'confidence': 0.85})
        
        if 'laravel' in powered_by.lower() or 'livewire' in html_lower:
            technologies.append({'tech': 'Laravel', 'confidence': 0.85})
        
        if 'django' in html_lower or 'csrfmiddlewaretoken' in html_lower:
            technologies.append({'tech': 'Django', 'confidence': 0.85})
        
        if 'react' in html_lower and 'react-dom' in html_lower:
            technologies.append({'tech': 'React', 'confidence': 0.7})
        
        if 'grafana' in html_lower:
            tech = {'tech': 'Grafana', 'confidence': 0.9}
            match = re.search(r'grafana-([0-9.]+)', html_lower)
            if match:
                tech['version'] = match.group(1)
                tech['confidence'] = 0.95
            technologies.append(tech)
        
        if 'jenkins' in html_lower:
            technologies.append({'tech': 'Jenkins', 'confidence': 0.9})
        
        if 'gitlab' in html_lower:
            technologies.append({'tech': 'GitLab', 'confidence': 0.9})
        
        if 'nginx' in server.lower():
            tech = {'tech': 'nginx', 'confidence': 0.85}
            match = re.search(r'nginx/([0-9.]+)', server)
            if match:
                tech['version'] = match.group(1)
                tech['confidence'] = 0.95
            technologies.append(tech)
        
        if 'apache' in server.lower():
            tech = {'tech': 'Apache', 'confidence': 0.85}
            match = re.search(r'Apache/([0-9.]+)', server)
            if match:
                tech['version'] = match.group(1)
                tech['confidence'] = 0.95
            technologies.append(tech)
        
        return technologies
    
    # =======================================================
    #  TLS SCANNER (теперь работает)
    # =======================================================
    
    def _scan_tls(self):
        for service in self.result.services:
            if self._cancel_event.is_set():
                return
            if not service.extra.get("tls"):
                continue
            
            tls_versions = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
            supported = []
            
            for version in tls_versions:
                if self._cancel_event.is_set():
                    return
                if self._test_tls_version(service, version):
                    supported.append(version)
            
            self._check_row('TLS-VERSIONS',service,'PASS' if supported else 'UNKNOWN',
                            'Confirmed: '+', '.join(supported) if supported else 'No TLS version confirmed')
            service.extra['tls_versions_confirmed'] = supported
            service.extra['tls_note'] = 'Failed handshakes are inconclusive; local TLS policy can prevent legacy tests.'
            if "TLSv1.0" in supported or "TLSv1.1" in supported:
                vuln = Vulnerability(
                    id=f"TLS-DEPRECATED-{service.port}",
                    title=f"Deprecated TLS versions supported",
                    description=f"Server supports outdated TLS versions: {', '.join([v for v in supported if v in ['TLSv1.0', 'TLSv1.1']])}",
                    risk=RiskLevel.HIGH,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.EXPOSED,
                    service=service,
                    evidence=[Evidence(source="TLS scanner", value=f"Supported: {', '.join(supported)}", confidence=0.95)],
                    remediation="Disable TLS 1.0 and 1.1, enable TLS 1.2 and 1.3"
                )
                with self._lock:
                    self.result.vulnerabilities.append(vuln)
            
            self._check_certificate(service)
    
    def _test_tls_version(self, service: Service, version_str: str) -> bool:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            if version_str == "TLSv1.0":
                context.minimum_version = ssl.TLSVersion.TLSv1
                context.maximum_version = ssl.TLSVersion.TLSv1
            elif version_str == "TLSv1.1":
                context.minimum_version = ssl.TLSVersion.TLSv1_1
                context.maximum_version = ssl.TLSVersion.TLSv1_1
            elif version_str == "TLSv1.2":
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.maximum_version = ssl.TLSVersion.TLSv1_2
            elif version_str == "TLSv1.3":
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                context.maximum_version = ssl.TLSVersion.TLSv1_3
            else:
                return False
            
            with socket.create_connection((service.address, service.port), timeout=self._application_timeout()) as sock:
                with context.wrap_socket(sock, server_hostname=self._server_name(service.address)) as ssock:
                    return True
        except (ssl.SSLError, socket.error, AttributeError):
            return False
    
    def _check_certificate(self, service: Service):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((service.address,service.port),timeout=self._application_timeout()) as sock:
                with context.wrap_socket(sock,server_hostname=self._server_name(service.address)):
                    service.extra['certificate_validation'] = 'trusted'
                    self._check_row('TLS-CERTIFICATE',service,'PASS','Certificate trusted for the supplied IP/hostname')
        except ssl.SSLCertVerificationError as exc:
            service.extra['certificate_validation'] = 'failed'
            self._check_row('TLS-CERTIFICATE',service,'FINDING',exc.verify_message)
            self.result.vulnerabilities.append(Vulnerability(
                id=f'CERT-VALIDATION-{service.port}',title='Certificate validation failed',
                description=exc.verify_message,risk=RiskLevel.MEDIUM,confidence=Confidence.HIGH,
                status=FindingStatus.MISCONFIGURED,service=service,
                evidence=[Evidence('TLS verification',f'code={exc.verify_code}: {exc.verify_message}',0.95)],
                remediation='Check certificate validity, hostname and trusted certificate chain.'))
        except OSError as exc:
            service.extra['certificate_validation'] = 'unknown'
            self._record_error('certificate',str(exc),service.address)
            self._check_row('TLS-CERTIFICATE',service,'UNKNOWN',str(exc))
    
    def _detect_devices(self):
        addresses = list(self.result.resolved_addresses)
        if not addresses:
            return
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_workers, 20)) as executor:
            futures = {executor.submit(self._profile_device, addr): addr for addr in addresses}
            for future in concurrent.futures.as_completed(futures):
                if self._cancel_event.is_set():
                    break
                addr = futures[future]
                try:
                    profile = future.result()
                    if profile:
                        with self._lock:
                            self.result.devices.append(profile)
                except Exception as e:
                    self._record_error("os_detect", str(e), addr)
    
    def _profile_device(self, address: str) -> DeviceProfile:
        profile = DeviceProfile(address=address)
        if self._cancel_event.is_set():
            return profile
        scores = {"windows": 0.0, "linux": 0.0, "macos": 0.0, "ios": 0.0, "android": 0.0, "network_device": 0.0}
        svc_by_addr = [s for s in self.result.services if s.address == address]
        open_ports = {s.port for s in svc_by_addr}
        
        # 1. TTL — грубая эвристика (Linux/macOS/*nix обычно ~64, Windows ~128, некоторые сетевые устройства ~255)
        ttl = self._get_ttl(address)
        if ttl is not None:
            if ttl <= 64:
                scores["linux"] += 0.25
                scores["macos"] += 0.2
                scores["android"] += 0.15
                scores["ios"] += 0.15
            elif ttl <= 128:
                scores["windows"] += 0.35
            else:
                scores["network_device"] += 0.3
            profile.evidence.append(Evidence(source="TTL", value=str(ttl), confidence=0.4))
        
        # 2. Сигнатуры портов
        if {135, 139, 445, 3389} & open_ports:
            scores["windows"] += 0.3
            profile.evidence.append(Evidence(source="Ports", value="SMB/RDP/RPC открыты", confidence=0.7))
        if 548 in open_ports:
            scores["macos"] += 0.5
            profile.evidence.append(Evidence(source="Ports", value="AFP (548) открыт", confidence=0.7))
        if 62078 in open_ports:
            scores["ios"] += 0.3
            profile.device_type = "possible_mobile"
            profile.evidence.append(Evidence(source="Ports", value="Port 62078 open; possible lockdownd", confidence=0.3))
        if 5555 in open_ports:
            scores["android"] += 0.3
            profile.device_type = "possible_mobile"
            profile.evidence.append(Evidence(source="Ports", value="Port 5555 open; possible ADB", confidence=0.3))
        if 22 in open_ports:
            scores["linux"] += 0.15
            scores["macos"] += 0.1
        
        # 3. Баннеры сервисов (SSH/HTTP часто прямо называют ОС)
        for s in svc_by_addr:
            b = (s.banner or "").lower()
            if not b:
                continue
            if any(k in b for k in ["ubuntu", "debian", "centos", "fedora", "red hat", " linux"]):
                scores["linux"] += 0.5
                profile.evidence.append(Evidence(source="Banner", value=s.banner[:100], confidence=0.8))
            if "darwin" in b or "mac os" in b or "macos" in b:
                scores["macos"] += 0.6
                profile.evidence.append(Evidence(source="Banner", value=s.banner[:100], confidence=0.8))
            if "microsoft-iis" in b or "windows" in b:
                scores["windows"] += 0.3
                profile.evidence.append(Evidence(source="Banner", value=s.banner[:100], confidence=0.8))
        
        # 4. NBNS (UDP 137) — отклик почти однозначно означает Windows/Samba-хост
        if self.udp_enabled and (445 in open_ports or 139 in open_ports):
            nbns = self._nbns_probe(address)
            if nbns:
                scores["windows"] += 0.2
                profile.evidence.append(Evidence(source="NBNS", value=nbns, confidence=0.85))
        
        # 5. mDNS/Bonjour — лучший шанс опознать конкретную Apple/Android модель
        mdns_info = self._mdns_probe(address) if self.udp_enabled and not self._cancel_event.is_set() else None
        if mdns_info:
            m = mdns_info.lower()
            if any(x in m for x in ["iphone", "ipad", "ipod"]):
                scores["ios"] += 0.9
                profile.device_type = "mobile"
            elif any(x in m for x in ["macbook", "imac", "mac mini", "macpro", "mac studio"]):
                scores["macos"] += 0.9
                profile.device_type = "workstation"
            elif "android" in m:
                scores["android"] += 0.3
                profile.device_type = "mobile"
            profile.evidence.append(Evidence(source="mDNS", value=mdns_info[:100], confidence=0.85))
        
        best_os, best_score = max(scores.items(), key=lambda kv: kv[1])
        if best_score < 0.5:
            profile.os_family = "unknown"
            profile.confidence = 0.0
        else:
            profile.os_family = best_os
            profile.confidence = min(best_score, 0.95)
            if not profile.os_name:
                names = {
                    "windows": "Windows", "linux": "Linux", "macos": "macOS",
                    "ios": "iOS", "android": "Android", "network_device": "Сетевое устройство / IoT"
                }
                profile.os_name = names.get(best_os, best_os)
        
        if not profile.device_type:
            if profile.os_family in ("ios", "android"):
                profile.device_type = "mobile"
            elif profile.os_family == "network_device":
                profile.device_type = "router/iot"
            elif open_ports & {22, 80, 443, 3306, 5432, 445, 3389}:
                profile.device_type = "server"
            elif open_ports:
                profile.device_type = "workstation"
            else:
                profile.device_type = "unknown"
        
        identity = self._identity(address)
        if identity.get('vendor') == 'Keenetic':
            profile.os_family = 'network_device'
            profile.os_name = 'KeeneticOS'
            profile.os_version = identity.get('version','')
            profile.device_type = 'Keenetic ' + (identity.get('model') or '(model unknown)')
            profile.confidence = 0.85 if identity.get('observed') else 0.55
            profile.evidence.append(Evidence('Keenetic identity',
                '; '.join(identity.get('sources',[])) + ('; conflicting firmware observations' if identity.get('conflict') else ''),
                profile.confidence))
        return profile

    def _get_ttl(self, address: str) -> Optional[int]:
        """TTL через системный ping — кроссплатформенно (Windows/Linux/macOS)."""
        try:
            if os.name == 'nt':
                cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000))]
            else:
                cmd = ["ping", "-c", "1", "-W", str(max(1, int(self.timeout)))]
            cmd.append(address)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout + 2)
            match = re.search(r'ttl[=:]\s*(\d+)', result.stdout, re.IGNORECASE)
            if match:
                return int(match.group(1))
        except Exception:
            pass
        return None
    
    def _nbns_probe(self, address: str) -> Optional[str]:
        """NetBIOS Name Service запрос (UDP 137). Ответ — сильный сигнал Windows/Samba."""
        try:
            transaction_id = random.randint(0, 0xFFFF)
            encoded_name = "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # first-level encoding имени "*"
            packet = struct.pack(">H", transaction_id)
            packet += b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            packet += b"\x20" + encoded_name.encode() + b"\x00"
            packet += b"\x00\x21\x00\x01"
            with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout * 0.5)
                sock.sendto(packet, (address, 137))
                data, _ = sock.recvfrom(1024)
                if data and len(data) > 12:
                    return "NetBIOS отвечает (Windows/Samba)"
        except Exception:
            pass
        return None
    
    def _mdns_probe(self, address: str) -> Optional[str]:
        """mDNS/Bonjour запрос _device-info._tcp — часто раскрывает модель Apple-устройства.
        Best-effort: юникаст-запрос напрямую на адрес вместо мультикаста 224.0.0.251,
        поэтому срабатывает не всегда — многие устройства отвечают только на мультикаст."""
        try:
            qname = b"\x0c_device-info\x04_tcp\x05local\x00"
            packet = struct.pack(">H", 0) + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            packet += qname + b"\x00\x0c\x00\x01"
            with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout * 0.5)
                sock.sendto(packet, (address, 5353))
                data, _ = sock.recvfrom(2048)
                if data:
                    text = data.decode('utf-8', errors='ignore')
                    match = re.search(r'model=([\w,]+)', text)
                    if match:
                        return match.group(1)
                    for marker in ["iPhone", "iPad", "MacBook", "iMac", "AppleTV", "Android"]:
                        if marker.lower() in text.lower():
                            return marker
        except Exception:
            pass
        return None
    
    def _application_timeout(self):
        return max(3.0,self.timeout) if self.mode in (ScanMode.KEENETIC,ScanMode.UNIVERSAL) else self.timeout

    @staticmethod
    def _clean_banner(text):
        return re.sub(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]', '', text).strip()

    def _check_row(self, check_id, service, status, detail, references=None):
        with self._lock:
            self.result.checks.append({'id':check_id,'address':service.address,'port':service.port,
                                       'status':status,'detail':detail[:2000],
                                       'references':references or []})

    def _add_finding(self, check_id, service, title, detail, risk=RiskLevel.LOW,
                     status=FindingStatus.MISCONFIGURED, remediation='', references=None):
        self._check_row(check_id,service,'FINDING',detail,references)
        with self._lock:
            self.result.vulnerabilities.append(Vulnerability(check_id,title,detail,risk,Confidence.MEDIUM,
                status,service,evidence=[Evidence(check_id,detail[:500],0.75)],
                remediation=remediation,references=references or []))

    def _fingerprint_telnet(self, service):
        """Bounded Telnet negotiation: decline options, never submit credentials or CLI commands."""
        stream = bytearray()
        plain = bytearray()
        offset = 0
        negotiated = False
        deadline = time.monotonic()+self._application_timeout()
        try:
            with socket.create_connection((service.address,service.port),timeout=self._application_timeout()) as sock:
                while len(stream) < 4096 and not self._cancel_event.is_set():
                    left = deadline-time.monotonic()
                    if left <= 0:
                        break
                    sock.settimeout(left)
                    data = sock.recv(min(1024,4096-len(stream)))
                    if not data:
                        break
                    stream.extend(data)
                    replies = bytearray()
                    while offset < len(stream):
                        if stream[offset] != 255:
                            plain.append(stream[offset]);offset += 1
                            continue
                        if offset+1 >= len(stream):
                            break
                        command = stream[offset+1]
                        if command == 255:
                            plain.append(255);offset += 2
                        elif command in (251,252,253,254):
                            if offset+2 >= len(stream):
                                break
                            negotiated = True
                            option = stream[offset+2]
                            if command == 251:
                                replies.extend((255,254,option))
                            elif command == 253:
                                replies.extend((255,252,option))
                            offset += 3
                        elif command == 250:
                            end = stream.find(b'\xff\xf0',offset+2)
                            if end < 0:
                                break
                            offset = end+2
                        else:
                            offset += 2
                    if replies:
                        sock.sendall(replies)
                    if re.search(rb'(?:login|username|password)\s*:',plain,re.I):
                        break
        except OSError as exc:
            service.extra['telnet_note'] = f'{type(exc).__name__}: {exc}'
        banner = self._clean_banner(plain.decode('utf-8',errors='replace'))[:512]
        service.banner = banner
        self._observe_keenetic(service.address,banner,{},'Telnet banner')
        confirmed = negotiated or bool(re.search(r'\btelnet\b',banner,re.I))
        service.extra.update(telnet_confirmed=confirmed,telnet_negotiation=negotiated,
                             login_prompt=bool(re.search(r'(?:login|username|password)\s*:',banner,re.I)))
        if confirmed:
            service.service='telnet';service.product='Telnet';service.confidence=0.95
            service.extra['identification']='telnet_negotiation' if negotiated else 'banner'
            self._add_finding('TELNET-CLEARTEXT',service,'Telnet доступен без шифрования',
                'Протокол Telnet подтверждён. Доступность установлена только из сети сканера; пароли не проверялись.',
                RiskLevel.MEDIUM,FindingStatus.EXPOSED,
                'Отключите Telnet, если он не нужен; используйте SSH и ограничьте доступ к управлению.')
        else:
            self._check_row('TELNET-PROTOCOL',service,'UNKNOWN',
                            'Порт открыт, но Telnet не подтверждён. '+service.extra.get('telnet_note',''))
        return service

    def _observe_keenetic(self,address,text,headers,source):
        combined = text + '\n' + headers.get('x-ndm-product','')
        brand = bool(re.search(r'\bkeenetic(?:os)?\b',combined,re.I))
        models = set(re.findall(r'\bKN-[0-9]{4}\b',combined,re.I))
        meta_source = source.endswith('/version.js') or source.endswith('/rci/show/version')
        with self._lock:
            known = self._device_metadata.get(address,{}).get('vendor') == 'Keenetic'
        signature = brand or (meta_source and models and bool(re.search(r'\b(?:release|ndmVersion|ndm)\b',text,re.I)))
        if not signature and not (known and meta_source):
            return
        versions = set(re.findall(r'\bKeeneticOS\s*[/v: ]\s*([0-9][A-Za-z0-9.()_+-]*)',text,re.I))
        if meta_source:
            for key in ('release','ndmVersion','firmware','firmwareVersion'):
                versions.update(re.findall(r'[\'\"]?'+key+r'[\'\"]?\s*[:=]\s*[\'\"]([^\'\"\r\n]{1,80})[\'\"]',text,re.I))
            # version.js may use a scalar `var version = "..."`.
            versions.update(re.findall(r'\b(?:var|const|let)\s+(?:ndm)?version\s*=\s*[\'\"]([0-9][^\'\"\r\n]{0,79})',text,re.I))
        if headers.get('x-ndm-version'):
            versions.add(headers['x-ndm-version'][:80])
        with self._lock:
            record = self._device_metadata.setdefault(address,{'vendor':'Keenetic','models':set(),'versions':set(),'sources':[]})
            record['observed'] = record.get('observed',False) or bool(signature)
            record['models'].update(m.upper() for m in models)
            record['versions'].update(v.strip() for v in versions)
            if source not in record['sources']:
                record['sources'].append(source)

    def _identity(self,address):
        record = self._device_metadata.get(address)
        if not record:
            return {}
        models = set(record['models']);versions = set(record['versions'])
        if record.get('manual_model'):
            models.add(record['manual_model'])
        if record.get('manual_version'):
            versions.add(record['manual_version'])
        return {'vendor':'Keenetic','model':next(iter(models)) if len(models)==1 else '',
                'version':next(iter(versions)) if len(versions)==1 else '',
                'conflict':len(models)>1 or len(versions)>1,
                'models':sorted(models),'versions':sorted(versions),
                'sources':list(record['sources']),'observed':record.get('observed',False)}

    def _probe_keenetic_web(self):
        for web in self.result.web_services:
            if self._cancel_event.is_set():
                return
            if self.mode != ScanMode.KEENETIC and not self._identity(web.address):
                continue
            svc = Service(web.address,web.port,ServiceProtocol.TCP,PortState.OPEN,service=web.protocol)
            samples = []
            for path in ('/version.js','/ndmComponents.js','/rci/show/version','/auth'):
                if self._cancel_event.is_set():
                    return
                check_id = 'KEENETIC GET '+path
                try:
                    status,headers,raw = self._http_request(web.address,web.port,web.protocol,path)
                    text = raw.decode('utf-8',errors='replace')
                    sample = {'path':path,'status':status,'content_type':headers.get('content-type',''),
                              'bytes_inspected':len(raw)}
                    if status == 200 and len(raw)<65536:
                        self._observe_keenetic(web.address,text,headers,'GET '+path)
                    version_data = status==200 and any(v in text for v in self._identity(web.address).get('versions',[])) and (
                        path in ('/version.js','/rci/show/version')) and bool(re.search(r'\b(?:release|ndmVersion|firmware|version)\b',text,re.I))
                    component_data = status==200 and bool(self._identity(web.address)) and path=='/ndmComponents.js' and bool(
                        re.search(r'\b(?:ndmComponents|components)\s*[:=]\s*[\[{]',text,re.I))
                    if (version_data or component_data) and '<html' not in text.lower():
                        sample['metadata_exposed']=True
                        self._add_finding('KEENETIC-METADATA-'+path,svc,
                            'Публичные метаданные Keenetic: '+path,
                            'Без входа доступны '+('сведения о версии' if version_data else 'названия компонентов')+
                            '. Это не подтверждает доступ к настройкам или паролям.',
                            RiskLevel.INFO,FindingStatus.EXPOSED,
                            'Сверьте применимость бюллетеней по модели и версии; ограничьте доступ к управлению.',
                            ['https://keenetic.com/en/security'])
                        self._check_row(check_id,svc,'FINDING','Распознаны публичные метаданные; значения не копируются в отчёт')
                    else:
                        detail=f'HTTP {status}'
                        if status in (401,403):detail+=' — аутентификация требуется / доступ отклонён'
                        elif status==404:detail+=' — ресурс не найден'
                        elif 300<=status<400:detail+=' — редирект не выполнялся'
                        else:detail+=' — метаданные не подтверждены'
                        self._check_row(check_id,svc,'PASS' if status in (401,403,404,410) else 'UNKNOWN',detail)
                    samples.append(sample)
                except (OSError,http.client.HTTPException,ValueError) as exc:
                    self._check_row(check_id,svc,'UNKNOWN',f'{type(exc).__name__}: {exc}')
            web.extra['keenetic_endpoints']=samples
            web.extra['keenetic_identity']=self._identity(web.address)

    @staticmethod
    def _version_in_range(value,bound,inclusive=False):
        """Three states; a coarse prefix or prerelease must not imply a patched release."""
        if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,3}',value):
            return None
        parts = [int(x) for x in value.split('.')]
        target = [int(x) for x in bound.split('.')]
        target = tuple(target+[0]*(4-len(target)))
        lower = tuple(parts+[0]*(4-len(parts)))
        if len(parts)==4:
            return lower<=target if inclusive else lower<target
        upper_parts=parts[:];upper_parts[-1]+=1
        upper=tuple(upper_parts+[0]*(4-len(upper_parts)))
        if upper<=target:
            return True
        if lower>target or (lower==target and not inclusive):
            return False
        return None

    def _check_keenetic_advisories(self):
        for address in self.result.resolved_addresses:
            identity=self._identity(address)
            if self.mode != ScanMode.KEENETIC and not identity:
                continue
            svc=next((s for s in self.result.services if s.address==address and s.extra.get('identification')=='http_response'),
                     Service(address,0,ServiceProtocol.TCP,PortState.UNKNOWN,service='device'))
            model=identity.get('model','');version=identity.get('version','')
            self._check_row('KEENETIC-IDENTITY',svc,'PASS' if model and version and not identity.get('conflict') else 'UNKNOWN',
                json.dumps(identity,ensure_ascii=False) if identity else 'Нет признаков Keenetic в ответах; профиль не доказывает марку устройства')
            for rule in KEENETIC_ADVISORIES:
                references=['https://keenetic.com/en/security']
                if rule['id'].startswith('CVE-'):
                    references.append('https://nvd.nist.gov/vuln/detail/'+rule['id'])
                relation=self._version_in_range(version,rule['bound'],rule.get('inclusive',False)) if version else None
                model_ok = model in rule['models'] if rule.get('models') else bool(re.fullmatch(r'KN-[0-9]{4}',model))
                if identity.get('conflict') or not identity or not model or relation is None:
                    state='UNKNOWN';detail='Недостаточно точных данных о модели/прошивке или источники противоречат друг другу.'
                elif not model_ok or relation is False:
                    state='SKIPPED';detail='Модель/версия не попадает в область этого правила. Это не общий вывод о безопасности.'
                else:
                    state='POTENTIAL';detail=f"{model}, KeeneticOS {version}. {rule['condition']} Применимость не подтверждена эксплуатацией."
                    self.result.vulnerabilities.append(Vulnerability(rule['id'],rule['title'],detail,
                        RiskLevel[rule['risk']],Confidence.MEDIUM,FindingStatus.POTENTIALLY_VULNERABLE,svc,
                        evidence=[Evidence('Model/version',f'{model} / {version}; '+ '; '.join(identity['sources']),0.75)],
                        cves=[rule['id']] if rule['id'].startswith('CVE-') else [],
                        remediation='Сверьте исправления для своей модели с бюллетенем производителя и установите поддерживаемую прошивку.',
                        references=references,extra={'catalog_date':'2026-09-08','requires':rule['condition']}))
                self._check_row(rule['id']+' '+rule['title'],svc,state,detail,references)
            for name,detail in (
                ('WAN-EXPOSURE','Проверка из LAN не определяет доступность управления из интернета.'),
                ('WIFI-SECURITY','WPA/WPS/PMF и устойчивость Wi-Fi к атакам не проверялись через TCP/IP.'),
                ('PASSWORD-POLICY','Пароли не перебирались. Сложность пароля и права пользователей неизвестны.')):
                self._check_row(name,svc,'UNKNOWN',detail)

    def _check_web_security(self,web):
        svc=Service(web.address,web.port,ServiceProtocol.TCP,PortState.OPEN,service=web.protocol)
        h={k.lower():v for k,v in web.headers.items()}
        is_page=web.extra.get('html',False) and web.status_code==200
        admin=bool(self._identity(web.address)) or web.extra.get('password_form',False)
        if not web.is_https and admin and (is_page or web.status_code==401):
            self._add_finding('HTTP-ADMIN-CLEARTEXT',svc,'Интерфейс входа доступен по HTTP',
                'Получен ответ интерфейса управления по незашифрованному HTTP. Содержимое страницы может быть подменено в сети.',
                RiskLevel.MEDIUM,remediation='Используйте HTTPS для управления и ограничьте доступ доверенными клиентами.')
        elif not web.is_https:
            self._check_row('HTTP-ADMIN-CLEARTEXT',svc,'PASS' if 300<=web.status_code<400 else 'UNKNOWN',
                            'HTTP '+str(web.status_code)+'; перенаправление не проверялось до конечной страницы' if 300<=web.status_code<400 else 'Страница входа не установлена')
        if not web.is_https and h.get('www-authenticate','').lower().startswith('basic'):
            self._add_finding('HTTP-BASIC-CLEARTEXT',svc,'HTTP Basic предлагается без TLS',
                'WWW-Authenticate содержит Basic на HTTP. Учётные данные не отправлялись.',RiskLevel.MEDIUM,
                remediation='Защитите интерфейс TLS; не вводите пароль по HTTP.')
        if is_page:
            csp=h.get('content-security-policy','')
            framed = h.get('x-frame-options','').upper() in ('DENY','SAMEORIGIN') or bool(re.search(r'(?:^|;)\s*frame-ancestors\s+(?:\x27none\x27|\x27self\x27)(?:\s*;|\s*$)',csp,re.I))
            if not framed:
                self._add_finding('WEB-FRAME-PROTECTION',svc,'Не обнаружена строгая защита страницы от встраивания',
                    'Нет X-Frame-Options DENY/SAMEORIGIN или строгой CSP frame-ancestors. Clickjacking не эксплуатировался.',
                    RiskLevel.LOW,remediation='Настройте frame-ancestors в CSP либо X-Frame-Options для интерфейса управления.')
            else:self._check_row('WEB-FRAME-PROTECTION',svc,'PASS','Обнаружено ограничение встраивания страницы')
            if h.get('x-content-type-options','').lower()!='nosniff':
                self._add_finding('WEB-NOSNIFF',svc,'Отсутствует X-Content-Type-Options: nosniff',
                    'Усиление защиты браузера: заголовок nosniff не обнаружен. Само по себе это не подтверждает XSS.',
                    RiskLevel.LOW,remediation='Добавьте X-Content-Type-Options: nosniff.')
            else:self._check_row('WEB-NOSNIFF',svc,'PASS','nosniff установлен')
        if web.is_https:
            try:
                ipaddress.ip_address(self._server_name(web.address))
                self._check_row('WEB-HSTS',svc,'SKIPPED','HSTS не применяется к IP-литералам; задайте имя устройства для проверки политики')
            except ValueError:
                match=re.search(r'(?:^|;)\s*max-age\s*=\s*([0-9]+)',h.get('strict-transport-security',''),re.I)
                if not match or int(match.group(1))==0:
                    self._add_finding('WEB-HSTS',svc,'HSTS не включён для имени устройства',
                        'У HTTPS-ответа отсутствует положительный HSTS max-age.',RiskLevel.LOW,
                        remediation='При использовании доверенного HTTPS включите HSTS для имени интерфейса.')
                else:self._check_row('WEB-HSTS',svc,'PASS','HSTS max-age='+match.group(1))
        for cookie in web.extra.get('cookies',[]):
            if not cookie['nonempty'] or not re.search(r'sess|sid|auth|token',cookie['name'],re.I):
                continue
            missing=[]
            if web.is_https and not cookie['secure']:missing.append('Secure')
            if not cookie['httponly']:missing.append('HttpOnly')
            if missing:
                self._add_finding('COOKIE-FLAGS-'+cookie['name'],svc,'Проверьте флаги cookie '+cookie['name'],
                    'У cookie с похожим на сессионное именем отсутствуют '+', '.join(missing)+'. Назначение cookie требует проверки.',
                    RiskLevel.LOW,remediation='Для сессионных cookies настройте Secure и HttpOnly с учётом логики приложения.')

    def _correlate_cves(self):
        if not self.cve_lookup:
            self._emit(ScanPhase.CVE, 'Online CVE lookup disabled; vulnerability coverage is incomplete')
            return
        items = list(self.result.services)
        for web in self.result.web_services:
            for tech in web.technologies:
                items.append(Service(web.address,web.port,ServiceProtocol.TCP,PortState.OPEN,
                                     service=web.protocol,product=tech.get('tech',''),version=tech.get('version','')))
        for service in items:
            if self._cancel_event.is_set():
                return
            records = self._get_cves_cpe(service.product,service.version)
            for record in records:
                self.result.vulnerabilities.append(Vulnerability(
                    id=record['id'],title=f"{record['id']}: {service.product} {service.version}",
                    description='NVD CPE candidate; installed patch level and configuration require verification.',
                    risk=self._calculate_risk([record]),confidence=Confidence.MEDIUM,
                    status=FindingStatus.POTENTIALLY_VULNERABLE,service=service,
                    cves=[record['id']],cvss_score=record.get('cvss'),
                    evidence=[Evidence('NVD CPE query',record['_query_cpe'],0.75)],
                    references=['https://nvd.nist.gov/vuln/detail/' + record['id']],
                    remediation='Verify applicability against vendor advisories and installed patches.'))
    
    def _get_cves_cpe(self, product: str, version: str) -> List[Dict]:
        products = {'nginx': ('nginx','nginx'), 'apache': ('apache','http_server'),
                    'openssh': ('openbsd','openssh'), 'wordpress': ('wordpress','wordpress'),
                    'vsftpd': ('vsftpd','vsftpd'), 'proftpd': ('proftpd','proftpd'),
                    'grafana': ('grafana','grafana'), 'drupal': ('drupal','drupal')}
        pair = products.get(product.lower())
        if not self.cve_lookup or not pair or not re.fullmatch(r'[0-9]+(?:\.[0-9]+)+',version):
            return []  # Unknown product/version is not evidence of vulnerability.
        cpe = f'cpe:2.3:a:{pair[0]}:{pair[1]}:{version}:*:*:*:*:*:*:*'
        key = 'nvd-v2:' + cpe
        try:
            cached = self._cve_cache.get(key)
            if cached is not None:
                return cached
        except (sqlite3.Error, ValueError) as exc:
            self._record_error('cve_cache',str(exc))
        records = []
        start = 0
        for page in range(10):  # Bounded pagination; explicit incomplete diagnostic.
            if self._cancel_event.wait(max(0,6.1-(time.monotonic()-self._last_api_call))):
                return records
            query = urllib.parse.urlencode({'cpeName': cpe,'isVulnerable':'','noRejected':'',
                                            'resultsPerPage':200,'startIndex':start})
            headers = {'User-Agent':'NetworkSecurityScanner/6.5'}
            if os.environ.get('NVD_API_KEY'):
                headers['apiKey'] = os.environ['NVD_API_KEY']
            req = urllib.request.Request('https://services.nvd.nist.gov/rest/json/cves/2.0?' + query,headers=headers)
            self._last_api_call = time.monotonic()
            try:
                with urllib.request.urlopen(req,timeout=min(10,self.timeout*3)) as response:
                    raw = response.read(4_000_001)
                if len(raw)>4_000_000:
                    raise ValueError('NVD response too large')
                data = json.loads(raw)
                entries = data['vulnerabilities']
                for entry in entries:
                    record = entry['cve']
                    if not re.fullmatch(r'CVE-[0-9]{4}-[0-9]+',record.get('id','')):
                        continue
                    score = 0.0
                    metrics = record.get('metrics',{})
                    for group in ('cvssMetricV40','cvssMetricV31','cvssMetricV30','cvssMetricV2'):
                        if metrics.get(group):
                            score = max(float(m['cvssData']['baseScore']) for m in metrics[group])
                            break
                    records.append({'id':record['id'],'cvss':score,'_query_cpe':cpe})
                start += len(entries)
                if start >= data['totalResults']:
                    try:
                        self._cve_cache.set(key,records)
                    except sqlite3.Error as exc:
                        self._record_error('cve_cache',str(exc))
                    return records
                if not entries:
                    raise ValueError('NVD pagination made no progress')
            except (OSError, ValueError, KeyError, TypeError) as exc:
                self._record_error('cve_lookup',f'NVD lookup incomplete: {exc}')
                return records  # No recursion, no caching failures as a clean result.
        self._record_error('cve_lookup','NVD page limit reached; results incomplete')
        return records
    
    def _calculate_risk(self, cves: List[Dict]) -> RiskLevel:
        max_cvss = self._max_cvss(cves)
        if max_cvss >= 9.0:
            return RiskLevel.CRITICAL
        elif max_cvss >= 7.0:
            return RiskLevel.HIGH
        elif max_cvss >= 4.0:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
    
    def _max_cvss(self, cves: List[Dict]) -> float:
        return max([c.get('cvss', 0) for c in cves]) if cves else 0.0
    
    # =======================================================
    #  CONFIGURATION CHECKS
    # =======================================================
    
    def _check_configuration(self):
        for service in self.result.services:
            if self._cancel_event.is_set():
                return
            if service.protocol != ServiceProtocol.TCP:
                continue
            if service.extra.get("protocol_audit"):
                continue
            if service.port == 23 and service.extra.get("telnet_confirmed"):
                continue
            if service.port in (21,23,445,3389,1883,2375,5555,5900,6379,9100,27017):
                self.result.vulnerabilities.append(Vulnerability(
                    id=f'SERVICE-EXPOSURE-{service.port}',title=f'Accessible service on TCP {service.port}',
                    description='Reachable from scanner. Port alone does not establish protocol, authentication or vulnerability.',
                    risk=RiskLevel.INFO,confidence=Confidence.HIGH,status=FindingStatus.EXPOSED,
                    service=service,evidence=[Evidence('TCP connect','Connection succeeded',0.95)],
                    remediation='Confirm intended exposure and restrict access to trusted clients.'))
        for web in self.result.web_services:
            if self._cancel_event.is_set():
                return
            self._check_web_security(web)
            self._check_web_paths(web)
    
    def _check_web_paths(self, web: WebService):
        if self.mode == ScanMode.SAFE:
            return
        
        baseline = self._get_baseline(web)
        paths = ['/.env', '/.git/HEAD', '/phpinfo.php', '/backup.sql']
        
        for path in paths:
            if self._cancel_event.is_set():
                break
            result = self._check_path(web, path, baseline)
            if result:
                with self._lock:
                    self.result.vulnerabilities.append(result)
    
    def _get_baseline(self, web: WebService) -> Dict[str, Any]:
        try:
            status, headers, raw = self._http_request(web.address,web.port,web.protocol,
                                                     '/nonexistent-' + os.urandom(12).hex())
            return {'hash':hashlib.sha256(raw).hexdigest(),'status':status}
        except (OSError,http.client.HTTPException,ValueError):
            return {}
    
    def _check_path(self, web: WebService, path: str, baseline: Dict[str, Any]) -> Optional[Vulnerability]:
        try:
            status, headers, raw = self._http_request(web.address,web.port,web.protocol,path)
            svc = Service(web.address,web.port,ServiceProtocol.TCP,PortState.OPEN,service=web.protocol)
            self._check_row('PATH '+path,svc,'PASS' if status in (401,403,404,410) else 'UNKNOWN',f'HTTP {status}; content signature not confirmed')
            if status != 200 or hashlib.sha256(raw).hexdigest() == baseline.get('hash'):
                return None
            body = raw.decode('utf-8',errors='replace')
            if path == '/.git/HEAD':
                matched = bool(re.fullmatch(r'(?:ref: refs/[A-Za-z0-9_./-]+|[0-9a-f]{40}|[0-9a-f]{64})\s*',body))
            elif path == '/.env':
                matched = '<html' not in body.lower() and bool(re.search(r'(?m)^(?:DB_|APP_|AWS_)[A-Z_0-9]*\s*=\s*[^\r\n]+',body))
            elif path == '/phpinfo.php':
                matched = 'phpinfo()' in body and 'PHP Version' in body
            elif path == '/backup.sql':
                matched = bool(re.search(r'(?im)^CREATE TABLE\s',body))
            else:
                return None
            if not matched:
                return None
            self._check_row('PATH '+path,svc,'FINDING','Recognizable file content without login')
            return Vulnerability(id='WEB-PATH-' + path,title=f'Exposed diagnostic/configuration file: {path}',
                description='Recognizable content returned without authentication; secret values are omitted.',
                risk=RiskLevel.HIGH,confidence=Confidence.MEDIUM,status=FindingStatus.EXPOSED,
                service=Service(web.address,web.port,ServiceProtocol.TCP,PortState.OPEN,service=web.protocol),
                evidence=[Evidence('HTTP content signature',path + ': signature matched',0.75)],
                remediation='Restrict access and remove sensitive files from the web root.')
        except (OSError,http.client.HTTPException,ValueError) as exc:
            svc = Service(web.address,web.port,ServiceProtocol.TCP,PortState.OPEN,service=web.protocol)
            self._check_row('PATH '+path,svc,'UNKNOWN',f'{type(exc).__name__}: {exc}')
            return None
    
    def _score_and_deduplicate(self):
        seen = set()
        unique = []
        for v in self.result.vulnerabilities:
            key = f"{v.id}_{v.service.address}_{v.service.protocol.value}_{v.service.port}"
            if key not in seen:
                seen.add(key)
                unique.append(v)
        
        risk_order = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 3, RiskLevel.INFO: 4, RiskLevel.NONE: 5}
        unique.sort(key=lambda v: risk_order.get(v.risk, 99))
        self.result.vulnerabilities = unique
        checks = {(c['id'],c['address'],c['port']): c for c in self.result.checks}
        self.result.checks = list(checks.values())


# =======================================================
#  REPORT GENERATORS
# =======================================================

def generate_html_report(result: ScanResult, filename: str = 'scan_report.html'):
    """Self-contained report. All target-controlled content is escaped, no external assets."""
    def esc(value):
        return html_escape.escape(str(value),quote=True)
    labels={'PASS':'Проверено','FINDING':'Наблюдение','UNKNOWN':'Не установлено',
            'SKIPPED':'Не применяется / пропущено','POTENTIAL':'Кандидат по версии'}
    def refs(items):
        links=[]
        for item in items:
            if urlparse(item).scheme in ('http','https'):
                links.append(f'<a href="{esc(item)}" rel="noreferrer noopener">{esc(item)}</a>')
        return '<br>'.join(links)
    candidates=[v for v in result.vulnerabilities if v.status==FindingStatus.POTENTIALLY_VULNERABLE]
    observations=[v for v in result.vulnerabilities if v.status!=FindingStatus.POTENTIALLY_VULNERABLE]
    unknown=sum(c['status']=='UNKNOWN' for c in result.checks)
    title='Аудит '+result.target
    out=[f'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{esc(title)}</title><style>
    :root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#101722;color:#e4eaf2;font:15px/1.6 system-ui,sans-serif}}
    main{{max-width:1180px;margin:auto;padding:32px 22px}}h1{{font-size:32px;margin:4px 0}}h2{{margin:30px 0 12px}}
    .muted{{color:#a9b7ca}}.cards{{display:flex;flex-wrap:wrap;gap:12px;margin:22px 0}}.card{{flex:1;min-width:150px;background:#1a2637;padding:18px;border-radius:10px}}
    .card strong{{display:block;font-size:28px}}.note{{padding:14px 18px;border-left:4px solid #73aaf7;background:#18263a}}
    .finding{{background:#192536;padding:16px;margin:12px 0;border-left:4px solid #7799bf;border-radius:6px}}
    .high,.critical{{border-color:#ff9c85}}.medium{{border-color:#e4bd64}}.low{{border-color:#74b4df}}
    .table{{overflow-x:auto}}table{{border-collapse:collapse;width:100%;margin:12px 0;background:#151f2d}}td,th{{padding:10px 12px;text-align:left;border-bottom:1px solid #2b394c;vertical-align:top}}
    th{{color:#a9b7ca;font-size:12px;text-transform:uppercase}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;padding:12px;background:#101a27;border-radius:6px;font-size:12px}}
    a{{color:#9bc7ff;overflow-wrap:anywhere}}summary{{cursor:pointer}}.status{{white-space:nowrap}}small{{color:#a9b7ca}}
    </style></head><body><main><small>NETWORK SECURITY SCANNER 6.5</small><h1>{esc(title)}</h1>
    <div class="muted">{esc(result.start_time)} · {result.duration:.2f} с · {esc(result.stats.get('status','unknown'))}</div>
    <div class="cards"><div class="card"><strong>{len(result.services)}</strong>доступных сервисов</div>
    <div class="card"><strong>{len(observations)}</strong>наблюдений конфигурации</div>
    <div class="card"><strong>{len(candidates)}</strong>кандидатов по версии</div>
    <div class="card"><strong>{unknown}</strong>проверок без вывода</div></div>
    <div class="note">Отчёт отражает доступность из сети сканера. Кандидат CVE не означает подтверждённый взлом.
    Отсутствие находок не доказывает безопасность. WAN, пароли и Wi-Fi-радиоканал автоматически не проверялись.</div>
    <p class="muted">Профиль: {esc(result.stats.get('mode','unknown'))}. Встроенный каталог Keenetic: {esc(result.stats.get('keenetic_catalog_date','не использован'))}.
    Дополнительный онлайн-поиск NVD: {'включён' if result.stats.get('cve_lookup') else 'выключен'}.</p>''']
    out.append('<h2>Устройства и исходные данные</h2>')
    for device in result.devices:
        out.append(f'<div class="finding"><b>{esc(device.address)} — {esc(device.device_type or "тип неизвестен")}</b><br>'
                   f'{esc(device.os_name or "ОС неизвестна")} {esc(device.os_version)} · уверенность {device.confidence:.0%}')
        for evidence in device.evidence:
            out.append(f'<br><small>{esc(evidence.source)}: {esc(evidence.value)}</small>')
        out.append('</div>')
    if not result.devices:out.append('<p>Устройства не идентифицированы.</p>')
    for heading,items in [('Наблюдения и настройки',observations),('Известные уязвимости: кандидаты на проверку',candidates)]:
        out.append('<h2>'+heading+'</h2>')
        if not items:out.append('<p class="muted">Нет записей. Смотрите незавершённые и пропущенные проверки ниже.</p>')
        for v in items:
            out.append(f'<article class="finding {esc(v.risk.value.lower())}"><b>[{esc(v.risk.value)}] {esc(v.title)}</b>'
                       f'<br><small>{esc(v.service.address)}:{v.service.port}/{esc(v.service.protocol.value)} · {esc(v.status.value)}</small>'
                       f'<p>{esc(v.description)}</p><p><b>Что сделать:</b> {esc(v.remediation)}</p>')
            if v.evidence:
                out.append('<details><summary>Основание вывода</summary>')
                for evidence in v.evidence:
                    out.append(f'<p>{esc(evidence.source)}: {esc(evidence.value)}</p>')
                out.append('</details>')
            out.append(refs(v.references)+'</article>')
    out.append('<h2>Сервисы и баннеры</h2><div class="table"><table><tr><th>Адрес / порт</th><th>Протокол</th><th>Основание</th><th>Данные</th></tr>')
    for svc in result.services:
        detail={'port_hint':svc.extra.get('port_hint'),'TLS':svc.extra.get('tls'),
                'TLS_confirmed_versions':svc.extra.get('tls_versions_confirmed'),
                'certificate':svc.extra.get('certificate_validation'),'TLS_note':svc.extra.get('tls_note'),
                'protocol_audit':svc.extra.get('protocol_audit'),'protocol_metadata':svc.extra.get('protocol_metadata')}
        out.append(f'<tr><td>{esc(svc.address)}:{svc.port}/{esc(svc.protocol.value)}</td><td>{esc(svc.service or "unknown")}</td>'
                   f'<td>{esc(svc.extra.get("identification","port open"))}<br>{svc.confidence:.0%}</td>'
                   f'<td>{esc(svc.product)} {esc(svc.version)}<pre>{esc(svc.banner or "Нет баннера")}</pre>'
                   f'<details><summary>Протокольные данные</summary><pre>{esc(json.dumps(detail,ensure_ascii=False,indent=2))}</pre></details></td></tr>')
    out.append('</table></div><h2>Веб-интерфейсы</h2>')
    for web in result.web_services:
        out.append(f'<div class="finding"><b>{esc(web.url)}</b><br>HTTP {web.status_code} · {esc(web.title or "Заголовок страницы не получен")}'
                   f'<pre>{esc(json.dumps(web.headers,ensure_ascii=False,indent=2))}</pre>'
                   f'<details><summary>Cookies (без значений), метаданные и endpoints</summary><pre>{esc(json.dumps(web.extra,ensure_ascii=False,indent=2))}</pre></details></div>')
    out.append('<h2>Что именно проверено</h2><div class="table"><table><tr><th>Проверка</th><th>Цель</th><th>Результат</th><th>Пояснение</th></tr>')
    for check in result.checks:
        out.append(f'<tr><td>{esc(check["id"])}</td><td>{esc(check["address"])}:{check["port"]}</td>'
                   f'<td>{esc(labels.get(check["status"],check["status"]))}</td><td>{esc(check["detail"])}'
                   f'<details><summary>Источники</summary>{refs(check.get("references",[]))}</details></td></tr>')
    out.append('</table></div><h2>Ошибки выполнения</h2>')
    if not result.errors:out.append('<p class="muted">Ошибок выполнения не зарегистрировано; это не исключает результаты «не установлено».</p>')
    for error in result.errors:
        out.append(f'<p><b>{esc(error.get("module",""))}</b>: {esc(error.get("message",""))}<br><small>{esc(error.get("details",""))}</small></p>')
    out.append('</main></body></html>')
    with open(filename,'w',encoding='utf-8') as f:f.write(''.join(out))
    print('[+] HTML report saved to '+filename)


def generate_json_report(result: ScanResult, filename: str = "scan_report.json"):
    def to_dict(obj):
        if hasattr(obj, '__dataclass_fields__'):
            return {k: to_dict(v) for k, v in asdict(obj).items()}
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, list):
            return [to_dict(item) for item in obj]
        if isinstance(obj, dict):
            return {k: to_dict(v) for k, v in obj.items()}
        return obj
    
    data = to_dict(result)
    data['schema_version'] = "1.1"
    data['scanner_version'] = "6.5"
    
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[+] JSON report saved to {filename}")


# =======================================================
#  MAIN (CLI)
# =======================================================

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Network security audit for authorized targets')
    parser.add_argument('target')
    parser.add_argument('--mode',choices=[m.value for m in ScanMode],default='universal')
    parser.add_argument('--timeout',type=float,default=1.5)
    parser.add_argument('--workers',type=int,default=20)
    parser.add_argument('--ports',default='',help='TCP ports, e.g. 22,80,443,8000-8100')
    parser.add_argument('--max-hosts',type=int,default=256)
    parser.add_argument('--udp',action='store_true',help='DNS/NTP discovery and device UDP hints')
    parser.add_argument('--cve',action='store_true',help='Enable online NVD product/version lookup')
    parser.add_argument('--service-map',default='',help='Nonstandard protocol ports, e.g. 1884=mqtt,33389=rdp')
    parser.add_argument('--model',default='',help='Keenetic KN-model for one device; user-supplied evidence')
    parser.add_argument('--firmware',default='',help='Numeric KeeneticOS release from device UI')
    parser.add_argument('--output',default='scan_report',help='Report filename prefix')
    args = parser.parse_args()
    try:
        engine = ScannerEngineV6(args.target,ScanMode(args.mode),args.timeout,args.workers,
                                 ports=args.ports,max_hosts=args.max_hosts,udp=args.udp,cve_lookup=args.cve,device_model=args.model,firmware=args.firmware,service_map=args.service_map)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        result = engine.scan()
    except KeyboardInterrupt:
        engine.cancel()
        result = engine.result
        result.stats.update(status='cancelled',cancelled=True)
    generate_html_report(result,args.output+'.html')
    generate_json_report(result,args.output+'.json')
    raise SystemExit(130 if result.stats.get('cancelled') else 2 if result.errors else 0)
