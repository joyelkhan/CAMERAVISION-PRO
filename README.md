# CAMSCAN ELITE - Premium CCTV Reconnaissance Suite

<div align="center">

![Version](https://img.shields.io/badge/version-5.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

**Enterprise-Grade Security Scanner with Advanced Exploitation Detection & Risk Assessment**

</div>

---

## 🚀 Overview

CAMSCAN PRO is a comprehensive security reconnaissance tool designed for researchers and security enthusiasts to identify exposed CCTV cameras and surveillance systems. This tool provides advanced scanning capabilities with a focus on security research and vulnerability assessment.

⚠️ **Disclaimer**: This tool is intended for educational and security research purposes only. Unauthorized scanning of systems you do not own is illegal. Use responsibly.

## 🆕 What's New in v5.0.0

- ✅ **Enterprise-Grade Scanning**: 200+ threads, 1000+ ports, optimized performance
- ✅ **Advanced Brand Detection**: Hikvision, Dahua, Axis, CP Plus with deep fingerprinting
- ✅ **Risk Assessment System**: Automated security scoring (0-100 scale)
- ✅ **Exploit Testing Framework**: CVE validation and vulnerability confirmation
- ✅ **Enhanced Credential Testing**: 50+ default credentials per brand
- ✅ **Live Stream Discovery**: RTSP, HTTP, MJPEG with content-type validation
- ✅ **Endpoint Discovery**: Comprehensive API and interface enumeration
- ✅ **Firmware Detection**: Version identification for vulnerability mapping
- ✅ **Deep Scan Mode**: Exhaustive endpoint and configuration discovery
- ✅ **Colorful Logging**: Professional console output with progress tracking
- ✅ **Statistics Dashboard**: Real-time scan metrics and performance data

## ✨ Features

### Core Capabilities
- 🔍 **Enterprise Port Scanning**: 1000+ ports with 200-thread concurrency
- 📹 **Advanced Camera Detection**: Deep fingerprinting for Hikvision, Dahua, Axis, CP Plus
- 🎯 **Risk Assessment**: Automated security scoring with visual indicators
- 🔑 **Credential Testing**: 50+ default passwords per brand with smart detection
- 🌐 **Network Scanning**: CIDR support with multi-port host discovery
- 📡 **Stream Discovery**: RTSP, HTTP, MJPEG with content validation
- 🗺️ **Geolocation**: IP location with Google Maps/Earth integration
- 🛡️ **Vulnerability Assessment**: CVE validation and exploit testing
- 🔧 **Endpoint Discovery**: Comprehensive API and interface enumeration
- 📊 **Rich Reporting**: Markdown, JSON, CSV with statistics dashboard

### Supported Brands & Devices
- **Hikvision**: Full CVE database, backdoor detection, 15+ credentials
- **Dahua**: Authentication bypass testing, 18+ credentials
- **Axis**: Buffer overflow detection, 9+ credentials
- **CP Plus**: Information disclosure testing, 14+ credentials
- **Generic**: Universal detection with 16+ common credentials
- ONVIF-compliant cameras
- Any device exposing RTSP, HTTP, MJPEG, or MMS streams

## 🛠️ Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/joyelkhan/CAMSCAN-PRO-.git
cd CAMSCAN-PRO-
```

### 2️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 📝 Requirements
- Python 3.8+
- aiohttp>=3.8.0
- requests>=2.28.0
- urllib3>=1.26.0
- pycryptodome>=3.15.0

## 🎯 Usage

### Basic Scan
```bash
python camscan-pro.py 192.168.1.1
```

### Network Range Scan
```bash
python camscan-pro.py 192.168.1.0/24
```

### Advanced Scan with Deep Discovery
```bash
python camscan-pro.py 192.168.1.1 -t 200 --timeout 5 --deep-scan
```

### Enterprise Scan with Exploit Testing
```bash
python camscan-pro.py 192.168.1.1 --enable-exploits --rate-limit 0.01 -f json
```

### Scan Multiple Targets from File
```bash
python camscan-pro.py targets.txt --format csv --deep-scan
```

### Command Line Arguments
```
-t, --threads          Number of threads (default: 100)
--timeout              Timeout in seconds (default: 8)
-o, --output           Output filename
-f, --format           Output format: markdown, json, csv (default: markdown)
--rate-limit           Rate limit between requests (default: 0.05)
--enable-exploits      Enable exploit testing (Educational only)
--deep-scan            Perform comprehensive endpoint discovery
-v, --verbose          Verbose output with debug information
```

## 📊 Output Formats

### Markdown Report
Enterprise-grade report with:
- Camera details, model, and firmware
- Risk assessment scores with visual indicators
- Working credentials with security warnings
- Location information with ISP details
- Comprehensive vulnerability analysis
- Discovered endpoints and APIs
- Investigation links (Shodan, Google Dorking)
- Scan statistics dashboard

### JSON Report
Structured data format for:
- Automation and scripting
- Integration with other tools
- Data analysis and processing

### CSV Report
Spreadsheet-friendly format for:
- Data processing in Excel/Google Sheets
- Database imports
- Statistical analysis

## 🔒 Security Features

- ⏱️ **Advanced Rate Limiting**: Configurable delays (0.01-1.0s) to avoid detection
- 🔄 **Smart Retry Logic**: 5-attempt retry with exponential backoff
- 🛡️ **SSL/TLS Support**: Full certificate handling and validation
- 🔐 **Safe Credential Testing**: Rate-limited with 50+ passwords per brand
- ✅ **Input Validation**: IP, CIDR, and network range validation
- 📝 **Colorful Logging**: Professional console output with progress bars
- 🎯 **Risk Scoring**: Automated 0-100 security risk assessment
- 🔧 **Exploit Framework**: Educational CVE validation (opt-in)

## 📁 Project Structure

```
CAMSCAN-PRO-/
├── camscan-pro.py      # Main elite scanner (1400+ lines)
├── requirements.txt    # Python dependencies
├── LICENSE            # MIT License
├── README.md          # Comprehensive documentation
└── reports/           # Auto-generated scan reports
```

## 🔍 What It Does

1. **Enterprise Port Scanning**: Multi-threaded scanning of 1000+ CCTV ports
2. **Service Detection**: Advanced HTTP/RTSP service identification
3. **Deep Brand Fingerprinting**: Manufacturer, model, and firmware detection
4. **Credential Testing**: Tests 50+ default passwords per brand
5. **Stream Discovery**: RTSP, HTTP, MJPEG with content validation
6. **Vulnerability Assessment**: CVE validation and exploit testing
7. **Endpoint Discovery**: Comprehensive API and interface enumeration
8. **Risk Assessment**: Automated 0-100 security scoring
9. **Geolocation**: IP location with Google Maps/Earth links
10. **Report Generation**: Markdown, JSON, CSV with statistics dashboard

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is intended for:
- ✅ Security research
- ✅ Educational purposes
- ✅ Authorized penetration testing
- ✅ Vulnerability assessment on systems you own or have permission to test

**Usage Restrictions**:
- ❌ Only use on networks you own or have explicit written permission to test
- ❌ Comply with all applicable laws and regulations in your jurisdiction
- ❌ Do not use for unauthorized access or malicious activities
- ❌ Respect privacy and ethical boundaries

**The developers are not responsible for misuse of this tool. Users are solely responsible for their actions.**

## 🐛 Bug Reports & Features

Found a bug or have a feature request? Please open an issue on GitHub Issues.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🛡️ Security

If you discover a security vulnerability, please disclose it responsibly by contacting the maintainers directly rather than opening a public issue.

## 📞 Support

For questions, issues, or discussions:
- Open an issue on GitHub
- Check existing issues for solutions
- Read the documentation carefully

---

<div align="center">

**Built for security researchers by security researchers. Use responsibly.**

⭐ If you find this tool useful, please consider giving it a star!

</div>