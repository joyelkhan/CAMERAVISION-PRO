# CAMSCAN PRO - Advanced CCTV Reconnaissance Toolkit

<div align="center">

![Version](https://img.shields.io/badge/version-4.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

**A powerful reconnaissance tool for identifying exposed CCTV cameras and surveillance systems**

</div>

---

## 🚀 Overview

CAMSCAN PRO is a comprehensive security reconnaissance tool designed for researchers and security enthusiasts to identify exposed CCTV cameras and surveillance systems. This tool provides advanced scanning capabilities with a focus on security research and vulnerability assessment.

⚠️ **Disclaimer**: This tool is intended for educational and security research purposes only. Unauthorized scanning of systems you do not own is illegal. Use responsibly.

## 🆕 What's New in v4.0.0

- ✅ **Massive Port Scanning**: 1000+ ports including custom and high camera ports
- ✅ **Enhanced Brand Detection**: Hikvision, Dahua, Axis, CP Plus, and more
- ✅ **Live Stream Detection**: RTSP, HTTP, RTMP, MMS with real validation
- ✅ **Multi-threaded Authentication**: Fast credential testing with rate limiting
- ✅ **Vulnerability Assessment**: CVE detection and security analysis
- ✅ **Comprehensive Reporting**: Multiple formats (Markdown, JSON, CSV)
- ✅ **Geolocation Integration**: IP location data with Google Maps/Earth links
- ✅ **Network Range Scanning**: CIDR notation support for large-scale scans
- ✅ **ONVIF Protocol Support**: Standardized camera communication
- ✅ **Smart Brute-force Protection**: Rate limiting and safety measures

## ✨ Features

### Core Capabilities
- 🔍 **Comprehensive Port Scanning**: Scans 1000+ common CCTV ports
- 📹 **Camera Detection**: Identifies Hikvision, Dahua, Axis, Sony, Bosch, Samsung, Panasonic, Vivotek, CP Plus
- 🔐 **Authentication Testing**: Tests default credentials with rate limiting
- 🌐 **Network Scanning**: CIDR notation support for scanning entire networks
- 📡 **Stream Detection**: RTSP, RTMP, HTTP, and MMS protocol support
- 🗺️ **Geolocation**: IP location data with Google Maps/Earth integration
- 🛡️ **Vulnerability Scanning**: CVE detection and security analysis
- 📊 **Multiple Output Formats**: Markdown, JSON, and CSV reports

### Supported Brands & Devices
- Hikvision, Dahua, Axis, Sony, Bosch, Samsung, Panasonic, Vivotek, CP Plus
- Generic DVR/NVR systems
- ONVIF-compliant cameras
- Any device exposing RTSP, HTTP, RTMP, or MMS video streams

## 🛠️ Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/your-username/camscan-pro.git
cd camscan-pro
```

### 2️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 📋 Requirements
- Python 3.8+
- aiohttp>=3.8.0
- requests>=2.28.0
- urllib3>=1.26.0

## 🎯 Usage

### Basic Scan
```bash
python camscan-pro.py 192.168.1.1
```

### Network Range Scan
```bash
python camscan-pro.py 192.168.1.0/24
```

### Advanced Options
```bash
python camscan-pro.py 192.168.1.1 -t 100 --timeout 5 -f json -o scan_results
```

### Scan Multiple Targets from File
```bash
python camscan-pro.py targets.txt --format csv
```

### Command Line Arguments
```
-t, --threads       Number of threads (default: 50)
--timeout           Timeout in seconds (default: 10)
-o, --output        Output filename
-f, --format        Output format: markdown, json, csv (default: markdown)
--rate-limit        Rate limit between requests (default: 0.1)
-v, --verbose       Verbose output
```

## 📊 Output Formats

### Markdown Report
Human-readable report with:
- Camera details and specifications
- Working credentials
- Location information
- Vulnerability analysis
- Investigation links (Shodan, Google Dorking)

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

- ⏱️ **Rate Limiting**: Configurable delays to avoid detection
- 🔄 **Retry Mechanisms**: Smart error handling and retry strategies
- 🛡️ **SSL/TLS Support**: Certificate verification for secure connections
- 🔐 **Safe Credential Testing**: Rate-limited authentication attempts
- ✅ **Input Validation**: IP address and network validation
- 📝 **Comprehensive Logging**: Detailed logging for debugging

## 📁 Project Structure

```
camscan-pro/
├── camscan-pro.py      # Main scanner application
├── requirements.txt    # Python dependencies
├── LICENSE            # MIT License
├── README.md          # Documentation
└── reports/           # Output directory (auto-created)
```

## 🔍 What It Does

1. **Port Scanning**: Scans common CCTV ports on target IP(s)
2. **Service Detection**: Identifies camera web interfaces and services
3. **Brand Identification**: Detects camera manufacturer and model
4. **Authentication Testing**: Tests default credentials if authentication required
5. **Stream Discovery**: Locates live video streams (RTSP, HTTP, etc.)
6. **Vulnerability Assessment**: Checks for known CVEs and security issues
7. **Geolocation**: Retrieves IP location data with map links
8. **Report Generation**: Creates comprehensive reports in multiple formats

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