# Security Suite - Firewall & EDR

A comprehensive cross-platform security solution that combines firewall protection, endpoint detection and response (EDR), threat modeling, and malicious activity detection.

## Features

### 🔥 Firewall Module
- **Network Monitoring**: Real-time monitoring of network connections
- **Packet Analysis**: Deep packet inspection for suspicious traffic
- **IP Blocking**: Dynamic IP blocking capabilities
- **Platform Support**: Windows, Linux, and macOS firewall integration
- **Suspicious Connection Detection**: Identifies connections to known malicious ports and IPs

### 🛡️ EDR (Endpoint Detection & Response)
- **Process Monitoring**: Real-time monitoring of running processes
- **File Integrity**: SHA256 hash-based file change detection
- **Behavior Analysis**: Advanced behavioral analysis for suspicious activities
- **Process Relationships**: Analysis of parent-child process relationships
- **Resource Monitoring**: CPU and memory usage anomaly detection
- **Quarantine System**: File quarantine capabilities

### 🎯 Threat Modeling
- **Risk Assessment**: Comprehensive system risk scoring
- **Attack Surface Analysis**: Identifies potential attack vectors
- **Vulnerability Detection**: Automated vulnerability identification
- **Security Recommendations**: Actionable security recommendations
- **Platform-Specific Analysis**: Tailored analysis for different operating systems

### 🚨 Malicious Activity Detection
- **Heuristic Detection**: Pattern-based malicious activity detection
- **Behavioral Analysis**: Advanced behavioral analysis algorithms
- **File Analysis**: Suspicious file detection and analysis
- **Network Analysis**: Malicious network activity detection
- **Process Analysis**: Suspicious process behavior detection

### 🔍 VirusTotal Integration
- **File Scanning**: Integration with VirusTotal API for file analysis
- **URL Scanning**: URL reputation checking
- **Hash Lookup**: Known malicious hash detection
- **Cached Results**: Local caching for improved performance
- **Rate Limiting**: Proper API rate limiting implementation

## Installation

### Prerequisites
- Python 3.8 or higher
- Administrator/root privileges (for firewall functionality)

### Setup

1. **Clone the repository**:
```bash
git clone <repository-url>
cd security-suite
```

2. **Create virtual environment**:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Configure environment variables**:
```bash
# Copy the example file
cp .env.example .env

# Edit .env and add your VirusTotal API key
nano .env
```

5. **Run the application**:
```bash
python run.py
```

## Usage

### Starting the Application

1. **Launch the Security Suite**:
```bash
python main.py
```

2. **Dashboard Overview**:
   - View real-time security status
   - Monitor active connections
   - Check recent alerts
   - View risk assessment

3. **Firewall Management**:
   - Monitor network connections
   - Block/unblock IP addresses
   - View connection statistics
   - Analyze suspicious traffic

4. **EDR Monitoring**:
   - Monitor running processes
   - Track file changes
   - Analyze process behavior
   - Quarantine suspicious files

5. **Threat Modeling**:
   - Run comprehensive system analysis
   - View risk assessment
   - Review vulnerabilities
   - Get security recommendations

6. **Malicious Detection**:
   - View detection statistics
   - Monitor suspicious activities
   - Analyze behavioral patterns
   - Review detection alerts

7. **VirusTotal Integration**:
   - Set your VirusTotal API key
   - Scan files for malware
   - Check URL reputation
   - View scan results

### VirusTotal API Key

To use the VirusTotal integration:

1. Get a free API key from [VirusTotal](https://www.virustotal.com/gui/join-us)
2. In the application, go to the "VirusTotal" tab
3. Enter your API key and click "Set API Key"
4. You can now scan files and URLs

## Configuration

### Environment Variables
The application uses the following environment variables:

- `VIRUSTOTAL_API_KEY`: Your VirusTotal API key (required for VirusTotal integration)
- `LOG_LEVEL`: Logging level (default: INFO)
- `CACHE_ENABLED`: Enable/disable caching (default: true)

### Getting a VirusTotal API Key
1. Go to [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Create a free account
3. Get your API key from your profile
4. Add it to your `.env` file

### Firewall Rules

The application automatically configures platform-specific firewall rules:

**Windows**:
- Enables Windows Firewall
- Configures basic security rules

**Linux**:
- Uses iptables for firewall management
- Requires root privileges

**macOS**:
- Enables macOS firewall
- Configures application firewall

### Monitoring Directories

The EDR module monitors critical system directories:

**Windows**:
- `%SystemRoot%\System32`
- `%SystemRoot%\SysWOW64`
- `%ProgramFiles%`
- `%ProgramFiles(x86)%`

**Linux**:
- `/bin`, `/sbin`
- `/usr/bin`, `/usr/sbin`
- `/etc`, `/var`, `/boot`

**macOS**:
- `/System/Library/CoreServices`
- `/usr/bin`, `/usr/sbin`
- `/Applications`

## Security Features

### Real-time Monitoring
- Continuous monitoring of system activities
- Immediate alert generation for suspicious activities
- Real-time risk assessment updates

### Threat Detection
- **Signature-based**: Known malicious patterns
- **Behavioral**: Anomaly detection
- **Heuristic**: Pattern-based analysis
- **Network**: Suspicious connection detection

### Response Capabilities
- **Automated**: Immediate response to high-threat activities
- **Manual**: User-controlled response actions
- **Quarantine**: Safe isolation of suspicious files
- **Blocking**: Network-level threat blocking

## Logging

The application maintains detailed logs in `security_suite.log`:

- **Firewall Events**: Network connection alerts
- **EDR Events**: Process and file monitoring alerts
- **Threat Analysis**: Risk assessment results
- **Detection Events**: Malicious activity alerts
- **VirusTotal**: Scan results and API interactions

## Troubleshooting

### Common Issues

1. **Permission Errors**:
   - Ensure you're running with administrator/root privileges
   - Check file permissions for log directories

2. **Firewall Not Working**:
   - Verify platform-specific firewall is enabled
   - Check for conflicting firewall software

3. **VirusTotal API Errors**:
   - Verify API key is correct
   - Check internet connectivity
   - Ensure API quota hasn't been exceeded

4. **Performance Issues**:
   - Reduce monitoring frequency in settings
   - Exclude large directories from file monitoring
   - Adjust detection sensitivity

### Debug Mode

Enable debug logging by modifying the logging level in `main.py`:

```python
logging.basicConfig(level=logging.DEBUG)
```

## Development

### Project Structure
```
security-suite/
├── main.py                 # Main application entry point
├── requirements.txt        # Python dependencies
├── modules/               # Security modules
│   ├── __init__.py
│   ├── firewall.py        # Firewall functionality
│   ├── edr.py            # EDR functionality
│   ├── threat_modeling.py # Threat modeling
│   ├── malicious_detection.py # Malicious detection
│   ├── virustotal.py     # VirusTotal integration
│   └── gui.py            # GUI interface
├── security_suite.log     # Application logs
└── virustotal_cache.json # VirusTotal cache
```

### Adding New Features

1. **New Detection Module**:
   - Create new module in `modules/`
   - Implement monitoring interface
   - Add GUI integration in `gui.py`

2. **New Threat Indicators**:
   - Add patterns to detection modules
   - Update behavioral analysis
   - Integrate with alert system

3. **Platform Support**:
   - Add platform-specific code
   - Update firewall implementations
   - Test on target platform

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This security suite is designed for educational and testing purposes. Always use in controlled environments and ensure compliance with local laws and regulations. The authors are not responsible for any misuse of this software.

## Support

For issues and questions:
- Check the troubleshooting section
- Review the logs for error details
- Create an issue on the repository
- Contact the development team

---

**⚠️ Important**: This tool requires administrator/root privileges for full functionality. Use responsibly and only on systems you own or have explicit permission to test. 