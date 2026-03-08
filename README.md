# Network Scanner Tool

A professional-grade network scanning tool built with Python, featuring async port scanning, host discovery, service detection, vulnerability checking, and a REST API backend.

## Features

### Core Scanning Capabilities
- **Async Port Scanning** - Fast concurrent port scanning with configurable timeouts
- **Host Discovery** - ICMP ping and ARP-based network host detection
- **Service Detection** - Identify running services and versions
- **CVE Vulnerability Checking** - Basic vulnerability database integration
- **Network Mapping** - Visualize subnet topology

### Advanced Features
- **REST API** - FastAPI backend for programmatic access
- **CLI Interface** - Rich command-line interface with multiple output formats
- **Database Storage** - SQLite/PostgreSQL for scan history
- **Configuration Management** - YAML-based configuration
- **HTML/JSON Reports** - Professional scan result reporting
- **Docker Support** - Containerized deployment
- **Comprehensive Logging** - Detailed operation logging

## Quick Start

### Installation
```bash
git clone https://github.com/prabhatjalpota/Network-scanner.git
cd Network-scanner
pip install -r requirements.txt
```

### Basic Usage

#### CLI Port Scan
```bash
python main.py scan -t 192.168.1.0/24 -p 22,80,443,3306,5432
```

#### Host Discovery
```bash
python main.py discover -n 192.168.1.0/24
```

#### REST API
```bash
uvicorn api.app:app --reload
```

## Project Structure
```
nnetwork-scanner/
├── main.py                 # CLI entry point
├── api/
│   ├── app.py             # FastAPI application
│   └── routes/            # API endpoints
├── scanner/
│   ├── port_scanner.py    # Port scanning logic
│   ├── host_discovery.py  # Host detection
│   ├── service_detector.py # Service identification
│   └── cve_checker.py     # Vulnerability checking
├── models/
│   └── scan_models.py     # Data models
├── database/
│   └── db.py              # Database configuration
├── utils/
│   ├── logger.py          # Logging setup
│   ├── config.py          # Configuration management
│   └── report_generator.py # Report generation
├── tests/
│   ├── test_scanner.py    # Scanner tests
│   └── test_api.py        # API tests
├── requirements.txt       # Python dependencies
├── docker-compose.yml     # Docker setup
├── .github/
│   └── workflows/         # CI/CD workflows
└── docs/                  # Documentation
```

## API Endpoints

### POST /api/scan
Start a new network scan
```json
{
  "target": "192.168.1.0/24",
  "ports": [22, 80, 443],
  "timeout": 5
}
```

### GET /api/scans
Retrieve scan history

### GET /api/scans/{scan_id}
Get detailed scan results

## Configuration

Edit `config.yaml`:
```yaml
scanner:
  timeout: 5
  threads: 100
  ports_per_batch: 1000

database:
  type: sqlite
  path: ./scans.db

logging:
  level: INFO
  file: ./logs/scanner.log
```

## Requirements
- Python 3.8+
- pip

## Installation
```bash
pip install -r requirements.txt
```

## Testing
```bash
pytest tests/ -v
```

## Docker

Build and run:
```bash
docker-compose up --build
```

## Technologies Used
- **FastAPI** - High-performance web framework
- **asyncio** - Asynchronous I/O
- **SQLAlchemy** - ORM for database
- **Pydantic** - Data validation
- **pytest** - Testing framework
- **Docker** - Containerization

## Security Considerations
- Use in authorized networks only
- Respect network policies and regulations
- Scan only networks you own or have permission to scan
- Review logs for suspicious activity

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License
MIT License - see LICENSE file for details

## Author
Prabhat Jalpota

## Support
For issues and questions, please open an issue on GitHub.