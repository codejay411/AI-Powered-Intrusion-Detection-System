# AI-Powered Intrusion Detection System (IDS)

A hybrid, AI-powered Intrusion Detection System that combines signature-based detection with machine learning anomaly detection to identify both known and novel threats across network traffic and host-level activity.

## Features

### Current Implementation (Chunk 1 - Foundation)

✅ **Data Layer**
- SQLite/PostgreSQL database with comprehensive schema
- Event storage for network and host data
- Alert management system
- Model versioning and IOC tracking

✅ **Configuration Management**
- YAML-based configuration with environment variable overrides
- Centralized settings for all system components

✅ **Network Traffic Ingestion**
- PCAP file parsing with scapy
- Support for live packet capture
- NetFlow/IPFIX compatibility
- Automatic protocol detection (TCP/UDP/ICMP)

✅ **Host Log Ingestion**
- JSON log parsing
- Syslog format support
- Windows Event Log (EVTX/XML) parsing
- Auditd log parsing
- Multi-format detection

✅ **Feature Extraction**
- Network features: flow statistics, port analysis, protocol distribution
- Host features: process behavior, command-line analysis, temporal patterns
- Temporal/behavioral tracking with time-window analysis
- 30+ extracted features per event type

✅ **Data Pipeline**
- Batch processing with configurable batch sizes
- Automatic feature extraction and storage
- Event retrieval and statistics

## Project Structure

```
AI Powered Intrusion Detection System/
├── config/
│   ├── config.yaml              # Main configuration
│   └── rules/                   # Signature rules (future)
├── data/
│   ├── pcaps/                   # Network capture files
│   ├── logs/                    # Host log files
│   └── datasets/                # ML training datasets
├── src/
│   ├── core/
│   │   ├── config.py           # Configuration management
│   │   ├── database.py         # Database connection
│   │   ├── models.py           # SQLAlchemy models
│   │   └── logger.py           # Logging setup
│   └── ingestion/
│       ├── network_ingestion.py  # Network traffic parser
│       ├── host_ingestion.py     # Host log parser
│       ├── feature_extraction.py # Feature engineering
│       └── pipeline.py           # Data pipeline orchestrator
├── models/                      # Trained ML models
├── logs/                        # Application logs
├── cli.py                       # Command-line interface
├── requirements.txt             # Python dependencies
└── .env.example                 # Environment template
```

## Installation

### Prerequisites
- Python 3.8+
- pip

### Setup

1. **Clone or navigate to the project directory**

2. **Create virtual environment**
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment**
```bash
cp .env.example .env
# Edit .env with your settings
```

5. **Initialize the system**
```bash
python cli.py init
```

## Usage

### Command-Line Interface

**Initialize the system:**
```bash
python cli.py init
```

**Ingest network traffic (PCAP files):**
```bash
# Place PCAP files in data/pcaps/
python cli.py ingest --network
```

**Ingest host logs:**
```bash
# Place log files in data/logs/
python cli.py ingest --host
```

**Ingest all sources:**
```bash
python cli.py ingest
```

**View statistics:**
```bash
python cli.py stats

# With verbose output (show recent events)
python cli.py stats --verbose
```

### Python API

```python
from src.core import setup_logging, init_database
from src.ingestion import DataPipeline

# Initialize
setup_logging()
init_database()

# Create pipeline
pipeline = DataPipeline()

# Ingest data
results = pipeline.ingest_all(batch_size=100)
print(f"Processed {results['total']} events")

# Get statistics
total = pipeline.get_event_count()
network = pipeline.get_event_count(event_type='network')
host = pipeline.get_event_count(event_type='host')

# Retrieve events
recent_events = pipeline.get_events(limit=10)
```

## Configuration

Edit `config/config.yaml` to customize:

- **Database settings**: SQLite (default) or PostgreSQL
- **Ingestion sources**: PCAP directories, log paths, live capture
- **Feature extraction**: Enabled features for network/host
- **ML models**: Training datasets, model parameters
- **Performance**: Batch sizes, cache settings, worker threads

Key settings can be overridden via environment variables in `.env`:
- `DB_TYPE`, `DB_PATH`
- `API_HOST`, `API_PORT`
- `LOG_LEVEL`

## Data Formats

### Supported Network Sources
- **PCAP/PCAPNG files**: Standard packet capture format
- **Live capture**: Real-time packet sniffing (requires privileges)
- **NetFlow/IPFIX**: Flow records (planned)

### Supported Host Log Sources
- **JSON logs**: One JSON object per line
- **Syslog**: RFC 3164 format
- **Windows Event Logs**: EVTX (XML export)
- **Auditd**: Linux audit logs
- **Generic text logs**: Basic parsing

## Development Roadmap

### ✅ Chunk 1: Foundation & Data Layer (COMPLETE)
- Project structure and configuration
- Database schema and models
- Network and host ingestion
- Feature extraction
- Data pipeline

### 🔄 Chunk 2: Signature Detection Engine (Next)
- Rule definition format
- Pattern matching engine
- IOC feed integration
- YARA rule support

### 📋 Chunk 3: ML Anomaly Detection
- Dataset preprocessing
- Model training (Isolation Forest, One-Class SVM, Autoencoder)
- Inference pipeline

### 📋 Chunk 4: Fusion & Alert Management
- Signature + ML signal fusion
- Alert scoring and prioritization
- Deduplication and enrichment

### 📋 Chunk 5: Backend API
- Flask REST API
- WebSocket support for real-time updates
- Authentication

### 📋 Chunks 6-10: Advanced Dashboard
- Real-time monitoring
- Alert investigation tools
- Advanced visualizations
- Analyst workflow
- Reporting

### 📋 Chunks 11-15: Intelligence, Performance, Streaming
- Threat intelligence integration
- Performance optimization
- Real-time streaming
- Automated response

## Testing

### Sample Data

**Network traffic:**
Place PCAP files in `data/pcaps/` or download public datasets:
- [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
- [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html)
- [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset)

**Host logs:**
Place log files in `data/logs/`:
- JSON logs (e.g., from ELK stack)
- Syslog exports
- Windows Event Log XML exports
- Auditd logs

### Verify Installation

```bash
# Initialize
python cli.py init

# Check stats (should show 0 events)
python cli.py stats

# Add sample data to data/pcaps or data/logs

# Ingest and verify
python cli.py ingest
python cli.py stats
```

## Troubleshooting

**Scapy import errors on Windows:**
- Install Npcap: https://npcap.com/
- Or use WSL for better compatibility

**Permission denied during live capture:**
- Linux: Run with `sudo` or add capabilities
- Windows: Run as Administrator

**Database locked errors:**
- SQLite doesn't handle high concurrency well
- Switch to PostgreSQL in config.yaml for production

## Contributing

This is a phased development project. Current focus: **Chunk 1 (Foundation) - Complete**.

## License

MIT License

## Acknowledgments

- Public datasets: CIC-IDS2017, NSL-KDD, UNSW-NB15
- Network analysis: scapy, pyshark
- MITRE ATT&CK Framework for threat taxonomy

---

**Status:** Chunk 1 Complete - Foundation & Data Layer operational
**Next:** Chunk 2 - Signature Detection Engine
