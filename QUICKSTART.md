# Quick Start Guide

## Get Started in 5 Minutes

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Initialize the System
```bash
python cli.py init
```

### 3. Add Sample Data
Place your data files in the appropriate directories:
- **Network traffic**: `data/pcaps/*.pcap`
- **Host logs**: `data/logs/*.log` or `*.json`

### 4. Run Ingestion
```bash
python cli.py ingest
```

### 5. View Results
```bash
python cli.py stats --verbose
```

## Example Workflow

```bash
# 1. Setup
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt

# 2. Initialize
python cli.py init

# 3. Download sample PCAP (optional)
# Visit: https://www.netresec.com/pcap/
# Place in: data/pcaps/

# 4. Ingest
python cli.py ingest --network --batch-size 100

# 5. Check results
python cli.py stats
```

## What's Next?

After Chunk 1 is working:
- **Chunk 2**: Implement signature-based detection rules
- **Chunk 3**: Train ML anomaly detection models
- **Chunk 4**: Build alert fusion and scoring
- **Chunk 5**: Create REST API backend
- **Chunks 6-10**: Build advanced dashboard

## Common Commands

```bash
# Initialize database
python cli.py init

# Ingest only network traffic
python cli.py ingest --network

# Ingest only host logs
python cli.py ingest --host

# Ingest everything
python cli.py ingest

# Show statistics
python cli.py stats

# Verbose mode
python cli.py -v stats --verbose
```

## Testing Without Real Data

If you don't have PCAP files or logs yet, you can:

1. **Download public datasets**:
   - [PCAP samples](https://www.netresec.com/pcap/)
   - [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/)

2. **Generate test data**:
   ```python
   from scapy.all import wrpcap, IP, TCP
   # Create simple packets and save as PCAP
   ```

3. **Use system logs**:
   - Linux: `/var/log/auth.log`, `/var/log/syslog`
   - Windows: Export Event Viewer logs as XML

## Troubleshooting

**"Scapy not found"**
```bash
pip install scapy
# Windows: Also install Npcap from https://npcap.com/
```

**"No PCAP files found"**
- Check `data/pcaps/` directory exists
- Verify PCAP files have `.pcap` or `.pcapng` extension

**"Database locked"**
- Only one process can write to SQLite at a time
- Close any other CLI instances
- Or switch to PostgreSQL in config.yaml

## Next Steps

✅ **Chunk 1 Complete** - You have a working data ingestion pipeline!

Ready for **Chunk 2** - Signature Detection Engine:
- Define attack signatures
- Build rule matching engine
- Integrate IOC feeds
- Generate alerts

Let me know when you're ready to proceed!
