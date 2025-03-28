# PAN-OS Connection Analyzer: Quick Usage Guide

A tool to analyze Palo Alto firewall traffic logs and generate connection reports with address object and NAT rule matching.

## Required Files

- **traffic.csv**: Your exported PAN-OS traffic logs
- **nat.csv**: NAT rules exported from your firewall (optional)
- **addresses.csv**: Address objects (optional)
- **address_groups.csv**: Address groups (optional)

## CLI Usage

Basic usage with IP filtering:
```bash
python main.py --logs traffic.csv --ip 10.1.1.100
```

Output to a specific file:
```bash
python main.py --logs traffic.csv --zone Trust-INSIDE --output trust_connections.xlsx
```

Filter by hostname (with DNS resolution):
```bash
python main.py --logs traffic.csv --hostname server1.example.com
```

Full options:
```bash
python main.py --logs traffic.csv --ip 10.1.1.100 --output report.xlsx --no-dns --dns-timeout 1.0 --max-workers 50
```

## Interactive Menu

Launch the interactive menu:
```bash
python main.py
```

The menu will guide you through:
1. Loading traffic logs
2. Selecting filter type (IP, hostname, zone, or none)
3. Choosing output filename

## Command Options

| Option | Description |
|--------|-------------|
| `--logs` | Path to CSV log file |
| `--ip` | Filter by IP address |
| `--zone` | Filter by zone (e.g., Trust-INSIDE) |
| `--hostname` | Filter by hostname (resolved to IP) |
| `--output` | Output file path (default: connection_report.xlsx) |
| `--no-dns` | Disable DNS resolution |
| `--dns-timeout` | DNS timeout in seconds (default: 2.0) |
| `--max-workers` | Max parallel DNS workers (default: 50) |
| `--interactive` | Launch interactive menu |
| `--nat-file` | Custom path to NAT rules file |
| `--address-file` | Custom path to address objects file |
| `--address-group-file` | Custom path to address groups file |

## Output Reports

The report includes:
- Source/destination IPs and their resolved hostnames
- Address objects and groups associated with each IP
- NAT rules applied to each connection
- Traffic statistics and metadata

## Export Logs from Palo Alto Firewall

1. Go to **Monitor > Logs > Traffic**
2. Apply any desired filters
3. Click **Export as CSV**
