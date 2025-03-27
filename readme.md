# PAN-OS Connection Analyzer

A handy tool that makes sense of your Palo Alto Networks firewall logs, showing you traffic patterns and helping you build better security rules.

## What This Tool Does

This script transforms your PAN-OS logs into a clean Excel report of unique connections, helping you:

- See exactly what's talking to what in your network
- Build appropriate security rules with the right parameters
- Identify unexpected or suspicious traffic patterns
- Create documentation your team can actually understand

## Getting Started

### Requirements
- Python 3.6+
- Required packages: `pip install pandas openpyxl`

## How to Use It

### Step 1: Export Your Logs
From your Palo Alto firewall:
1. Go to Monitor > Logs > Traffic
2. Apply filters as needed
3. Click "Export" and save as CSV

### Step 2: Analyze Your Traffic

Filter by IP address:
```
python panos-connection-analyzer.py --ip 10.1.1.100 --logs traffic.csv
```

Filter by hostname (faster - tries direct resolution first):
```
python panos-connection-analyzer.py --hostname server1.example.com --logs traffic.csv
```

Filter by zone:
```
python panos-connection-analyzer.py --zone untrust --logs traffic.csv
```

Analyze everything:
```
python panos-connection-analyzer.py --logs traffic.csv
```

Speed up processing by disabling DNS resolution:
```
python panos-connection-analyzer.py --zone dmz --logs traffic.csv --no-dns
```

### Step 3: Review Your Report

The output includes:
- An Excel file with all connection details
- Console summary showing top applications, zone traffic, and actions

## Command Options

```
--ip IP_ADDRESS      Filter by specific IP address
--hostname HOSTNAME  Filter by hostname (resolves to IP when possible)
--zone ZONE_NAME     Filter by specific zone
--logs FILE_PATH     CSV log file (required)
--output FILE_PATH   Output filename (default: connection_report.xlsx)
--no-dns             Skip DNS resolution for faster processing
--dns-timeout SEC    DNS resolution timeout in seconds (default: 2.0)
--max-workers NUM    Maximum parallel DNS workers (default: 50)
```

## Performance Tips

- For faster results with large log files, use the `--no-dns` option
- For analyzing devices by name instead of IP, the `--hostname` option works best
- If you need both speed and hostname resolution, adjust the timeouts: 
  `--dns-timeout 0.5 --max-workers 100`

## Troubleshooting

If you encounter issues:
- Verify your log file is in CSV format with the expected columns
- For large log files, try increasing workers: `--max-workers 100`
- If DNS resolution is slow, adjust the timeout: `--dns-timeout 1.0`
- Use `--no-dns` if you only care about IP addresses

## Key Fields Used

- Source and destination zones/IPs
- Protocol and port
- Application name
- Rule name that allowed/denied the traffic
- Traffic volume (bytes sent/received)
- Timestamps
