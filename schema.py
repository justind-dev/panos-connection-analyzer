"""
schema.py
---------
Contains shared field mappings and constants for standardizing PAN-OS CSV logs.

Usage:
- COLUMN_MAPPING defines how raw CSV headers map to normalized internal names.
- REQUIRED_COLUMNS are the minimal fields needed to uniquely define a connection.

To add support for new columns:
- Add the original column name (as seen in the CSV export) as the key.
- Set the desired internal field name (snake_case) as the value.

To remove or ignore a column:
- Remove it from COLUMN_MAPPING (or just don't include it).

All scripts should rely on these definitions to avoid hardcoded column names.
"""

# Mapping of PAN-OS CSV headers → normalized internal field names
COLUMN_MAPPING = {
    'Source address': 'source_ip',
    'Destination address': 'destination_ip',
    'IP Protocol': 'protocol',
    'Destination Port': 'port',
    'Application': 'application',
    'Action': 'action',
    'Source Zone': 'from_zone',
    'Destination Zone': 'to_zone',
    'Receive Time': 'receive_time',
    'Bytes': 'bytes',
    'Rule': 'rule',
    'Bytes Sent': 'bytes_sent',
    'Bytes Received': 'bytes_received',
    'Packets': 'packets',
    'Category of app': 'app_category',
    'Technology of app': 'app_technology',
    'Risk of app': 'app_risk',
    'Source Hostname': 'source_hostname',
    'Destination Hostname': 'destination_hostname',
    
    # NAT-related fields
    'NAT Source IP': 'nat_source_ip',
    'NAT Destination IP': 'nat_destination_ip',
    'NAT Source Port': 'nat_source_port',
    'NAT Destination Port': 'nat_destination_port'
}

# Minimum required fields to define a unique connection
REQUIRED_COLUMNS = ['source_ip', 'destination_ip', 'protocol', 'port']