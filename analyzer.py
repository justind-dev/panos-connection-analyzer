""" 
analyzer.py
-----------
Core logic for analyzing PAN-OS traffic logs.

Optimized: hostname filtering now uses forward-lookup before analysis.
Supports NAT rule matching when a NAT matcher is provided.
"""

import pandas as pd
import datetime
from typing import List, Dict, Optional
from dns_resolver import DNSResolver
from schema import COLUMN_MAPPING, REQUIRED_COLUMNS

# Import NATMatcher conditionally to maintain backward compatibility
try:
    from nat_matcher import NATMatcher
except ImportError:
    NATMatcher = None

# Import AddressManager conditionally
try:
    from address_manager import AddressManager
except ImportError:
    AddressManager = None


class PANOSAnalyzer:
    def __init__(self, dns: DNSResolver, nat_matcher=None, target_ip=None, target_zone=None, target_hostname=None):
        self.dns = dns
        self.nat_matcher = nat_matcher
        self.target_ip = target_ip
        self.target_zone = target_zone
        self.target_hostname = target_hostname
        self.analysis_mode = self._determine_mode()

    def _determine_mode(self):
        if self.target_ip:
            return "ip"
        if self.target_zone:
            return "zone"
        return "all"

    def load_logs(self, csv_path: str) -> pd.DataFrame:
        df = pd.read_csv(csv_path)
        df = df.rename(columns={k: v for k, v in COLUMN_MAPPING.items() if k in df.columns})
        df = df.dropna(subset=[col for col in REQUIRED_COLUMNS if col in df.columns])
        return df

    def filter_logs(self, df: pd.DataFrame) -> pd.DataFrame:
        if self.analysis_mode == "ip" and self.target_ip:
            return df[(df["source_ip"] == self.target_ip) | (df["destination_ip"] == self.target_ip)]

        if self.analysis_mode == "zone" and self.target_zone:
            return df[(df["from_zone"] == self.target_zone) | (df["to_zone"] == self.target_zone)]

        return df

    def aggregate_connections(self, df: pd.DataFrame) -> List[Dict]:
        connections = {}
        logs = df.to_dict("records")

        for log in logs:
            src = str(log.get("source_ip", ""))
            dst = str(log.get("destination_ip", ""))
            proto = str(log.get("protocol", ""))
            port = str(log.get("port", ""))
            app = str(log.get("application", ""))
            key = self._build_connection_key(log, src, dst, proto, port, app)

            if key not in connections:
                connections[key] = self._init_connection_record(log, src, dst, proto, port, app)

            conn = connections[key]
            conn["hits"] += 1
            conn["bytes"] += int(float(log.get("bytes", 0) or 0))
            conn["bytes_sent"] += int(float(log.get("bytes_sent", 0) or 0))
            conn["bytes_received"] += int(float(log.get("bytes_received", 0) or 0))
            conn["packets"] += int(float(log.get("packets", 0) or 0))
            self._update_timestamps(conn, log.get("receive_time", ""))

            # Copy NAT fields if they exist and have values
            for nat_field in ["nat_source_ip", "nat_destination_ip", "nat_source_port", "nat_destination_port"]:
                if nat_field in log and log.get(nat_field):
                    conn[nat_field] = log.get(nat_field)

        # Resolve hostnames for source and destination IPs
        all_ips = {c["source_ip"] for c in connections.values()} | {c["destination_ip"] for c in connections.values()}
        resolved = self.dns.resolve_ips(all_ips)

        for conn in connections.values():
            conn["source_hostname"] = resolved.get(conn["source_ip"], "NotFound")
            conn["destination_hostname"] = resolved.get(conn["destination_ip"], "NotFound")

            # Match connection to NAT rule if NAT matcher is available
            if self.nat_matcher:
                # Use the simplified NAT matcher to get NAT rule info
                nat_info = self.nat_matcher.match_connection(conn)
                
                # Update connection direction if not already set
                if not conn["direction"] and 'direction' in nat_info:
                    conn["direction"] = nat_info['direction']
                
                # Add NAT rule information if available
                if nat_info and nat_info.get('nat_rule'):
                    conn["nat_rule"] = nat_info['nat_rule']
                    
                    # Add NAT type if available
                    if nat_info.get('nat_type'):
                        conn["nat_type"] = nat_info['nat_type']
                
                # Add address objects and groups if available
                if 'address_objects' in nat_info:
                    # Add source address objects and groups
                    if 'source' in nat_info['address_objects']:
                        source_objects = nat_info['address_objects']['source']
                        
                        if 'objects' in source_objects and source_objects['objects']:
                            conn["source_addr_objects"] = ";".join(source_objects['objects'])
                            
                        if 'groups' in source_objects and source_objects['groups']:
                            conn["source_addr_groups"] = ";".join(source_objects['groups'])
                    
                    # Add destination address objects and groups
                    if 'destination' in nat_info['address_objects']:
                        dest_objects = nat_info['address_objects']['destination']
                        
                        if 'objects' in dest_objects and dest_objects['objects']:
                            conn["destination_addr_objects"] = ";".join(dest_objects['objects'])
                            
                        if 'groups' in dest_objects and dest_objects['groups']:
                            conn["destination_addr_groups"] = ";".join(dest_objects['groups'])

        return list(connections.values())

    def _build_connection_key(self, log, src, dst, proto, port, app):
        if self.analysis_mode == "ip":
            direction = "outbound" if src == self.target_ip else "inbound"
            return f"{direction}:{src}:{dst}:{proto}:{port}:{app}"
        if self.analysis_mode == "zone":
            return f"{log.get('from_zone','')}:{log.get('to_zone','')}:{src}:{dst}:{proto}:{port}:{app}"
        return f"{src}:{dst}:{proto}:{port}:{app}"

    def _init_connection_record(self, log, src, dst, proto, port, app):
        record = {
            "source_ip": src,
            "destination_ip": dst,
            "protocol": proto,
            "port": port,
            "application": app,
            "from_zone": log.get("from_zone", ""),
            "to_zone": log.get("to_zone", ""),
            "rule": log.get("rule", ""),
            "action": log.get("action", ""),
            "app_category": log.get("app_category", ""),
            "app_technology": log.get("app_technology", ""),
            "app_risk": log.get("app_risk", ""),
            "hits": 0,
            "bytes": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "packets": 0,
            "first_seen": None,
            "last_seen": None,
            "direction": log.get("direction", ""),
            "nat_rule": "",  # Add empty nat_rule field
            "nat_type": "",  # Add empty nat_type field
            "source_addr_objects": "",  # Add empty fields for address objects
            "source_addr_groups": "",   # Add empty fields for address groups
            "destination_addr_objects": "",  # Add empty fields for destination objects
            "destination_addr_groups": ""    # Add empty fields for destination groups
        }
        
        # Add NAT fields if they exist in the log
        for nat_field in ["nat_source_ip", "nat_destination_ip", "nat_source_port", "nat_destination_port"]:
            if nat_field in log:
                record[nat_field] = log.get(nat_field, "")
                
        return record

    def _update_timestamps(self, conn, timestamp_str):
        for fmt in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.datetime.strptime(timestamp_str, fmt)
                if not conn["first_seen"] or dt < conn["first_seen"]:
                    conn["first_seen"] = dt
                if not conn["last_seen"] or dt > conn["last_seen"]:
                    conn["last_seen"] = dt
                break
            except Exception:
                continue
