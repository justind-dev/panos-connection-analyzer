"""
nat_matcher.py
-------------
Matches traffic log connections to NAT rules based on address objects and NAT IPs.

Loads NAT rule definitions from a CSV file and provides
functions to match connection details against those rules.
Integrates with AddressManager to resolve address objects.

Usage:
    # Initialize with both NAT rules and address manager
    addr_manager = AddressManager()
    addr_manager.load_address_files("addresses.csv", "address_groups.csv")
    
    matcher = NATMatcher("nat.csv", addr_manager)
    nat_info = matcher.match_connection(connection)
"""

import pandas as pd
import logging
from typing import Dict, List, Optional, Set, Union, Any, Tuple

# Configure logging to show info level logs
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger("nat_matcher")

try:
    from address_manager import AddressManager
except ImportError:
    # Define a stub class for environments without AddressManager
    class AddressManager:
        def __init__(self): 
            self.loaded = False
            
        def get_address_objects_containing_ip(self, ip): 
            return []
            
        def get_address_groups_containing_ip(self, ip): 
            return []


class NATMatcher:
    def __init__(self, nat_csv_path: Optional[str] = None, addr_manager: Optional[AddressManager] = None):
        """
        Initialize the NAT matcher with rules from a CSV file.
        
        Args:
            nat_csv_path: Path to the NAT rules CSV file (optional)
            addr_manager: Instance of AddressManager for address resolution (optional)
        """
        self.rules = []
        self.loaded = False
        self.addr_manager = addr_manager
        
        if nat_csv_path:
            self.load_rules(nat_csv_path)
    
    def load_rules(self, nat_csv_path: str) -> bool:
        """
        Load NAT rules from a CSV file.
        
        Args:
            nat_csv_path: Path to the NAT rules CSV file
            
        Returns:
            True if rules were loaded successfully, False otherwise
        """
        try:
            # Load NAT rules CSV
            df = pd.read_csv(nat_csv_path)
            
            # Find rule name column
            name_col = self._find_column(df.columns, ["Name", "Rule Name"])
            if not name_col:
                if len(df.columns) > 1:
                    name_col = df.columns[1]  # Try second column as fallback
                else:
                    logger.error("Could not find rule name column in NAT CSV.")
                    return False
            
            # Process rules and store in our internal format
            for _, row in df.iterrows():
                rule_name = str(row.get(name_col, ""))
                
                # Skip disabled rules
                if rule_name.startswith("[Disabled]"):
                    continue
                
                # Extract fields with standardized column name handling
                rule = self._extract_rule_fields(row, df.columns)
                
                # Only add non-empty rules
                if rule and rule.get('name'):
                    self.rules.append(rule)
            
            logger.info(f"Loaded {len(self.rules)} active NAT rules")
            self.loaded = True
            return True
            
        except Exception as e:
            logger.error(f"Failed to load NAT rules: {e}")
            return False
    
    def _find_column(self, columns, possible_names):
        """Find a column name from a list of possibilities."""
        for name in possible_names:
            if name in columns:
                return name
        return None
    
    def _extract_rule_fields(self, row, columns) -> Dict:
        """
        Extract relevant fields from a NAT rule row.
        Focus only on fields needed for NAT matching.
        
        Args:
            row: The pandas Series containing the rule data
            columns: Available column names in the dataframe
            
        Returns:
            Dict containing the rule fields
        """
        # Find column names based on possible variants
        name_col = self._find_column(columns, ['Name', 'Rule Name'])
        if not name_col and len(columns) > 1:
            name_col = columns[1]
        
        # Common column pattern tests
        src_zone_col = self._find_column(columns, [
            'Original Packet Source Zone', 'Source Zone', 'From Zone'
        ])
        dst_zone_col = self._find_column(columns, [
            'Original Packet Destination Zone', 'Destination Zone', 'To Zone'
        ])
        src_addr_col = self._find_column(columns, [
            'Original Packet Source Address', 'Source Address'
        ])
        dst_addr_col = self._find_column(columns, [
            'Original Packet Destination Address', 'Destination Address'
        ])
        src_trans_col = self._find_column(columns, [
            'Translated Packet Source Translation', 'Source Translation', 'Source NAT'
        ])
        dst_trans_col = self._find_column(columns, [
            'Translated Packet Destination Translation', 'Destination Translation', 'Destination NAT'
        ])
        tags_col = self._find_column(columns, ['Tags'])
        
        # Extract the rule fields
        rule = {
            'name': str(row.get(name_col, "")),
            'src_zone': self._extract_field(row, src_zone_col),
            'dst_zone': self._extract_field(row, dst_zone_col),
            'src_addr': self._extract_field(row, src_addr_col),
            'dst_addr': self._extract_field(row, dst_addr_col),
            'src_translation': self._extract_field(row, src_trans_col),
            'dst_translation': self._extract_field(row, dst_trans_col),
            'tags': self._extract_field(row, tags_col)
        }
        
        # Parse NAT type and translation details
        if rule['src_translation']:
            rule.update(self._parse_translation(rule['src_translation'], 'source'))
        
        if rule['dst_translation']:
            rule.update(self._parse_translation(rule['dst_translation'], 'destination'))
        
        return rule
    
    def _parse_translation(self, translation_str: str, direction: str) -> Dict:
        """
        Parse NAT translation string into components.
        Handle format like: "static-ip;address-name;bi-directional: yes"
        
        Args:
            translation_str: NAT translation string
            direction: 'source' or 'destination'
            
        Returns:
            Dictionary with parsed components
        """
        result = {}
        
        if not translation_str or translation_str.lower() == 'none':
            return {'nat_type': None}
            
        parts = [p.strip() for p in translation_str.split(';')]
        
        # First part is usually the NAT type
        if parts and parts[0]:
            result['nat_type'] = parts[0]
            
        # Second part is usually the address object or interface
        if len(parts) > 1 and parts[1]:
            result[f'{direction}_nat_addr'] = parts[1]
            
        # Additional parts might have key-value pairs
        for part in parts[2:] if len(parts) > 2 else []:
            if ':' in part:
                key, value = [p.strip() for p in part.split(':', 1)]
                result[key] = value
                
        return result
    
    def _extract_field(self, row, column_name) -> Optional[str]:
        """Safely extract a field from a row."""
        if column_name and column_name in row:
            value = row.get(column_name)
            if pd.notna(value):
                return str(value).strip()
        return None
        
    def match_connection(self, conn: Dict) -> Dict:
        """
        Match a connection to a NAT rule and identify address objects.
        Uses a deterministic matching approach with precise criteria.
        
        Args:
            conn: Connection dictionary with NAT details
            
        Returns:
            Dictionary containing NAT rule info and address object details
        """
        if not self.loaded:
            logger.info("No NAT rules loaded, skipping match")
            return {'nat_rule': None, 'nat_type': None}
        
        # Extract connection details
        src_ip = self._safe_str(conn.get('source_ip', ''))
        dst_ip = self._safe_str(conn.get('destination_ip', ''))
        src_zone = self._safe_str(conn.get('from_zone', ''))
        dst_zone = self._safe_str(conn.get('to_zone', ''))
        
        # Skip invalid IPs
        if not src_ip or src_ip in ('nan', 'None'):
            src_ip = ''
        if not dst_ip or dst_ip in ('nan', 'None'):
            dst_ip = ''
            
        # If no IPs to match, there's nothing to do
        if not (src_ip or dst_ip):
            logger.info("No valid IPs in connection, skipping match")
            return {'nat_rule': None, 'nat_type': None}
        
        # Find address objects for IPs
        src_addr_objects = []
        src_addr_groups = []
        dst_addr_objects = []
        dst_addr_groups = []
        
        if self.addr_manager and self.addr_manager.loaded:
            if src_ip:
                src_addr_objects = self.addr_manager.get_address_objects_containing_ip(src_ip)
                src_addr_groups = self.addr_manager.get_address_groups_containing_ip(src_ip)
                
            if dst_ip:
                dst_addr_objects = self.addr_manager.get_address_objects_containing_ip(dst_ip)
                dst_addr_groups = self.addr_manager.get_address_groups_containing_ip(dst_ip)
        
        # Collect objects/groups for later use in result
        address_objects = {}
        if src_addr_objects or src_addr_groups:
            address_objects['source'] = {
                'objects': src_addr_objects,
                'groups': src_addr_groups
            }
        
        if dst_addr_objects or dst_addr_groups:
            address_objects['destination'] = {
                'objects': dst_addr_objects,
                'groups': dst_addr_groups
            }
        
        # Try to match the rule in order of specificity
        matched_rule = None
        match_method = None
        
        # Create sets of all possible address identifiers for source and destination
        src_identifiers = set(src_addr_objects + src_addr_groups + [src_ip])
        dst_identifiers = set(dst_addr_objects + dst_addr_groups + [dst_ip])
        
        # 1. Exact match: Both source and destination addresses match
        for rule in self.rules:
            rule_src = rule.get('src_addr')
            rule_dst = rule.get('dst_addr')
            
            # Skip rules without address specifications
            if not rule_src and not rule_dst:
                continue
                
            # Check for direct matches - both source and destination
            if ((rule_src in src_identifiers or rule_src == 'any') and
                (rule_dst in dst_identifiers or rule_dst == 'any')):
                
                # Check zone match too if specified
                if self._zones_match(rule.get('src_zone'), src_zone) and \
                   self._zones_match(rule.get('dst_zone'), dst_zone):
                    matched_rule = rule
                    match_method = "address_and_zone_match"
                    logger.info(f"Matched rule {rule['name']} by address objects/groups and zones")
                    break
        
        # 2. If no match yet, try zone matching with more flexibility
        if not matched_rule:
            for rule in self.rules:
                # If zones match but addresses don't specify or are 'any'
                if (self._zones_match(rule.get('src_zone'), src_zone) and 
                    self._zones_match(rule.get('dst_zone'), dst_zone)):
                    
                    # Check if at least one address matches or is 'any'
                    src_match = not rule.get('src_addr') or rule.get('src_addr') == 'any' or rule.get('src_addr') in src_identifiers
                    dst_match = not rule.get('dst_addr') or rule.get('dst_addr') == 'any' or rule.get('dst_addr') in dst_identifiers
                    
                    if src_match or dst_match:
                        matched_rule = rule
                        match_method = "zone_match_with_partial_address"
                        logger.info(f"Matched rule {rule['name']} by zones with partial address match")
                        break
        
        # 3. Last resort: Just zone matching
        if not matched_rule:
            for rule in self.rules:
                # Pure zone matching
                if (self._zones_match(rule.get('src_zone'), src_zone) and 
                    self._zones_match(rule.get('dst_zone'), dst_zone)):
                    matched_rule = rule
                    match_method = "zone_match_only"
                    logger.info(f"Matched rule {rule['name']} by zones only")
                    break
        
        # If still no match, look for catchall rules (e.g., NAT rules with 'any' for both source and destination)
        if not matched_rule:
            for rule in self.rules:
                if ((not rule.get('src_addr') or rule.get('src_addr') == 'any') and
                    (not rule.get('dst_addr') or rule.get('dst_addr') == 'any')):
                    
                    # Still check zone match
                    if (self._zones_match(rule.get('src_zone'), src_zone) and 
                        self._zones_match(rule.get('dst_zone'), dst_zone)):
                        matched_rule = rule
                        match_method = "catchall_rule"
                        logger.info(f"Matched catchall rule {rule['name']}")
                        break
        
        # No match found
        if not matched_rule:
            logger.info("No matching NAT rule found")
            return {
                'nat_rule': None, 
                'nat_type': None,
                'address_objects': address_objects
            }
        
        # Build the result with the matched rule
        result = {
            'nat_rule': matched_rule['name'],
            'nat_type': matched_rule.get('nat_type'),
            'address_objects': address_objects
        }
        
        # Log match details instead of including in the result
        logger.info(f"Match method: {match_method}")
        logger.info(f"Source address objects: {src_addr_objects}")
        logger.info(f"Source address groups: {src_addr_groups}")
        logger.info(f"Destination address objects: {dst_addr_objects}")
        logger.info(f"Destination address groups: {dst_addr_groups}")
        logger.info(f"Rule details: {matched_rule}")
        
        return result
    
    def _zones_match(self, rule_zone: Optional[str], conn_zone: str) -> bool:
        """
        Check if a connection's zone matches a rule's zone specification.
        Handles semicolon-separated zone lists.
        
        Args:
            rule_zone: Zone from the rule (can be None, 'any', or semicolon-separated list)
            conn_zone: Zone from the connection
            
        Returns:
            True if zones match, False otherwise
        """
        # If rule doesn't specify a zone, it's a wildcard match
        if not rule_zone:
            return True
            
        # If rule has 'any', it matches any zone
        if rule_zone.lower() == 'any':
            return True
            
        # Handle semicolon-separated lists
        if ';' in rule_zone:
            rule_zones = [z.strip() for z in rule_zone.split(';')]
            return conn_zone in rule_zones or 'any' in rule_zones
            
        # Direct match
        return rule_zone == conn_zone
    
    def _safe_str(self, value) -> str:
        """Safely convert any value to string, handling None and special types."""
        if value is None:
            return ''
        try:
            return str(value).strip()
        except:
            return ''
    
    def get_nat_type(self, rule_name: str) -> Optional[str]:
        """
        Get the NAT type for a given rule name.
        
        Args:
            rule_name: Name of the NAT rule
            
        Returns:
            NAT type string (e.g., 'static-ip', 'dynamic-ip-and-port') or None
        """
        if not self.loaded or not rule_name:
            return None
        
        for rule in self.rules:
            if rule['name'] == rule_name:
                return rule.get('nat_type')
        
        return None
