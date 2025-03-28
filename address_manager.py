"""
address_manager.py
-----------------
Manages address objects and address groups for Palo Alto Networks configurations.

Loads address objects and groups from CSV files, provides methods to check if an IP 
matches an address object or group, and resolves address object and group names to their 
actual values.

Usage:
    manager = AddressManager()
    manager.load_address_files("addresses.csv", "address_groups.csv")
    
    # Check if an IP matches an address object
    is_match = manager.ip_matches_address("192.168.1.100", "Internal_Network")
    
    # Resolve an address object to its value
    address_value = manager.resolve_address("Web_Server")
    
    # Get all IPs in an address group
    ips = manager.get_all_ips_in_group("DMZ-Servers")
"""

import os
import ipaddress
import csv
import re
from typing import Dict, List, Set, Optional, Tuple, Union


class AddressManager:
    def __init__(self):
        """Initialize the address manager with empty collections."""
        # Maps address object names to their values and types
        self.addresses: Dict[str, Dict] = {}
        
        # Maps address group names to their member names
        self.address_groups: Dict[str, List[str]] = {}
        
        # Cache of resolved IPs for groups to avoid repeated resolution
        self._group_ip_cache: Dict[str, Set[str]] = {}
        
        # Flag to track if files have been loaded
        self.loaded = False

    def load_address_files(self, address_file: Optional[str] = "addresses.csv", 
                          group_file: Optional[str] = "address_groups.csv") -> bool:
        """
        Load address objects and groups from CSV files.
        
        Args:
            address_file: Path to the address objects CSV file
            group_file: Path to the address groups CSV file
            
        Returns:
            True if at least one file was loaded successfully, False otherwise
        """
        address_loaded = self._load_addresses(address_file) if address_file else False
        groups_loaded = self._load_address_groups(group_file) if group_file else False
        
        self.loaded = address_loaded or groups_loaded
        return self.loaded

    def _load_addresses(self, csv_path: str) -> bool:
        """
        Load address objects from a CSV file.
        
        Args:
            csv_path: Path to the address CSV file
            
        Returns:
            True if addresses were loaded successfully, False otherwise
        """
        if not os.path.exists(csv_path):
            print(f"⚠ Address file not found: {csv_path}")
            return False
            
        try:
            with open(csv_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                
                # Verify required columns exist
                required_cols = {"Name", "Type", "Address"}
                header_set = set(reader.fieldnames or [])
                if not required_cols.issubset(header_set):
                    missing = required_cols - header_set
                    print(f"⚠ Address CSV missing required columns: {missing}")
                    return False
                
                count = 0
                for row in reader:
                    name = row.get("Name", "").strip()
                    addr_type = row.get("Type", "").strip()
                    address = row.get("Address", "").strip()
                    
                    if name and address:
                        self.addresses[name] = {
                            "type": addr_type,
                            "value": address,
                            # Store additional metadata if needed
                            "location": row.get("Location", ""),
                            "tags": row.get("Tags", "")
                        }
                        count += 1
                        
            print(f"✅ Loaded {count} address objects from {csv_path}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to load address objects: {e}")
            return False

    def _load_address_groups(self, csv_path: str) -> bool:
        """
        Load address groups from a CSV file.
        
        Args:
            csv_path: Path to the address groups CSV file
            
        Returns:
            True if address groups were loaded successfully, False otherwise
        """
        if not os.path.exists(csv_path):
            print(f"⚠ Address group file not found: {csv_path}")
            return False
            
        try:
            with open(csv_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                
                # Verify required columns exist
                required_cols = {"Name", "Addresses"}
                header_set = set(reader.fieldnames or [])
                if not required_cols.issubset(header_set):
                    missing = required_cols - header_set
                    print(f"⚠ Address group CSV missing required columns: {missing}")
                    return False
                
                count = 0
                for row in reader:
                    name = row.get("Name", "").strip()
                    addresses_str = row.get("Addresses", "").strip()
                    
                    if name and addresses_str:
                        # Split by semicolon and clean up each member
                        members = [m.strip() for m in addresses_str.split(';') if m.strip()]
                        self.address_groups[name] = members
                        count += 1
                        
            print(f"✅ Loaded {count} address groups from {csv_path}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to load address groups: {e}")
            return False

    def ip_matches_address(self, ip: str, address_name: str) -> bool:
        """
        Check if an IP matches a specific address object or group.
        
        Args:
            ip: The IP address to check
            address_name: Name of the address object or group
            
        Returns:
            True if the IP matches the address object or group, False otherwise
        """
        if not self.loaded:
            return False
            
        # Check if it's an address group
        if address_name in self.address_groups:
            group_ips = self.get_all_ips_in_group(address_name)
            return ip in group_ips
            
        # Check if it's an address object
        if address_name in self.addresses:
            address_obj = self.addresses[address_name]
            return self._ip_matches_address_object(ip, address_obj)
            
        return False

    def _ip_matches_address_object(self, ip: str, address_obj: Dict) -> bool:
        """
        Check if an IP matches an address object definition.
        
        Args:
            ip: The IP address to check
            address_obj: The address object dictionary
            
        Returns:
            True if the IP matches the address object, False otherwise
        """
        addr_type = address_obj.get("type", "")
        value = address_obj.get("value", "")
        
        if not addr_type or not value:
            return False
            
        try:
            # If we can't parse the IP, it can't be a match
            ip_obj = ipaddress.ip_address(ip)
            
            # Handle different address types
            if addr_type == "IP Netmask":
                # Check if the value is a single IP or a network
                if '/' in value:
                    try:
                        # It's a CIDR network
                        network = ipaddress.ip_network(value, strict=False)
                        
                        # Check IP version compatibility silently
                        if ip_obj.version != network.version:
                            return False
                            
                        return ip_obj in network
                    except ValueError:
                        # Network parsing error - silently return False
                        return False
                else:
                    try:
                        # It's a single IP - check version compatibility
                        addr_ip = ipaddress.ip_address(value)
                        if ip_obj.version != addr_ip.version:
                            return False
                        return ip == value
                    except ValueError:
                        # IP parsing error - silently return False
                        return False
                    
            elif addr_type == "IP Range":
                # Format: start-end
                if '-' in value:
                    try:
                        start, end = value.split('-')
                        start_ip = ipaddress.ip_address(start.strip())
                        end_ip = ipaddress.ip_address(end.strip())
                        
                        # Check IP version compatibility silently
                        if ip_obj.version != start_ip.version or ip_obj.version != end_ip.version:
                            return False
                            
                        return start_ip <= ip_obj <= end_ip
                    except ValueError:
                        # Range parsing error - silently return False
                        return False
                    
            elif addr_type == "IP Wildcard Mask":
                # Convert wildcard mask to CIDR and check
                try:
                    base_ip, wildcard = value.split(' ')
                    
                    # Ensure IP version compatibility
                    base_ip_obj = ipaddress.ip_address(base_ip)
                    if ip_obj.version != base_ip_obj.version:
                        return False
                        
                    return self._ip_matches_wildcard(ip, base_ip, wildcard)
                except ValueError:
                    # Wildcard parsing error - silently return False
                    return False
                
            elif addr_type == "FQDN":
                # FQDN matching would typically require a DNS lookup
                # For now, just return False as we can't match IP to FQDN directly
                return False
                
            # Unknown type, try direct match
            return ip == value
            
        except Exception:
            # Any error in IP matching - silently return False
            return False

    def _ip_matches_wildcard(self, ip: str, base_ip: str, wildcard: str) -> bool:
        """
        Check if an IP matches a base IP with a wildcard mask.
        
        Args:
            ip: The IP to check
            base_ip: The base IP in the wildcard expression
            wildcard: The wildcard mask
            
        Returns:
            True if the IP matches the wildcard expression, False otherwise
        """
        try:
            # Convert to integer representations
            ip_int = int(ipaddress.IPv4Address(ip))
            base_int = int(ipaddress.IPv4Address(base_ip))
            wildcard_int = int(ipaddress.IPv4Address(wildcard))
            
            # In a wildcard mask, 0 bits must match, 1 bits can be anything
            # XOR base_ip and ip, then AND with inverse of wildcard
            # If result is 0, they match according to the wildcard
            return ((base_int ^ ip_int) & ~wildcard_int) == 0
            
        except Exception:
            # Silently fail on any error
            return False

    def resolve_address(self, address_name: str) -> Optional[str]:
        """
        Resolve an address object name to its actual value.
        
        Args:
            address_name: The name of the address object
            
        Returns:
            The address value, or None if not found
        """
        if not self.loaded:
            return None
            
        if address_name in self.addresses:
            return self.addresses[address_name].get("value")
            
        return None

    def get_all_ips_in_group(self, group_name: str) -> Set[str]:
        """
        Get all IP addresses contained in an address group, resolving nested groups.
        
        Args:
            group_name: The name of the address group
            
        Returns:
            Set of all resolved IP addresses in the group
        """
        if not self.loaded:
            return set()
            
        # Check cache first
        if group_name in self._group_ip_cache:
            return self._group_ip_cache[group_name]
            
        result = set()
        # Track groups we've seen to avoid infinite recursion with circular references
        return self._resolve_group_members(group_name, result, set())

    def _resolve_group_members(self, group_name: str, result: Set[str], visited: Set[str]) -> Set[str]:
        """
        Recursively resolve all members in a group, including nested groups.
        
        Args:
            group_name: The group name to resolve
            result: Set to collect IP addresses
            visited: Set to track visited groups to avoid circular references
            
        Returns:
            Set of all resolved IP addresses
        """
        if group_name in visited:
            # Avoid circular references
            return result
            
        if group_name not in self.address_groups:
            return result
            
        visited.add(group_name)
        
        for member in self.address_groups[group_name]:
            # Check if the member is another group
            if member in self.address_groups:
                self._resolve_group_members(member, result, visited)
                
            # Check if it's an address object
            elif member in self.addresses:
                addr_obj = self.addresses[member]
                self._add_ips_from_address_object(addr_obj, result)
                
            # Try to interpret as a direct IP or network
            else:
                self._add_direct_ip_or_network(member, result)
                
        # Cache the result for this group
        self._group_ip_cache[group_name] = result.copy()
        
        return result

    def _add_ips_from_address_object(self, addr_obj: Dict, result: Set[str]) -> None:
        """
        Add IPs from an address object to the result set.
        
        Args:
            addr_obj: The address object dictionary
            result: Set to collect IP addresses
        """
        addr_type = addr_obj.get("type", "")
        value = addr_obj.get("value", "")
        
        if not value:
            return
            
        try:
            if addr_type == "IP Netmask":
                if '/' in value:
                    # It's a CIDR network - add each IP in the network
                    # For large networks, just store the network definition
                    network = ipaddress.ip_network(value, strict=False)
                    if network.num_addresses <= 1024:  # Arbitrary limit to avoid memory issues
                        for ip in network:
                            result.add(str(ip))
                    else:
                        # For large networks, store the network definition
                        result.add(value)
                else:
                    # Single IP
                    result.add(value)
                    
            elif addr_type == "IP Range":
                if '-' in value:
                    start, end = value.split('-')
                    start_ip = ipaddress.ip_address(start.strip())
                    end_ip = ipaddress.ip_address(end.strip())
                    
                    # Check if range is too large
                    ip_count = int(end_ip) - int(start_ip) + 1
                    if ip_count <= 1024:  # Arbitrary limit
                        current = start_ip
                        while current <= end_ip:
                            result.add(str(current))
                            current += 1
                    else:
                        # For large ranges, store the range definition
                        result.add(value)
                        
            elif addr_type in ("IP Wildcard Mask", "FQDN"):
                # For these types, just store the definition
                result.add(value)
                
            else:
                # Unknown type, just add the value
                result.add(value)
                
        except Exception:
            # Silently skip any errors
            pass

    def _add_direct_ip_or_network(self, ip_or_network: str, result: Set[str]) -> None:
        """
        Try to interpret a string as an IP or network and add to result set.
        
        Args:
            ip_or_network: String that might be an IP or network
            result: Set to collect IP addresses
        """
        try:
            # Check if it's a CIDR network
            if '/' in ip_or_network:
                network = ipaddress.ip_network(ip_or_network, strict=False)
                if network.num_addresses <= 1024:  # Arbitrary limit
                    for ip in network:
                        result.add(str(ip))
                else:
                    result.add(ip_or_network)
                return
                
            # Check if it's an IP range
            if '-' in ip_or_network:
                start, end = ip_or_network.split('-')
                start_ip = ipaddress.ip_address(start.strip())
                end_ip = ipaddress.ip_address(end.strip())
                
                ip_count = int(end_ip) - int(start_ip) + 1
                if ip_count <= 1024:  # Arbitrary limit
                    current = start_ip
                    while current <= end_ip:
                        result.add(str(current))
                        current += 1
                else:
                    result.add(ip_or_network)
                return
                
            # Try as a single IP
            ipaddress.ip_address(ip_or_network)
            result.add(ip_or_network)
            
        except Exception:
            # Not a valid IP format, just ignore
            pass

    def get_address_objects_containing_ip(self, ip: str) -> List[str]:
        """
        Find all address objects that contain the given IP.
        
        Args:
            ip: The IP address to look for
            
        Returns:
            List of address object names containing this IP
        """
        if not self.loaded or not ip or ip in ('nan', 'None', ''):
            return []
            
        matching_objects = []
        
        for name, addr_obj in self.addresses.items():
            if self._ip_matches_address_object(ip, addr_obj):
                matching_objects.append(name)
                
        return matching_objects

    def get_address_groups_containing_ip(self, ip: str) -> List[str]:
        """
        Find all address groups that contain the given IP.
        
        Args:
            ip: The IP address to look for
            
        Returns:
            List of address group names containing this IP
        """
        if not self.loaded or not ip or ip in ('nan', 'None', ''):
            return []
            
        matching_groups = []
        
        for group_name in self.address_groups:
            if self.ip_matches_address(ip, group_name):
                matching_groups.append(group_name)
                
        return matching_groups

    def get_address_groups_containing_object(self, object_name: str) -> List[str]:
        """
        Find all address groups that directly contain the given object.
        
        Args:
            object_name: The address object or group name to look for
            
        Returns:
            List of address group names containing this object
        """
        if not self.loaded:
            return []
            
        matching_groups = []
        
        for group_name, members in self.address_groups.items():
            if object_name in members:
                matching_groups.append(group_name)
                
        return matching_groups

    def is_address_group(self, name: str) -> bool:
        """
        Check if a name refers to an address group.
        
        Args:
            name: The name to check
            
        Returns:
            True if it's an address group, False otherwise
        """
        return name in self.address_groups

    def is_address_object(self, name: str) -> bool:
        """
        Check if a name refers to an address object.
        
        Args:
            name: The name to check
            
        Returns:
            True if it's an address object, False otherwise
        """
        return name in self.addresses

    def get_address_type(self, name: str) -> Optional[str]:
        """
        Get the type of an address object.
        
        Args:
            name: The address object name
            
        Returns:
            The address type, or None if not found
        """
        if name in self.addresses:
            return self.addresses[name].get("type")
        return None
