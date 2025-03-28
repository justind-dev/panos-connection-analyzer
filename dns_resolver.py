""" 
dns_resolver.py
---------------
Provides parallel DNS resolution with caching and optional file persistence.
Supports both forward (hostname→IP) and reverse (IP→hostname) lookups.

Usage:
    resolver = DNSResolver(timeout=2.0, max_workers=50, enabled=True, dns_cache_path="dns.txt")
    
    # Forward lookup (hostname → IP)
    ip = resolver.hostname_to_ip("server.example.com")
    
    # Reverse lookup (IP → hostname)
    hostnames = resolver.resolve_ips(set_of_ips)

Notes:
- All failed lookups return "NotFound"
- If disabled, returns "DNS-disabled"
- Cached results are stored in dns.txt between runs
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Set, Optional


class DNSResolver:
    def __init__(self, timeout=2.0, max_workers=50, enabled=True, dns_cache_path: Optional[str] = None):
        self.timeout = timeout
        self.max_workers = max_workers
        self.enabled = enabled
        self.dns_cache_path = dns_cache_path
        
        # Separate caches for forward and reverse lookups
        self.reverse_cache: Dict[str, str] = {}  # IP → hostname
        self.forward_cache: Dict[str, str] = {}  # hostname → IP

        if self.dns_cache_path:
            self._load_cache_from_file()

    def _load_cache_from_file(self):
        """Load cached DNS results from file."""
        try:
            with open(self.dns_cache_path, 'r') as f:
                for line in f:
                    parts = line.strip().split(maxsplit=1)
                    if len(parts) == 2:
                        ip, hostname = parts
                        self.reverse_cache[ip] = hostname
                        # Also populate the forward cache when possible
                        if hostname != "NotFound" and hostname != "DNS-disabled":
                            self.forward_cache[hostname.lower()] = ip
        except FileNotFoundError:
            pass  # No cache yet

    def _save_cache_to_file(self):
        """Save the reverse DNS cache to file."""
        if not self.dns_cache_path:
            return
        try:
            with open(self.dns_cache_path, 'w') as f:
                for ip, hostname in self.reverse_cache.items():
                    f.write(f"{ip} {hostname}\n")
        except Exception:
            pass  # Don't crash on save errors

    def hostname_to_ip(self, hostname: str) -> Optional[str]:
        """
        Resolve a hostname to an IP address (forward DNS lookup).

        Args:
            hostname: The hostname to resolve

        Returns:
            The IP address as string, or None if resolution fails
        """
        if not self.enabled:
            return "DNS-disabled"

        if not hostname:
            return None

        # Check if we already have this in our forward cache
        hostname_lower = hostname.lower()
        if hostname_lower in self.forward_cache:
            return self.forward_cache[hostname_lower]

        # First, check if it's already an IP address
        try:
            socket.inet_aton(hostname)  # IPv4 check
            return hostname  # It's already an IP
        except socket.error:
            pass  # Not an IP, continue with hostname resolution

        # Perform forward lookup
        original_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.timeout)

        try:
            ip = socket.gethostbyname(hostname)

            # Validate we got a valid IP format
            try:
                socket.inet_aton(ip)  # Verify it's a valid IPv4 format
                # Cache the result both ways
                self.forward_cache[hostname_lower] = ip
                self.reverse_cache[ip] = hostname
                return ip
            except socket.error:
                # If we didn't get a valid IP format, return None
                return None
        except socket.gaierror:
            return None
        finally:
            socket.setdefaulttimeout(original_timeout)
            self._save_cache_to_file()

    def ip_to_hostname(self, ip: str) -> str:
        """
        Resolve an IP address to a hostname (reverse DNS lookup).
        
        Args:
            ip: The IP address to resolve
            
        Returns:
            The hostname as string, or "NotFound"/"DNS-disabled" on failure
        """
        if not self.enabled:
            return "DNS-disabled"

        if not ip or ip in ("any", ""):
            return "NotFound"

        if ip in self.reverse_cache:
            return self.reverse_cache[ip]

        original_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.timeout)

        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            self.reverse_cache[ip] = hostname
            self.forward_cache[hostname.lower()] = ip
            return hostname
        except Exception:
            self.reverse_cache[ip] = "NotFound"
            return "NotFound"
        finally:
            socket.setdefaulttimeout(original_timeout)
            self._save_cache_to_file()
    
    def resolve_ips(self, ips: Set[str]) -> Dict[str, str]:
        """
        Resolve multiple IP addresses to hostnames in parallel.
        
        Args:
            ips: Set of IP addresses to resolve
            
        Returns:
            Dictionary mapping each IP to its hostname or "NotFound"/"DNS-disabled"
        """
        if not self.enabled:
            return {ip: "DNS-disabled" for ip in ips}

        unresolved = [ip for ip in ips if ip not in self.reverse_cache and ip not in ("", "any")]
        results = {}

        if not unresolved:
            return {ip: self.reverse_cache[ip] for ip in ips if ip in self.reverse_cache}

        def worker(ip):
            return ip, self.ip_to_hostname(ip)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(worker, ip): ip for ip in unresolved}
            for future in as_completed(futures):
                ip, hostname = future.result()
                results[ip] = hostname
                self.reverse_cache[ip] = hostname

        self._save_cache_to_file()

        return {ip: self.reverse_cache.get(ip, "NotFound") for ip in ips}
