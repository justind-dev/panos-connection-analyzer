""" 
main.py
-------
Entry point for PAN-OS Connection Analyzer.
Supports both command-line and interactive modes.
Includes persistent DNS cache and optimized hostname filtering.
"""

import argparse
import os
from analyzer import PANOSAnalyzer
from dns_resolver import DNSResolver
from reporter import Reporter

# Import conditionally to handle missing dependencies
try:
    from nat_matcher import NATMatcher
    has_nat_matcher = True
except ImportError:
    has_nat_matcher = False

try:
    from address_manager import AddressManager
    has_address_manager = True
except ImportError:
    has_address_manager = False


def run_cli(args):
    # Initialize DNS resolver
    resolver = DNSResolver(
        timeout=args.dns_timeout,
        max_workers=args.max_workers,
        enabled=not args.no_dns,
        dns_cache_path="dns.txt"
    )

    # Try hostname resolution first
    ip = args.ip
    if args.hostname and not ip:
        ip = resolver.hostname_to_ip(args.hostname)
        if not ip:
            print(f"⚠ Unable to resolve hostname '{args.hostname}' to IP.")
            return
        print(f"✅ Resolved hostname '{args.hostname}' to IP: {ip}")

    # Set up address manager if available
    addr_manager = None
    if has_address_manager:
        addr_manager = AddressManager()
        addr_loaded = addr_manager.load_address_files(
            address_file="addresses.csv" if os.path.exists("addresses.csv") else None,
            group_file="address_groups.csv" if os.path.exists("address_groups.csv") else None
        )
        if addr_loaded:
            print("✅ Loaded address objects and groups.")
        else:
            print("ℹ No address object files found. NAT address object matching will be limited.")

    # Set up NAT matcher if available
    nat_matcher = None
    if has_nat_matcher:
        nat_matcher = NATMatcher(
            nat_csv_path="nat.csv" if os.path.exists("nat.csv") else None,
            addr_manager=addr_manager
        )
        if nat_matcher.loaded:
            print("✅ Loaded NAT rules for matching.")
        else:
            print("ℹ No NAT rules loaded. NAT rule matching will be disabled.")

    # Initialize analyzer with NAT matcher
    analyzer = PANOSAnalyzer(
        dns=resolver,
        nat_matcher=nat_matcher,
        target_ip=ip,
        target_zone=args.zone,
        target_hostname=args.hostname  # Keep original hostname for reference
    )

    # Process the logs
    df = analyzer.load_logs(args.logs)
    filtered = analyzer.filter_logs(df)
    connections = analyzer.aggregate_connections(filtered)
    Reporter().generate(connections, args.output)


def run_interactive_menu():
    resolver = DNSResolver(dns_cache_path="dns.txt")
    df_cache = None

    # Set up address manager if available
    addr_manager = None
    if has_address_manager:
        addr_manager = AddressManager()
        addr_loaded = addr_manager.load_address_files(
            address_file="addresses.csv" if os.path.exists("addresses.csv") else None,
            group_file="address_groups.csv" if os.path.exists("address_groups.csv") else None
        )
        if addr_loaded:
            print("✅ Loaded address objects and groups.")
        else:
            print("ℹ No address object files found. NAT address object matching will be limited.")

    # Set up NAT matcher if available
    nat_matcher = None
    if has_nat_matcher:
        nat_matcher = NATMatcher(
            nat_csv_path="nat.csv" if os.path.exists("nat.csv") else None,
            addr_manager=addr_manager
        )
        if nat_matcher.loaded:
            print("✅ Loaded NAT rules for matching.")
        else:
            print("ℹ No NAT rules loaded. NAT rule matching will be disabled.")

    while True:
        print("\n=== PAN-OS Connection Analyzer ===")
        print("1. Load log file")
        print("2. Create new report")
        print("0. Exit")

        choice = input("Select an option: ").strip()

        if choice == "1":
            path = input("Enter path to CSV log file: ").strip()
            try:
                # Initialize analyzer without filter criteria yet
                analyzer = PANOSAnalyzer(dns=resolver, nat_matcher=nat_matcher)
                df_cache = analyzer.load_logs(path)
                print(f"✔ Loaded {len(df_cache)} log entries.")
            except Exception as e:
                print(f"❌ Failed to load logs: {e}")

        elif choice == "2":
            if df_cache is None:
                print("⚠ You must load a log file first.")
                continue

            print("\nFilter options:")
            print("  1 = IP address")
            print("  2 = Hostname")
            print("  3 = Zone")
            print("  4 = No filter (analyze all)")
            mode = input("Choose filter type: ").strip()

            ip = zone = hostname = None

            if mode == "1":
                ip = input("Enter IP address: ").strip()
            elif mode == "2":
                hostname = input("Enter hostname: ").strip()
                ip = resolver.hostname_to_ip(hostname)
                if not ip:
                    print(f"⚠ Unable to resolve hostname '{hostname}' to IP.")
                    continue
                print(f"✅ Resolved hostname '{hostname}' to IP: {ip}")
            elif mode == "3":
                zone = input("Enter zone name: ").strip()
            elif mode == "4":
                pass
            else:
                print("Invalid selection.")
                continue

            output = input("Enter output filename (e.g., report.xlsx): ").strip()
            if not output:
                print("❌ Output file name required.")
                continue

            # Initialize analyzer with filter criteria
            analyzer = PANOSAnalyzer(
                dns=resolver, 
                nat_matcher=nat_matcher,
                target_ip=ip, 
                target_zone=zone, 
                target_hostname=hostname
            )
            
            try:
                filtered = analyzer.filter_logs(df_cache)
                connections = analyzer.aggregate_connections(filtered)
                Reporter().generate(connections, output)
                print(f"\n✅ Report written to: {output}")
                print(f"🔹 {len(connections)} unique connections\n")
            except Exception as e:
                print(f"❌ Failed to create report: {e}")
                import traceback
                traceback.print_exc()  # Print the full traceback for debugging

        elif choice == "0":
            print("Goodbye.")
            break

        else:
            print("Invalid choice. Try again.")


def parse_args():
    parser = argparse.ArgumentParser(description="PAN-OS Connection Analyzer")
    parser.add_argument("--logs", help="Path to CSV log file")
    parser.add_argument("--ip", help="Filter by IP address")
    parser.add_argument("--zone", help="Filter by zone")
    parser.add_argument("--hostname", help="Filter by hostname")
    parser.add_argument("--output", default="connection_report.xlsx", help="Output file path")
    parser.add_argument("--no-dns", action="store_true", help="Disable DNS resolution")
    parser.add_argument("--dns-timeout", type=float, default=2.0, help="DNS timeout in seconds")
    parser.add_argument("--max-workers", type=int, default=50, help="Max parallel DNS workers")
    parser.add_argument("--interactive", action="store_true", help="Launch interactive menu")
    parser.add_argument("--nat-file", help="Path to NAT rules CSV file (default: nat.csv)")
    parser.add_argument("--address-file", help="Path to address objects CSV file (default: addresses.csv)")
    parser.add_argument("--address-group-file", help="Path to address group CSV file (default: address_groups.csv)")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.interactive or not args.logs:
        run_interactive_menu()
    else:
        run_cli(args)


if __name__ == "__main__":
    main()
