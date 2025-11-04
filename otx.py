#!/usr/bin/env python

"""
AlienVault OTX CLI Tool - Simplified Version
Query threat intelligence data for IP, Domain, Hostname, or URL
"""

from OTXv2 import OTXv2
import IndicatorTypes
import argparse
import os
import json
import sys
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def format_ip_details(data):
    """Format and display IP address details"""
    print(f"\n{'=' * 60}")
    print(f"IP Address: {data.get('indicator', 'N/A')}")
    print(f"{'=' * 60}")
    
    # General Information
    if 'general' in data:
        general = data['general']
        print(f"\nGeneral Information:")
        print(f"  Reputation: {general.get('reputation', 0)}")
        print(f"  Country: {general.get('country_name', 'Unknown')}")
        print(f"  City: {general.get('city', 'Unknown')}")
        print(f"  ASN: {general.get('asn', 'N/A')}")
        print(f"  Pulse Count: {general.get('pulse_info', {}).get('count', 0)}")
        
        # Show related pulses
        if general.get('pulse_info', {}).get('pulses'):
            print(f"\nRelated Threat Pulses:")
            for pulse in general['pulse_info']['pulses'][:5]:  # Show first 5
                print(f"  • {pulse.get('name', 'Unnamed')}")
                print(f"    Created: {pulse.get('created', 'Unknown')}")
                if pulse.get('tags'):
                    print(f"    Tags: {', '.join(pulse['tags'][:5])}")
    
    # Malware samples
    if 'malware' in data and data['malware'].get('data'):
        print(f"\nAssociated Malware:")
        for malware in data['malware']['data'][:5]:  # Show first 5
            print(f"  • Hash: {malware.get('hash', 'N/A')}")
            print(f"    Date: {malware.get('date', 'Unknown')}")
    
    # URL list
    if 'url_list' in data and data['url_list'].get('url_list'):
        print(f"\nAssociated URLs:")
        for url in data['url_list']['url_list'][:5]:  # Show first 5
            print(f"  • {url.get('url', 'N/A')}")
            print(f"    HTTP Code: {url.get('result', {}).get('urlworker', {}).get('http_code', 'N/A')}")

def format_domain_details(data):
    """Format and display domain/hostname details"""
    print(f"\n{'=' * 60}")
    print(f"Domain/Hostname: {data.get('indicator', 'N/A')}")
    print(f"{'=' * 60}")
    
    # General Information
    if 'general' in data:
        general = data['general']
        print(f"\nGeneral Information:")
        print(f"  Alexa Rank: {general.get('alexa', 'N/A')}")
        print(f"  Pulse Count: {general.get('pulse_info', {}).get('count', 0)}")
        
        # Show related pulses
        if general.get('pulse_info', {}).get('pulses'):
            print(f"\nRelated Threat Pulses:")
            for pulse in general['pulse_info']['pulses'][:5]:
                print(f"  • {pulse.get('name', 'Unnamed')}")
                print(f"    Created: {pulse.get('created', 'Unknown')}")
                if pulse.get('tags'):
                    print(f"    Tags: {', '.join(pulse['tags'][:5])}")
    
    # Passive DNS
    if 'passive_dns' in data and data['passive_dns'].get('passive_dns'):
        print(f"\nPassive DNS Records:")
        for record in data['passive_dns']['passive_dns'][:10]:  # Show first 10
            print(f"  • {record.get('record_type', 'N/A')}: {record.get('address', 'N/A')}")
            print(f"    First: {record.get('first', 'N/A')} | Last: {record.get('last', 'N/A')}")
    
    # Associated malware
    if 'malware' in data and data['malware'].get('data'):
        print(f"\nAssociated Malware:")
        for malware in data['malware']['data'][:5]:
            print(f"  • Hash: {malware.get('hash', 'N/A')}")
            print(f"    Date: {malware.get('date', 'Unknown')}")

def format_url_details(data):
    """Format and display URL details"""
    print(f"\n{'=' * 60}")
    print(f"URL: {data.get('indicator', 'N/A')}")
    print(f"{'=' * 60}")
    
    if 'general' in data:
        general = data['general']
        print(f"\nGeneral Information:")
        print(f"  Alexa Rank: {general.get('alexa', 'N/A')}")
        print(f"  HTTP Code: {general.get('http_code', 'N/A')}")
        print(f"  Pulse Count: {general.get('pulse_info', {}).get('count', 0)}")
        
        if general.get('pulse_info', {}).get('pulses'):
            print(f"\nRelated Threat Pulses:")
            for pulse in general['pulse_info']['pulses'][:5]:
                print(f"  • {pulse.get('name', 'Unnamed')}")
                print(f"    Created: {pulse.get('created', 'Unknown')}")
                if pulse.get('tags'):
                    print(f"    Tags: {', '.join(pulse['tags'][:5])}")

def detect_indicator_type(indicator):
    """Detect the type of indicator based on the input string"""
    import re
    
    # Check for URL (starts with http:// or https://)
    if indicator.startswith('http://') or indicator.startswith('https://'):
        return 'url'
    
    # Check for IPv4 address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, indicator):
        # Validate IP range
        parts = indicator.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            return 'ip'
    
    # Check if it's a domain or hostname
    # If it has a subdomain (www., mail., etc.) treat as hostname
    # Otherwise treat as domain
    if '.' in indicator:
        parts = indicator.split('.')
        if len(parts) > 2 or parts[0] in ['www', 'mail', 'ftp', 'smtp', 'pop', 'imap']:
            return 'hostname'
        else:
            return 'domain'
    
    return None

def main():
    parser = argparse.ArgumentParser(
        description='Query AlienVault OTX for threat intelligence on IP, Domain, Hostname, or URL',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                # Interactive mode - will prompt for indicator
  %(prog)s 8.8.8.8                       # Query IP address
  %(prog)s example.com                   # Query domain
  %(prog)s www.example.com               # Query hostname  
  %(prog)s http://example.com/path       # Query URL
  %(prog)s --raw                         # Get raw JSON output (interactive)
  %(prog)s --save results.json           # Save output to file (interactive)
        """
    )
    
    parser.add_argument('indicator', nargs='?', help='IP address, domain, hostname, or URL to query (optional - will prompt if not provided)')
    parser.add_argument('--raw', help='Output raw JSON instead of formatted text', action='store_true')
    parser.add_argument('--save', help='Save output to file', metavar='FILENAME')
    
    args = parser.parse_args()
    
    # If no indicator provided as argument, prompt the user
    if not args.indicator:
        args.indicator = input("Enter IP address, domain, hostname, or URL to query: ").strip()
        if not args.indicator:
            print("Error: No indicator provided")
            sys.exit(1)
    
    # Get API key
    API_KEY = os.getenv("OTX_API_KEY")
    if not API_KEY:
        print("Error: OTX_API_KEY environment variable not set")
        print("Please set your API key: export OTX_API_KEY='your-key-here'")
        print("Or add it to a .env file in the current directory")
        sys.exit(1)
    
    # Initialize OTX client
    try:
        otx = OTXv2(API_KEY)
    except Exception as e:
        print(f"Error initializing OTX client: {e}")
        sys.exit(1)
    
    # Detect indicator type
    indicator_type = detect_indicator_type(args.indicator)
    
    if not indicator_type:
        print(f"Error: Could not determine the type of indicator: {args.indicator}")
        print("Please provide a valid IP address, domain, hostname, or URL")
        sys.exit(1)
    
    print(f"Detected type: {indicator_type}")
    print(f"Querying: {args.indicator}")
    
    try:
        # Query based on detected type
        if indicator_type == 'ip':
            data = otx.get_indicator_details_full(IndicatorTypes.IPv4, args.indicator)
            if args.raw:
                print(json.dumps(data, indent=2))
            else:
                format_ip_details(data)
        
        elif indicator_type == 'domain':
            data = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, args.indicator)
            if args.raw:
                print(json.dumps(data, indent=2))
            else:
                format_domain_details(data)
        
        elif indicator_type == 'hostname':
            data = otx.get_indicator_details_full(IndicatorTypes.HOSTNAME, args.indicator)
            if args.raw:
                print(json.dumps(data, indent=2))
            else:
                format_domain_details(data)
        
        elif indicator_type == 'url':
            data = otx.get_indicator_details_full(IndicatorTypes.URL, args.indicator)
            if args.raw:
                print(json.dumps(data, indent=2))
            else:
                format_url_details(data)
        
        # Save to file if requested
        if args.save:
            with open(args.save, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"\nOutput saved to: {args.save}")
            
    except Exception as e:
        print(f"Error querying OTX: {e}")
        sys.exit(1)
    
    print(f"\nQuery completed successfully!")

if __name__ == "__main__":
    main()