import requests
import os
from dotenv import load_dotenv
import time

# Load environment variables from .env file
load_dotenv()

vt_api_key = os.getenv("VT_API_KEY")

if not vt_api_key:
    raise ValueError("VT_API_KEY environment variable not set")

def ensure_url_protocol(url):
    """Ensure URL has proper protocol"""
    if not url.startswith(('http://', 'https://')):
        # Default to http:// for unknown protocols
        return f'https://{url}'
    return url

def scan_url(url_to_scan):
    """Submit a URL for scanning and return the analysis ID"""
    endpoint = "https://www.virustotal.com/api/v3/urls"
    
    # Ensure URL has protocol
    url_to_scan = ensure_url_protocol(url_to_scan)
    
    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": api_key
    }
    
    data = {
        "url": url_to_scan
    }
    
    response = requests.post(endpoint, headers=headers, data=data)
    
    if response.status_code == 200:
        result = response.json()
        analysis_id = result['data']['id']
        return analysis_id, url_to_scan  # Return the formatted URL too
    else:
        print(f"Error scanning URL: {response.status_code}")
        print(response.text)
        return None, None

def get_analysis(analysis_id, max_retries=5):
    """Retrieve the analysis results using the analysis ID with retries"""
    endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    for attempt in range(max_retries):
        response = requests.get(endpoint, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            # Check if analysis is complete
            if 'data' in result and 'attributes' in result['data']:
                status = result['data']['attributes'].get('status', '')
                if status == 'completed':
                    return result
                elif status == 'queued' or status == 'in-progress':
                    print(f"Analysis still in progress... waiting (attempt {attempt + 1}/{max_retries})")
                    time.sleep(2)  # Wait 2 seconds before retry
                    continue
            return result
        else:
            print(f"Error getting analysis: {response.status_code}")
            print(response.text)
            return None
    
    print("Analysis taking longer than expected. Returning latest status...")
    return result

def print_scan_summary(analysis_result, url_to_scan):
    """Print a formatted scan summary with vendors by category and tags"""
    if 'data' in analysis_result and 'attributes' in analysis_result['data']:
        attributes = analysis_result['data']['attributes']
        stats = attributes.get('stats', {})
        results = attributes.get('results', {})
        
        # Categorize vendors and collect their details
        malicious_vendors = []
        suspicious_vendors = []
        harmless_vendors = []
        undetected_vendors = []
        all_tags = []
        
        for vendor, result in results.items():
            category = result.get('category', '')
            vendor_result = result.get('result', '')
            
            # Create vendor string with their specific detection if available
            vendor_str = vendor
            if vendor_result and vendor_result != 'clean' and vendor_result != 'unrated':
                vendor_str = f"{vendor} ({vendor_result})"
            
            if category in ['malicious', 'malware', 'phishing']:
                malicious_vendors.append(vendor_str)
            elif category == 'suspicious':
                suspicious_vendors.append(vendor_str)
            elif category == 'harmless' or category == 'clean':
                harmless_vendors.append(vendor)
            elif category == 'undetected' or category == 'unrated':
                undetected_vendors.append(vendor)
                
            # Collect tags from this vendor
            if 'tags' in result and result['tags']:
                all_tags.extend(result['tags'])
        
        # Print summary
        print("\n" + "=" * 80)
        print(f"SCAN SUMMARY FOR: {url_to_scan}")
        print("=" * 80)
        
        # Overall status
        total_vendors = len(results)
        print(f"\n📊 OVERALL: {stats.get('malicious', 0) + stats.get('suspicious', 0)}/{total_vendors} flagged as threat")
        
        # Stats with vendor lists
        print(f"\n📈 DETECTION BREAKDOWN:")
        print(f"{'─' * 60}")
        
        # Malicious
        print(f"\n🔴 MALICIOUS: {stats.get('malicious', 0)}/{total_vendors}")
        if malicious_vendors:
            for i in range(0, len(malicious_vendors), 3):  # Print 3 per line for readability
                batch = malicious_vendors[i:i+3]
                print(f"   {' | '.join(batch)}")
        
        # Suspicious
        print(f"\n🟡 SUSPICIOUS: {stats.get('suspicious', 0)}/{total_vendors}")
        if suspicious_vendors:
            for i in range(0, len(suspicious_vendors), 3):
                batch = suspicious_vendors[i:i+3]
                print(f"   {' | '.join(batch)}")
        
        # Harmless
        print(f"\n🟢 HARMLESS/CLEAN: {stats.get('harmless', 0)}/{total_vendors}")
        if harmless_vendors and len(harmless_vendors) <= 10:  # Only show if not too many
            for i in range(0, len(harmless_vendors), 5):
                batch = harmless_vendors[i:i+5]
                print(f"   {', '.join(batch)}")
        elif harmless_vendors:
            print(f"   {len(harmless_vendors)} vendors marked as clean")
        
        # Undetected
        print(f"\n⚪ UNDETECTED: {stats.get('undetected', 0)}/{total_vendors}")
        if undetected_vendors and len(undetected_vendors) <= 10:
            for i in range(0, len(undetected_vendors), 5):
                batch = undetected_vendors[i:i+5]
                print(f"   {', '.join(batch)}")
        elif undetected_vendors:
            print(f"   {len(undetected_vendors)} vendors with no detection")
        
        # Tags
        print(f"\n🏷️  TAGS/CLASSIFICATIONS:")
        print(f"{'─' * 60}")
        
        # Remove duplicates and sort
        unique_tags = sorted(list(set(all_tags))) if all_tags else []
        
        if unique_tags:
            for tag in unique_tags:
                print(f"   • {tag}")
        else:
            print("   No tags assigned")
        
        # Analysis metadata
        print(f"\n📝 ANALYSIS INFO:")
        print(f"{'─' * 60}")
        print(f"   Analysis ID: {analysis_result['data'].get('id', 'N/A')}")
        print(f"   Status: {attributes.get('status', 'N/A')}")
        
        print("\n" + "=" * 80)

# Main execution
if __name__ == "__main__":
    # URL to scan - can be with or without protocol
    url_to_scan = input("Enter the URL to scan: ").strip()
    
    print(f"Initiating scan for: {url_to_scan}")
    print("Processing...")
    
    # Step 1: Submit URL for scanning
    analysis_id, formatted_url = scan_url(url_to_scan)
    
    if analysis_id:
        print(f"Analysis ID obtained: {analysis_id}")
        print("Waiting for analysis to complete...")
        
        # Initial wait
        time.sleep(3)
        
        # Step 2: Get the analysis results with retries
        analysis_result = get_analysis(analysis_id)
        
        if analysis_result:
            # Print formatted summary
            print_scan_summary(analysis_result, formatted_url)
        else:
            print("Failed to retrieve analysis results")
    else:
        print("Failed to initiate URL scan")