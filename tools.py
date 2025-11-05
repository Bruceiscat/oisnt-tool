import requests
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def check_virustotal_ip(ip_address):
    """Check if an IP address is malicious using VirusTotal"""

    api_key = os.getenv("Virus_Api_key")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers)
        data = response.json()

        # Get the malicious score
        stats = data['data']['attributes']['last_analysis_stats']
        malicious = stats['malicious']
        suspicious = stats['suspicious']
        harmless = stats['harmless']

        return f"VirusTotal Results: {malicious} malicious, {suspicious} suspicious, {harmless} harmless"

    except Exception as e:
        return f"Error checking VirusTotal: {str(e)}"


# Test the function
if __name__ == "__main__":
    print("Testing VirusTotal API...")
    print("-" * 50)

    # Test with Google DNS (should be safe)
    result = check_virustotal_ip("8.8.8.8")
    print(result)

    print("-" * 50)
    print("If you see results above, IT WORKS! ")