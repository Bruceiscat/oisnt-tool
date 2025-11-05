import requests
import os
from dotenv import load_dotenv
load_dotenv()

def check_virustotal_domains(domain):
    """Check if domain address is malicious using VirusTotal"""

    api_key = os.getenv("Virus_Api_key")

    if not api_key:
        return "Error: Virus_Api_key not found in .env file"

    print(f"API Key loaded: {api_key[:10]}..." if len(api_key) > 10 else f"API Key loaded: {api_key}")

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    print(f"URL: {url}")

    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers)
        data = response.json()

        # Debug: Print response status and structure
        print(f"Status Code: {response.status_code}")
        print(f"Response keys: {data.keys()}")

        # Check if there's an error in the response
        if 'error' in data:
            return f"API Error: {data['error']['message']}"

        # Get the malicious score
        stats = data['data']['attributes']['last_analysis_stats']
        malicious = stats['malicious']
        suspicious = stats['suspicious']
        harmless = stats['harmless']

        return f"VirusTotal Results: {malicious} malicious, {suspicious} suspicious, {harmless} harmless"

    except Exception as e:
        return f"Error checking VirusTotal: {str(e)}"

if __name__ == "__main__":
    print("Testing VirusTotal API...")
    print("-" * 50)

    # Test with Google domain (should be safe)
    result = check_virustotal_domains("google.com")
    print(result)

    print("-" * 50)
    print("If you see results above, IT WORKS! ")
