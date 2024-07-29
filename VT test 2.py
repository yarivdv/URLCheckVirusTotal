import requests
import base64
import time

# Replace 'YOUR_API_KEY' with your actual VirusTotal API key
API_KEY = 'apiKey'
BASE_URL = 'https://www.virustotal.com/api/v3'

def encode_url(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return url_id

def analyze_url(url):
    analyze_url_endpoint = f"{BASE_URL}/urls"
    headers = {
        'x-apikey': API_KEY
    }
    data = {
        'url': url
    }

    response = requests.post(analyze_url_endpoint, headers=headers, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}")
        print(response.json())
        return None

def get_analysis_report(url_id):
    get_url_report_endpoint = f"{BASE_URL}/urls/{url_id}"
    headers = {
        'x-apikey': API_KEY
    }

    response = requests.get(get_url_report_endpoint, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}")
        print(response.json())
        return None

def extract_malicious_and_suspicious_vendors(report):
    flagged_vendors = {}
    if 'data' in report and 'attributes' in report['data']:
        last_analysis_results = report['data']['attributes'].get('last_analysis_results', {})
        for vendor, result in last_analysis_results.items():
            if result.get('category') in ['malicious', 'suspicious']:
                flagged_vendors[vendor] = result
    return flagged_vendors

def main(url):
    print("Analyzing URL...")
    analysis_response = analyze_url(url)
    
    if analysis_response:
        url_id = encode_url(url)
        print(f"URL ID: {url_id}")
        
        # Wait for a few seconds to allow the analysis to complete
        time.sleep(20)
        
        print("Getting analysis report...")
        report = get_analysis_report(url_id)
        if report:
            flagged_vendors = extract_malicious_and_suspicious_vendors(report)
            print("Flagged Vendors (malicious and suspicious only):")
            for vendor, result in flagged_vendors.items():
                print(f"{vendor}: {result['result']} ({result['category']})")

if __name__ == "__main__":
    url = input("Enter the URL to analyze: ")
    main(url)