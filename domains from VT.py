import requests

# Replace with your VirusTotal API key
API_KEY = "XX"
BASE_URL = "https://www.virustotal.com/api/v3"

def fetch_passive_dns(ip_address):
    url = f"{BASE_URL}/ip_addresses/{ip_address}"
    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        print(data)
        # Extract passive DNS replication domains
        if "data" in data and "attributes" in data["data"]:
            attributes = data["data"]["attributes"]
            if "last_https_certificate" in attributes and "extensions" in attributes["last_https_certificate"]:
                extensions = attributes["last_https_certificate"]["extensions"]
                if "subject_alternative_name" in extensions:
                    domains = extensions["subject_alternative_name"]
                    print(f"Passive DNS Replication Domains for {ip_address}:")
                    for domain in domains:
                        print(domain)
                else:
                    print("No Passive DNS Replication domains found.")
            else:
                print("No Passive DNS Replication information available.")
        else:
            print("Unexpected response format.")
    else:
        print(f"Error: Unable to fetch data for {ip_address}. Status Code: {response.status_code}")
        print(f"Response: {response.text}")

# Main function
if __name__ == "__main__":
    # api_key = input("Enter your VirusTotal API key: ")
    ip_address = input("Enter the IP address to analyze: ")
    fetch_passive_dns(ip_address)
