import subprocess
import json
import argparse
import requests
from Wappalyzer import Wappalyzer, WebPage
import shodan
from concurrent.futures import ThreadPoolExecutor
import csv
import dns.resolver
import os

def run_amass(domain):
    """Run Amass to enumerate subdomains."""
    print(f"[+] Running Amass on {domain}")
    command = f"amass enum -d {domain} -json amass_results.json"
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Amass failed: {e}")
        return set()
    
    # Load results from Amass
    try:
        with open("amass_results.json", "r") as f:
            results = [json.loads(line) for line in f]
        subdomains = set(result['name'] for result in results)
    except FileNotFoundError:
        print("[-] Amass results file not found.")
        return set()
    
    return subdomains

def run_sublist3r(domain):
    """Run Sublist3r to enumerate subdomains."""
    print(f"[+] Running Sublist3r on {domain}")
    command = f"sublist3r -d {domain} -o sublist3r_results.txt"
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Sublist3r failed: {e}")
        return set()
    
    # Load results from Sublist3r
    try:
        with open("sublist3r_results.txt", "r") as f:
            subdomains = set(line.strip() for line in f)
    except FileNotFoundError:
        print("[-] Sublist3r results file not found.")
        return set()
    
    return subdomains

def get_subdomains(domain):
    """Combine results from Amass and Sublist3r."""
    amass_subdomains = run_amass(domain)
    sublist3r_subdomains = run_sublist3r(domain)
    all_subdomains = amass_subdomains.union(sublist3r_subdomains)
    return all_subdomains

def run_masscan(subdomains, ports="1-1000"):
    """Run Masscan to scan for open ports."""
    print(f"[+] Running Masscan on {len(subdomains)} subdomains")
    open_ports = {}
    
    for subdomain in subdomains:
        command = f"masscan {subdomain} -p{ports} --rate 1000 -oJ masscan_results.json"
        try:
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[-] Masscan failed for {subdomain}: {e}")
            continue
        
        # Load results from Masscan
        try:
            with open("masscan_results.json", "r") as f:
                results = json.load(f)
            open_ports[subdomain] = [result['ports'][0]['port'] for result in results]
        except FileNotFoundError:
            print(f"[-] Masscan results file not found for {subdomain}.")
            continue
    
    return open_ports

def run_ffuf(subdomain, wordlist="common.txt"):
    """Run FFuf to discover directories."""
    print(f"[+] Running FFuf on {subdomain}")
    command = f"ffuf -w {wordlist} -u http://{subdomain}/FUZZ -o ffuf_results.json -of json"
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] FFuf failed for {subdomain}: {e}")
        return []
    
    # Load results from FFuf
    try:
        with open("ffuf_results.json", "r") as f:
            results = json.load(f)
        discovered_dirs = [result['url'] for result in results['results']]
    except FileNotFoundError:
        print(f"[-] FFuf results file not found for {subdomain}.")
        return []
    
    return discovered_dirs

def subdomain_takeover_scan(subdomains):
    """Check for subdomain takeover vulnerabilities."""
    print(f"[+] Checking for subdomain takeovers")
    with open("subdomains.txt", "w") as f:
        f.write("\n".join(subdomains))
    
    command = "subjack -w subdomains.txt -t 100 -timeout 30 -o subjack_results.txt"
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Subjack failed: {e}")
        return ""
    
    try:
        with open("subjack_results.txt", "r") as f:
            results = f.read()
    except FileNotFoundError:
        print("[-] Subjack results file not found.")
        return ""
    
    return results

def dns_enumeration(domain):
    """Perform DNS enumeration for a domain."""
    print(f"[+] Performing DNS enumeration for {domain}")
    records = {}
    
    # Common record types to check
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
    
    return records

def cloud_asset_discovery(domain):
    """Discover cloud assets (e.g., AWS S3 buckets)."""
    print(f"[+] Discovering cloud assets for {domain}")
    command = f"python3 cloud_enum.py -k {domain} -l cloud_enum_results.txt"
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Cloud_enum failed: {e}")
        return ""
    
    try:
        with open("cloud_enum_results.txt", "r") as f:
            results = f.read()
    except FileNotFoundError:
        print("[-] Cloud_enum results file not found.")
        return ""
    
    return results

def nuclei_scan(domain):
    """Run Nuclei to scan for vulnerabilities."""
    print(f"[+] Running Nuclei on {domain}")
    command = f"nuclei -u {domain} -o nuclei_results.txt"
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Nuclei failed: {e}")
        return ""
    
    try:
        with open("nuclei_results.txt", "r") as f:
            results = f.read()
    except FileNotFoundError:
        print("[-] Nuclei results file not found.")
        return ""
    
    return results

def fetch_wayback_urls(domain):
    """Fetch historical URLs from Wayback Machine."""
    print(f"[+] Fetching Wayback Machine data for {domain}")
    wayback_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        response = requests.get(wayback_url)
        if response.status_code == 200:
            urls = response.json()
            return [url[0] for url in urls[1:]]  # Skip the header row
        else:
            print(f"[-] Failed to fetch Wayback data for {domain}")
            return []
    except requests.RequestException as e:
        print(f"[-] Wayback Machine request failed: {e}")
        return []

def javascript_analysis(url):
    """Analyze JavaScript files for endpoints and secrets."""
    print(f"[+] Analyzing JavaScript files for {url}")
    command = f"python3 LinkFinder.py -i {url} -o js_results.txt"
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] LinkFinder failed: {e}")
        return ""
    
    try:
        with open("js_results.txt", "r") as f:
            results = f.read()
    except FileNotFoundError:
        print("[-] LinkFinder results file not found.")
        return ""
    
    return results

def fingerprint_tech(url):
    """Identify technologies used by the target."""
    print(f"[+] Fingerprinting technologies for {url}")
    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url)
        technologies = wappalyzer.analyze(webpage)
        return technologies
    except Exception as e:
        print(f"[-] Technology fingerprinting failed: {e}")
        return {}

def shodan_scan(domain, api_key):
    """Use Shodan to gather information about the target."""
    print(f"[+] Running Shodan scan for {domain}")
    try:
        api = shodan.Shodan(api_key)
        results = api.search(f"hostname:{domain}")
        shodan_data = [{
            'ip': result['ip_str'],
            'port': result['port'],
            'org': result['org'],
            'data': result['data']
        } for result in results['matches']]
        return shodan_data
    except shodan.APIError as e:
        print(f"[-] Shodan API error: {e}")
        return []

def threaded_ffuf(subdomains, wordlist="common.txt"):
    """Run FFuf on multiple subdomains in parallel."""
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(run_ffuf, subdomains, [wordlist]*len(subdomains)))
    return results

def save_results(results, filename="recon_results.json"):
    """Save results to a JSON file."""
    try:
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
        print(f"[+] Results saved to {filename}")
    except IOError as e:
        print(f"[-] Failed to save results: {e}")

def save_results_csv(results, filename="recon_results.csv"):
    """Save results to a CSV file."""
    try:
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Subdomain", "Open Ports", "Discovered URLs", "Technologies"])
            for result in results:
                writer.writerow([
                    result['subdomain'],
                    result['open_ports'],
                    result['discovered_urls'],
                    result['technologies']
                ])
        print(f"[+] Results saved to {filename}")
    except IOError as e:
        print(f"[-] Failed to save CSV results: {e}")

def main(domain, shodan_api_key=None):
    print(f"[+] Starting reconnaissance on {domain}")
    
    # Step 1: Get subdomains
    subdomains = get_subdomains(domain)
    print(f"[+] Found {len(subdomains)} subdomains")
    
    # Step 2: Perform DNS enumeration
    dns_records = dns_enumeration(domain)
    print(f"[+] DNS records: {dns_records}")
    
    # Step 3: Check for subdomain takeovers
    takeover_results = subdomain_takeover_scan(subdomains)
    print(f"[+] Subdomain takeover results: {takeover_results}")
    
    # Step 4: Discover cloud assets
    cloud_assets = cloud_asset_discovery(domain)
    print(f"[+] Cloud assets: {cloud_assets}")
    
    # Step 5: Run Nuclei for vulnerability scanning
    nuclei_results = nuclei_scan(domain)
    print(f"[+] Nuclei results: {nuclei_results}")
    
    # Step 6: Analyze JavaScript files
    js_results = javascript_analysis(f"http://{domain}")
    print(f"[+] JavaScript analysis results: {js_results}")
    
    # Step 7: Scan for open ports
    open_ports = run_masscan(subdomains)
    
    # Step 8: Fuzz for directories
    discovered_urls = threaded_ffuf(subdomains)
    
    # Step 9: Fetch Wayback Machine URLs
    wayback_urls = fetch_wayback_urls(domain)
    
    # Step 10: Fingerprint technologies
    tech_fingerprints = {}
    for subdomain in subdomains:
        tech_fingerprints[subdomain] = fingerprint_tech(f"http://{subdomain}")
    
    # Step 11: Shodan scan (if API key is provided)
    shodan_data = []
    if shodan_api_key:
        shodan_data = shodan_scan(domain, shodan_api_key)
    
    # Step 12: Save results
    results = {
        "domain": domain,
        "subdomains": list(subdomains),
        "dns_records": dns_records,
        "subdomain_takeovers": takeover_results,
        "cloud_assets": cloud_assets,
        "nuclei_results": nuclei_results,
        "js_results": js_results,
        "open_ports": open_ports,
        "discovered_urls": discovered_urls,
        "wayback_urls": wayback_urls,
        "technologies": tech_fingerprints,
        "shodan_data": shodan_data
    }
    save_results(results)
    save_results_csv(results)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reconnaissance Automation Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("--shodan-api-key", help="Shodan API key")
    args = parser.parse_args()
    
    main(args.domain, args.shodan_api_key)