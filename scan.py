import kamene.all as kamene
from kamene.all import TCP, IP, sr1

import concurrent.futures
import requests
import nmap
import socket
import kamene.all as kamene
from bs4 import BeautifulSoup
import json
import time
import re
import subprocess
import shodan
import urllib3
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from kamene.all import *
from colorama import Fore, Style, init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

class UltimateAdvancedWebScanner:
    def __init__(self, target, threads=20):
        self.target = target
        self.threads = threads

    def advanced_port_scan(self):
        try:
            scanner = nmap.PortScanner()
            scanner.scan(self.target, arguments='-sV -sC -O -T4')
            scan_results = scanner[self.target]
            return scan_results
        except Exception as e:
            return f"Error in advanced port scanning: {e}"

    def subdomain_enumeration(self):
        subdomains = set()
        try:
            sources = [
                f"https://api.hackertarget.com/hostsearch/?q={self.target}",
                f"https://crt.sh/?q=%25.{self.target}&output=json",
                f"https://api.threatminer.org/v2/domain.php?q={self.target}&rt=5"
            ]
            for source in sources:
                response = requests.get(source)
                if response.status_code == 200:
                    if 'crt.sh' in source:
                        crt_data = json.loads(response.text)
                        subdomains.update([entry['name_value'] for entry in crt_data])
                    else:
                        subdomains.update([line.split(',')[0] for line in response.text.splitlines() if ',' in line])
            return list(subdomains)
        except Exception as e:
            return f"Error in subdomain enumeration: {e}"

    def advanced_content_discovery(self):
        try:
            wordlist = "/usr/share/wordlists/dirb/big.txt"
            discovered_paths = []
            if not os.path.exists(wordlist):
                return "Wordlist file does not exist."
            with open(wordlist, "r") as file:
                for line in file:
                    path = line.strip()
                    url = f"{self.target}/{path}"
                    response = requests.get(url, verify=False)
                    if response.status_code == 200:
                        discovered_paths.append(url)
            return discovered_paths
        except Exception as e:
            return f"Error in content discovery: {e}"

    def security_headers_analysis(self):
        try:
            response = requests.get(self.target, verify=False)
            security_headers = {
                "Content-Security-Policy": response.headers.get("Content-Security-Policy", "Missing"),
                "Strict-Transport-Security": response.headers.get("Strict-Transport-Security", "Missing"),
                "X-Content-Type-Options": response.headers.get("X-Content-Type-Options", "Missing"),
                "X-Frame-Options": response.headers.get("X-Frame-Options", "Missing"),
                "X-XSS-Protection": response.headers.get("X-XSS-Protection", "Missing"),
                "Referrer-Policy": response.headers.get("Referrer-Policy", "Missing"),
                "Permissions-Policy": response.headers.get("Permissions-Policy", "Missing")
            }
            return security_headers
        except Exception as e:
            return f"Error in security headers analysis: {e}"

    def cms_detection(self):
        try:
            response = requests.get(self.target, verify=False)
            cms_patterns = {
                "WordPress": re.compile(r'wp-content|wp-includes'),
                "Joomla": re.compile(r'Joomla!'),
                "Drupal": re.compile(r'Drupal'),
                "Magento": re.compile(r'Magento'),
                "Shopify": re.compile(r'Shopify'),
                "Wix": re.compile(r'Wix')
            }
            detected_cms = []
            for cms, pattern in cms_patterns.items():
                if pattern.search(response.text):
                    detected_cms.append(cms)
            return detected_cms if detected_cms else "No CMS detected."
        except Exception as e:
            return f"Error in CMS detection: {e}"

    def advanced_xss_testing(self):
        payloads = [
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "<body onload=alert(1)>", "<svg/onload=alert(1)>"
        ]
        vulnerable = False
        try:
            for payload in payloads:
                response = requests.get(self.target, params={"q": payload}, verify=False)
                if payload in response.text:
                    vulnerable = True
                    break
            return "Potential XSS Vulnerability found!" if vulnerable else "No XSS Vulnerability detected."
        except Exception as e:
            return f"Error in XSS testing: {e}"

    def command_injection_testing(self):
        payloads = ["; ls", "&& ls", "| ls"]
        vulnerable = False
        try:
            for payload in payloads:
                response = requests.get(self.target, params={"cmd": payload}, verify=False)
                if "bin" in response.text or "root" in response.text:
                    vulnerable = True
                    break
            return "Potential Command Injection Vulnerability found!" if vulnerable else "No Command Injection Vulnerability detected."
        except Exception as e:
            return f"Error in Command Injection testing: {e}"

    def misconfiguration_detection(self):
        try:
            headers = {
                'Server': 'Server header not present',
                'X-Powered-By': 'X-Powered-By header not present'
            }
            response = requests.get(self.target, verify=False)
            headers.update({k: v for k, v in response.headers.items() if k in headers})
            return headers
        except Exception as e:
            return f"Error in misconfiguration detection: {e}"

    def exploit_check(self):
        try:
            domain = self.target.replace('http://', '').replace('https://', '').split('/')[0]
            command = f"searchsploit --json {domain}"
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            exploits = json.loads(result.stdout.decode('utf-8'))
            return exploits
        except Exception as e:
            return f"Error in exploit check: {e}"

    def shodan_integration(self):
        try:
            api_key = "your_shodan_api_key"
            ip = socket.gethostbyname(self.target)
            api = shodan.Shodan(api_key)
            host = api.host(ip)
            return host
        except shodan.APIError as e:
            return f"Shodan API error: {e}"
        except Exception as e:
            return f"Error in Shodan integration: {e}"

    def anomaly_detection(self):
        try:
            response = requests.get(self.target, verify=False)
            if "Set-Cookie" in response.headers:
                return "Anomaly Detected: Set-Cookie header present."
            return "No anomalies detected."
        except Exception as e:
            return f"Error in anomaly detection: {e}"

    def machine_learning_based_detection(self):
        try:
            response = requests.get(self.target, verify=False)
            text = response.text
            vectorizer = TfidfVectorizer(stop_words='english')
            X = vectorizer.fit_transform([text])
            kmeans = KMeans(n_clusters=2, random_state=0).fit(X)
            clusters = kmeans.labels_.tolist()
            return "Potential Zero-Day Exploit Detected!" if clusters.count(1) > clusters.count(0) else "No Zero-Day Exploit Detected."
        except Exception as e:
            return f"Error in machine learning based detection: {e}"

    def dns_lookup(self):
        try:
            dns_info = socket.gethostbyname_ex(self.target)
            return dns_info
        except socket.gaierror:
            return "DNS lookup failed: Invalid hostname."
        except Exception as e:
            return f"Error in DNS lookup: {e}"

    def whois_lookup(self):
        try:
            command = f"whois {self.target}"
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0:
                return result.stdout.decode('utf-8')
            return "WHOIS lookup failed."
        except Exception as e:
            return f"Error in WHOIS lookup: {e}"

    def ssrf_testing(self):
        payload = f"http://localhost:8080/"
        try:
            response = requests.get(self.target, params={"url": payload}, verify=False)
            if "localhost" in response.text or "127.0.0.1" in response.text:
                return "Potential SSRF Vulnerability found!"
            return "No SSRF Vulnerability detected."
        except Exception as e:
            return f"Error in SSRF testing: {e}"

    def protocol_level_testing(self):
        try:
            pkt = IP(dst=self.target) / TCP(dport=80, flags="S")
            response = sr1(pkt, timeout=2, verbose=False)
            if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 18:
                return "Potential Protocol-Level Vulnerability found!"
            return "No Protocol-Level Vulnerability detected."
        except Exception as e:
            return f"Error in protocol-level testing: {e}"

    def scan_website(self):
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(method): method.__name__ for method in [
                    self.advanced_port_scan, self.subdomain_enumeration, 
                    self.advanced_content_discovery, self.security_headers_analysis, 
                    self.cms_detection, self.advanced_xss_testing, 
                    self.command_injection_testing, self.misconfiguration_detection,
                    self.exploit_check, self.shodan_integration, 
                    self.anomaly_detection, self.machine_learning_based_detection, 
                    self.dns_lookup, self.whois_lookup, 
                    self.ssrf_testing, self.protocol_level_testing
                ]
            }
            for future in concurrent.futures.as_completed(futures):
                method_name = futures[future]
                try:
                    results[method_name] = future.result()
                except Exception as e:
                    results[method_name] = f"Error: {e}"
        return results

def save_results_to_file(results):
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    file_name = f"scan_results_{timestamp}.json"
    with open(file_name, "w") as f:
        json.dump(results, f, indent=4)
    return file_name

def print_colored_results(results):
    def colored_text(text, color):
        return f"{color}{text}{Style.RESET_ALL}"

    for technique, result in results.items():
        if isinstance(result, dict):
            print(colored_text(f"\n{technique} Results:", Fore.CYAN))
            for key, value in result.items():
                print(colored_text(f"{key}: {value}", Fore.YELLOW))
        else:
            print(colored_text(f"\n{technique}:", Fore.CYAN))
            print(colored_text(result, Fore.YELLOW))

def main():
    target_website = input(Fore.GREEN + "Enter the website URL to scan: " + Style.RESET_ALL)
    try:
        scanner = UltimateAdvancedWebScanner(target_website)
        results = scanner.scan_website()

        print(Fore.MAGENTA + "\nScan Results:" + Style.RESET_ALL)
        print_colored_results(results)

        file_name = save_results_to_file(results)
        print(Fore.GREEN + f"\nResults saved to {file_name}" + Style.RESET_ALL)

    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}" + Style.RESET_ALL)

if __name__ == "__main__":
    main()
