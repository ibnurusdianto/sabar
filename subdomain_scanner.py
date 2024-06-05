import requests
import re
import dns.resolver
import socket
import concurrent.futures
import sys
from urllib.parse import urlparse
from collections import Counter

def find_subdomains_with_dns_zone_transfer(domain):
    subdomains = []
    try:
        answers = dns.resolver.resolve(domain, "NS")
        for server in answers:
            try:
                zone_transfer = dns.zone.from_xfr(dns.query.xfr(str(server), domain))
                for name, node in zone_transfer.nodes.items():
                    for rdataset in node.rdatasets:
                        if rdataset.rdtype == dns.rdatatype.A:
                            subdomain = str(name) + "." + domain
                            subdomains.append((subdomain, "Zone Transfer"))
                            print(f"\033[92mSubdomain ditemukan (Zone Transfer):\033[0m {subdomain}")
            except (dns.exception.FormError, dns.exception.Timeout, dns.resolver.NoNameservers):
                pass  # Lewati jika zone transfer gagal atau tidak diizinkan
    except dns.resolver.NoAnswer:
        print(f"\033[93mTidak ada jawaban untuk query NS pada domain {domain}\033[0m")
    except dns.resolver.NXDOMAIN:
        print(f"\033[91mDomain tidak ditemukan: {domain}\033[0m")
    return subdomains

def find_subdomains_with_search_engines(domain):
    subdomains = []
    search_engines = [
        "https://www.google.com/search?q=site:{}",
        "https://bing.com/search?q=site:{}",
        "https://duckduckgo.com/?q=site:{}",
    ]

    for engine in search_engines:
        url = engine.format(domain)
        try:
            response = requests.get(url)
            if response.status_code == 200:
                subdomains += [(subdomain, "Search Engine") for subdomain in re.findall(r"https?://([a-z0-9-]+\." + domain + ")", response.text)]
        except requests.exceptions.RequestException:
            pass 

    return list(set(subdomains))  # Hapus duplikat

def find_subdomains_with_certificate_transparency(domain):
    subdomains = []
    url = f"https://crt.sh/?q={domain}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            subdomains += [(subdomain, "Certificate Transparency") for subdomain in re.findall(r"<TD>([a-z0-9-]+\." + domain + ")</TD>", response.text)]
    except requests.exceptions.RequestException:
        pass 

    return list(set(subdomains)) 

def enumerate_subdomains(domain):
    """Melakukan enumerasi subdomain menggunakan berbagai teknik."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = [
            executor.submit(find_subdomains_with_dns_zone_transfer, domain),
            executor.submit(find_subdomains_with_search_engines, domain),
            executor.submit(find_subdomains_with_certificate_transparency, domain)
        ]

        subdomains = []
        for future in concurrent.futures.as_completed(futures):
            subdomains.extend(future.result())
        return subdomains

def main():
    if len(sys.argv) != 2:
        print("Penggunaan: python3 subdomain_scanner.py <domain>")
        return

    domain = sys.argv[1]
    print("Memulai pemindaian subdomain...")

    subdomains = enumerate_subdomains(domain)

    if subdomains:
        print("\nDaftar Subdomain yang Ditemukan:")
        for subdomain, method in subdomains:
            print(f"  - {subdomain} (melalui {method})")
    else:
        print("\nTidak ada subdomain yang ditemukan.")

if __name__ == "__main__":
    main()
