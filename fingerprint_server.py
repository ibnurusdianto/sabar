import requests
import re
import nmap
import sys
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import phonenumbers

def fingerprint_server(url):
    """
    Melakukan fingerprinting server web untuk mengumpulkan informasi.

    Args:
        url: URL situs web target.
    """

    print(f"\nMemulai fingerprinting server: {url}")

    try:
        # 1. Mengirimkan permintaan HTTP GET
        response = requests.get(url)

        # 2. Mendapatkan informasi dari header HTTP
        server_header = response.headers.get("Server", "Tidak diketahui")
        x_powered_by_header = response.headers.get("X-Powered-By", "Tidak diketahui")

        print("\033[92mInformasi dari Header HTTP:\033[0m")
        print(f"  - Server: {server_header}")
        print(f"  - X-Powered-By: {x_powered_by_header}")

        # 3. Mendeteksi teknologi menggunakan nmap
        nm = nmap.PortScanner()
        nm.scan(urlparse(url).hostname, arguments="-sV -p 80,443")  # Pindai port 80 dan 443
        if urlparse(url).hostname in nm.all_hosts():
            print("\n\033[92mInformasi dari Nmap:\033[0m")
            for port in nm[urlparse(url).hostname].all_protocols():
                if nm[urlparse(url).hostname][port]["state"] == "open":
                    product = nm[urlparse(url).hostname][port]["product"]
                    version = nm[urlparse(url).hostname][port]["version"]
                    print(f"  - Port {port}: {product} {version}")

        # 4. Mendeteksi CMS dan teknologi lain dari HTML
        soup = BeautifulSoup(response.content, "html.parser")

        # Deteksi CMS
        cms_signatures = {
            "WordPress": ["wp-content", "wp-includes"],
            "Joomla": ["/media/system/js/caption.js"],
            "Drupal": ["/core/misc/drupal.js"],
        }

        for cms, signatures in cms_signatures.items():
            if any(signature in str(soup) for signature in signatures):
                print(f"\033[92mCMS terdeteksi:\033[0m {cms}")

        # Deteksi library JavaScript
        js_libraries = ["jquery", "bootstrap", "react", "vue", "angular"]
        for library in js_libraries:
            if library in str(soup):
                print(f"\033[92mLibrary JavaScript terdeteksi:\033[0m {library}")

        # Deteksi email
        emails = re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", response.text, re.I)
        if emails:
            print("\033[92mEmail yang ditemukan:\033[0m")
            for email in emails:
                print(f"  - {email}")

        # Deteksi nomor telepon
        phone_numbers = []
        for match in phonenumbers.PhoneNumberMatcher(response.text, "ID"): # Mencari nomor telepon dengan kode negara Indonesia
            phone_numbers.append(phonenumbers.format_number(match.number, phonenumbers.PhoneNumberFormat.E164))
        if phone_numbers:
            print("\033[92mNomor telepon yang ditemukan:\033[0m")
            for phone_number in phone_numbers:
                print(f"  - {phone_number}")

    except requests.exceptions.RequestException as e:
        print(f"\033[91mKesalahan: {e}\033[0m")

def main():
    if len(sys.argv) != 2:
        print("Penggunaan: python3 fingerprint_server.py <url>")
        return

    url = sys.argv[1]
    fingerprint_server(url)

if __name__ == "__main__":
    main()
