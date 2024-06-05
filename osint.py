import requests
from bs4 import BeautifulSoup
import re
import argparse
from datetime import datetime
import sys

def osint_investigation(query, query_type):
    print(f"\nMemulai investigasi OSINT untuk {query_type}: {query}")
    if query_type == "nama":
        sites = {
            "Facebook": f"https://www.facebook.com/public/{query}",
            "LinkedIn": f"https://www.linkedin.com/search/results/people/?keywords={query}",
            "Instagram": f"https://www.instagram.com/{query}",
            "GitHub": f"https://github.com/search?q={query}",
            "Shodan": f"https://www.shodan.io/search?query={query}",  
            "HaveIBeenPwned": f"https://haveibeenpwned.com/search?query={query}",  
            "pipl": f"https://pipl.com/search/?q={query}",  
            "PeekYou": f"https://www.peekyou.com/{query}",  
            "Google Scholar": f"https://scholar.google.com/scholar?q={query}",  
        }
        for site, url in sites.items():
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    print(f"\033[92mHasil {site}:\033[0m Profil/Informasi ditemukan - {url}")
                else:
                    print(f"\033[93mHasil {site}:\033[0m Tidak ada profil/informasi yang ditemukan atau akses terbatas.")
            except requests.exceptions.RequestException as e:
                print(f"\033[91mKesalahan {site}: {e}\033[0m")

    elif query_type == "tanggal_lahir":
    
        sites = {
            "FamilySearch": f"https://www.familysearch.org/search/record/results?count=20&query=%2Bbirth_place%3A*%20%2Bbirth_year%3A{query[-4:]}",  # Mencari berdasarkan tahun lahir
            "MyHeritage": f"https://www.myheritage.com/research?action=query&formId=master&formMode=1&qname={query}",
        }

        for site, url in sites.items():
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    print(f"\033[92mHasil {site}:\033[0m Hasil ditemukan - {url}")
                else:
                    print(f"\033[93mHasil {site}:\033[0m Tidak ada hasil yang ditemukan atau akses terbatas.")
            except requests.exceptions.RequestException as e:
                print(f"\033[91mKesalahan {site}: {e}\033[0m")

def main():
    parser = argparse.ArgumentParser(description="Alat Investigasi OSINT")
    parser.add_argument("-n", "--nama", help="Nama lengkap target (contoh: John Doe)")
    parser.add_argument("-t", "--tanggal_lahir", help="Tanggal lahir target (contoh: 01-01-1990)")
    args = parser.parse_args()

    if args.nama:
        osint_investigation(args.nama, "nama")
    elif args.tanggal_lahir:
        osint_investigation(args.tanggal_lahir, "tanggal_lahir")
    else:
        print("Penggunaan: python3 osint_investigation.py [-n <nama>] [-t <tanggal_lahir>]")

if __name__ == "__main__":
    main()
