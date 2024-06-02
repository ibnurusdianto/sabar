import requests
import dns.resolver
import whois as whois_lib 
import socket
from datetime import datetime
import sys

def check_domain_spoofing(domain):
    print(f"\nMemeriksa domain: {domain}")
    try:
        answers = dns.resolver.resolve(domain, "A")
        ip_addresses = [str(rdata) for rdata in answers]
        print("\033[92mAlamat IP yang terkait:\033[0m", ", ".join(ip_addresses)) 

        if len(ip_addresses) > 1:
            print("\033[93mPeringatan: Domain memiliki beberapa alamat IP, mungkin mengindikasikan spoofing atau load balancing.\033[0m")

    except dns.resolver.NXDOMAIN:
        print("\033[91mKesalahan: Domain tidak ditemukan.\033[0m")
        return

    except dns.resolver.NoAnswer:
        print("\033[93mPeringatan: Domain tidak memiliki record A.\033[0m")

    try:
        whois_info = whois_lib.whois(domain)  # Menggunakan whois_lib
        print("\n\033[92mInformasi WHOIS:\033[0m")

        relevant_fields = ["registrar", "creation_date", "updated_date", "expiration_date", "name_servers"]
        for field in relevant_fields:
            value = getattr(whois_info, field, "Tidak tersedia")
            print(f"  - {field.capitalize()}: {value}")

        if whois_info.updated_date and (datetime.now() - whois_info.updated_date).days < 30:
            print("\033[93mPeringatan: Informasi WHOIS baru saja diperbarui, mungkin mengindikasikan pembajakan.\033[0m")

    except whois_lib.parser.PywhoisError:  
        print("\033[93mPeringatan: Tidak dapat mengambil informasi WHOIS.\033[0m")

    if ip_addresses:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((ip_addresses[0], 80))  # Coba koneksi ke port 80 (HTTP)
                print("\033[92mBerhasil terhubung ke server web.\033[0m")

                # Periksa header server
                response = s.recv(1024)
                server_header = response.decode().split("\r\n")[0]
                print(f"Header Server: {server_header}")
                if "cloudflare" in server_header.lower():
                    print("\033[93mPeringatan: Domain menggunakan Cloudflare, mungkin sulit dideteksi spoofing.\033[0m")
        except (socket.timeout, ConnectionRefusedError):
            print("\033[91mKesalahan: Tidak dapat terhubung ke server web.\033[0m")

def main():
    if len(sys.argv) != 2:
        print("Penggunaan: python3 domain_spoof_check.py <domain>")
        return

    domain = sys.argv[1]
    check_domain_spoofing(domain)

if __name__ == "__main__":
    main()
