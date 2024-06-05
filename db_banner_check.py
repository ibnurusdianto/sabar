import requests
import re
import socket
import nmap

def detect_db_banner(url):
    """
    Melakukan berbagai teknik untuk mendeteksi banner database pada server web.
    """
    print(f"\nMemulai deteksi banner database: {url}")

    try:
        # 1. Pengujian Injeksi SQL Sederhana
        payloads = [
            "'",
            "\"",
            "')",
            "\")",
            ";--",
            "' or '1'='1",
        ]

        for payload in payloads:
            response = requests.get(url + "?id=" + payload)  # Contoh injeksi pada parameter id
            if response.status_code == 500:  # Atau kode error lainnya yang relevan
                error_message = response.text.lower()
                if any(db in error_message for db in ["mysql", "postgresql", "mssql", "oracle"]):
                    print(f"\033[93mKemungkinan banner database terdeteksi (Injeksi SQL):\033[0m {error_message}")
                    return True

        # 2. Pemindaian Port dengan Nmap
        nm = nmap.PortScanner()
        nm.scan(urlparse(url).hostname, arguments="-sV -p 1433,3306,5432,1521")  # Port umum untuk MySQL, MSSQL, PostgreSQL, Oracle

        for proto in nm[urlparse(url).hostname].all_protocols():
            lport = nm[urlparse(url).hostname][proto].keys()
            for port in lport:
                if nm[urlparse(url).hostname][proto][port]['state'] == 'open':
                    service_name = nm[urlparse(url).hostname][proto][port]['name']
                    if service_name in ["ms-sql-s", "mysql", "postgresql", "oracle"]:
                        print(f"\033[93mKemungkinan banner database terdeteksi (Nmap):\033[0m {service_name}")
                        return True

        # 3. Pengujian Koneksi Langsung ke Port Database
        db_ports = {
            "MySQL": 3306,
            "PostgreSQL": 5432,
            "MSSQL": 1433,
            "Oracle": 1521,
        }

        for db, port in db_ports.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    s.connect((urlparse(url).hostname, port))
                    banner = s.recv(1024)
                    if banner:
                        print(f"\033[93mKemungkinan banner database terdeteksi (Koneksi Langsung):\033[0m {banner.decode()}")
                        return True
            except:
                pass

        print("\033[92mTidak ada banner database yang terdeteksi.\033[0m")
        return False

    except requests.exceptions.RequestException as e:
        print(f"\033[91mKesalahan: {e}\033[0m")
        return None

def main():
    if len(sys.argv) != 2:
        print("Penggunaan: python3 db_banner_check.py <url>")
        return

    url = sys.argv[1]
    detect_db_banner(url)

if __name__ == "__main__":
    main()
