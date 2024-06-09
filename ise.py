import requests
from termcolor import colored
import re
from urllib.parse import quote

def check_internal_server_error(url, payloads=None):
    if not url.startswith("http://") and not url.startswith("https://"):
        print(colored("[!] Error: Masukkan target harus lengkap dengan http:// atau https://", "red"))
        return

    try:
        response = requests.get(url)

        if response.status_code == 500:
            print(colored("[!] Kerentanan Ditemukan: Internal Server Error", "red"))

            # Analisis lebih lanjut
            content = response.text
            if "SQL syntax" in content or "database" in content:
                print(colored("    - Kemungkinan SQL Injection", "yellow"))
                if payloads:
                    for payload in payloads:
                        encoded_payload = quote(payload)
                        try:
                            bypass_response = requests.get(url + encoded_payload)
                            if bypass_response.status_code != 500:
                                print(colored(f"    - Bypass berhasil dengan payload: {payload}", "green"))
                        except requests.exceptions.RequestException:
                            pass
            elif "error" in content or "exception" in content:
                print(colored("    - Kemungkinan error pada kode server", "yellow"))
            elif "stack trace" in content:
                print(colored("    - Terdapat informasi stack trace (perlu analisis lebihlanjut)", "yellow"))
            else:
                print(colored("    - Tidak ada informasi tambahan dalam respons", "yellow"))
        else:
            print(colored("[-] Tidak ada Internal Server Error (HTTP 500)", "green"))

    except requests.exceptions.RequestException as e:
        print(colored(f"[!] Error: {e}", "red"))

# Input URL
target_url = input("Masukkan URL target (dengan http:// atau https://): ")

# Payload untuk bypass (contoh)
payloads = ["'", "--", "/*", "1=1"]  # Ganti dengan payload yang sesuai

# Jalankan validasi
check_internal_server_error(target_url, payloads)
