import requests
from termcolor import colored
from bs4 import BeautifulSoup
import re

def check_cookie_httponly(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        print(colored("[!] Error: Masukkan target harus lengkap dengan http:// atau https://", "red"))
        return

    try:
        vulnerable_cookies = []

        # 1. Coba akses URL dan parsing HTML
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # 2. Dapatkan semua cookie dari halaman utama
        cookies = response.cookies
        for cookie in cookies:
            if not cookie.get("HttpOnly"):
                vulnerable_cookies.append((url, cookie.name))

        # 3. Cari semua formulir yang berpotensi sebagai formulir login
        login_forms = soup.find_all('form', {'id': re.compile(r'login|masuk|sign-in', re.IGNORECASE)})

        for login_form in login_forms:
            action_url = login_form.get('action')
            if action_url:
                if not action_url.startswith("http"):
                    action_url = url + action_url

                # 4. Coba kirim permintaan POST ke URL action formulir
                try:
                    response = requests.post(action_url)  # Sesuaikan data POST jika perlu
                except requests.exceptions.RequestException as e:
                    print(colored(f"[!] Error saat mengakses {action_url}: {e}", "red"))
                    continue

                # 5. Periksa cookie pada respons setelah mengirimkan formulir
                cookies = response.cookies
                if cookies:
                    for cookie in cookies:
                        if not cookie.get("HttpOnly"):
                            vulnerable_cookies.append((url, cookie.name))

        # 6. Tampilkan hasil di luar perulangan form login
        if vulnerable_cookies:
            print(colored("[!] Kerentanan Ditemukan: Cookie Tidak Ditandai sebagai HttpOnly", "red"))
            for path, cookie_name in vulnerable_cookies:
                print(colored(f"    - Path: {path}, Cookie: {cookie_name}", "yellow"))
        else:
            print(colored("[-] Tidak ada cookie yang ditemukan tanpa atribut HttpOnly", "blue"))
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] Error: {e}", "red"))

# Input URL
target_url = input("Masukkan URL target (dengan http:// atau https://): ")

# Jalankan validasi
check_cookie_httponly(target_url)
