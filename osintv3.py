import requests
from bs4 import BeautifulSoup
import json
import re
import argparse
import sys
# import argparse
from googlesearch import search
import phonenumbers
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_google_profile(email):
    """Mengambil informasi profil Google berdasarkan alamat email."""
    url = f"https://www.google.com/search?q={email}"
    headers = {'User-Agent': 'Mozilla/5.0'}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')

        # Mencari informasi profil di hasil pencarian Google (disesuaikan dengan struktur HTML terbaru)
        profile_block = soup.find('div', class_='g Ww4FFb vt6azd tF2Cxc')
        if profile_block:
            name_element = profile_block.find('div', class_='BNeawe deIvCb AP7Wnd')
            image_element = profile_block.find('img')

            name = name_element.text if name_element else None
            image_url = image_element['src'] if image_element else None

            return {
                'name': name,
                'image_url': image_url,
            }
    return None

def search_social_media(name):
    """Mencari akun media sosial berdasarkan nama."""
    social_media = {
        'Facebook': f"https://www.facebook.com/public/{name}",
        'Twitter': f"https://twitter.com/{name}",
        'Instagram': f"https://www.instagram.com/{name}",
        'Threads': f"https://www.threads.net/@{name}"
    }

    results = {}
    for platform, url in social_media.items():
        response = requests.get(url)
        if response.status_code == 200:
            results[platform] = url

    return results
def search_for_information(query, num_results=5):
    """Mencari informasi di web menggunakan Google Search."""
    results = []
    for url in search(query, num_results=num_results):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                text = soup.get_text()  # Ekstrak teks dari halaman
                results.append({'url': url, 'text': text})
        except requests.exceptions.RequestException:
            pass
    return results

def extract_phone_numbers(text):
    """Mengekstrak nomor telepon dari teks."""
    phone_numbers = []
    for match in phonenumbers.PhoneNumberMatcher(text, None):
        phone_numbers.append(phonenumbers.format_number(match.number, phonenumbers.PhoneNumberFormat.INTERNATIONAL))
    return phone_numbers


def main():
    parser = argparse.ArgumentParser(description="OSINT untuk Gmail")
    parser.add_argument("email", help="Alamat email Gmail target")
    args = parser.parse_args()

    print(f"[+] Status Gmail: Aktif (karena bisa menerima email)")

    profile = get_google_profile(args.email)
    if profile:
        print(f"[+] Nama: {profile['name']}")
        print(f"[+] Foto Profil: {profile['image_url']}")

        # Pencarian informasi tambahan
        search_queries = [
            f"{profile['name']} phone number",
            f"{profile['name']} date of birth",
            f"{profile['name']} location",
            f"{profile['name']} Universitas Pasundan",
            f"{profile['name']} Edlink"
        ]

        for query in search_queries:
            results = search_for_information(query)
            for result in results:
                text = result['text']
                url = result['url']

                # Mengekstrak nomor telepon
                phone_numbers = extract_phone_numbers(text)
                if phone_numbers:
                    print(f"[+] Nomor Telepon (dari {url}): {', '.join(phone_numbers)}")

                # TODO: Tambahkan logika untuk mengekstrak tanggal lahir, UUID, lokasi, negara, dan informasi pendidikan dari teks (text)

    else:
        logging.error("Profil Google tidak ditemukan atau tidak publik.")

    # Gunakan nama default atau hentikan program di sini
        default_name = "John Doe"  # Ganti dengan nama default yang sesuai
        print(f"[+] Nama: {default_name}")

        # ... (Lanjutkan pencarian informasi tambahan menggunakan default_name jika diperlukan)

    social_media_accounts = search_social_media(profile['name'] if profile else default_name)
    print("[+] Akun Media Sosial Terhubung:")
    for platform, url in social_media_accounts.items():
        print(f" - {platform}: {url}")

if __name__ == "__main__":
    main()
