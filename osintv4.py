import requests
from bs4 import BeautifulSoup
import argparse
import logging
from termcolor import colored
from googlesearch import search
from chardet import detect

# Konfigurasi logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def search_dummy_data(nama, num_results=10):
    """
    Mencari dummy data terkait nama target di internet.
    """
    query = f"{nama} dummy data"
    results = []
    for url in search(query, num_results=num_results):
        try:
            response = requests.get(url)
            if response.status_code == 200:

                # Deteksi encoding dan decode konten
                encoding = detect(response.content)['encoding']
                response.encoding = encoding 
                soup = BeautifulSoup(response.text, 'html.parser')

                text = soup.get_text()  # Ekstrak teks dari halaman
                if nama in text:  # Filter hasil yang relevan
                    results.append({'url': url, 'text': text})
        except requests.exceptions.RequestException as e:
            logging.error(colored(f"Error saat mengakses {url}: {e}", "red"))
    return results

def main():
    parser = argparse.ArgumentParser(description="Pencarian Dummy Data untuk OSINT")
    parser.add_argument("nama", help="Nama target")
    parser.add_argument("-n", "--num_results", type=int, default=10, help="Jumlah hasil pencarian (default: 10)")
    args = parser.parse_args()

    results = search_dummy_data(args.nama, args.num_results)

    if results:
        logging.info(colored(f"Ditemukan {len(results)} hasil pencarian yang relevan:", "green"))
        for result in results:
            print(f"- URL: {result['url']}")
            print(f"- Cuplikan Teks: {result['text'][:200]}...")  # Tampilkan 200 karakter pertama
    else:
        logging.warning(colored("Tidak ditemukan dummy data yang relevan.", "yellow"))

if __name__ == "__main__":
    main()
