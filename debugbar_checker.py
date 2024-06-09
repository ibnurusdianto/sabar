import requests
import argparse
from termcolor import colored

def check_debugbar(url):
    """
    Memeriksa apakah website memiliki kerentanan Debugbar for Laravel.
    """
    try:
        response = requests.get(url + "_debugbar/open")
        if response.status_code == 200 and "PHP Debug Bar" in response.text:
            print(colored(f"[VULNERABLE] Kerentanan Debugbar for Laravel ditemukan pada {url}", "red"))
            print(colored(f"URL Debugbar: {url}_debugbar/open", "yellow"))
        else:
            print(colored(f"[SECURE] Tidak ditemukan kerentanan Debugbar pada {url}", "green"))
    except requests.exceptions.RequestException as e:
        print(colored(f"Error saat mengakses {url}: {e}", "red"))

def main():
    parser = argparse.ArgumentParser(description="Pemeriksa Kerentanan Debugbar for Laravel")
    parser.add_argument("url", help="URL website yang akan diperiksa")
    args = parser.parse_args()

    check_debugbar(args.url)

if __name__ == "__main__":
    main()
