import pyshark
import socket
import ssl
import argparse
import time
import logging
from termcolor import colored

# Konfigurasi logging untuk debugging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Daftar weak cipher suites
weak_ciphers = [
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "SSLv3",  # Ditambahkan untuk POODLE
]

def test_cipher_suite(hostname, port, cipher_suite):
    """Menguji koneksi TLS dengan cipher suite tertentu."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        context.set_ciphers(cipher_suite)
    except ssl.SSLError as e:
        if "No cipher can be selected" in str(e):
            logging.info(colored(f"Cipher suite {cipher_suite} tidak didukung oleh server.", "yellow"))
            return False
        else:
            raise e

def exploit_poodle(hostname, port):
    """Mencoba eksploitasi kerentanan POODLE."""
    if test_cipher_suite(hostname, port, "SSLv3"):
        logging.warning(colored("Potensi kerentanan POODLE terdeteksi!", "red"))

        # Tambahkan kode untuk mengirimkan data dan menangkap lalu lintas jaringan di sini
        # ...

def analyze_pcap(filename, hostname):
    """Menganalisis file pcap untuk mencari weak cipher suites."""
    capture = pyshark.FileCapture(filename, display_filter="tls.handshake")
    for packet in capture:
        if hasattr(packet, "tls"):
            try:
                if (packet.tls.handshake_type == "1" and
                    hasattr(packet.tls, "handshake_extensions_server_name") and
                    packet.tls.handshake_extensions_server_name == hostname):
                    for cipher in weak_ciphers:
                        if cipher in packet.tls.handshake_ciphersuites:
                            logging.warning(colored(f"Cipher suite lemah '{cipher}' ditemukan dalam Client Hello ke {hostname}", "yellow"))
                elif packet.tls.handshake_type == "2":
                    if packet.tls.handshake_ciphersuite in weak_ciphers:
                        logging.warning(colored(f"Cipher suite lemah '{packet.tls.handshake_ciphersuite}' dipilih oleh {hostname}", "red"))
            except AttributeError as e:
                logging.debug(f"Paket tidak memiliki layer TLS yang valid atau atribut yang diperlukan: {e}")

def main():
    parser = argparse.ArgumentParser(description="Analisis dan Eksploitasi Kerentanan TLS")
    parser.add_argument("hostname", help="Nama host atau alamat IP target")
    parser.add_argument("-p", "--port", type=int, default=443, help="Nomor port (default: 443)")
    parser.add_argument("-f", "--file", help="File pcap untuk dianalisis (opsional)")
    args = parser.parse_args()

    if args.file:
        analyze_pcap(args.file, args.hostname)

    for cipher in weak_ciphers:
        test_cipher_suite(args.hostname, args.port, cipher)

    exploit_poodle(args.hostname, args.port)

if __name__ == "__main__":
    main()
