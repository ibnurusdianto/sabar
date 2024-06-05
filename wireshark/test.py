import pyshark
import logging
from termcolor import colored

# Konfigurasi logging untuk debugging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Daftar weak cipher suites - jika ingin tambahkan disini
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
]

# Domain yang menjadi target
target_domain = "situ2.unpas.ac.id"

# Fungsi untuk memeriksa kerentanan POODLE
def check_poodle_vulnerability(packet):
    if "TLSv1" in packet.tls.handshake_version:
        if packet.tls.handshake_ciphersuite in weak_ciphers:
            logging.warning(colored(f"Potensi kerentanan POODLE terdeteksi pada {target_domain}. Berhasil terhubung dengan {packet.tls.handshake_version} menggunakan cipher suite: {packet.tls.handshake_ciphersuite}", "red"))

# Fungsi untuk memproses paket
def process_packet(packet):
    if hasattr(packet, "tls"):
        try:
            # Filter berdasarkan SNI (Server Name Indication) pada Client Hello
            if (packet.tls.handshake_type == "1" and 
                hasattr(packet.tls, "handshake_extensions_server_name") and
                packet.tls.handshake_extensions_server_name == target_domain):  

                logging.info(colored(f"Client Hello ke {target_domain} terdeteksi dengan cipher suites: {packet.tls.handshake_ciphersuites}", "green"))

            elif packet.tls.handshake_type == "2":  # Server Hello
                logging.info(colored(f"Server Hello dari {target_domain} terdeteksi dengan cipher suite: {packet.tls.handshake_ciphersuite}", "blue")) # Menggunakan pemformatan string gaya baru
                check_poodle_vulnerability(packet)
        except AttributeError as e:
            logging.warning(f"Paket tidak memiliki layer TLS yang valid atau atribut yang diperlukan: {e}")

# Membuka file capture Wireshark
capture = pyshark.FileCapture("test.pcapng", display_filter="tls.handshake")

# Memproses setiap paket dalam capture
for packet in capture:
    process_packet(packet)

# Menutup file capture
capture.close()
