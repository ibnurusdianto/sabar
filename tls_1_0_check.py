import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import sys
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)


def check_tls_1_0_vulnerability(hostname, port=443):
    print(f"\nMemulai pemeriksaan kerentanan TLS 1.0 pada {hostname}:{port}")
    weak_ciphers = [
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    ]

    for cipher in weak_ciphers:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.set_ciphers(cipher)

            context.options |= ssl.OP_NO_TLSv1_1 
            context.options |= ssl.OP_NO_TLSv1_2

            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    print(f"\033[91mPeringatan: Server rentan terhadap downgrade ke TLS 1.0 dengan cipher suite: {cipher}\033[0m")
                    return True
        except ssl.SSLError:
            pass  

    print("\033[92mServer tidak rentan terhadap downgrade ke TLS 1.0.\033[0m")
    return False

def main():
    if len(sys.argv) != 2:
        print("Penggunaan: python3 tls_1_0_check.py <hostname>")
        return

    hostname = sys.argv[1]
    is_vulnerable = check_tls_1_0_vulnerability(hostname)

    if is_vulnerable:
        print(f"\n\033[93mRekomendasi:\033[0m")
        print("  - Nonaktifkan cipher suite yang lemah pada server.")
        print("  - Pastikan konfigurasi server sesuai dengan standar keamanan terbaru.")

if __name__ == "__main__":
    main()
