import ssl
import socket
import OpenSSL
from datetime import datetime
import sys
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)


def check_tls_1_0(hostname, port=443):

    print(f"\nMemulai pemeriksaan TLS 1.0 pada {hostname}:{port}")

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.set_ciphers('DEFAULT@SECLEVEL=1')

        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:

         
                tls_version = ssock.version()
                print(f"\tVersi TLS yang dinegosiasikan: {tls_version}")

          
                if tls_version == "TLSv1":
                    print("\033[91mPeringatan: Server mendukung TLS 1.0 yang rentan!\033[0m")
                    print("  - Risiko serangan Man-in-the-Middle (MiTM) dan BEAST (Browser Exploit Against SSL/TLS).")
                    print("  - Tidak memenuhi standar PCI sejak 30 Juni 2018.")
                    return True, tls_version

                else:
                    print("\033[92mServer tidak mendukung TLS 1.0.\033[0m")
                    return False, tls_version
    except Exception as e:
        print(f"\033[91mKesalahan: {e}\033[0m")
        return None, None


def main():
    if len(sys.argv) != 2:
        print("Penggunaan: python3 tls_1_0_check.py <hostname>")
        return

    hostname = sys.argv[1]
    tls_1_0_supported, version = check_tls_1_0(hostname)

    if tls_1_0_supported:
        print(f"\n\033[93mRekomendasi:\033[0m")
        print("  - Segera nonaktifkan dukungan TLS 1.0 pada server Anda.")
        print("  - Upgrade ke versi TLS yang lebih aman (TLS 1.2 atau lebih baru).")
        print("  - Pastikan konfigurasi server Anda sesuai dengan standar keamanan terbaru.")

if __name__ == "__main__":
    main()
