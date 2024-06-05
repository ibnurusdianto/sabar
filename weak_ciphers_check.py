import ssl
import socket
import sys

def check_weak_ciphers(hostname, port=443):
    print(f"\nMemulai pemeriksaan cipher suite lemah pada {hostname}:{port}")
    
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
        "TLS_RSA_WITH_AES_256_GCM_SHA384"
    ]

    for cipher in weak_ciphers:
        try:
            # Membuat konteks SSL dengan cipher suite yang lemah
            context = ssl.create_default_context()
            context.set_ciphers(cipher)
            
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Jika berhasil terhubung, cipher suite lemah didukung
                    print(f"\033[91mPeringatan: Server mendukung cipher suite lemah: {cipher}\033[0m")
                    return True, cipher
        except ssl.SSLError:
            pass  # Abaikan jika cipher suite tidak didukung

    print("\033[92mServer tidak mendukung cipher suite lemah yang umum.\033[0m")
    return False, None

def main():
    if len(sys.argv) != 2:
        print("Penggunaan: python3 weak_ciphers_check.py <hostname>")
        return

    hostname = sys.argv[1]
    is_vulnerable, weak_cipher = check_weak_ciphers(hostname)

    if is_vulnerable:
        print(f"\n\033[93mRekomendasi:\033[0m")
        print("  - Nonaktifkan cipher suite yang lemah pada server Anda.")
        print(f"  - Contoh cipher suite yang lemah dan harus dinonaktifkan: {weak_cipher}")
        print("  - Pertimbangkan untuk menggunakan cipher suite yang lebih kuat seperti:")
        print("    - TLS_AES_128_GCM_SHA256")
        print("    - TLS_AES_256_GCM_SHA384")
        print("    - TLS_CHACHA20_POLY1305_SHA256")
        print("  - Pastikan konfigurasi server Anda sesuai dengan standar keamanan terbaru.")

if __name__ == "__main__":
    main()
