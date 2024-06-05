import socket
import ssl
import time
import sys

def check_renegotiation(hostname, port=443):
    try:
        # konteks SSL/TLS dengan pengaturan default yang aman
        context = ssl.create_default_context()

        context.options &= ~ssl.OP_NO_RENEGOTIATION

        # Buat socket dan bungkus dengan SSL
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)  # Atur timeout
        s_wrapped = context.wrap_socket(s, server_hostname=hostname)
        s_wrapped.connect((hostname, port))

        # Kirim Client Hello untuk memulai handshake awal
        hello = b"\x16\x03\x01\x00\xc4\x01\x00\x00\xc0\x03\x03\x4f\xa0\x52\x9a\x67\x13\x69\x5a\x16\x81\xfa\x1f\xae\x31\x80\x7b\xfe\x46\x6c\x37\x1d\x6d\x00\x00\x00\x9a\xc0\x2b\xc0\x2f\x00\x3c\x00\x2f\xc0\x2c\xc0\x30\x00\x9f\x00\x6b\x00\x6a\x00\x3d\x00\x35\x00\x84\xc0\x23\xc0\x27\x00\x9e\xc0\x24\xc0\x28\x00\x67\x00\x40\xc0\x0a\xc0\x14\x00\x39\x00\x38\x00\x88\x00\x87\xc0\x0f\xc0\x05\x00\x35\x00\x84\xc0\x12\xc0\x08\xc0\x1c\xc0\x1b\x00\x16\x00\x13\x00\xff\x01\x00\x00\x49\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x0c\x00\x0a\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18\x00\x0b\x00\x0c\x00\x1a\x00\x16\x00\x0e\x00\x0d\x00\x03\x00\x0f\x00\x10\x00\x11\x00\x23\x00\x00\x00\x0d\x00\x1f\x00\x01\x01"
        s_wrapped.sendall(hello)

        # Tunggu server merespons dengan Server Hello
        while True:
            data = s_wrapped.recv(4096)
            if data:
                break  

        # Coba picu renegotiasi
        reneg_hello = b"\x16\x03\x01\x00\x01\x01"
        s_wrapped.sendall(reneg_hello)

        # Tunggu respons renegotiasi
        time.sleep(1)  # Beri waktu server untuk merespons
        try:
            data = s_wrapped.recv(4096)
        except socket.timeout:
            print("\033[92mServer tidak mendukung renegotiasi atau telah menerapkan mitigasi.\033[0m")
            return False

        # Periksa apakah renegotiasi berhasil
        if b"\x16\x03" in data:
            print("\033[91mServer mendukung renegotiasi yang tidak aman, rentan terhadap serangan Plain-Text Injection.\033[0m")
            return True
        else:
            print("\033[92mServer tidak mendukung renegotiasi atau telah menerapkan mitigasi.\033[0m")
            return False

    except ConnectionRefusedError:
        print("Koneksi ditolak. Pastikan host dan port benar.")
        return None

    except socket.timeout:
        print("Timeout. Server mungkin tidak merespons.")
        return None

    except Exception as e:
        print(f"Terjadi kesalahan: {e}")
        return None

    finally:
        if s_wrapped:
            s_wrapped.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Penggunaan: python3 renegotiation_check.py <hostname>")
    else:
        hostname = sys.argv[1]
        check_renegotiation(hostname)
