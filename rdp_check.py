import socket
import sys

def check_rdp_over_udp(hostname, port=3389):
    try:
        # Membuat socket UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)

        # Mengirimkan X.224 Connection Request PDU
        pdu = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
        sock.sendto(pdu, (hostname, port))

        # Menerima respons
        data, addr = sock.recvfrom(1024)

        if b"\x03\x00\x00\x0b" in data:
            print("\033[91mServer RDP terdeteksi pada port UDP 3389!\033[0m")
            print("Potensi kerentanan terhadap serangan brute-force atau eksploitasi remote.")
            try:
                sock.sendto(b"\x03\x00\x01\x00", (hostname, port))
                data, addr = sock.recvfrom(1024)
                banner = data[23:].decode("utf-8", errors="replace")  # Ekstrak banner
                print(f"Banner RDP: {banner}")
            except:
                print("Gagal mendapatkan banner RDP.")

            return True
        else:
            print("\033[92mTidak ada server RDP yang terdeteksi pada port UDP 3389.\033[0m")
            return False

    except socket.timeout:
        print("\033[93mTimeout. Port UDP 3389 mungkin tertutup atau tidak merespons.\033[0m")
        return None

    except Exception as e:
        print(f"\033[91mTerjadi kesalahan: {e}\033[0m")
        return None

def main():
    if len(sys.argv) != 2:
        print("Penggunaan: python3 rdp_udp_check.py <hostname>")
        return

    hostname = sys.argv[1]
    check_rdp_over_udp(hostname)

if __name__ == "__main__":
    main()
