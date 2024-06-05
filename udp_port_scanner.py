import socket
import concurrent.futures
import time
import sys

def udp_scan(target_ip, port):
    try:
        # Membuat socket UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)  # Atur timeout koneksi

        # Mengirimkan data dummy
        sock.sendto(b"\x00\x00", (target_ip, port))

        # Menerima respons (jika ada)
        try:
            data, addr = sock.recvfrom(1024)
            service = socket.getservbyport(port, "udp")  # Mencari nama layanan
            print(f"\033[92mPort {port}/UDP terbuka\033[0m - Layanan: {service} (Respons: {data.hex()})")
            return port, service, data.hex()  # Mengembalikan port, layanan, dan respons heksadesimal
        except socket.timeout:
            print(f"\033[93mPort {port}/UDP terbuka (tidak ada respons)\033[0m")
            return port, None, None

    except socket.error:
        return port, None, None  # Port tertutup atau error

def full_udp_scan(target_ip, start_port=1, end_port=65535):
    open_ports = []
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(udp_scan, target_ip, port) for port in range(start_port, end_port + 1)]
        for future in concurrent.futures.as_completed(futures):
            port, service, response = future.result()
            if service:
                open_ports.append((port, service, response))

    end_time = time.time()
    print("\nPemindaian selesai dalam {:.2f} detik.".format(end_time - start_time))
    return open_ports

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Penggunaan: python3 udp_port_scanner.py <target_ip> [start_port] [end_port]")
    else:
        target_ip = sys.argv[1]
        start_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1
        end_port = int(sys.argv[3]) if len(sys.argv) > 3 else 65535

        print("Memulai pemindaian port UDP...")
        open_ports = full_udp_scan(target_ip, start_port, end_port)

        if open_ports:
            print("\nHasil Pemindaian:")
            for port, service, response in open_ports:
                if response:
                    print(f"  - Port {port}/UDP - Layanan: {service} (Respons: {response})")
                else:
                    print(f"  - Port {port}/UDP - Layanan: {service}")
        else:
            print("\nTidak ada port UDP terbuka yang ditemukan.")
