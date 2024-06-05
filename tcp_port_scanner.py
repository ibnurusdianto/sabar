import socket
import concurrent.futures
import time
import sys 

def scan_port(hostname, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            result = s.connect_ex((hostname, port))
            if result == 0:
                try:
                    banner = s.recv(1024).decode().strip()
                    service = socket.getservbyport(port, "tcp")
                    print(f"\033[92mPort {port}/TCP terbuka\033[0m - Layanan: {service} (Banner: {banner})")
                    return port, service, banner
                except:
                    print(f"\033[92mPort {port}/TCP terbuka\033[0m (tidak ada banner)")
                    return port, None, None
            else:
                print(f"\033[91mPort {port}/TCP tertutup\033[0m")
                return port, None, None
    except socket.error:
        return port, None, None

def port_scan(hostname, start_port, end_port):
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_port, hostname, port): port for port in range(start_port, end_port + 1)}
        for future in concurrent.futures.as_completed(future_to_port):
            _ = future.result()  # Tidak perlu menyimpan hasilnya, karena sudah dicetak di scan_port

def main():
    if len(sys.argv) != 4:
        print("Penggunaan: python3 tcp_port_scanner.py <hostname> <start_port> <end_port>")
        return

    hostname = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])

    print("Memulai pemindaian port TCP...")
    port_scan(hostname, start_port, end_port)

if __name__ == "__main__":
    main()
