import socket
import concurrent.futures

def scan_port(hostname, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((hostname, port))
            if result == 0:
                service = socket.getservbyport(port, "tcp")
                print(f"\033[92mPort {port} terbuka\033[0m - Layanan: {service}")
                return port, service
            else:
                return port, None
    except:
        return port, None

def port_scan(hostname, start_port, end_port):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:  # Pindai paralel dengan 100 thread
        future_to_port = {executor.submit(scan_port, hostname, port): port for port in range(start_port, end_port + 1)}
        for future in concurrent.futures.as_completed(future_to_port):
            port, service = future.result()
            if service:
                open_ports.append((port, service))
    return open_ports

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Penggunaan: python3 tcp_port_scanner.py <hostname> <start_port> <end_port>")
    else:
        hostname = sys.argv[1]
        start_port = int(sys.argv[2])
        end_port = int(sys.argv[3])
        print("Memulai pemindaian port TCP...")
        open_ports = port_scan(hostname, start_port, end_port)

        if open_ports:
            print("\nPort-port terbuka yang ditemukan:")
            for port, service in open_ports:
                print(f"  - Port {port} - Layanan: {service}")
        else:
            print("\nTidak ada port terbuka yang ditemukan dalam rentang yang ditentukan.")
