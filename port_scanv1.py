import socket
import sys

def port_scan(hostname, ports):
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1) 
            s.connect((hostname, port))
            open_ports.append(port)
            s.close()
        except:
            pass

    return open_ports

def banner_grabbing(hostname, ports):
    banners = {}
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1) 
            s.connect((hostname, port))
            s.send(b"Hello\r\n") 
            banner = s.recv(1024).decode().strip()
            banners[port] = banner
            s.close()
        except:
            pass

    return banners

def main():
    if len(sys.argv) != 2:
        print("Penggunaan: python3 port_scanner.py <hostname>")
        return

    hostname = sys.argv[1]
    ports = range(1, 1025) 

    print("Memulai pemindaian port...")
    open_ports = port_scan(hostname, ports)
    print("Port terbuka:", open_ports)

    if open_ports:
        print("Melakukan banner grabbing...")
        banners = banner_grabbing(hostname, open_ports)
        for port, banner in banners.items():
            print(f"Port {port}: {banner}")
    else:
        print("Tidak ada port terbuka yang ditemukan.")

if __name__ == "__main__":
    main()
