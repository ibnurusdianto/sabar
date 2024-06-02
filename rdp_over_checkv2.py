import socket
import struct
import random
import time
import requests
import nmap
import concurrent.futures
from scapy.all import *

def check_rdp_over_udp(hostname, port=3389):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        pdu = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
        sock.sendto(pdu, (hostname, port))
        data, addr = sock.recvfrom(1024)
        if b"\x03\x00\x00\x0b" in data:
            return True, "Koneksi langsung"

        for _ in range(5):
            sock.sendto(b"\x00", (hostname, port))
            time.sleep(0.1)

        # Pemeriksaan Melalui Web Requests
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "X-Forwarded-For": f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        }
        response = requests.get(f"https://{hostname}:{port}", headers=headers, verify=False)
        if response.status_code == 400 and "mstshash" in response.text:
            return True, "Web request"

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(lambda: nmap.PortScanner().scan(hostname, arguments=f"-sU -p {port} --script rdp-ntlm-info"))
            nm = future.result()
            if hostname in nm.all_hosts() and nm[hostname].has_tcp(port):
                return True, "Nmap scan"

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(
                lambda: sr1(IP(dst=hostname)/UDP(dport=port)/b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00", timeout=3, verbose=0)
            )
            response = future.result()
            if response and b"\x03\x00\x00\x0b" in bytes(response[UDP].payload):
                return True, "Scapy scan"

        return False, None

    except Exception as e:
        return False, str(e)

def main():
    if len(sys.argv) != 2:
        print("Penggunaan: python3 rdp_udp_check.py <hostname>")
        return

    hostname = sys.argv[1]
    rdp_detected, method = check_rdp_over_udp(hostname)

    if rdp_detected:
        print(f"\033[91mServer RDP terdeteksi pada port UDP 3389 ({method})!\033[0m")
        print("Potensi kerentanan terhadap serangan brute-force atau eksploitasi remote.")
    else:
        if method is None:
            print("\033[92mTidak ada server RDP yang terdeteksi pada port UDP 3389.\033[0m")
        else:
            print(f"\033[93mPemindaian gagal: {method}\033[0m")

if __name__ == "__main__":
    main()
