import socket
import ipaddress
import sys

def check_ipv6(hostname):
    """
    Memeriksa dukungan IPv6 untuk hostname dan memberikan informasi detail.
    """
    try:
        # alamat IP (IPv4 dan IPv6)
        results = socket.getaddrinfo(hostname, None, family=socket.AF_UNSPEC)

        has_ipv6 = False
        for result in results:
            family, socktype, proto, canonname, sockaddr = result
            ip_address = sockaddr[0]

            # Periksa alamat IP adalah IPv6 yang valid
            try:
                ipaddress.IPv6Address(ip_address)
                has_ipv6 = True
                print("\033[92mHost memiliki alamat IPv6:\033[0m")
                print(f"  - Alamat: {ip_address}")
                print(f"  - Tipe: {'Global' if ipaddress.IPv6Address(ip_address).is_global else 'Link-local'}")
                print(f"  - Scope: {ipaddress.IPv6Address(ip_address).scope_id}")
            except ipaddress.AddressValueError:
                pass

        if not has_ipv6:
            print("\033[93mHost tidak memiliki alamat IPv6 yang valid.\033[0m")
            return False

        return True

    except socket.gaierror:
        print(f"\033[91mGagal melakukan resolusi DNS untuk {hostname}\033[0m")
        return None

def main():
    if len(sys.argv) != 2:
        print("Penggunaan: python3 ipv6_checker.py <hostname>")
        return

    hostname = sys.argv[1]
    has_ipv6 = check_ipv6(hostname)

    if has_ipv6 is False:
        print("\n\033[93mInformasi:\033[0m")
        print("  - IPv6 penting untuk keamanan karena mendukung IPSec yang menjamin kerahasiaan (Confidentiality), integritas (Integrity), dan ketersediaan (Availability) data.")
        print("  - Disarankan untuk mengonfigurasi IPv6 pada host Anda untuk meningkatkan keamanan.")

if __name__ == "__main__":
    main()
