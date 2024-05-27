#!/usr/bin/env python3
import subprocess
import re

def enumerate_snmp(ip_address, community_string):
    oids = {
        "System Description": "1.3.6.1.2.1.1.1.0",
        "System Uptime": "1.3.6.1.2.1.1.3.0",
        "Contact Details": "1.3.6.1.2.1.1.4.0",
        "Location": "1.3.6.1.2.1.1.6.0",
        "Running Processes": "1.3.6.1.2.1.25.1.6.0",
        "Installed Software": "1.3.6.1.2.1.25.6.3.1.2",
        "Interfaces": "1.3.6.1.2.1.2.2.1",
        "Routing Table": "1.3.6.1.2.1.4.21.1",
        "ARP Table": "1.3.6.1.2.1.4.22.1",
        "TCP Connections": "1.3.6.1.2.1.6.13.1",
        "UDP Endpoints": "1.3.6.1.2.1.7.5.1",
        "User Accounts": "1.3.6.1.4.1.77.1.2.25",  
        "Installed Software Details": "1.3.6.1.2.1.25.6.3.1",  
        "Storage Information": "1.3.6.1.2.1.25.2.1", 
        "System Processes Detail": "1.3.6.1.2.1.25.4.2.1" 
    }

    tampers = [
        "",
        "-u",
        "-H 'X-Forwarded-For: 127.0.0.1'",
        "-r 10",
        "-I -p udp", 
        "-L 10",
        "-v1",      
        "-c public"
    ]

    for oid_name, oid in oids.items():
        for tamper in tampers:
            command = f"snmpwalk -v2c -c {community_string} {tamper} -t 5 -m +ALL {ip_address} {oid}"
            result = subprocess.run(command, shell=True, capture_output=True, text=True)

            if result.returncode == 0 and result.stdout.strip():
                print(f"\n[+] {oid_name}:")
                print(result.stdout.strip())
                break
        else:
            print(f"[-] {oid_name}: Gagal mendapatkan informasi (semua tamper gagal)")

if __name__ == "__main__":
    ip_address = "" # ip target masukan disini
    community_string = "public" # ubah sesuai com strings

    print(f"[*] Melakukan enumerasi SNMP pada {ip_address} dengan community string: {community_string}")
    enumerate_snmp(ip_address, community_string)
