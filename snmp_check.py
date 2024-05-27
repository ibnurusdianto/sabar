#!/usr/bin/env python3

import subprocess
import re
from itertools import product  

def snmp_check_with_tampers(ip_address, community_strings):
    for community in community_strings:
        # community string tanpa tamper
        command = f"snmp-check -c {community} {ip_address}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if "SNMPv" in result.stdout:  # Jika terdeteksi SNMP version, berarti berhasil
            print(f"[+] SNMP terbuka pada {ip_address} dengan community string: {community}")
            return True

        # tamper untuk Cloudflare dan Apache
        tampers = [
            "",  # Tanpa tamper 
            "-u",  # user agent untuk melewati Cloudflare
            "-H 'X-Forwarded-For: 127.0.0.1'",  # Tambahkan header X-Forwarded-For
            "-r 10"  # jumlah retries untuk mengatasi timeout
        ]

        for tamper in tampers:
            command = f"snmp-check -c {community} {tamper} {ip_address}"
            result = subprocess.run(command, shell=True, capture_output=True, text=True)

            if "SNMPv" in result.stdout:
                print(f"[+] SNMP terbuka pada {ip_address} dengan community string: {community} (menggunakan tamper: {tamper})")
                return True

    print(f"[-] SNMP tidak terbuka pada {ip_address} dengan community strings yang dicoba.")
    return False

if __name__ == "__main__":
    ip_address = "" # masukan ip target disini
    wordlist_file = "./community.txt"  # File wordlist community strings - jika ingin tambahkan ubah nama wordlist.txtnya (isinya)

    with open(wordlist_file, "r") as file:
        community_strings = [line.strip() for line in file]

    # Tambahkan beberapa community strings umum jika belum ada di wordlist
    common_strings = ["public", "private", "cisco", "admin"]
    community_strings.extend([s for s in common_strings if s not in community_strings])

    # Generate combinations of community strings (optional)
    combinations = product(community_strings, repeat=2)

    if snmp_check_with_tampers(ip_address, community_strings):
        print("[+] SNMP ditemukan! Analisis lebih lanjut diperlukan.")
    else:
        print("[-] SNMP tidak ditemukan atau tidak dapat diakses dengan community strings dan tamper yang dicoba.")
