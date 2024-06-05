import requests
import re
from urllib.parse import urlparse
import nmap
import whois
import socket
from bs4 import BeautifulSoup, Comment
import sys
# import emoji

def check_vulnerable_headers(url):
    print(f"\nMemulai pemeriksaan header rentan: {url}")
    try:
        response = requests.get(url)
        vulnerable_headers = {
            "Server": 'Mengungkapkan jenis dan versi server web.',
            "X-Powered-By": 'Mengungkapkan teknologi yang digunakan (misalnya, PHP, ASP.NET).',
            "X-AspNet-Version": 'Mengungkapkan versi ASP.NET.',
            "X-AspNetMvc-Version": 'Mengungkapkan versi ASP.NET MVC.',
            "X-Generator": 'Mengungkapkan generator situs web (misalnya, CMS).',
            "X-Debug-Token": 'Mengungkapkan token debug yang dapat digunakan untuk debugging jarak jauh.',
            "X-Runtime": 'Mengungkapkan informasi tentang waktu eksekusi skrip.',
            "X-Backend-Server": 'Mengungkapkan nama atau alamat IP server backend.',
            "Via": 'Mengungkapkan informasi tentang proxy atau load balancer yang digunakan.',
            "X-Cache": 'Mengungkapkan informasi tentang sistem cache yang digunakan.',
            "X-Frame-Options": 'Kurangnya header ini dapat memungkinkan serangan Clickjacking.',
            "Strict-Transport-Security": 'Kurangnya header ini dapat menurunkan keamanan HTTPS.',
            "Content-Security-Policy": 'Kurangnya header ini dapat memungkinkan berbagai serangan injeksi konten.',
            "X-Content-Type-Options": 'Kurangnya header ini dapat memungkinkan serangan MIME Sniffing.',
            "Referrer-Policy": 'Kurangnya header ini dapat membocorkan informasi referer.',
            "Permissions-Policy": 'Kurangnya header ini dapat mengizinkan akses yang tidak diinginkan ke fitur browser.',
            "Expect-CT": 'Kurangnya header ini dapat mengurangi perlindungan terhadap kesalahan sertifikat.',
            "Feature-Policy": 'Kurangnya header ini dapat mengizinkan akses yang tidak diinginkan ke fitur browser.',
            "X-XSS-Protection": 'Kurangnya header ini dapat membuat browser rentan terhadap serangan XSS.',
            "Public-Key-Pins": 'Kurangnya header ini dapat mengurangi perlindungan terhadap serangan downgrade HTTPS.',
            "X-Pingback": 'Mengungkapkan URL Pingback yang dapat digunakan untuk serangan DDoS.',
            "X-Author": 'Mengungkapkan informasi tentang penulis konten.',
            "X-AspNet-Trace": 'Mengungkapkan informasi debug ASP.NET.',
            "X-Backend": 'Mengungkapkan informasi tentang server backend.',
            "X-Cache-Hits": 'Mengungkapkan informasi tentang penggunaan cache.',
            "X-Content-Powered-By": 'Mengungkapkan teknologi yang digunakan untuk menghasilkan konten.',
            "X-Generator-Version": 'Mengungkapkan versi generator situs web.',
            "X-Mod-Pagespeed": 'Mengungkapkan penggunaan modul PageSpeed Apache.',
            "X-Page-Speed": 'Mengungkapkan informasi tentang pengoptimalan kecepatan halaman.',
            "X-Varnish": 'Mengungkapkan penggunaan Varnish Cache.',
            "X-Proxy-Cache": 'Mengungkapkan informasi tentang penggunaan proxy cache.',
            "X-Redirect-By": 'Mengungkapkan teknologi yang digunakan untuk melakukan redirect.',
            "X-UA-Compatible": 'Mengungkapkan informasi tentang mode kompatibilitas browser.',
            "Etag": 'Mengungkapkan informasi unik tentang versi sumber daya.',
            "Last-Modified": 'Mengungkapkan waktu terakhir sumber daya dimodifikasi.',
            "X-Aspnet-State": 'Mengungkapkan informasi tentang status sesi ASP.NET.',
            "X-Drupal-Cache": 'Mengungkapkan informasi tentang sistem cache Drupal.',
            "X-Drupal-Dynamic-Cache": 'Mengungkapkan informasi tentang sistem cache dinamis Drupal.',
            "X-Powered-Cms": 'Mengungkapkan CMS yang digunakan (misalnya, WordPress, Joomla).',
            "X-Content-Security-Policy-Report-Only": 'Mengungkapkan laporan pelanggaran kebijakan keamanan konten.'
        }
        found_vulnerabilities = False
        for header, description in vulnerable_headers.items():
            value = response.headers.get(header)
            if value:
                found_vulnerabilities = True
                print(f"\033[93mPeringatan: Header '{header}' ditemukan: {value}\033[0m")
                print(f"  - {description}")

        nm = nmap.PortScanner()
        nm.scan(urlparse(url).hostname, arguments="-sV -p 80,443")
        if urlparse(url).hostname in nm.all_hosts():
            print("\n\033[92mInformasi dari Nmap:\033[0m")
            for port in nm[urlparse(url).hostname].all_protocols():
                if nm[urlparse(url).hostname][port]["state"] == 'open':
                    product = nm[urlparse(url).hostname][port]["product"]
                    version = nm[urlparse(url).hostname][port]["version"]
                    if product and version:
                        print(f"  - Port {port}: {product} {version}")
                    else:
                        print(f"  - Port {port}: {nm[urlparse(url).hostname][port]['name']}")

        try:
            whois_info = whois.whois(urlparse(url).netloc)
            if whois_info:
                print("\n\033[92mInformasi WHOIS:\033[0m")
                for key, value in whois_info.items():
                    if value and key not in ['query', 'referral_url']:  # Filter informasi yang relevan
                        print(f"  - {key}: {value}")
        except Exception as e:
            print(f"\033[93mPeringatan: Tidak dapat mengambil informasi WHOIS - {e}\033[0m")

        content_type = response.headers.get("Content-Type")
        if content_type:
            # Mendeteksi teknologi berdasarkan Content-Type
            if "text/html" in content_type:
                # Analisis pada konten HTML
                soup = BeautifulSoup(response.content, "html.parser")
                
                # Deteksi generator meta tag
                generator_tag = soup.find("meta", attrs={"name": "generator"})
                if generator_tag:
                    print(f"\033[93mPeringatan: Generator tag ditemukan: {generator_tag['content']}\033[0m")

                # Deteksi komentar HTML yang mungkin mengandung informasi sensitif
                comments = soup.find_all(string=lambda text: isinstance(text, Comment))
                for comment in comments:
                    if any(keyword in comment for keyword in ["debug", "password", "secret", "key"]):
                        print(f"\033[93mPeringatan: Komentar HTML yang mencurigakan ditemukan: {comment}\033[0m")

                # Deteksi teknologi spesifik (contoh: WordPress)
                if soup.find("meta", attrs={"name": "generator", "content": "WordPress"}):
                    print("\033[93mPeringatan: Situs web menggunakan WordPress.\033[0m")
                    
                    # Periksa versi WordPress
                    wp_version = re.search(r"content='WordPress (\d+\.\d+\.\d+)'", str(soup))
                    if wp_version:
                        print(f"  - Versi WordPress: {wp_version.group(1)}")

                    # Periksa plugin yang rentan
                    vulnerable_plugins = ["revslider", "woocommerce", "wp-file-manager", "contact-form-7"]
                    for plugin in vulnerable_plugins:
                        if f"/wp-content/plugins/{plugin}/" in str(soup):
                            print(f"\033[93m  - Peringatan: Plugin '{plugin}' yang berpotensi rentan terdeteksi.\033[0m")

                    # Periksa tema yang rentan
                    vulnerable_themes = ["twentytwenty", "astra", "Divi"]
                    for theme in vulnerable_themes:
                        if f"/wp-content/themes/{theme}/" in str(soup):
                            print(f"\033[93m  - Peringatan: Tema '{theme}' yang berpotensi rentan terdeteksi.\033[0m")

                    # Periksa direktori wp-admin dan wp-login
                    for path in ["/wp-admin/", "/wp-login.php"]:
                        try:
                            response = requests.get(url + path)
                            if response.status_code == 200:
                                print(f"\033[93m  - Peringatan: Direktori '{path}' dapat diakses publik.\033[0m")
                        except requests.exceptions.RequestException:
                            pass

            elif "application/json" in content_type:
                # Analisis pada konten JSON
                try:
                    json_data = response.json()
                    if "version" in json_data:
                        print(f"\033[93mPeringatan: Versi API ditemukan: {json_data['version']}\033[0m")
                    # Cari informasi lain yang relevan dalam JSON
                except ValueError:
                    pass

        if not found_vulnerabilities:
            print("\033[92mTidak ada header rentan yang ditemukan dalam pemeriksaan awal.\033[0m")
        else:
            print("\n\033[93mRekomendasi:\033[0m")
            print("  - Pertimbangkan untuk menghapus atau mengkonfigurasi ulang header yang tidak perlu.")
            print("  - Terapkan header keamanan yang direkomendasikan untuk meningkatkan keamanan situs web.")
            print("  - Thanks you, semoga membantu, jangan lupa follow ya \U0001f600.")

    except requests.exceptions.RequestException as e:
        print(f"\033[91mKesalahan: {e}\033[0m")

def main():
    if len(sys.argv) != 2:
        print("Penggunaan: python3 vulnerable_headers_check.py <url>")
        return

    url = sys.argv[1]
    check_vulnerable_headers(url)

if __name__ == "__main__":
    main()
        
