import argparse
import requests

def check_clickjacking(domain):
    try:
        response = requests.get(domain, timeout=5)  
        return "x-frame-options" not in response.headers
    except requests.RequestException:
        return None  

def main():
    parser = argparse.ArgumentParser(description="Alat Pengujian Clickjacking")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Domain untuk diuji (contoh: http://contoh.com/)")
    group.add_argument("-f", "--file", help="File berisi daftar domain untuk diuji")

    args = parser.parse_args()

    if args.domain:
        domains = [args.domain]
    else:
        with open(args.file, "r") as f:
            domains = [line.strip() for line in f if line.strip()]

    for domain in domains:
        if not domain.startswith("http"): 
            domain = "http://" + domain

        is_vulnerable = check_clickjacking(domain)
        if is_vulnerable is True:
            print(f"[\033[31mclickjacking\033[0m] \033[32m{domain}\033[0m") 
        elif is_vulnerable is None:
            print(f"[\033[33mERROR\033[0m] \033[32m{domain}\033[0m")
        else:
            print(f"[\033[36mTidak Rentan - Aman dari clickjacking\033[0m] \033[32m{domain}\033[0m")

if __name__ == "__main__":
    main()
