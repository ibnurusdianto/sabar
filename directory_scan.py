import requests
from urllib.parse import urljoin
import sys

def check_open_directories(url):
    # jika ingin menambahkan dir, tambahkan disini
    # disini sudah menyediakan 100+ dir ya
    common_dirs = [
        "admin", "administrator", "admin_area", "backend", "backoffice", "backup", "config", "cms", "controlpanel", "dashboard",
        "database", "db", "data", "download", "downloads", "dump", "examples", "export", "files", "forum", "gallery", "images",
        "import", "inc", "include", "info", "install", "js", "lib", "library", "logs", "maintenance", "manager", "media", "misc",
        "modules", "old", "phpinfo", "phpmyadmin", "private", "secret", "secure", "settings", "shell", "site", "sites", "sql",
        "src", "stats", "store", "system", "temp", "tmp", "test", "tests", "thumb", "thumbs", "tools", "upload", "uploads", 
        "user", "users", "vendor", "webdav", "wordpress", "wp", "wp-admin", "wp-content", "wp-includes", "wp-login", "xmlrpc",
        "old_site", "cgi-bin", ".git", ".svn", ".htaccess", "cgi-bin", "cgi", "cgi-sys", "cpanel", "server-status", "server-info",
        "test", "testing", "example", "examples", "demo", "demos", "dev", "devel", "new", "beta", "archive", "archives", "stats",
        "statistics", "reports", "private_html", "public_html", "wwwroot", "web", "website", "blog", "forum", "shop", "store",
        "cart", "checkout", "order", "orders", "invoice", "invoices", "payment", "payments", "login", "logout", "register", 
        "profile", "account", "member", "members", "user", "users", "staff", "employee", "employees", "customer", "customers",
        "client", "clients", "contact", "about", "faq", "help", "support", "download", "downloads", "software", "manual", 
        "docs", "documentation", "api", "sdk"
    ]

    for directory in common_dirs:
        target_url = urljoin(url, directory)
        try:
            response = requests.get(target_url)
            status_code = response.status_code

            # Warna status code
            if 100 <= status_code < 200:
                color = "\033[92m"  
            elif 200 <= status_code < 300:
                color = "\033[92m"  
            elif 300 <= status_code < 400:
                color = "\033[91m"  
            elif 400 <= status_code < 500:
                color = "\033[93m"  
            else:
                color = "\033[95m" 
           
            # output directory and status code dengan color 
            print(f"  - {target_url} - {color}{status_code}\033[0m") 

        except requests.exceptions.RequestException:
            pass  # Abaikan jika tidak dapat diakses


def main():
    if len(sys.argv) != 2:
        print("Penggunaan: python3 open_directory_scanner.py <URL>")
        return

    url = sys.argv[1]
    check_open_directories(url)

if __name__ == "__main__":
    main()
