import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def validate_hsts(url):
    result = {
        "url": url,
        "hsts_enabled": False,
        "hsts_header": None,
        "max_age": None,
        "includesubdomains": False,
        "preload": False,
        "redirect_http_to_https": False,
        "observations": []
    }

    try:
      
        response = requests.get("http://" + url, allow_redirects=False, verify=False)
        if response.status_code == 301 and "Location" in response.headers:
            result["redirect_http_to_https"] = response.headers["Location"].startswith("https://")

    
        response = requests.get("https://" + url, verify=False)
        if "Strict-Transport-Security" in response.headers:
            result["hsts_enabled"] = True
            result["hsts_header"] = response.headers["Strict-Transport-Security"]

            for directive in result["hsts_header"].split(';'):
                if directive.startswith("max-age="):
                    result["max_age"] = int(directive.split('=')[1])
                if directive.strip() == "includeSubDomains":
                    result["includesubdomains"] = True
                if directive.strip() == "preload":
                    result["preload"] = True

      
        if not result["redirect_http_to_https"]:
            result["observations"].append("Situs tidak mengalihkan dari HTTP ke HTTPS.")
        if result["hsts_enabled"] and result["max_age"] < 31536000:  # Kurang dari 1 tahun
            result["observations"].append("Max-age HSTS kurang dari 1 tahun.")
        if result["hsts_enabled"] and not result["includesubdomains"]:
            result["observations"].append("HSTS tidak mencakup subdomain.")

    except requests.exceptions.RequestException as e:
        result["observations"].append(f"Error saat melakukan permintaan: {e}")

    return result

# Contoh Penggunaan
url = "situ2.unpas.ac.id"
result = validate_hsts(url)
print(result)
