import requests

url = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=alanaktion/phproject"

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36"
}

response = requests.get(url=url, headers=headers)
html = response.text

print(html)