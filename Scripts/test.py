import requests
from bs4 import BeautifulSoup
import re

url = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=Cross-site+scripting+%28XSS%29+vulnerability+in+index.php+in+Greg+Neustaetter+gCards+1.45"

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36"
}

response = requests.get(url=url, headers=headers)
html = response.text

bs = BeautifulSoup(html, "html.parser")
cve_number_regex = re.compile("CVE-[0-9]{4}-[0-9]{4,}")

cve_numbers = bs.find_all(name="a", text=cve_number_regex)
for cve_number in cve_numbers:
    print(cve_number.text)