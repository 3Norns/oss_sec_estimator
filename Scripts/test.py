import requests
from bs4 import BeautifulSoup
import datetime
import os

# relate to network operation
os.environ["http_proxy"] = "http://127.0.0.1:33210"
os.environ["https_proxy"] = "http://127.0.0.1:33210"

response = requests.get("https://github.com/podium-lib/proxy/security/advisories/GHSA-3hjg-vc7r-rcrw")
if response.status_code == 200:
    html = response.text
    bs = BeautifulSoup(html, "html.parser")
    result = bs.find(name="relative-time").attrs["datetime"]
    advisory_data = datetime.datetime.strptime(result, "%Z")
else:
    advisory_date = datetime.datetime.strptime("1970-1-1 0:00:00", "%Y-%m-%dT%H:%M:%SZ")