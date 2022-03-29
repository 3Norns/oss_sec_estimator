import requests
from bs4 import BeautifulSoup
from main.constants import HTTP_REQUEST_HEADER
from main.run import get_repository
import os

os.environ["http_proxy"] = "http://127.0.0.1:33210"
os.environ["https_proxy"] = "http://127.0.0.1:33210"

url = "https://cve.mitre.org/cgi-bin/cvename.cgi"
unfixed_vulnerability_numbers = []
repo = get_repository("https://github.com/microweber/microweber")

response = requests.get(url=url, headers=HTTP_REQUEST_HEADER, params={"name": "CVE-2018-1000826"})
if response.status_code == 200:
    html = response.text
    bs = BeautifulSoup(html, "html.parser")
    result_set = bs.select("li a[target='_blank']")
    for result in result_set:
        href = result.attrs["href"]
        expected_issue_path = f"https://github.com/microweber/microweber/issues"
        if expected_issue_path in href:
            repo_contributors = repo.get_contributors()
            issue_number = href.split("/")[-1].strip()
            issue = repo.get_issue(issue_number)
            state = issue.state
            if "closed" in state:
                continue
            else:
                comments = issue.get_comments()
                # see if any contributor comment to this issue
                flag = False
                for comment in comments:
                    comment_user = comment.user.name
                    for contributor in repo_contributors:
                        contributor_name = contributor.name
                        if comment_user is contributor_name:
                            flag = True
                            break

                if flag:
                    continue

else:
    raise Exception("CVE info query error, status code:" + str(response.status_code))