import os
import requests
from bs4 import BeautifulSoup
import re
import pandas

ROW_THRESHOLD = 500

if __name__ == "__main__":
    os.environ["http_proxy"] = "http://127.0.0.1:33210"
    os.environ["https_proxy"] = "http://127.0.0.1:33210"
    response = requests.get(url="https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=github")

    if response.status_code == 200:
        html = response.text
        bs = BeautifulSoup(html, "html.parser")
        cve_number_regex = re.compile("CVE-[0-9]{4}-[0-9]{4,}")
        target_tag_set = bs.find_all(name="a", text=cve_number_regex)
        df = pandas.DataFrame(columns=("CVE ID", "REFER TO COMMIT", "REFER TO ISSUE", "REFER TO RELEASE",
                                       "REFER TO ADVISORY", "REFER TO HUNTR"))
        row_count = 0
        for target in target_tag_set:
            row = {}
            cve_number = target.text.strip()
            row["CVE ID"] = cve_number
            row["REFER TO COMMIT"] = [0]
            row["REFER TO ISSUE"] = [0]
            row["REFER TO RELEASE"] = [0]
            row["REFER TO ADVISORY"] = [0]
            row["REFER TO HUNTR"] = [0]
            response = requests.get(url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_number}")
            html = response.text
            bs = BeautifulSoup(html, "html.parser")
            ref_set = bs.select("li a[target='_blank']")
            commit_ref_regex = r"https://github.com/[\w\.]+/[\w\.]+/commit"
            issue_ref_regex = r"https://github.com/[\w\.]+/[\w\.]+/issues"
            release_ref_regex = r"https://github.com/[\w\.]+/[\w\.]+/releases"
            advisory_ref_regex = r"https://github.com/[\w\.]+/[\w\.]+/security/advisories"
            huntr_ref_regex = r"https://huntr.dev/bounties"
            for ref in ref_set:
                href = ref.attrs["href"]
                if re.search(commit_ref_regex, href) and not row["REFER TO COMMIT"][0]:
                    row["REFER TO COMMIT"][0] = 1
                    continue

                if re.search(issue_ref_regex, href) and not row["REFER TO ISSUE"][0]:
                    row["REFER TO ISSUE"][0] = 1
                    continue

                if re.search(release_ref_regex, href) and not row["REFER TO RELEASE"][0]:
                    row["REFER TO RELEASE"][0] = 1
                    continue

                if re.search(advisory_ref_regex, href) and not row["REFER TO ADVISORY"][0]:
                    row["REFER TO ADVISORY"][0] = 1
                    continue

                if re.search(huntr_ref_regex, href) and not row["REFER TO HUNTR"][0]:
                    row["REFER TO HUNTR"][0] = 1
                    continue

            df_pai = pandas.DataFrame(row)
            df = pandas.concat([df, df_pai], ignore_index=True)
            row_count += 1
            if row_count >= ROW_THRESHOLD:
                break

    else:
        raise Exception("page open error")

    # export to csv
    df.to_csv("../dataset/report_fix_survey.csv")
