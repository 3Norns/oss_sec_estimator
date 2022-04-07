import os
import requests
import re
import pandas
import pymysql
import json
from bs4 import BeautifulSoup

ROW_THRESHOLD = 10000
COMMIT_REF_REGEX = r"https://github.com/[\w\.-]+/[\w\.-]+/commit"
ISSUE_REF_REGEX = r"https://github.com/[\w\.-]+/[\w\.-]+/issues"
RELEASE_REF_REGEX = r"https://github.com/[\w\.-]+/[\w\.-]+/releases"
ADVISORY_REF_REGEX = r"https://github.com/[\w\.-]+/[\w\.-]+/security/advisories"
PULL_REF_REGEX = r"https://github.com/[\w\.-]+/[\w\.-]+/pull"
HUNTR_REF_REGEX = r"https://huntr.dev/bounties"


def retrieve_data_from_nvd_db():
    nvd_api_key = os.getenv("NVD_API_KEY")
    assert nvd_api_key, "NVD_API_KEY needs to be set."
    nvd_request_url = "https://services.nvd.nist.gov/rest/json/cves/1.0/"
    result_per_page = 2000 if 2000 < ROW_THRESHOLD else ROW_THRESHOLD
    params = {
        "keyword": "github",
        "apiKey": nvd_api_key,
        "resultsPerPage": result_per_page
    }
    response = requests.get(url=nvd_request_url, params=params)
    data = json.loads(response.content)
    start_index = data["startIndex"]
    total_result = data["totalResults"]
    df = pandas.DataFrame(columns=("CVE ID", "REFER TO COMMIT", "REFER TO ISSUE", "REFER TO RELEASE",
                                   "REFER TO ADVISORY", "REFER TO PULL", "REFER TO HUNTR"))
    row_count = 0
    reach_limitation = False
    while start_index < total_result:
        if reach_limitation:
            break

        if start_index:
            params["startIndex"] = start_index
            data = json.loads(requests.get(url=nvd_request_url, params=params).content)
            _result = data["result"]
        else:
            _result = data["result"]

        items = _result["CVE_Items"]
        for item in items:
            cve_number = item.get("cve").get("CVE_data_meta").get("ID")
            row = {"CVE ID": cve_number, "REFER TO COMMIT": [0], "REFER TO ISSUE": [0], "REFER TO RELEASE": [0],
                   "REFER TO ADVISORY": [0], "REFER TO PULL": [0], "REFER TO HUNTR": [0]}
            references = item.get("cve").get("references").get("reference_data")
            for reference in references:
                url = reference.get("url")
                if re.search(COMMIT_REF_REGEX, url) and not row["REFER TO COMMIT"][0]:
                    row["REFER TO COMMIT"][0] = 1
                    continue

                if re.search(ISSUE_REF_REGEX, url) and not row["REFER TO ISSUE"][0]:
                    row["REFER TO ISSUE"][0] = 1
                    continue

                if re.search(RELEASE_REF_REGEX, url) and not row["REFER TO RELEASE"][0]:
                    row["REFER TO RELEASE"][0] = 1
                    continue

                if re.search(ADVISORY_REF_REGEX, url) and not row["REFER TO ADVISORY"][0]:
                    row["REFER TO ADVISORY"][0] = 1
                    continue

                if re.search(PULL_REF_REGEX, url) and not row["REFER TO PULL"][0]:
                    row["REFER TO PULL"][0] = 1
                    continue

                if re.search(HUNTR_REF_REGEX, url) and not row["REFER TO HUNTR"][0]:
                    row["REFER TO HUNTR"][0] = 1
                    continue

            df_pai = pandas.DataFrame(row)
            df = pandas.concat([df, df_pai], ignore_index=True)
            row_count += 1
            if row_count >= ROW_THRESHOLD:
                reach_limitation = True
                break

        start_index += result_per_page

    # export to csv
    df.to_csv("../dataset/report_fix_survey.csv")


def retrieve_data_from_mysql():
    conn = pymysql.connect(
        host="localhost",
        user="root",
        password="SteinsGate0",
        database="oss_security_estimator",
        charset="utf8"
    )
    cursor = conn.cursor()
    sql = f"select cve_number from project_cve_table limit {ROW_THRESHOLD}"
    cursor.execute(sql)
    cve_number_tuples = cursor.fetchall()
    cursor.close()
    conn.close()
    df = pandas.DataFrame(columns=("CVE ID", "REFER TO COMMIT", "REFER TO ISSUE", "REFER TO RELEASE",
                                   "REFER TO ADVISORY", "REFER TO PULL", "REFER TO HUNTR"))
    row_count = 0
    for cve_number_tuple in cve_number_tuples:
        cve_number = cve_number_tuple[0]
        row = {"CVE ID": cve_number, "REFER TO COMMIT": [0], "REFER TO ISSUE": [0], "REFER TO RELEASE": [0],
               "REFER TO ADVISORY": [0], "REFER TO PULL": [0], "REFER TO HUNTR": [0]}
        cve_request_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_number}"
        response = requests.get(cve_request_url)
        if response.status_code == 200:
            html = response.text
            bs = BeautifulSoup(html, "html.parser")
            ref_set = bs.select("li a[target='_blank']")
            for ref in ref_set:
                href = ref.attrs["href"]
                if re.search(COMMIT_REF_REGEX, href) and not row["REFER TO COMMIT"][0]:
                    row["REFER TO COMMIT"][0] = 1
                    continue

                if re.search(ISSUE_REF_REGEX, href) and not row["REFER TO ISSUE"][0]:
                    row["REFER TO ISSUE"][0] = 1
                    continue

                if re.search(RELEASE_REF_REGEX, href) and not row["REFER TO RELEASE"][0]:
                    row["REFER TO RELEASE"][0] = 1
                    continue

                if re.search(ADVISORY_REF_REGEX, href) and not row["REFER TO ADVISORY"][0]:
                    row["REFER TO ADVISORY"][0] = 1
                    continue

                if re.search(PULL_REF_REGEX, href) and not row["REFER TO PULL"][0]:
                    row["REFER TO PULL"][0] = 1
                    continue

                if re.search(HUNTR_REF_REGEX, href) and not row["REFER TO HUNTR"][0]:
                    row["REFER TO HUNTR"][0] = 1
                    continue

            df_pai = pandas.DataFrame(row)
            df = pandas.concat([df, df_pai], ignore_index=True)
            row_count += 1
            if row_count >= ROW_THRESHOLD:
                break

        else:
            raise Exception("cve query error")

    # nvd_api_key = os.getenv("NVD_API_KEY")
    # assert nvd_api_key, "NVD_API_KEY needs to be set."
    # for cve_number_tuple in cve_number_tuples:
    #     cve_number = cve_number_tuple[0]
    #     row = {"CVE ID": cve_number, "REFER TO COMMIT": [0], "REFER TO ISSUE": [0], "REFER TO RELEASE": [0],
    #            "REFER TO ADVISORY": [0], "REFER TO PULL": [0], "REFER TO HUNTR": [0]}
    #     url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_number}"
    #     params = {
    #         "q": "CVE",
    #         "apiKey": nvd_api_key
    #     }
    #     response = requests.get(url=url, params=params)
    #     data = json.loads(response.content)
    #     references = (data.get("result").get("CVE_Items"))[0].get("cve").get("references").get("reference_data")
    #     for reference in references:
    #         url = reference.get("url")
    #         if re.search(COMMIT_REF_REGEX, url) and not row["REFER TO COMMIT"][0]:
    #             row["REFER TO COMMIT"][0] = 1
    #             continue
    #
    #         if re.search(ISSUE_REF_REGEX, url) and not row["REFER TO ISSUE"][0]:
    #             row["REFER TO ISSUE"][0] = 1
    #             continue
    #
    #         if re.search(RELEASE_REF_REGEX, url) and not row["REFER TO RELEASE"][0]:
    #             row["REFER TO RELEASE"][0] = 1
    #             continue
    #
    #         if re.search(ADVISORY_REF_REGEX, url) and not row["REFER TO ADVISORY"][0]:
    #             row["REFER TO ADVISORY"][0] = 1
    #             continue
    #
    #         if re.search(PULL_REF_REGEX, url) and not row["REFER TO PULL"][0]:
    #             row["REFER TO PULL"][0] = 1
    #             continue
    #
    #         if re.search(HUNTR_REF_REGEX, url) and not row["REFER TO HUNTR"][0]:
    #             row["REFER TO HUNTR"][0] = 1
    #             continue
    #
    #     df_pai = pandas.DataFrame(row)
    #     df = pandas.concat([df, df_pai], ignore_index=True)
    #     row_count += 1
    #     if row_count >= ROW_THRESHOLD:
    #         break

    # export to csv
    df.to_csv("../dataset/report_fix_survey2.csv")


if __name__ == "__main__":
    os.environ["http_proxy"] = "http://127.0.0.1:33210"
    os.environ["https_proxy"] = "http://127.0.0.1:33210"
    retrieve_data_from_nvd_db()
    retrieve_data_from_mysql()
