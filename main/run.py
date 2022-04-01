"""

Main script for calculating open source software security score.

"""
from abc import ABC

import requests
import urllib
from main.constants import *
import time
import datetime
import github
import os
import json
from bs4 import BeautifulSoup
from urllib.parse import quote
import re
import git

_CACHED_GITHUB_TOKEN = None
_CACHED_GITHUB_TOKEN_OBJ = None

PARAMS = {
    "basic_information": [
        "name", "description", "created_since", "main_language", "star_count", "watcher_count", "clone_count",
        "dependency_count"
    ],
    "vulnerability_related_params": [
        "history_vulnerability_count", "unfixed_vulnerability_count", "dependency_vulnerability_count",
        "history_vulnerability_severity", "unfixed_vulnerability_severity"
    ],
    "project_vitality_params": [
        "commit_count", "commit_frequency", "issue_count", "closed_issue_count", "pull_request_count",
        "release_count", "comment_frequency", "updated_since", "vulnerability_fix_timeliness"
    ],
    "contributor_related_params": [
        "contributor_count", "organization_count", "contributor_capacity", "contributor_background",
        "contribution_centralization", "organization_centralization"
    ],
    "practice_related_params": [
        "binary_artifact", "branch_protection", "ci_test", "cii_best_practice", "code_review", "dependency_update_tool",
        "maintained", "packaging", "pinned_dependency", "sast", "security_policy", "signed_release", "token_permission"
    ],
    "code_related_params": [
        "code_complexity", "code_standardization", "code_obfuscation"
    ]
}


# definition of general source repository
class Repository:

    def __init__(self, repo):
        self._repo = repo
        self._dependencies = []
        self._vulnerability_cve_numbers = []
        self._unfixed_vulnerability_numbers = []

    @property
    def name(self):
        raise NotImplementedError

    @property
    def url(self):
        raise NotImplementedError

    @property
    def description(self):
        raise NotImplementedError

    @property
    def created_since(self):
        raise NotImplementedError

    @property
    def main_language(self):
        raise NotImplementedError

    @property
    def star_count(self):
        raise NotImplementedError

    @property
    def watcher_count(self):
        raise NotImplementedError

    @property
    def clone_count(self):
        raise NotImplementedError

    @property
    def dependency_count(self):
        raise NotImplementedError

    @property
    def history_vulnerability_count(self):
        raise NotImplementedError

    @property
    def unfixed_vulnerability_count(self):
        raise NotImplementedError

    @property
    def dependency_vulnerability_count(self):
        raise NotImplementedError

    @property
    def history_vulnerability_severity(self):
        raise NotImplementedError

    @property
    def unfixed_vulnerability_severity(self):
        raise NotImplementedError

    @property
    def commit_count(self):
        raise NotImplementedError

    @property
    def commit_frequency(self):
        raise NotImplementedError

    @property
    def issue_count(self):
        raise NotImplementedError

    @property
    def closed_issue_count(self):
        raise NotImplementedError

    @property
    def pull_request_count(self):
        raise NotImplementedError

    @property
    def release_count(self):
        raise NotImplementedError

    @property
    def comment_frequency(self):
        raise NotImplementedError

    @property
    def updated_since(self):
        raise NotImplementedError

    @property
    def vulnerability_fix_timeliness(self):
        raise NotImplementedError

    @property
    def contributor_count(self):
        raise NotImplementedError

    @property
    def organization_count(self):
        raise NotImplementedError

    @property
    def contributor_capacity(self):
        raise NotImplementedError

    # @property
    # def contributor_background(self):
    #     raise NotImplementedError

    @property
    def contribution_centrality(self):
        raise NotImplementedError

    @property
    def organization_centralization(self):
        raise NotImplementedError

    @property
    def binary_artifact(self):
        raise NotImplementedError

    @property
    def branch_protection(self):
        raise NotImplementedError

    @property
    def ci_test(self):
        raise NotImplementedError

    @property
    def cii_best_practice(self):
        raise NotImplementedError

    @property
    def code_review(self):
        raise NotImplementedError

    @property
    def dependency_update_tool(self):
        raise NotImplementedError

    @property
    def maintained(self):
        raise NotImplementedError

    @property
    def packaging(self):
        raise NotImplementedError

    @property
    def pinned_dependency(self):
        raise NotImplementedError

    @property
    def sast(self):
        raise NotImplementedError

    @property
    def security_polity(self):
        raise NotImplementedError

    @property
    def signed_release(self):
        raise NotImplementedError

    @property
    def token_permission(self):
        raise NotImplementedError

    @property
    def code_complexity(self):
        raise NotImplementedError

    @property
    def code_standardization(self):
        raise NotImplementedError

    @property
    def code_obfuscation(self):
        raise NotImplementedError


# source repository on github
class GitHubRepository(Repository):

    @property
    def name(self):
        return self._repo.name

    @property
    def url(self):
        return self._repo.url

    @property
    def description(self):
        return self._repo.description

    def _request_url_with_auth_header(self, url):
        headers = {}
        if 'github.com' in url and _CACHED_GITHUB_TOKEN:
            headers = {'Authorization': f'token {_CACHED_GITHUB_TOKEN}'}

        return requests.get(url, headers=headers)

    def _get_first_commit_time(self):

        def __parse_links(response):
            link_string = response.headers.get("Link")
            if not link_string:
                return None

            links = {}
            for part in link_string.split(','):
                match = re.match(r'<(.*)>; rel="(.*)"', part.strip())
                if match:
                    links[match.group(2)] = match.group(1)
            return links

        for i in range(FAIL_RETRIES):
            result = self._request_url_with_auth_headers(
                f'{self._repo.url}/commits')
            links = __parse_links(result)
            if links and links.get('last'):
                result = self._request_url_with_auth_headers(links['last'])
            if result.status_code == 200:
                commits = json.loads(result.content)
                if commits:
                    last_commit_time_string = (
                        commits[-1]['commit']['committer']['date'])
                    return datetime.datetime.strptime(last_commit_time_string,
                                                      "%Y-%m-%dT%H:%M:%SZ")
            time.sleep(2 ** i)

        return None

    @property
    def created_since(self):
        creation_time = self._repo.created_at

        # See if there are exist any commits before this repository creation
        # time on GitHub. If yes, then the repository creation time is not
        # correct, and it was residing somewhere else before. So, use the first
        # commit date.
        if self._repo.get_commits(until=creation_time).totalCount:
            first_commit_time = self._get_first_commit_time()
            if first_commit_time:
                creation_time = min(creation_time, first_commit_time)

        difference = datetime.datetime.utcnow() - creation_time
        return round(difference.days / 30)

    @property
    def main_language(self):
        return self._repo.language

    @property
    def star_count(self):
        return self._repo.stargazers_count

    @property
    def watcher_count(self):
        return self._repo.subscribers_count

    @property
    def clone_count(self):
        return self._repo.forks_count

    @property
    def dependency_count(self):
        if self._dependencies:
            return len(self._dependencies)

        url = self._repo.html_url + "/network/dependencies"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/99.0.4844.74 Safari/537.36 "
        }
        response = requests.get(url=url, headers=headers)
        dependencies = []
        if response.status_code == 200:
            html = response.text
            bs = BeautifulSoup(html, "html.parser")
            result_set = bs.find_all(name="a", attrs={"data-octo-click": "dep_graph_package"})
            for result in result_set:
                dependency = result.attrs["href"].split("/", 1)[1]
                dependencies.append(dependency)
        else:
            raise Exception("page didn't properly loaded, status code:" + str(response.status_code))

        self._dependencies = dependencies

        return len(dependencies)

    def _get_vulnerability_cve_numbers(self):

        def __pad_params(value):
            return {
                "keyword": quote(value)
            }

        vulnerability_cve_numbers = []
        url = "https://cve.mitre.org/cgi-bin/cvekey.cgi"

        response = requests.get(url=url, headers=HTTP_REQUEST_HEADER, params=__pad_params(self._repo.full_name))
        if response.status_code == 200:
            html = response.text
            bs = BeautifulSoup(html, "html.parser")
            cve_number_regex = re.compile("CVE-[0-9]{4}-[0-9]{4,}")
            result_set = bs.find_all(name="a", text=cve_number_regex)
            for result in result_set:
                cve_number = result.text.strip()
                vulnerability_cve_numbers.append(cve_number)

        else:
            raise Exception("history vulnerability query error, status code:" + str(response.status_code))

        return vulnerability_cve_numbers

    @property
    def history_vulnerability_count(self):
        if self._vulnerability_cve_numbers:
            return len(self._vulnerability_cve_numbers)

        try:
            self._vulnerability_cve_numbers = self._get_vulnerability_cve_numbers()
        except Exception:
            self._vulnerability_cve_numbers = []

        return len(self._vulnerability_cve_numbers)

    def _get_branches_contain_given_commit(self, commit_sha):
        git_instance = git.Git(TEMP_REPOSITORY_PATH)
        return git_instance.branch("--contains", commit_sha)

    @property
    def unfixed_vulnerability_count(self):
        if self._unfixed_vulnerability_numbers:
            return len(self._unfixed_vulnerability_numbers)

        # collecting unfixed cve vulnerability
        unfixed_vulnerability_numbers = []
        if self._vulnerability_cve_numbers:
            vulnerability_cve_numbers = self._vulnerability_cve_numbers
        else:
            vulnerability_cve_numbers = self._get_vulnerability_cve_numbers()

        def __pad_params(value):
            return {
                "name": value
            }

        url = "https://cve.mitre.org/cgi-bin/cvename.cgi"
        for cve_number in vulnerability_cve_numbers:
            # see if there is a commit for the CVE
            response = requests.get(url=url, headers=HTTP_REQUEST_HEADER, params=__pad_params(cve_number))
            if response.status_code == 200:
                html = response.text
                bs = BeautifulSoup(html, "html.parser")
                result_set = bs.select("li a[target='_blank']")
                for result in result_set:
                    href = result.attrs["href"]
                    expected_commit_path = f"https://github.com/{self._repo.full_name}/commit"
                    if expected_commit_path in href:
                        # query commit
                        commit_sha = href.split("/")[-1].strip()
                        branches = self._get_branches_contain_given_commit(commit_sha)
                        default_branch = self._repo.default_branch
                        if default_branch not in branches:
                            unfixed_vulnerability_numbers.append(cve_number)

                        continue

                    expected_issue_path = f"https://github.com/{self._repo.full_name}/issues"
                    if expected_issue_path in href:
                        contributors = self._repo.get_contributors()
                        issue_number = int(href.split("/")[-1].strip())
                        issue = self._repo.get_issue(issue_number)
                        state = issue.state
                        if "closed" in state:
                            continue
                        else:
                            comments = issue.get_comments()
                            # see if any contributor comment to this issue
                            flag = False
                            for comment in comments:
                                comment_user = comment.user
                                if comment_user in contributors:
                                    flag = True

                        if flag:
                            continue

                    unfixed_vulnerability_numbers.append(cve_number)

            else:
                raise Exception("CVE info query error, status code:" + str(response.status_code))

            self._unfixed_vulnerability_numbers = unfixed_vulnerability_numbers

            return len(self._unfixed_vulnerability_numbers)

    @property
    def dependency_vulnerability_count(self):
        if not self._dependencies:
            self.dependency_count

        total_vul_count = 0
        for dependency in self._dependencies:
            repo = get_repository(f"https://github.com/{dependency}")
            repo_vul_count = repo.history_vulnerability_count
            total_vul_count += repo_vul_count

        return total_vul_count

    @property
    def history_vulnerability_severity(self):
        if not self._vulnerability_cve_numbers:
            self.history_vulnerability_count

        nvd_api_key = os.getenv("NVD_API_KEY")
        assert nvd_api_key, "NVD_API_KEY needs to be set."
        effective_vul_count = 0
        total_cvss_score = 0
        for cve_number in self._vulnerability_cve_numbers:
            nvd_api_request_url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_number}?apiKey={nvd_api_key}"
            params = {"q": "CVE"}
            response = requests.get(url=nvd_api_request_url, params=params)
            if response.status_code == 200:
                data = json.loads(response.content)
                cve_item_impact = data.get("result").get("CVE_Items")[0].get("impact")
                if "baseMetricV3" in cve_item_impact:
                    base_score = cve_item_impact.get("baseMetricV3").get("cvssV3").get("baseScore")
                    effective_vul_count += 1
                    total_cvss_score += base_score
                else:
                    continue

            else:
                raise Exception("NVD query error.")

        return round(total_cvss_score / effective_vul_count, 2)

    @property
    def unfixed_vulnerability_severity(self):
        if not self._unfixed_vulnerability_numbers:
            self.unfixed_vulnerability_count

        nvd_api_key = os.getenv("NVD_API_KEY")
        assert nvd_api_key, "NVD_API_KEY needs to be set."
        effective_vul_count = 0
        total_cvss_score = 0
        for cve_number in self._unfixed_vulnerability_numbers:
            nvd_api_request_url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_number}?apiKey={nvd_api_key}"
            params = {"q": "CVE"}
            response = requests.get(url=nvd_api_request_url, params=params)
            if response.status_code == 200:
                data = json.loads(response.content)
                cve_item_impact = data.get("result").get("CVE_Items")[0].get("impact")
                if "baseMetricV3" in cve_item_impact:
                    base_score = cve_item_impact.get("baseMetricV3").get("cvssV3").get("baseScore")
                    effective_vul_count += 1
                    total_cvss_score += base_score
                else:
                    continue

            else:
                raise Exception("NVD query error.")

        return round(total_cvss_score / effective_vul_count, 2)

    @property
    def commit_count(self):
        # total commit of all time
        return self._repo.get_commits().totalCount

    @property
    def commit_frequency(self):
        # list the last year of commit activity grouped by week
        total = 0
        for week_stat in self._repo.get_stats_commit_activity():
            total += week_stat

        return round(total / 52, 1)

    @property
    def issue_count(self):
        issues_since_time = datetime.datetime.utcnow() - datetime.timedelta(days=ISSUE_LOOKBACK_DAYS)
        return self._repo.get_issues(state="all", since=issues_since_time).totalCOunt

    @property
    def closed_issue_count(self):
        def issue_count(self):
            issues_since_time = datetime.datetime.utcnow() - datetime.timedelta(days=ISSUE_LOOKBACK_DAYS)
            return self._repo.get_issues(state="closed", since=issues_since_time).totalCOunt

    @property
    def pull_request_count(self):
        return self._repo.get_pulls(state="all").totalCount

    @property
    def release_count(self):
        total = 0
        for release in self._repo.get_releases():
            if (datetime.datetime.utcnow() - release.created_at).days < RELEASE_LOOKBACK_DAYS:
                total += 1

        if not total:
            # make a estimation of release over the last 90 days
            days_since_creation = self.created_since * 30
            if not days_since_creation:
                return 0
            try:
                total_tags = self._repo.get_tags().totalCount
            except Exception:
                # Very large number of tags, i.e. 5000+. Cap at 26.
                return RECENT_RELEASES_THRESHOLD

            total = (total_tags / days_since_creation) * RELEASE_LOOKBACK_DAYS

        return total

    @property
    def comment_frequency(self):
        issues_since_time = datetime.datetime.utcnow() - datetime.timedelta(
            days=ISSUE_LOOKBACK_DAYS)
        issue_count = self._repo.get_issues(state='all',
                                            since=issues_since_time).totalCount
        if not issue_count:
            return 0

        comment_count = self._repo.get_issues_comments(
            since=issues_since_time).totalCount

        return round(comment_count / issue_count, 1)

    @property
    def updated_since(self):
        last_commit = self._repo.get_commits()[0]
        last_commit_time = last_commit.commit.committer.date
        time_delta = datetime.datetime.utcnow() - last_commit_time

        return time_delta.days

    @property
    def vulnerability_fix_timeliness(self):
        # start date: CVE record release date, issue opened date, and the date report on huntr.dev
        # fix date: commit date, issue closed date, the date release security advisory

        if not self._vulnerability_cve_numbers:
            self.history_vulnerability_count

        total_days = 0
        for cve_number in self._vulnerability_cve_numbers:
            # CVE record release date
            url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_number}"
            response = requests.get(url=url, headers=HTTP_REQUEST_HEADER)
            if response.status_code == 200:
                html = response.text
                bs = BeautifulSoup(html, "html.parser")
                record_release_date_regex = re.compile("[0-9]{8}")
                result = bs.find(name="b", text=record_release_date_regex).text
                ref_set = bs.select("li a[target='_blank']")
                cve_release_date = datetime.datetime.strptime(f"{result[0: 4]}-{result[4: 6]}-{result[6:]}", "%Y-%m"
                                                                                                             "-%d")
            else:
                raise Exception("CVE query error.")

            issue_href = None
            huntr_href = None
            commit_href = None
            # advisory_href = None
            # TODO: add feature the date that release a security advisory

            for ref in ref_set:
                href = ref.attrs["href"]
                expected_issue_path = f"https://github.com/{self._repo.full_name}/issues"
                if expected_issue_path in href:
                    issue_href = href

                expected_huntr_path = "https://huntr.dev/bounties"
                if expected_huntr_path in href:
                    huntr_href = href

                expected_commit_path = f"https://github.com/{self._repo.full_name}/commit"
                if expected_commit_path in href:
                    commit_href = expected_commit_path

            # issue opened date
            if issue_href:
                issue_number = int(issue_href.split("/")[-1].strip())
                issue = self._repo.get_issue(issue_number)
                issue_opened_date = issue.created_at
            else:
                issue_opened_date = datetime.datetime.utcnow()

            # huntr report date
            if huntr_href:
                response = requests.get(url=huntr_href, headers=HTTP_REQUEST_HEADER)
                if response.status_code == 200:
                    html = response.text
                    bs = BeautifulSoup(html, "html.parser")
                    result = bs.find(name="p", text="Reported on").findNext("p").text.strip()
                    splitted_result = result.split(" ", 2)
                    formatted_result = f"{splitted_result[0]} {splitted_result[1][: -2]} {splitted_result[2]}"
                    huntr_report_date = datetime.datetime.strptime(formatted_result, "%b %d %Y")
                else:
                    raise Exception("huntr.dev query error.")
            else:
                huntr_report_date = datetime.datetime.utcnow()

            # commit date
            if commit_href:
                commit_sha = href.split("/")[-1].strip()
                commit = self._repo.get_commit(commit_sha)
                commit_date = commit.commit.author.date
            else:
                commit_date = datetime.datetime.strptime("1970-1-1 0:00:00", "%Y-%m-%d %H:%M:%S")

            # issue close date
            if issue_href:
                issue_closed_date = issue.closed_at
                if issue_closed_date:
                    issue_closed_date = datetime.datetime.strptime("1970-1-1 0:00:00", "%Y-%m-%d %H:%M:%S")

            else:
                issue_closed_date = datetime.datetime.strptime("1970-1-1 0:00:00", "%Y-%m-%d %H:%M:%S")

            reported_date = min(cve_release_date, issue_opened_date, huntr_report_date)
            fix_date = max(commit_date, issue_closed_date)
            time_gap = max((fix_date - reported_date).days, 0)
            total_days += time_gap

        return round(total_days / len(self._vulnerability_cve_numbers), 2)

    @property
    def contributor_count(self):
        try:
            return self._repo.get_contributors(anon='true').totalCount
        except Exception:
            # Very large number of contributors, i.e. 5000+. Cap at 5,000.
            return 5000

    @property
    def organization_count(self):

        def __filter_name(org_name):
            return org_name.lower().replace('inc.', '').replace(
                'llc', '').replace('@', '').replace(' ', '').rstrip(',')

        orgs = set()
        contributors = self._repo.get_contributors()[:TOP_CONTRIBUTOR_COUNT]
        try:
            for contributor in contributors:
                if contributor.company:
                    orgs.add(__filter_name(contributor.company))
        except Exception:
            # Very large number of contributors, i.e. 5000+. Cap at 10.
            return 10
        return len(orgs)

    @property
    def contributor_capacity(self):
        contributors = self._repo.get_contributors()
        valid_contributor_count = 0
        follower_count = 0
        for contributor in contributors:
            contributions = contributor.contributions
            if contributions < 50:
                continue

            valid_contributor_count += 1
            company = contributor.company
            if company:
                follower_count += contributor.followers
            else:
                follower_count += round(contributor.followers * 0.5)

        return round(follower_count / valid_contributor_count, 2)

    @property
    def contribution_centrality(self):
        pass


# return expiry information of the given github token
def get_github_token_info(token_obj):
    rate_limit = token_obj.get_rate_limit()
    near_expiry = rate_limit.core.remaining < 50
    wait_time = (rate_limit.core.reset - datetime.datetime.utcnow()).seconds
    return near_expiry, wait_time


# get a github authorization token
def get_github_auth_token():
    global _CACHED_GITHUB_TOKEN
    global _CACHED_GITHUB_TOKEN_OBJ
    if _CACHED_GITHUB_TOKEN_OBJ:
        near_expiry, _ = get_github_token_info(_CACHED_GITHUB_TOKEN_OBJ)
        if not near_expiry:
            return _CACHED_GITHUB_TOKEN_OBJ

    github_auth_token = os.getenv("GITHUB_AUTH_TOKEN")
    assert github_auth_token, "GITHUB_AUTH_TOKEN needs to be set."
    tokens = github_auth_token.split(',')

    min_wait_time = None
    token_obj = None
    for token in tokens:
        token_obj = github.Github(token)
        near_expiry, wait_time = get_github_token_info(token_obj)
        if not min_wait_time or wait_time < min_wait_time:
            min_wait_time = wait_time
        if not near_expiry:
            _CACHED_GITHUB_TOKEN = token
            _CACHED_GITHUB_TOKEN_OBJ = token_obj
            return token_obj

    time.sleep(min_wait_time)
    return token_obj


# return repository object, given a url
def get_repository(url):
    if "://" not in url:
        url = "https://" + url

    parsed_url = urllib.parse.urlparse(url)
    repo_url = parsed_url.path.strip("/")
    if parsed_url.netloc.endswith("github.com"):
        repo = None
        try:
            repo = get_github_auth_token().get_repo(repo_url)
        except github.GithubException as e:
            if e.status == 404:
                return None
        return GitHubRepository(repo)

    raise Exception("Unsupported url!")


def init(repo_url):
    git_url = repo_url + ".git"
    if not os.path.exists(TEMP_REPOSITORY_PATH):
        os.mkdir(TEMP_REPOSITORY_PATH)

    os.system("rmdir /s /q ..\\temp_repository")

    git.Repo.clone_from(git_url, TEMP_REPOSITORY_PATH)


def close():
    os.system("rmdir /s /q ..\\temp_repository")


def main():
    # init("https://github.com/microweber/microweber")
    repo = get_repository("https://github.com/microweber/microweber")
    # print(repo.name)
    # print(repo.url)
    # print(repo.description)
    # print(repo.created_since)
    # print(repo.main_language)
    # print(repo.star_count)
    # print(repo.watcher_count)
    # print(repo.clone_count)
    # print(repo.contributor_count)
    # print(repo.dependency_count)
    # print(repo.history_vulnerability_count)
    # print(repo.unfixed_vulnerability_count)
    # print(repo.dependency_vulnerability_count)
    # print(repo.history_vulnerability_severity)
    # print(repo.commit_count)
    # print(repo.commit_frequency)
    # print(repo.issue_count)
    # print(repo.closed_issue_count)
    # print(repo.pull_request_count)
    # print(repo.vulnerability_fix_timeliness)
    print(repo.contributor_capacity)
    # close()


if __name__ == "__main__":
    # http(s) proxy setting
    os.environ["http_proxy"] = "http://127.0.0.1:33210"
    os.environ["https_proxy"] = "http://127.0.0.1:33210"

    main()
