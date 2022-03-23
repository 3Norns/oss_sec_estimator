"""

Main script for calculating open source software security score.

"""

import requests
import urllib
from constants import *
import time
import datetime
import github
import os
import json
from bs4 import BeautifulSoup
from urllib.parse import quote
import re

_CACHED_GITHUB_TOKEN = None
_CACHED_GITHUB_TOKEN_OBJ = None

PARAMS = {
    "basic_information": [
        "name", "description", "created_since", "main_language", "star_count", "watcher_count", "clone_count",
        "contributor_count", "organization_count", "dependency_count"
    ],
    "vulnerability_related_params": [
        "history_vulnerability_count", "unfixed_vulnerability_count", "dependency_vulnerability_count",
        "history_vulnerability_severity", "unfixed_vulnerability_severity", "vulnerability_exploit_ability"
    ],
    "project_vitality_params": [
        "commit_count", "security_related_commit_count", "issue_count", "closed_issue_count", "pull_request_count",
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
    def contributor_count(self):
        raise NotImplementedError

    @property
    def organization_count(self):
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
    def vulnerability_exploit_ability(self):
        raise NotImplementedError

    @property
    def commit_count(self):
        raise NotImplementedError

    @property
    def security_related_commit_count(self):
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
    def comment_count(self):
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

    @property
    def contributor_background(self):
        raise NotImplementedError

    @property
    def contribution_centralization(self):
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
    def cii_best_prectice(self):
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
    def contributor_count(self):
        try:
            return self._repo.get_contributors(anon='true').totalCount
        except Exception:
            # Very large number of contributors, i.e. 5000+. Cap at 5,000.
            return 5000

    @property
    def org_count(self):

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

        self._vulnerability_cve_numbers = self._get_vulnerability_cve_numbers()
        return len(self._vulnerability_cve_numbers)

    @property
    def unfixed_vulnerability_count(self):
        if self._unfixed_vulnerability_numbers:
            return self._vulnerability_cve_numbers

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
                result_set = bs.select("tr > td > ul > li > a[target='_blank']")
                for result in result_set:
                    pass
            else:
                raise Exception("CVE info query error, status code:" + str(response.status_code))

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


def main():
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
    print(repo.unfixed_vulnerability_count)
    pass


if __name__ == "__main__":
    # http(s) proxy setting
    os.environ["http_proxy"] = "http://127.0.0.1:33210"
    os.environ["https_proxy"] = "http://127.0.0.1:33210"

    main()
