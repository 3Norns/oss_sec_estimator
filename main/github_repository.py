"""

A subclass of Repository, the abstract of repository on GitHub.

"""

import os
import json
import time
import yaml
import github
import urllib
import datetime
import requests
from copy import deepcopy
from bs4 import BeautifulSoup
from urllib.parse import quote

from constants import *
from exceptions import *
from repository import Repository
from job_matchers import JOB_MATCHERS


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

    def _get_first_commit_time_(self):

        def _parse_links_(response):
            link_string = response.headers.get("Link")
            if not link_string:
                return None

            links_ = {}
            for part in link_string.split(','):
                match = re.match(r'<(.*)>; rel="(.*)"', part.strip())
                if match:
                    links_[match.group(2)] = match.group(1)
            return links_

        for i in range(FAIL_RETRIES):
            result = request_url_with_auth_header(
                f'{self._repo.url}/commits')
            links = _parse_links_(result)
            if links and links.get('last'):
                result = request_url_with_auth_header(links['last'])
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

        # See if there is existed any commit before this repository creation
        # time on GitHub. If yes, then the repository creation time is not
        # correct, and it was residing somewhere else before. So, use the first
        # commit date.
        if self._repo.get_commits(until=creation_time).totalCount:
            first_commit_time = self._get_first_commit_time_()
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
            raise PageOpenException(url, response.status_code)

        self._dependencies = dependencies

        return len(dependencies)

    def _get_vulnerability_cve_numbers_(self):

        def _pad_params_(value):
            return {
                "keyword": quote(value)
            }

        vulnerability_cve_numbers = []
        url = "https://cve.mitre.org/cgi-bin/cvekey.cgi"

        response = requests.get(url=url, headers=HTTP_REQUEST_HEADER, params=_pad_params_(self._repo.full_name))
        if response.status_code == 200:
            html = response.text
            bs = BeautifulSoup(html, "html.parser")
            cve_number_regex = re.compile("CVE-[0-9]{4}-[0-9]{4,}")
            result_set = bs.find_all(name="a", text=cve_number_regex)
            for result in result_set:
                cve_number = result.text.strip()
                vulnerability_cve_numbers.append(cve_number)

        else:
            raise PageOpenException(url, response.status_code)

        return vulnerability_cve_numbers

    @property
    def history_vulnerability_count(self):
        if self._vulnerability_cve_numbers:
            return len(self._vulnerability_cve_numbers)

        try:
            self._vulnerability_cve_numbers = self._get_vulnerability_cve_numbers_()
        except PageOpenException:
            self._vulnerability_cve_numbers = []

        return len(self._vulnerability_cve_numbers)

    @property
    def unfixed_vulnerability_count(self):
        if self._unfixed_vulnerability_numbers:
            return len(self._unfixed_vulnerability_numbers)

        # collecting unfixed cve vulnerability
        unfixed_vulnerability_numbers = []
        if self._vulnerability_cve_numbers:
            vulnerability_cve_numbers = self._vulnerability_cve_numbers
        else:
            vulnerability_cve_numbers = self._get_vulnerability_cve_numbers_()

        def _pad_params_(value):
            return {
                "name": value
            }

        url = "https://cve.mitre.org/cgi-bin/cvename.cgi"
        for cve_number in vulnerability_cve_numbers:
            # see if there is a commit for the CVE
            response = requests.get(url=url, headers=HTTP_REQUEST_HEADER, params=_pad_params_(cve_number))
            if response.status_code == 200:
                html = response.text
                bs = BeautifulSoup(html, "html.parser")
                result_set = bs.select("li a[target='_blank']")
                for result in result_set:
                    href = result.attrs["href"]
                    expected_commit_path = f"https://github.com/{self._repo.full_name}/commit"
                    if expected_commit_path in href:
                        unfixed_vulnerability_numbers.append(cve_number)

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

                    expected_release_path = f"https://github.com/{self._repo.full_name}/releases"
                    if expected_release_path in href:
                        continue

                    expected_pull_request_path = f"https://github.com/{self._repo.full_name}/pull"
                    if expected_pull_request_path in href:
                        continue

                    unfixed_vulnerability_numbers.append(cve_number)

            else:
                raise PageOpenException(url, response.status_code)

        self._unfixed_vulnerability_numbers = unfixed_vulnerability_numbers

        return len(self._unfixed_vulnerability_numbers)

    @property
    def dependency_vulnerability_count(self):
        if not self._dependencies:
            _ = self.dependency_count

        total_vul_count = 0
        for dependency in self._dependencies:
            repo = get_repository(f"https://github.com/{dependency}")
            repo_vul_count = repo.history_vulnerability_count
            total_vul_count += repo_vul_count

        return total_vul_count

    @property
    def history_vulnerability_severity(self):
        if not self._vulnerability_cve_numbers:
            _ = self.history_vulnerability_count

        nvd_api_key = os.getenv("NVD_API_KEY")
        assert nvd_api_key, "NVD_API_KEY needs to be set."
        effective_vul_count = 0
        total_cvss_score = 0
        for cve_number in self._vulnerability_cve_numbers:
            nvd_api_request_url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_number}"
            params = {
                "q": "CVE",
                "apiKey": nvd_api_key
            }
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
                raise NVDQueryException

        return round(total_cvss_score / effective_vul_count, 2)

    @property
    def unfixed_vulnerability_severity(self):
        if not self._unfixed_vulnerability_numbers:
            _ = self.unfixed_vulnerability_count

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
                raise NVDQueryException

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
        issues_since_time = datetime.datetime.utcnow() - datetime.timedelta(days=ISSUE_LOOKBACK_DAYS)
        return self._repo.get_issues(state="closed", since=issues_since_time).totalCount

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
            except NumberExceedCapException:
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
            _ = self.history_vulnerability_count

        if not self._unfixed_vulnerability_numbers:
            _ = self.unfixed_vulnerability_count

        total_days = 0
        for cve_number in self._vulnerability_cve_numbers:
            if cve_number in self._unfixed_vulnerability_numbers:
                continue

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
                raise PageOpenException(url, response.status_code)

            issue_href = None
            huntr_href = None
            commit_href = None
            advisory_href = None
            release_href = None
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
                    commit_href = href

                expected_advisory_path = f"https://github.com/{self._repo.full_name}/security/advisories"
                if expected_advisory_path in href:
                    advisory_href = href

                expected_release_path = f"https://github.com/{self._repo.full_name}/releases"
                if expected_release_path in href:
                    release_href = href

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
                    raise PageOpenException(huntr_href, response.status_code)

            else:
                huntr_report_date = datetime.datetime.utcnow()

            # commit date
            if commit_href:
                commit_sha = commit_href.split("/")[-1].strip()
                commit = self._repo.get_commit(commit_sha)
                commit_date = commit.commit.author.date
            else:
                commit_date = datetime.datetime.utcnow()

            # issue close date
            if issue_href:
                issue_number = int(issue_href.split("/")[-1].strip())
                issue = self._repo.get_issue(issue_number)
                issue_closed_date = issue.closed_at
                if issue_closed_date:
                    issue_closed_date = datetime.datetime.utcnow()

            else:
                issue_closed_date = datetime.datetime.utcnow()

            # security advisory publish date
            if advisory_href:
                response = requests.get(advisory_href)
                if response.status_code == 200:
                    html = response.text
                    bs = BeautifulSoup(html, "html.parser")
                    result = bs.find(name="relative-time").attrs["relative-time"]
                    advisory_date = datetime.datetime.strptime(result, "%Y-%m-%dT%H:%M:%SZ")
                else:
                    advisory_date = datetime.datetime.utcnow()

            else:
                advisory_date = datetime.datetime.utcnow()

            # release date
            if release_href:
                response = requests.get(release_href)
                if response.status_code == 200:
                    html = response.text
                    bs = BeautifulSoup(html, "html.parser")
                    result = bs.find(name="relative-time").attrs["relative-time"]
                    release_date = datetime.datetime.strptime(result, "%Y-%m-%dT%H:%M:%SZ")
                else:
                    release_date = datetime.datetime.utcnow()

            else:
                release_date = datetime.datetime.utcnow()

            reported_date = min(cve_release_date, issue_opened_date, huntr_report_date)
            fix_date = min(commit_date, issue_closed_date, advisory_date, release_date)
            time_gap = max((fix_date - reported_date).days, 0)
            total_days += time_gap

        return round(total_days / len(self._vulnerability_cve_numbers), 2)

    @property
    def contributor_count(self):
        try:
            return self._repo.get_contributors(anon='true').totalCount
        except NumberExceedCapException:
            # Very large number of contributors, i.e. 5000+. Cap at 5,000.
            return 5000

    @property
    def outside_contributor_count(self):
        org = self._repo.organization.login
        outside_contributor_count = 0
        contributors = self._repo.get_contributors()
        for contributor in contributors[: 5000]:
            contributor_orgs = contributor.get_orgs()
            for contributor_org in contributor_orgs:
                if contributor_org.login == org:
                    outside_contributor_count += 1
                    break

        return outside_contributor_count

    @property
    def organization_count(self):

        def _filter_name_(org_name):
            return org_name.lower().replace('inc.', '').replace(
                'llc', '').replace('@', '').replace(' ', '').rstrip(',')

        orgs = set()
        contributors = self._repo.get_contributors()[:TOP_CONTRIBUTOR_COUNT]
        try:
            for contributor in contributors:
                if contributor.company:
                    orgs.add(_filter_name_(contributor.company))
        except NumberExceedCapException:
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
    def binary_artifact(self):
        score = MAX_SCORE

        # File suffixes are associated with binary artifacts.
        _binary_artifact_list_ = [
            "crx",
            "deb",
            "dex",
            "dey",
            "elf",
            "o",
            "so",
            "iso",
            "class",
            "jar",
            "bundle",
            "dylib",
            "lib",
            "msi",
            "dll",
            "drv",
            "efi",
            "exe",
            "ocx",
            "pyc",
            "pyo",
            "par",
            "rpm",
            "whl"
        ]

        # List all files in GitHub repository.
        default_branch = self._repo.default_branch
        files = self._repo.get_git_tree(sha=default_branch, recursive=True).tree
        for file in files:
            if file.type == "blob":
                path = file.path
                suffix = path.split(".")[-1].lower()
                if suffix in _binary_artifact_list_:
                    score -= 1

                if score <= MIN_SCORE:
                    break

        return score

    @property
    def branch_protection(self):
        # Points increment at each level
        _basic_level_ = 3  # Tier 1
        _review_level_ = 3  # Tier 2
        _context_level_ = 2  # Tier 3
        _thorough_review_level_ = 2  # Tier 4

        # Max scores for each tier.
        _max_score_for_basic_protection_ = 2
        _max_score_for_review_protection_ = 1
        _max_score_for_context_protection_ = 1
        _max_score_for_thorough_review_protection_ = 1

        # Checks branch protection on release and development branch.
        branch_name_list = []
        # Get development branches.
        repo_branches = self._repo.get_branches()
        for branch in repo_branches:
            branch_name_list.append(branch.name)

        # Get release branches.
        releases = self._repo.get_releases()
        for release in releases:
            target_commitish = release.target_commitish
            if target_commitish:
                if target_commitish not in branch_name_list:
                    branch_name_list.append(target_commitish)

        # Add default branch.
        if self._repo.default_branch not in branch_name_list:
            branch_name_list.append(self._repo.default_branch)

        branch_reference_list = []
        # Checks protection on all branches.
        for branch_name in branch_name_list:
            branch = self._repo.get_branch(branch_name)
            protected = branch.protected

            # Initialize branch protection.
            branch_protection = {
                "required_pull_request_reviews": {
                    "required_approving_review_count": 0,
                    "require_code_owner_reviews": False
                },
                "allow_deletions": False,
                "allow_force_pushes": False,
                "required_linear_history": False,
                "required_status_checks": {
                    "strict": False,
                    "required_status_checks": False,
                    "context": []
                }
            }

            # Check protection.
            protection = branch.get_protection()
            branch_protection["required_pull_request_reviews"]["required_approving_review_count"] = \
                protection.required_pill_request.reviews.required_approving_review_count
            branch_protection["required_pull_request_reviews"]["require_code_owner_reviews"] = \
                protection.required_pill_request.require_code_owner_reviews
            branch_protection["allow_deletions"] = protection.allow_deletions.enabled
            branch_protection["allow_force_pushes"] = protection.allow_force_pushes.enabled
            branch_protection["required_linear_history"] = protection.required_linear_history.enable
            branch_protection["required_status_checks"]["strict"] = protection.required_status_checks.strict
            branch_protection["required_status_checks"]["required_status_checks"] = True if \
                len(protection.required_status_checks.checks) != 0 else False
            branch_protection["required_status_checks"]["context"] = protection.required_status_checks.context

            branch_reference = {
                "protected": protected,
                "branch_protection": branch_protection
            }
            branch_reference_list.append(deepcopy(branch_reference))

        scores = []
        for branch_reference in branch_reference_list:
            is_protected = branch_reference["protected"]
            branch_protection = branch_reference["branch_protection"]
            if not is_protected:
                continue

            # Score template for calculating scores.
            score_template = {
                "basic": 0,
                "review": 0,
                "context": 0,
                "thorough_review": 0
            }

            # Calculating basic score.
            basic_score = 0
            if not branch_protection["allow_deletions"]:
                basic_score += 1

            if not branch_protection["allow_force_pushes"]:
                basic_score += 1

            score_template["basic"] = basic_score

            # Calculating review score.
            review_score = 0
            if branch_protection["required_pull_request_reviews"]["required_approving_review_count"] > 0:
                review_score += 1

            score_template["review"] = review_score

            # Calculating context score.
            context_score = 0
            if len(branch_protection["required_status_checks"]["context"]) > 0:
                context_score += 1

            score_template["context"] = context_score

            # Calculating thorough review score.
            thorough_review_score = 0
            if branch_protection["required_pull_request_reviews"]["required_approving_review_count"] >= 2:
                thorough_review_score += 1

            score_template["thorough_review"] = thorough_review_score

            scores.append(deepcopy(score_template))

        # Calculate score for all branches.
        if len(scores) == 0:  # No branch enables branch protection
            return 0

        score_sum = 0

        # Calculate score in terms of basic score.
        max_basic_score = len(scores) * _max_score_for_basic_protection_
        basic_score = 0
        for score in scores:
            basic_score += score["basic"]

        # Add normalized result for basic score.
        score_sum += int(basic_score / max_basic_score * _basic_level_)

        # Calculate score in terms of review score.
        max_review_score = len(scores) * _max_score_for_review_protection_
        review_score = 0
        for score in scores:
            review_score += score["review"]

        # Add normalized result for review score.
        score_sum += int(review_score / max_review_score * _review_level_)

        # Calculate score in terms of context score.
        max_context_score = len(scores) * _max_score_for_context_protection_
        context_score = 0
        for score in scores:
            context_score += score["context"]

        # Add normalized result for context score.
        score_sum += int(context_score / max_context_score * _context_level_)

        # Calculate score in terms of thorough review score.
        max_thorough_review_score = len(scores) * _max_score_for_thorough_review_protection_
        thorough_review_score = 0
        for score in scores:
            thorough_review_score += score["thorough_review"]

        # Add normalized result for thorough review score.
        score_sum += int(thorough_review_score / max_thorough_review_score * _thorough_review_level_)

        return score_sum

    @property
    def ci_test(self):
        def _is_test_(string):
            patterns = [
                "appveyor",
                "buildkite",
                "circleci",
                "e2e",
                "github-actions",
                "jenkins",
                "mergeable",
                "packit-as-a-service",
                "semaphoreci",
                "test",
                "travis-ci",
                "flutter-dashboard",
                "Cirrus CI"
            ]

            for pattern in patterns:
                if pattern in string.lower():
                    return True

            return False

        _look_back_commits_ = 30
        total_merged = 0
        total_tested = 0

        # Get recent commits.
        commits = self._repo.get_commits()[: _look_back_commits_]
        for commit in commits:
            associated_pulls = commit.get_pulls()
            if associated_pulls.totalCount == 0:
                # This commit is not associated with any pull request.
                continue

            total_merged += 1

            # GitHub statuses.
            statuses = commit.get_statuses()
            for status in statuses:
                if status.state != "success":
                    continue

                if _is_test_(status.context) or _is_test_(status.target_url):
                    total_tested += 1
                    continue

            # GitHub check runs.
            check_runs = commit.get_check_runs()
            for check_run in check_runs:
                if check_run.status != "completed" or check_run.conclusion != "success":
                    continue

                if _is_test_(check_run.app.slug):
                    total_tested += 1

        return int(min(total_tested / total_merged * MAX_SCORE), MAX_SCORE)

    @property
    def cii_best_practice(self):
        _non_badge_score_ = MIN_SCORE
        _in_progress_score_ = 2
        _passing_score_ = 5
        _silver_score_ = 7
        _gold_score_ = 10

        _in_progress_resp_ = "in_progress"
        _passing_resp_ = "passing"
        _silver_resp_ = "silver"
        _gold_resp_ = "gold"

        repo_url = f"https://github.com/{self._repo.full_name}"
        response = requests.get(f"https://bestpractices.coreinfrastructure.org/projects.json?url={repo_url}")
        data = json.loads(response.content)

        if len(data) == 0:
            return _non_badge_score_

        badge_level = data[0]["badge_level"]
        if badge_level == _in_progress_resp_:
            return _in_progress_score_
        elif badge_level == _passing_resp_:
            return _passing_score_
        elif badge_level == _silver_resp_:
            return _silver_score_
        elif badge_level == _gold_resp_:
            return _gold_score_
        else:
            return _non_badge_score_

    @property
    def code_review(self):
        _look_back_commits_ = 30
        total_reviewed = 0

        commits = self._repo.get_commits()[: _look_back_commits_]
        for commit in commits:
            associated_pulls = commit.get_pulls()
            if associated_pulls.totalCount == 0:
                # This commit is not associated with any pull request.
                total_reviewed += 1
                continue

            # Determine whether the project enables branch protection with at least one reviewer required.
            pull = associated_pulls[0]
            reviews = pull.get_reviews()
            found_approved_review = False
            for review in reviews:
                if review.state == "approved":
                    found_approved_review = True
                    total_reviewed += 1
                    break

            if found_approved_review:
                break

            # Determine whether the committer is different from that launch a merge request.
            merge_request_author = pull.user.login
            committer = commit.author.login
            if committer != "" and committer == merge_request_author:
                total_reviewed += 1

        total_commits = commits.totalCount
        return int(total_reviewed / total_commits * MAX_SCORE)

    @property
    def dangerous_workflow(self):
        file_paths = []
        default_branch = self._repo.default_branch
        files = self._repo.get_git_tree(sha=default_branch, recursive=True).tree
        for file in files:
            if file.type == "blob":
                path = file.path
                path = path.lower()
                if is_workflow_file(path):
                    file_name = path.split("/")[-1]
                    if get_file_dir(path, file_name) == ".github/workflows/":
                        file_paths.append(path)

        for file_path in file_paths:
            if is_workflow_file(file_path):
                continue
            try:
                workflow = get_yaml_content(self._repo.full_name, self._repo.default_branch, file_path)
                if not validate_untrusted_code_checkout(workflow):
                    return MIN_SCORE

                if not validate_script_injection(workflow):
                    return MAX_SCORE

            except yaml.YAMLError:
                break

        return MAX_SCORE

    @property
    def dependency_update_tool(self):
        _dependabot_configuration_ = [
            ".github/dependabot.yml",
            ".github/dependabot.yaml"
        ]

        _renovatebot_configuration_ = [
            ".github/renovate.json",
            ".github/renovate.json5",
            ".renovaterc.json",
            "renovate.json",
            "renovate.json5",
            ".renovaterc"
        ]

        file_paths = []
        default_branch = self._repo.default_branch
        files = self._repo.get_git_tree(sha=default_branch, recursive=True).tree
        for file in files:
            if file.type == "blob":
                path = file.path
                file_paths.append(path)

        # 1 for dependabot and 0 for renovate bot.
        dependency_update_tools = []
        found_dependabot = False
        found_renovatebot = False
        for file_path in file_paths:
            file_path = file_path.lower()
            for configuration in _dependabot_configuration_:
                if configuration in file_path:
                    dependency_update_tools.append(file_path)
                    found_dependabot = True
                    break

            if found_dependabot:
                continue

            for configuration in _renovatebot_configuration_:
                if configuration in file_path:
                    dependency_update_tools.append(file_path)
                    found_renovatebot = True
                    break

        # No update tool detected.
        if len(dependency_update_tools) == 0:
            return MIN_SCORE

        # Expected one tool at the project.
        if not found_dependabot ^ found_renovatebot:
            return INCONCLUSIVE_RESULT_SCORE

        # Expected on file per tool.
        if not len(dependency_update_tools) != 1:
            return INCONCLUSIVE_RESULT_SCORE

        # High score result.
        return MAX_SCORE

    @property
    def fuzzing(self):
        default_branch = self._repo.default_branch
        files = self._repo.get_git_tree(sha=default_branch, recursive=True).tree
        for file in files:
            if file.type == "blob":
                path = file.path
                if path == "project.yaml":
                    return MAX_SCORE

                if is_workflow_file(path):
                    file_name = path.split("/")[-1]
                    if get_file_dir(path, file_name) == ".clusterfuzzlite":
                        if file_name == "Dockerfile":
                            text = get_text(self._repo.full_name, default_branch, path)
                            lines = text.split("\s*")
                            for line in lines:
                                if line.strip().index("#") == 0:
                                    return MAX_SCORE

        return MIN_SCORE

    @property
    def maintained(self):
        _roles_ = [
            "COLLABORATOR",
            "MEMBER",
            "OWNER"
        ]

        # If the repository marked archived.
        if self._repo.archive:
            return MIN_SCORE

        # To check whether there is at least one commit per week.
        commit_since_time = datetime.datetime.utcnow() - datetime.timedelta(days=COMMIT_LOOKBACK_DAYS)
        recent_commits = self._repo.get_commits(since=commit_since_time)

        # To check whether there is issue from users who are collaborators, member or owner of the repository.
        issues_since_time = datetime.datetime.utcnow() - datetime.timedelta(days=ISSUE_LOOKBACK_DAYS)
        recent_issues = self._repo.get_issues(since=issues_since_time)

        activity_from_collaborator_or_higher = 0
        github_auth_headers = {
            "Authorization": f"bearer {_CACHED_GITHUB_TOKEN}"
        }
        graphql_url = "https://api.github.com/graphql"
        temp = self._repo.full_name.split("/")
        for issue in recent_issues:
            query = 'query($owner:String!, $name:String!, $issue_number:Int!) {repository(owner:$owner, name:$name) {' \
                    'issue(number:$issue_number) {authorAssociation}}} '
            data = {
                "query": query,
                "variables": {
                    "owner": temp[0],
                    "name": temp[1],
                    "issue_number": issue.id
                }
            }
            response = requests.post(url=graphql_url, data=json.dumps(data), headers=github_auth_headers)
            result = json.loads(response.content)
            author_association = result["data"]["repository"]["issue"]["authorAssociation"]
            if author_association in _roles_:
                activity_from_collaborator_or_higher += 1
                continue

            query = 'query($owner:String!, $name:String!, $issue_number:Int!) {repository(owner:$owner, name:$name) {' \
                    'issue(number:$issue_number) {comments(first:50) {' \
                    'edges{node{authorAssociation}}}}}} '
            data = {
                "query": query,
                "variables": {
                    "owner": temp[0],
                    "name": temp[1],
                    "issue_number": issue.id
                }
            }
            response = requests.post(url=graphql_url, data=json.dumps(data), headers=github_auth_headers)
            result = json.loads(response.content)
            edges = result["data"]["issue"]["comments"]["edges"]
            for edge in edges:
                author_association = edge["node"]["authorAssociation"]
                if author_association in _roles_:
                    activity_from_collaborator_or_higher += 1
                    break

        return int((recent_commits.totalCount + activity_from_collaborator_or_higher) /
                   (ACTIVITY_PER_WEEK * LOOK_BACK_DAYS / DAY_IN_ONT_WEEK) * MAX_SCORE)

    @property
    def packaging(self):
        file_paths = []
        default_branch = self._repo.default_branch
        files = self._repo.get_git_tree(sha=default_branch, recursive=True).tree
        for file in files:
            if file.type == "blob":
                path = file.path
                path = path.lower()
                if is_workflow_file(path):
                    file_name = path.split("/")[-1]
                    if get_file_dir(path, file_name) == ".github/workflows/":
                        file_paths.append(path)

        for file_path in file_paths:
            workflow = get_yaml_content(self._repo.full_name, self._repo.default_branch, file_path)
            if not workflow:
                return MIN_SCORE

            if not is_packaging_workflow(workflow):
                continue

            runs = self._repo.get_workflow(file_path.split("/")[-1]).get_runs(status="success")
            if runs.totalCount > 0:
                return MAX_SCORE

        return MIN_SCORE

    @property
    def sast(self):
        sast_weight = 0.3
        codeql_weight = 0.7
        sast_score = sast_tools_in_check_run(self._repo)
        codeql_score = codeql_in_check_definitions(self._repo)

        # Both results are inconclusive.
        if sast_score == INCONCLUSIVE_RESULT_SCORE and codeql_score == INCONCLUSIVE_RESULT_SCORE:
            return MIN_SCORE

        # Both results are conclusive.
        if sast_score != INCONCLUSIVE_RESULT_SCORE and codeql_score != INCONCLUSIVE_RESULT_SCORE:
            if sast_score == MAX_SCORE:
                return MAX_SCORE
            elif codeql_score == MIN_SCORE:
                return sast_score
            elif codeql_score == MAX_SCORE:
                return int(sast_score * sast_weight + codeql_weight * codeql_score)
            else:
                return MIN_SCORE

        # Sast inconclusive
        if codeql_score != INCONCLUSIVE_RESULT_SCORE:
            return codeql_score

        # Codeql inconclusive.
        if sast_score != INCONCLUSIVE_RESULT_SCORE:
            return sast_score

        return MIN_SCORE

    @property
    def security_polity(self):
        security_policy_file_path = {
            "security.md": True,
            ".github/security.md": True,
            "docs/security.md": True,
            "security.adoc": True,
            ".github/security.adoc": True,
            "docs/security.adoc": True,
            "doc/security.rst": True,
            "docs/security.rst": True
        }

        default_branch = self._repo.default_branch
        files = self._repo.get_git_tree(sha=default_branch, recursive=True).tree
        for file in files:
            if file.type == "blob":
                path = file.path
                path = path.lower()
                if security_policy_file_path[path]:
                    return MAX_SCORE

        return MIN_SCORE

    @property
    def signed_release(self):
        artifact_extension = {
            "asc": True,
            "minising": True,
            "sig": True,
            "sign": True
        }
        releases = self._repo.get_releases()[: 5]
        if releases.totalCount == 0:
            return MIN_SCORE

        total_releases = 0
        total_signed = 0
        for release in releases:
            assets = release.get_assets()
            if assets.totalCount == 0:
                continue

            total_releases += 1
            for asset in assets:
                suffix = asset.name.split(".")[-1]
                if artifact_extension[suffix]:
                    total_signed += 1
                    break

        if total_releases == 0:
            return MIN_SCORE

        return int(total_signed / total_releases * MAX_SCORE)

    @property
    def token_permission(self):
        permission_of_interest = [
            "statuses",
            "checks",
            "security-events",
            "deployments",
            "contents",
            "packages",
            "actions"
        ]

        ignored_permissions_for_job_level = [
            "packages",
            "contents",
            "security-events"
        ]
        file_paths = []
        default_branch = self._repo.default_branch
        files = self._repo.get_git_tree(sha=default_branch, recursive=True).tree
        for file in files:
            if file.type == "blob":
                path = file.path
                path = path.lower()
                if is_workflow_file(path):
                    file_name = path.split("/")[-1]
                    if get_file_dir(path, file_name) == ".github/workflows/":
                        file_paths.append(path)

        data = {}
        for file_path in file_paths:
            data[file_path] = {
                "top_level_write_permissions": {
                    "statuses": False,
                    "checks": False,
                    "security-events": False,
                    "deployments": False,
                    "contents": False,
                    "packages": False,
                    "actions": False,
                    "all": False
                },
                "job_level_write_permissions": {
                    "statuses": False,
                    "checks": False,
                    "security-events": False,
                    "deployments": False,
                    "contents": False,
                    "packages": False,
                    "actions": False,
                    "all": False
                }
            }
            try:
                workflow = get_yaml_content(self._repo.full_name, self._repo.default_branch, file_path)
                # Top level
                if workflow.get("permissions"):
                    permissions = workflow["permissions"]
                    if isinstance(permissions, dict):
                        for k, v in permissions.items():
                            if k in permission_of_interest:
                                if v == "write":
                                    data[file_path]["top_level_write_permissions"][k] = True

                else:
                    data[file_path]["top_level_write_permissions"]["all"] = True

                # Job level
                jobs = workflow.get("jobs", {})
                find_permission = False
                for job in jobs.values():
                    if job.get("permissions"):
                        find_permission = True
                        data[file_path]["job_level_write_permissions"]["all"] = False
                        permissions = job["permissions"]
                        if isinstance(permissions, str):
                            continue

                        for k, v in permissions.items():
                            if k in permission_of_interest and k not in ignored_permissions_for_job_level:
                                if v == "write":
                                    data[file_path]["job_level_write_permissions"][k] = True

                    else:
                        if not find_permission:
                            data[file_path]["job_level_write_permissions"]["all"] = True

            except yaml.YAMLError:
                break

        score = MAX_SCORE
        for permissions in data.values():
            # No top level permissions are defined.
            if permission_present_in_top_level(permissions, "all"):
                if permission_present_in_job_level(permissions, "all"):
                    # No run level permissions are defined either.
                    score = MIN_SCORE
                    return score
                else:
                    score -= 0.5

            # May allow an attacker to change the result of pre-submit and get a PR merged.
            # Low risk: -0.5.
            if permission_present(permissions, "statuses"):
                score -= 0.5

            # May allow an attacker to edit checks to remove pre-submit and introduce a bug.
            # Low risk: -0.5.
            if permission_present(permissions, "checks"):
                score -= 0.5

            # May allow attacker to read vulnerability reports before patch available.
            # Low risk: -1.
            if permission_present(permissions, "security-events"):
                score -= 1

            # May allow attacker to charge repo owner by triggering VM runs,
            # and tiny chance an attacker can trigger a remote
            # service with code they own if server accepts code/location var unsanitized.
            # Low risk: -1.
            if permission_present(permissions, "deployments"):
                score -= 1

            # Allows attackers to commit unreviewed code.
            # High risk: -10.
            if permission_present(permissions, "contents"):
                score -= 10

            # Allow attackers to publish packages.
            # High risk: -10.
            if permission_present(permissions, "packages"):
                score -= 10

            # May allow an attacker to steal GitHub secrets by approving to run an action that needs approval.
            if permission_present(permissions, "actions"):
                score -= 10

            if score <= MIN_SCORE:
                break

        if score < MIN_SCORE:
            score = MIN_SCORE

        return int(score)

    @property
    def community_standards(self):
        meet_requirement_count = 0
        total_requirement_count = 7

        # Find Description
        if self._repo.description:
            meet_requirement_count += 1

        # Find readme.
        default_branch = self._repo.default_branch
        files = self._repo.get_git_tree(sha=default_branch, recursive=True).tree
        for file in files:
            if file.type == "blob":
                path = file.path
                path = path.lower()
                if is_readme(path):
                    file_name = path.split("/")[-1]
                    if get_file_dir(path, file_name) == ".github/" or \
                            get_file_dir(path, file_name) == "docs" or \
                            get_file_dir(path, file_name) == "":
                        meet_requirement_count += 1
                        break

        # Find code of conduct
        for file in files:
            if file.type == "blob":
                path = file.path
                path = path.lower()
                if is_code_of_conduct(path):
                    file_name = path.split("/")[-1]
                    if get_file_dir(path, file_name) == ".github/" or \
                            get_file_dir(path, file_name) == "docs" or \
                            get_file_dir(path, file_name) == "":
                        meet_requirement_count += 1
                        break

        # Find contributing.
        for file in files:
            if file.type == "blob":
                path = file.path
                path = path.lower()
                if is_contributing(path):
                    file_name = path.split("/")[-1]
                    if get_file_dir(path, file_name) == ".github/" or \
                            get_file_dir(path, file_name) == "docs" or \
                            get_file_dir(path, file_name) == "":
                        meet_requirement_count += 1
                        break

        # Find License.
        for file in files:
            if file.type == "blob":
                path = file.path
                path = path.lower()
                if is_license(path):
                    file_name = path.split("/")[-1]
                    if get_file_dir(path, file_name) == "":
                        meet_requirement_count += 1
                        break

        # Find issue template.
        for file in files:
            path = file.path
            path = path.lower()
            if is_issue_template(path):
                file_name = path.split("/")[-1]
                if get_file_dir(path, file_name) == ".github/":
                    meet_requirement_count += 1
                    break

        # Find pull request template.
        for file in files:
            path = file.path
            path = path.lower()
            if is_pull_request_template(path):
                file_name = path.split("/")[-1]
                if get_file_dir(path, file_name) == ".github/":
                    meet_requirement_count += 1
                    break

        return int(meet_requirement_count / total_requirement_count * MAX_SCORE)


_CACHED_GITHUB_TOKEN = None
_CACHED_GITHUB_TOKEN_OBJ = None


def use_event_trigger(workflow, trigger_name):
    events = workflow[True]
    if isinstance(events, str):
        if events == trigger_name:
            return True
    elif isinstance(events, list):
        for event in events:
            if event == trigger_name:
                return True

    return False


def contains_untrusted_context_pattern(string):
    untrusted_context_pattern = ".*(issue\.title|)" \
                                "issue\.body|" \
                                "pull_request\.title|" \
                                "pull_request\.body|" \
                                "comment\.body|" \
                                "review\.body|" \
                                "review_comment\.body|" \
                                "pages.*\.page_name|" \
                                "commits.*\.message|" \
                                "head_commit\.message|" \
                                "head_commit\.author\.email|" \
                                "head_commit\.author\.name|" \
                                "commits.*\.author\.email|" \
                                "commits.*\.author\.name|" \
                                "pull_request\.head\.ref|" \
                                "pull_request\.head\.label|" \
                                "pull_request\.head\.repo\.default_branch).*"

    if "github.head_ref" in string:
        return True

    return "github.event." in string and re.search(untrusted_context_pattern, string)


def check_job_untrusted_code_checkout(job):
    if not job:
        return True

    for step in job["steps"]:
        uses = step.get("uses")
        # Check for a step that uses actions/checkout
        if "actions/checkout" not in uses:
            continue

        # Check for reference. If not defined for a pull_request_target event, this defaults to
        # the base branch of the pull request.
        with_ = step.get("with")
        if not isinstance(with_, dict):
            continue

        ref = with_.get("ref")
        if "github.event.pull_request" in ref or \
                "github.event.workflow_run" in ref:
            return False

    return True


def validate_untrusted_code_checkout(workflow):
    if not use_event_trigger(workflow, "github.event.pull_request") and \
            not use_event_trigger(workflow, "github.event.workflow_run"):
        return True

    jobs = workflow.get("jobs", {})
    for job in jobs.values():
        return check_job_untrusted_code_checkout(job)

    return True


def check_variables_in_script(script):
    while True:
        try:
            s = script.index("${{")
        except ValueError:
            break

        try:
            e = script.index("}}$")
        except ValueError:
            return False

        variable = script[s+3: e]
        if contains_untrusted_context_pattern(variable):
            return False

        script = script[s+e:]

    return True


def validate_script_injection(workflow):
    jobs = workflow.get("jobs", {})
    for job in jobs.values():
        if not job:
            continue

        for step in job["steps"]:
            if not step:
                continue

            with_ = step.get("with")
            if not with_:
                continue

            ref = with_.get("ref")
            return check_variables_in_script(ref)

    return True


def is_readme(file_path):
    if file_path.lower().split("/")[-1] == "readme.md":
        return True
    else:
        return False


def is_code_of_conduct(file_path):
    if file_path.lower().split("/")[-1] == "code_of_conduct.md":
        return True
    else:
        return False


def is_contributing(file_path):
    if file_path.lower().split("/")[-1] == "contributing.md":
        return True
    else:
        return False


def is_license(file_path):
    if "license" in file_path.lower().split("/")[-1]:
        return True
    else:
        return False


def is_issue_template(file_path):
    if "issue_template" in file_path.lower().split("/")[-1]:
        return True
    else:
        return False


def is_pull_request_template(file_path):
    if "pull_request_template" in file_path.lower().split("/")[-1]:
        return True
    else:
        return False


def permission_present_in_top_level(permissions, name):
    top_level_write_permissions = permissions["top_level_write_permissions"]
    return top_level_write_permissions[name]


def permission_present_in_job_level(permissions, name):
    job_level_write_permissions = permissions["job_level_write_permissions"]
    return job_level_write_permissions[name]


def permission_present(permissions, name):
    return permission_present_in_top_level(permissions, name) or permission_present_in_job_level(permissions, name)


def get_file_dir(file_path, file_name):
    splitted_paths = file_path.split("/")
    result = ""
    for splitted_path in splitted_paths:
        if splitted_path != file_name:
            result = result + splitted_path + "/"

        if result == file_path:
            return None

    return result


def is_workflow_file(file_path):
    suffix = file_path.split(".")[-1]
    if suffix == "yml" or suffix == "yaml":
        return True
    else:
        return False


def get_yaml_content(full_name, default_branch, file_path):
    url = f"https://raw.githubusercontent.com/{full_name}/{default_branch}/{file_path}"
    response = requests.get(url)
    try:
        return yaml.safe_load(bytes(response.text, encoding="utf-8"))
    except yaml.YAMLError:
        return {}


def get_text(full_name, default_branch, file_path):
    url = f"https://raw.githubusercontent.com/{full_name}/{default_branch}/{file_path}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    else:
        return ""


def get_file_content(full_name, default_branch, file_path):
    url = f"https://raw.githubusercontent.com/{full_name}/{default_branch}/{file_path}"
    response = requests.get(url)
    if response.status_code != 200:
        raise PageOpenException

    return response.text


def is_packaging_workflow(workflow):
    jobs = workflow.get("jobs", {})
    for matcher in JOB_MATCHERS:
        steps = matcher.get("steps")
        expected_matched_step_count = len(steps)
        matched_step_count = 0
        for step in steps:
            expected_matched_action_count = len(step)
            matched_action_count = 0
            for k, v in step.items():
                for job in jobs.values():
                    steps_in_job = job.get("steps")
                    for step_in_job in steps_in_job:
                        for k_, v_ in step_in_job.items():
                            if k != k_:
                                continue

                            if isinstance(step.get(k), str) and isinstance(step_in_job.get(k_), str):
                                if re.match(step.get(k), step_in_job.get(k_)):
                                    matched_action_count += 1
                            elif isinstance(step.get(k), dict) and isinstance(step_in_job.get(k_), dict):
                                if re.match(step.get(k).get("registry-url"), step_in_job.get(k_).get("registry-url")):
                                    matched_action_count += 1

            if matched_action_count >= expected_matched_action_count:
                matched_step_count += 1

        if matched_step_count >= expected_matched_step_count:
            return True

    return False


def sast_tools_in_check_run(repo):
    allow_conclusion = {
        "success": True,
        "neural": True
    }
    sast_tools = {
        "github-code-scanning": True,
        "lgtm-com": True,
        "sonarcloud": True
    }
    # Get sast score.
    commits = repo.get_commits()[: 30]
    total_merged = 0
    total_tested = 0
    if commits.totalCount == 0:
        return INCONCLUSIVE_RESULT_SCORE

    for commit in commits:
        associated_pulls = commit.get_pulls()
        if associated_pulls.totalCount == 0:
            continue

        check_runs = commit.get_check_runs()

        for check_run in check_runs:
            if check_run.status != "completed":
                continue

            if not allow_conclusion[check_run.conclusion]:
                continue

            if sast_tools[check_runs.app.slug]:
                total_tested += 1

    return int(total_tested / total_merged * MAX_SCORE)


def codeql_in_check_definitions(repo):
    # Get codeql score.
    file_paths = []
    default_branch = repo.default_branch
    files = repo.get_git_tree(sha=default_branch, recursive=True).tree
    for file in files:
        if file.type == "blob":
            path = file.path
            path = path.lower()
            if is_workflow_file(path):
                file_name = path.split("/")[-1]
                if get_file_dir(path, file_name) == ".github/workflows/":
                    file_paths.append(path)

    pattern = re.compile("github/codeql-action/analyze")
    for file_path in file_paths:
        try:
            file_content = get_file_content(repo.full_name, default_branch, file_path)
            if pattern.findall(file_content):
                return MAX_SCORE

        except PageOpenException:
            return INCONCLUSIVE_RESULT_SCORE

    return MIN_SCORE


# Source repository on GitHub.
def request_url_with_auth_header(url):
    headers = {}
    if 'github.com' in url and _CACHED_GITHUB_TOKEN:
        headers = {'Authorization': f'token {_CACHED_GITHUB_TOKEN}'}

    return requests.get(url, headers=headers)


# Return expiry information of the given GitHub token.
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

        if repo.fork:
            raise URLException("You MUST input a url of original repository.")

        return GitHubRepository(repo)

    raise URLException("Unsupported url!")
