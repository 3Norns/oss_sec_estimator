"""

Main script for calculating open source software security score.

"""

import os
import git

from constants import *
from exceptions import *
from github_repository import get_repository

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
    repo_url = "https://github.com/ossf/scorecard"
    try:
        repo = get_repository(repo_url)
    except URLException:
        return
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
    # print(repo.contributor_capacity)
    # repo.ci_test
    # repo.cii_best_practice
    repo.packaging
    # close()


if __name__ == "__main__":
    # http(s) proxy setting
    os.environ["http_proxy"] = "http://127.0.0.1:33210"
    os.environ["https_proxy"] = "http://127.0.0.1:33210"

    main()
