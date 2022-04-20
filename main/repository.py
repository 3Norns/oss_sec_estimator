"""

Repository is the super class of all source repository

"""


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
