import requests
import os
import yaml


if __name__ == "__main__":
    os.environ["http_proxy"] = "http://127.0.0.1:33210"
    os.environ["https_proxy"] = "http://127.0.0.1:33210"

    workflow = yaml.safe_load(bytes(requests.get("https://raw.githubusercontent.com/ossf/scorecard/main/checks/testdata/.github/workflows/github-workflow-dangerous-pattern-untrusted-script-injection-wildcard.yml").text, encoding="utf-8"))
    print(workflow[True])
    pass
