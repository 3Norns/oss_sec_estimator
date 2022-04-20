import yaml
import os
import requests
import re
from main.job_matchers import JOB_MATCHERS


def is_packaging_workflow(workflow):
    jobs = workflow.get("jobs")
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


if __name__ == "__main__":
    os.environ["http_proxy"] = "http://127.0.0.1:33210"
    os.environ["https_proxy"] = "http://127.0.0.1:33210"
    response = requests.get("https://raw.githubusercontent.com/ossf/scorecard/main/checks/testdata/.github/workflows"
                            "/github-workflow-packaging-npm.yaml")
    workflow = yaml.safe_load(bytes(response.text, encoding="utf-8"))
    print(is_packaging_workflow(workflow))
