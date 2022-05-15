JOB_MATCHERS = [
    {
        "steps": [
            {
                "uses": "actions/setup-node",
                "with": {
                    "registry-url": "https://registry.npmjs.org"
                }
            }
        ]
    },
    {
        "steps": [
            {
                "uses": "actions/setup-java"
            },
            {
                "run": "mvn.*deploy"
            }
        ]
    },
    {
        "steps": [
            {
                "uses": "actions/setup-java"
            },
            {
                "run": "gradle.*publish"
            }
        ]
    },
    {
        "steps": [
            {
                "run": "gem.*push"
            }
        ]
    },
    {
        "steps": [
            {
                "run": "nuget.*push"
            }
        ]
    },
    {
        "steps": [
            {
                "run": "docker.*push"
            }
        ]
    },
    {
        "steps": [
            {
                "uses": "docker/build-push-action"
            }
        ]
    },
    {
        "steps": [
            {
                "uses": "actions/setup-python"
            },
            {
                "uses": "pypa/gh-action-pypi-publish"
            }
        ]
    },
    {
        "steps": [
            {
                "uses": "relekang/python-semantic-release"
            }
        ]
    },
    {
        "steps": [
            {
                "uses": "actions/setup-go"
            },
            {
                "uses": "goreleaser/goreleaser-action"
            }
        ]
    },
    {
        "steps": [
            {
                "run": "cargo.*publish"
            }
        ]
    }
]


if __name__ == "__main__":
    a = JOB_MATCHERS
    pass
