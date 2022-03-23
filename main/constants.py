"""

Constant Variables used in security score calculation.

"""
import re

FAIL_RETRIES = 7
TOP_CONTRIBUTOR_COUNT = 15
HTTP_REQUEST_HEADER = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/99.0.4844.74 Safari/537.36 "
        }

# Regex to match dependents count
DEPENDENTS_REGEX = re.compile(b'.*[^0-9,]([0-9,]+).*commit result', re.DOTALL)