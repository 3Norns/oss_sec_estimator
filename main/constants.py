"""

Constant Variables used in security score calculation.

"""
import re

FAIL_RETRIES = 7

# Regex to match dependents count
DEPENDENTS_REGEX = re.compile(b'.*[^0-9,]([0-9,]+).*commit result', re.DOTALL)