import re

CATEGORY_PATTERNS = {
    "auth": re.compile(
        r"user|account|profile|member|admin|role|permission",
        re.I,
    ),
    "finance": re.compile(
        r"billing|invoice|payment|subscription|transaction",
        re.I,
    ),
    "secrets": re.compile(
        r"apikey|token|secret|credential|oauth|key",
        re.I,
    ),
    "infrastructure": re.compile(
        r"webhook|repository|deployment|environment|integration",
        re.I,
    ),
    "uploads": re.compile(
        r"upload|file|attachment|document|artifact",
        re.I,
    ),
    "workflow": re.compile(
        r"approve|reject|transfer|invite|assign|redeem|claim",
        re.I,
    ),
    "search": re.compile(
        r"search|filter|query|report|export",
        re.I,
    ),
    "ssrf": re.compile(
        r"url|uri|webhook|callback|endpoint",
        re.I,
    ),
}


def categorize(name):
    matches = []

    for category, pattern in CATEGORY_PATTERNS.items():
        if pattern.search(name):
            matches.append(category)

    return matches
