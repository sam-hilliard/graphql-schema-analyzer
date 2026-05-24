"""
heuristics.py

Knowledge base for scorer.py.
Keyword matches names and fields that could
indicate potential vulnerabilities.
"""



ACTION_TAGS = {
    "delete": ["destructive"],
    "update": ["modification"],
    "create": ["creation"],
    "download": ["file-access"],
    "upload": ["file-upload"],
    "export": ["data-export"],
    "import": ["data-import"],
    "login": ["authentication"],
    "token": ["secrets"],
    "apikey": ["secrets"],
}


OBJECT_TAGS = {
    "user": ["identity"],
    "admin": ["authorization"],
    "role": ["authorization"],
    "permission": ["authorization"],
    "billing": ["financial"],
    "payment": ["financial"],
    "invoice": ["financial"],
    "doc": ["document"],
    "document": ["document"],
    "file": ["document"],
}


ARG_TAGS = {
    "id": ["idor"],
    "userid": ["idor"],
    "accountid": ["idor"],
    "organizationid": ["idor"],
    "tenantid": ["idor"],
}


TAG_WEIGHTS = {
    "authorization": 5,
    "financial": 5,
    "secrets": 5,

    "idor": 4,

    "destructive": 4,
    "data-export": 4,

    "file-upload": 3,
    "file-access": 3,

    "identity": 2,
    "document": 2,
    "modification": 2,
}


HYPOTHESES = {
    "idor": [
        "horizontal privilege escalation",
        "cross-tenant object access",
    ],

    "authorization": [
        "vertical privilege escalation",
        "missing authorization checks",
    ],

    "file-access": [
        "unauthorized document retrieval",
        "arbitrary file access",
    ],

    "file-upload": [
        "malicious file upload",
        "content-type validation bypass",
    ],

    "financial": [
        "payment manipulation",
        "billing logic abuse",
    ],

    "secrets": [
        "credential disclosure",
        "token leakage",
    ]
}