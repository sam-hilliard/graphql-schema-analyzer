"""
heuristics.py

Knowledge base for GraphQL security prioritization.

This file defines:
- semantic risk categories
- token-based signals
- scoring weights
- analyst hypotheses
- checklist guidance
"""

#
# --------------------------------------------------
# Action Signals
# --------------------------------------------------
#

ACTION_TAGS = {

    #
    # Destructive
    #

    "delete": [
        "destructive",
    ],

    "remove": [
        "destructive",
    ],

    "destroy": [
        "destructive",
    ],

    #
    # Modification
    #

    "update": [
        "modification",
    ],

    "edit": [
        "modification",
    ],

    "set": [
        "modification",
    ],

    #
    # Creation
    #

    "create": [
        "creation",
    ],

    "invite": [
        "creation",
    ],

    #
    # File operations
    #

    "upload": [
        "file-upload",
    ],

    "download": [
        "file-access",
    ],

    "export": [
        "bulk-data",
        "file-access",
    ],

    "import": [
        "bulk-input",
    ],

    #
    # Authentication
    #

    "login": [
        "authentication",
    ],

    "signin": [
        "authentication",
    ],

    "token": [
        "secrets",
    ],

    "apikey": [
        "secrets",
    ],

    "secret": [
        "secrets",
    ],

    #
    # Administrative
    #

    "admin": [
        "admin-surface",
    ],

    "internal": [
        "internal-surface",
    ],

    #
    # Enumeration
    #

    "search": [
        "enumeration",
    ],

    "list": [
        "enumeration",
    ],

    "find": [
        "enumeration",
    ],
}


#
# --------------------------------------------------
# Sensitive Object Signals
# --------------------------------------------------
#

OBJECT_TAGS = {

    #
    # Identity / Accounts
    #

    "user": [
        "identity",
    ],

    "account": [
        "identity",
    ],

    "profile": [
        "identity",
    ],

    #
    # Authorization
    #

    "admin": [
        "authz",
        "admin-surface",
    ],

    "role": [
        "authz",
    ],

    "permission": [
        "authz",
    ],

    #
    # Tenancy
    #

    "organization": [
        "tenancy",
    ],

    "tenant": [
        "tenancy",
    ],

    "workspace": [
        "tenancy",
    ],

    #
    # Financial
    #

    "billing": [
        "financial",
    ],

    "payment": [
        "financial",
    ],

    "invoice": [
        "financial",
    ],

    "subscription": [
        "financial",
    ],

    #
    # Documents / Files
    #

    "document": [
        "document-access",
    ],

    "doc": [
        "document-access",
    ],

    "file": [
        "document-access",
    ],

    "attachment": [
        "document-access",
    ],

    #
    # Secrets
    #

    "token": [
        "secrets",
    ],

    "apikey": [
        "secrets",
    ],

    "credential": [
        "secrets",
    ],

    "key": [
        "secrets",
    ],
}


#
# --------------------------------------------------
# Argument Risk Signals
# --------------------------------------------------
#

ARG_TAGS = {

    #
    # IDOR indicators
    #

    "id": [
        "idor",
    ],

    "userid": [
        "idor",
    ],

    "accountid": [
        "idor",
    ],

    "organizationid": [
        "idor",
        "tenancy",
    ],

    "tenantid": [
        "idor",
        "tenancy",
    ],

    #
    # Pagination
    #

    "limit": [
        "pagination",
    ],

    "offset": [
        "pagination",
    ],

    "first": [
        "pagination",
    ],

    "last": [
        "pagination",
    ],

    #
    # Search/filter
    #

    "query": [
        "search-input",
    ],

    "search": [
        "search-input",
    ],

    "filter": [
        "search-input",
    ],

    "where": [
        "search-input",
    ],
}


#
# --------------------------------------------------
# Type Signals
# --------------------------------------------------
#

TYPE_TAGS = {

    #
    # Dangerous scalars
    #

    "json": [
        "unstructured-input",
    ],

    "JSONObject": [
        "unstructured-input",
    ],

    "upload": [
        "file-upload",
    ],

    #
    # Potential secret exposure
    #

    "token": [
        "secrets",
    ],
}


#
# --------------------------------------------------
# Return-Type Signals
# --------------------------------------------------
#

RETURN_KIND_TAGS = {

    #
    # Lists are commonly enumerable
    #

    "LIST": [
        "enumeration",
    ],
}


#
# --------------------------------------------------
# Traversal Signals
# --------------------------------------------------
#

REACHABLE_TYPE_TAGS = {

    "user": [
        "identity",
    ],

    "invoice": [
        "financial",
    ],

    "billing": [
        "financial",
    ],

    "apikey": [
        "secrets",
    ],

    "token": [
        "secrets",
    ],

    "admin": [
        "admin-surface",
    ],
}


#
# --------------------------------------------------
# Risk Weights
# --------------------------------------------------
#

TAG_WEIGHTS = {

    #
    # Critical trust boundaries
    #

    "authz": 6,

    "tenancy": 6,

    "secrets": 6,

    #
    # High-impact business logic
    #

    "financial": 5,

    "idor": 5,

    "admin-surface": 5,

    #
    # Dangerous actions
    #

    "destructive": 4,

    "bulk-data": 4,

    "file-upload": 4,

    #
    # Medium risk
    #

    "file-access": 3,

    "enumeration": 3,

    "search-input": 3,

    "unstructured-input": 3,

    #
    # Lower severity
    #

    "identity": 2,

    "modification": 2,

    "creation": 1,

    "pagination": 1,

    "mutation": 1,
}


#
# --------------------------------------------------
# Analyst Hypotheses
# --------------------------------------------------
#

HYPOTHESES = {

    "idor": [
        "test horizontal privilege escalation",
        "test cross-account object access",
    ],

    "authz": [
        "test missing authorization checks",
        "test privilege escalation",
    ],

    "tenancy": [
        "test tenant isolation",
        "test cross-tenant access",
    ],

    "financial": [
        "test billing manipulation",
        "test payment workflow abuse",
    ],

    "file-access": [
        "test unauthorized document retrieval",
        "test direct object access",
    ],

    "file-upload": [
        "test malicious file upload",
        "test content-type validation bypass",
    ],

    "bulk-data": [
        "test mass data export",
        "test unrestricted reporting access",
    ],

    "enumeration": [
        "test bulk enumeration",
        "test unauthenticated listing",
    ],

    "search-input": [
        "test backend query injection",
        "test filter bypasses",
    ],

    "unstructured-input": [
        "test JSON injection",
        "test mass assignment",
    ],

    "secrets": [
        "test credential disclosure",
        "test token leakage",
    ],
}


#
# --------------------------------------------------
# Checklist Guidance
# --------------------------------------------------
#

CHECKLISTS = {

    "idor": [
        "swap object identifiers",
        "test sequential IDs",
        "test UUID ownership validation",
    ],

    "authz": [
        "test low-privilege access",
        "test role enforcement",
        "test admin-only functionality",
    ],

    "tenancy": [
        "test cross-tenant references",
        "test organization boundary enforcement",
    ],

    "financial": [
        "review billing workflows",
        "review invoice access controls",
    ],

    "enumeration": [
        "test pagination limits",
        "test bulk data extraction",
    ],

    "file-upload": [
        "test content-type restrictions",
        "test malicious file extensions",
    ],

    "search-input": [
        "review backend filtering logic",
        "test malformed filter objects",
    ],

    "secrets": [
        "review token exposure",
        "review credential handling",
    ],
}
