"""
org_generator.py

Converts enriched GraphQL security analysis into
Emacs org-mode testing checklists.

Input: enriched operations JSON (from scorer.py)
Output: org-mode text to stdout
"""

import json
import sys
from collections import defaultdict


#
# -----------------------------
# Formatting Helpers
# -----------------------------
#

def format_tags(tags):
    return ": " + " ".join(tags) if tags else ""


def format_properties(op):
    """
    Create org-mode property drawer.
    """

    props = []

    if "risk_score" in op:
        props.append(f":RISK_SCORE: {op['risk_score']}")

    if "priority" in op:
        props.append(f":PRIORITY: {op['priority']}")

    if "operation_type" in op:
        props.append(f":TYPE: {op['operation_type']}")

    if "tags" in op:
        props.append(f":TAGS: {' '.join(op['tags'])}")

    return "\n".join(props)


def format_checklist(items):
    if not items:
        return ""
    return "\n".join(f"- [ ] {i}" for i in items)


def format_hypotheses(items):
    if not items:
        return ""
    return "\n".join(f"- {i}" for i in items)


#
# -----------------------------
# Optional Light Grouping
# -----------------------------
#

def infer_group(op):
    """
    Lightweight heuristic grouping for org sections.

    This is intentionally simple and deterministic.
    """

    tags = set(op.get("tags", []))
    name = op.get("name", "").lower()

    #
    # Billing / financial
    #
    if "financial" in tags:
        return "Billing / Financial Surface"

    #
    # Auth / identity
    #
    if "authz" in tags or "identity" in tags:
        return "Identity / Authorization Surface"

    #
    # Tenancy
    #
    if "tenancy" in tags:
        return "Tenant / Organization Surface"

    #
    # File / document
    #
    if "document-access" in tags:
        return "Document / File Surface"

    #
    # Secrets
    #
    if "secrets" in tags:
        return "Secrets / Credential Surface"

    #
    # Workflow / business logic
    #
    workflow_keywords = [
        "checkout",
        "refund",
        "approve",
        "submit",
        "finalize",
        "claim",
        "redeem",
    ]

    if any(k in name for k in workflow_keywords):
        return "Business Logic Surface"

    #
    # Default
    #
    return "General API Surface"


#
# -----------------------------
# Priority Labeling
# -----------------------------
#

def rank_label(index):
    """
    Convert ranking index into human label.
    """

    if index == 1:
        return "P1"
    if index <= 3:
        return "P2"
    if index <= 8:
        return "P3"
    return "P4"


#
# -----------------------------
# Org Generation
# -----------------------------
#

def generate_org(operations):
    """
    Convert enriched operations into org-mode checklist.
    """

    #
    # Sort by risk score descending
    #

    operations = sorted(
        operations,
        key=lambda x: x.get("risk_score", 0),
        reverse=True
    )

    #
    # Assign rank
    #

    for i, op in enumerate(operations, start=1):
        op["rank"] = i

    #
    # Group operations
    #

    groups = defaultdict(list)

    for op in operations:
        group = infer_group(op)
        groups[group].append(op)

    #
    # Build org output
    #

    lines = []

    lines.append("* GraphQL Security Testing Plan\n")

    for group_name, ops in groups.items():

        lines.append(f"* {group_name}\n")

        for op in ops:

            rank = rank_label(op["rank"])
            name = op.get("name", "unknown")

            lines.append(
                f"** [ ] {rank} {name}"
            )

            #
            # Properties
            #

            props = format_properties(op)

            if props:
                lines.append(props)

            #
            # Why important
            #

            hypotheses = op.get("attack_hypotheses", [])

            if hypotheses:
                lines.append("\n*** Why This Matters")
                lines.append(format_hypotheses(hypotheses))

            #
            # Checklist
            #

            checklist = op.get("checklist", [])

            if checklist:
                lines.append("\n*** Checklist")
                lines.append(format_checklist(checklist))

            lines.append("")  # spacing

    return "\n".join(lines)


#
# -----------------------------
# CLI
# -----------------------------
#

def main(path):

    with open(path) as f:
        operations = json.load(f)

    org_output = generate_org(operations)

    print(org_output)


if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            f"Usage: python {sys.argv[0]} enriched.json"
        )

        sys.exit(1)

    main(sys.argv[1])
