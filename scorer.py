"""
scorer.py

Adds semantic risk scoring and analyst guidance
to normalized GraphQL operations.
"""

import json
import sys

from heuristics import (

    ACTION_TAGS,
    OBJECT_TAGS,
    ARG_TAGS,
    TYPE_TAGS,
    RETURN_KIND_TAGS,
    REACHABLE_TYPE_TAGS,

    TAG_WEIGHTS,

    HYPOTHESES,
    CHECKLISTS,
)


#
# --------------------------------------------------
# Helpers
# --------------------------------------------------
#

def add_tag(tags, reasons, tag, reason):
    """
    Add tag and explanation.
    """

    tags.add(tag)

    reasons.append({
        "tag": tag,
        "reason": reason
    })


def normalize_token(token):
    """
    Normalize tokens for matching.
    """

    return token.lower().replace("_", "")


#
# --------------------------------------------------
# Signal Analysis
# --------------------------------------------------
#

def analyze_operation_tokens(op, tags, reasons):
    """
    Analyze operation name tokens.
    """

    for token in op.get("tokens", []):

        token = normalize_token(token)

        #
        # Action semantics
        #

        if token in ACTION_TAGS:

            for tag in ACTION_TAGS[token]:

                add_tag(
                    tags,
                    reasons,
                    tag,
                    f"action token: {token}"
                )

        #
        # Sensitive objects
        #

        if token in OBJECT_TAGS:

            for tag in OBJECT_TAGS[token]:

                add_tag(
                    tags,
                    reasons,
                    tag,
                    f"object token: {token}"
                )


def analyze_arguments(op, tags, reasons):
    """
    Analyze operation arguments.
    """

    for arg in op.get("args", []):

        #
        # Name token analysis
        #

        for token in arg.get("tokens", []):

            token = normalize_token(token)

            if token in ARG_TAGS:

                for tag in ARG_TAGS[token]:

                    add_tag(
                        tags,
                        reasons,
                        tag,
                        f"arg token: {token}"
                    )

        #
        # Type analysis
        #

        arg_type = arg.get("type", {})

        type_name = (
            arg_type.get("name") or ""
        ).lower()

        if type_name in TYPE_TAGS:

            for tag in TYPE_TAGS[type_name]:

                add_tag(
                    tags,
                    reasons,
                    tag,
                    f"arg type: {type_name}"
                )


def analyze_return_type(op, tags, reasons):
    """
    Analyze return type semantics.
    """

    returns = op.get("returns", {})

    #
    # List-returning operations
    #

    if returns.get("is_list"):

        for tag in RETURN_KIND_TAGS.get(
            "LIST",
            []
        ):

            add_tag(
                tags,
                reasons,
                tag,
                "returns list data"
            )

    #
    # Sensitive return object
    #

    return_name = (
        returns.get("name") or ""
    ).lower()

    if return_name in OBJECT_TAGS:

        for tag in OBJECT_TAGS[return_name]:

            add_tag(
                tags,
                reasons,
                tag,
                f"returns sensitive object: {return_name}"
            )


def analyze_reachable_types(op, tags, reasons):
    """
    Analyze nested traversal exposure.
    """

    for reachable in op.get(
        "reachable_types",
        []
    ):

        token = normalize_token(reachable)

        if token in REACHABLE_TYPE_TAGS:

            for tag in REACHABLE_TYPE_TAGS[token]:

                add_tag(
                    tags,
                    reasons,
                    tag,
                    f"reachable type: {reachable}"
                )


def analyze_operation_type(op, tags, reasons):
    """
    Analyze query vs mutation semantics.
    """

    if op["operation_type"] == "mutation":

        add_tag(
            tags,
            reasons,
            "mutation",
            "mutation operation"
        )


#
# --------------------------------------------------
# Workflow Semantics
# --------------------------------------------------
#

def analyze_workflow_patterns(op, tags, reasons):
    """
    Detect workflow/business-logic indicators.
    """

    tokens = set(
        normalize_token(t)
        for t in op.get("tokens", [])
    )

    #
    # Stateful operations
    #

    stateful = {
        "redeem",
        "claim",
        "reset",
        "rotate",
        "verify",
        "consume",
    }

    if tokens.intersection(stateful):

        add_tag(
            tags,
            reasons,
            "stateful-operation",
            "state transition operation"
        )

    #
    # Workflow-sensitive actions
    #

    workflow = {
        "checkout",
        "approve",
        "cancel",
        "refund",
        "submit",
        "finalize",
    }

    if tokens.intersection(workflow):

        add_tag(
            tags,
            reasons,
            "workflow-operation",
            "workflow-sensitive operation"
        )

    #
    # Async/bulk patterns
    #

    async_ops = {
        "export",
        "import",
        "generate",
        "sync",
    }

    if tokens.intersection(async_ops):

        add_tag(
            tags,
            reasons,
            "async-operation",
            "bulk/background operation"
        )


#
# --------------------------------------------------
# Priority Calculation
# --------------------------------------------------
#

def calculate_score(tags):
    """
    Compute weighted risk score.
    """

    score = 0

    for tag in tags:

        score += TAG_WEIGHTS.get(tag, 1)

    return score


def derive_priority(score):
    """
    Convert numeric score to analyst priority.
    """

    if score >= 20:
        return "critical"

    if score >= 14:
        return "high"

    if score >= 8:
        return "medium"

    return "low"


#
# --------------------------------------------------
# Guidance Aggregation
# --------------------------------------------------
#

def build_hypotheses(tags):
    """
    Aggregate analyst hypotheses.
    """

    hypotheses = set()

    for tag in tags:

        for h in HYPOTHESES.get(tag, []):

            hypotheses.add(h)

    return sorted(hypotheses)


def build_checklists(tags):
    """
    Aggregate analyst checklist guidance.
    """

    checklist = set()

    for tag in tags:

        for item in CHECKLISTS.get(tag, []):

            checklist.add(item)

    return sorted(checklist)


#
# --------------------------------------------------
# Main Scoring
# --------------------------------------------------
#

def score_operation(op):
    """
    Score a normalized GraphQL operation.
    """

    tags = set()

    reasons = []

    #
    # Signal extraction
    #

    analyze_operation_type(
        op,
        tags,
        reasons
    )

    analyze_operation_tokens(
        op,
        tags,
        reasons
    )

    analyze_arguments(
        op,
        tags,
        reasons
    )

    analyze_return_type(
        op,
        tags,
        reasons
    )

    analyze_reachable_types(
        op,
        tags,
        reasons
    )

    analyze_workflow_patterns(
        op,
        tags,
        reasons
    )

    #
    # Scoring
    #

    score = calculate_score(tags)

    priority = derive_priority(score)

    #
    # Analyst guidance
    #

    hypotheses = build_hypotheses(tags)

    checklist = build_checklists(tags)

    return {

        #
        # Original operation
        #

        **op,

        #
        # Enrichment
        #

        "risk_score": score,

        "priority": priority,

        "tags": sorted(tags),

        "reasons": reasons,

        #
        # Analyst guidance
        #

        "attack_hypotheses": hypotheses,

        "checklist": checklist,
    }


def enrich_operations(operations):
    """
    Score and prioritize all operations.
    """

    enriched = [
        score_operation(op)
        for op in operations
    ]

    enriched.sort(
        key=lambda x: x["risk_score"],
        reverse=True
    )

    return enriched


#
# --------------------------------------------------
# CLI
# --------------------------------------------------
#

def main(path):

    with open(path) as f:
        operations = json.load(f)

    enriched = enrich_operations(operations)

    print(json.dumps(enriched, indent=2))


if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            f"Usage: python {sys.argv[0]} operations.json"
        )

        sys.exit(1)

    main(sys.argv[1])
