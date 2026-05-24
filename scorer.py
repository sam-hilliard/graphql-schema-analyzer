"""
scorer.py

Adds risk and potential vulnerability assessment
based on field/query name matches.
"""

import json
import sys

from heuristics import (
    ACTION_TAGS,
    OBJECT_TAGS,
    ARG_TAGS,
    TAG_WEIGHTS,
    HYPOTHESES,
)


def add_tag(tags, reasons, tag, reason):
    tags.add(tag)
    reasons.append(reason)


def score_operation(op):

    tags = set()
    reasons = []

    #
    # Operation type bias
    #

    if op["operation_type"] == "mutation":
        add_tag(
            tags,
            reasons,
            "mutation",
            "mutation operation"
        )

    #
    # Name token analysis
    #

    for token in op["tokens"]:

        if token in ACTION_TAGS:
            for tag in ACTION_TAGS[token]:
                add_tag(
                    tags,
                    reasons,
                    tag,
                    f"contains action token: {token}"
                )

        if token in OBJECT_TAGS:
            for tag in OBJECT_TAGS[token]:
                add_tag(
                    tags,
                    reasons,
                    tag,
                    f"contains object token: {token}"
                )

    #
    # Arg analysis
    #

    for arg in op["args"]:

        for token in arg.get("tokens", []):

            if token in ARG_TAGS:
                for tag in ARG_TAGS[token]:
                    add_tag(
                        tags,
                        reasons,
                        tag,
                        f"sensitive argument: {arg['name']}"
                    )

    #
    # Return-type analysis
    #

    returns = op["returns"].lower()

    if "string" == returns:
        add_tag(
            tags,
            reasons,
            "raw-return",
            "returns raw string data"
        )

    #
    # Risk scoring
    #

    score = 0

    for tag in tags:
        score += TAG_WEIGHTS.get(tag, 1)

    #
    # Generate hypotheses
    #

    hypotheses = set()

    for tag in tags:
        for h in HYPOTHESES.get(tag, []):
            hypotheses.add(h)

    #
    # Final object
    #

    op["risk_score"] = score
    op["tags"] = sorted(tags)
    op["reasons"] = reasons
    op["attack_hypotheses"] = sorted(hypotheses)

    return op


def main(path):

    with open(path) as f:
        operations = json.load(f)

    enriched = []

    for op in operations:
        enriched.append(score_operation(op))

    enriched.sort(
        key=lambda x: x["risk_score"],
        reverse=True
    )

    print(json.dumps(enriched, indent=2))


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} operations.json")
        sys.exit(1)

    main(sys.argv[1])
