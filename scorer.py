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

    # Mutation bias
    if op["operation_type"] == "mutation":
        add_tag(tags, reasons, "mutation", "mutation operation")

    # Token analysis
    for token in op.get("tokens", []):

        if token in ACTION_TAGS:
            for tag in ACTION_TAGS[token]:
                add_tag(tags, reasons, tag, f"action token: {token}")

        if token in OBJECT_TAGS:
            for tag in OBJECT_TAGS[token]:
                add_tag(tags, reasons, tag, f"object token: {token}")

    # Arg analysis
    for arg in op.get("args", []):
        for token in arg.get("tokens", []):
            if token in ARG_TAGS:
                for tag in ARG_TAGS[token]:
                    add_tag(tags, reasons, tag, f"arg: {arg['name']}")

    # Return type analysis
    returns = op.get("returns", "").lower()

    if returns == "string":
        add_tag(tags, reasons, "raw-return", "returns raw string data")

    # Score
    score = sum(TAG_WEIGHTS.get(tag, 1) for tag in tags)

    # Hypotheses
    hypotheses = set()

    for tag in tags:
        for h in HYPOTHESES.get(tag, []):
            hypotheses.add(h)

    return {
        **op,
        "risk_score": score,
        "tags": sorted(tags),
        "reasons": reasons,
        "attack_hypotheses": sorted(hypotheses),
    }


def enrich_operations(operations):

    enriched = [score_operation(op) for op in operations]

    enriched.sort(key=lambda x: x["risk_score"], reverse=True)

    return enriched


def main(path):

    with open(path) as f:
        operations = json.load(f)

    enriched = enrich_operations(operations)

    print(json.dumps(enriched, indent=2))


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} operations.json")
        sys.exit(1)

    main(sys.argv[1])
