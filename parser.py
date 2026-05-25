"""
parser.py

Parses GraphQL introspection schema into normalized operations
for downstream security analysis and checklist generation.
"""

import json
import sys
import re


#
# ----------------------------
# Type Helpers
# ----------------------------
#

def unwrap_type(type_obj):
    """
    Convert nested GraphQL introspection type definitions
    into structured metadata.
    """

    wrappers = []

    current = type_obj

    while current:

        kind = current["kind"]

        if kind == "NON_NULL":
            wrappers.append("NON_NULL")
            current = current["ofType"]
            continue

        if kind == "LIST":
            wrappers.append("LIST")
            current = current["ofType"]
            continue

        return {
            "kind": kind,
            "name": current.get("name"),

            "is_list": "LIST" in wrappers,

            "non_null": (
                len(wrappers) > 0
                and wrappers[0] == "NON_NULL"
            ),

            "wrappers": wrappers
        }

    return {
        "kind": None,
        "name": None,
        "is_list": False,
        "non_null": False,
        "wrappers": []
    }


def format_type(type_meta):
    """
    Produce readable GraphQL type string.
    """

    name = type_meta["name"] or "Unknown"

    if type_meta["is_list"]:
        name = f"[{name}]"

    if type_meta["non_null"]:
        name += "!"

    return name


#
# ----------------------------
# Schema Helpers
# ----------------------------
#

def build_type_map(types):
    """
    Build fast lookup map for schema types.
    """

    return {
        t["name"]: t
        for t in types
        if t.get("name")
    }


def tokenize_name(name):
    """
    Split camelCase / PascalCase / snake_case into tokens.
    """

    if not name:
        return []

    parts = re.findall(
        r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)",
        name
    )

    tokens = []

    for part in parts:
        tokens.extend(part.split("_"))

    return [
        t.lower()
        for t in tokens
        if t
    ]


#
# ----------------------------
# Traversal Helpers
# ----------------------------
#

def collect_reachable_types(
    type_name,
    type_map,
    depth=0,
    max_depth=2,
    visited=None
):
    """
    Recursively collect reachable object types.

    Useful for:
    - traversal awareness
    - privilege boundary discovery
    - nested object visibility
    """

    if visited is None:
        visited = set()

    if depth > max_depth:
        return set()

    if type_name in visited:
        return set()

    visited.add(type_name)

    type_def = type_map.get(type_name)

    if not type_def:
        return set()

    if type_def.get("kind") != "OBJECT":
        return set()

    reachable = set()

    for field in type_def.get("fields", []):

        field_type = unwrap_type(field["type"])

        child_name = field_type.get("name")

        if not child_name:
            continue

        reachable.add(child_name)

        reachable.update(
            collect_reachable_types(
                child_name,
                type_map,
                depth + 1,
                max_depth,
                visited.copy()
            )
        )

    return reachable


#
# ----------------------------
# Extraction
# ----------------------------
#

def extract_args(field):
    """
    Normalize argument metadata.
    """

    args = []

    for arg in field.get("args", []):

        arg_type = unwrap_type(arg["type"])

        args.append({
            "name": arg["name"],

            "tokens": tokenize_name(arg["name"]),

            "description": arg.get("description"),

            "type": {
                **arg_type,
                "display": format_type(arg_type)
            }
        })

    return args


def extract_fields(
    root_type,
    type_map,
    operation_type
):
    """
    Extract normalized operations from Query/Mutation roots.
    """

    operations = []

    for field in root_type.get("fields", []):

        return_type = unwrap_type(field["type"])

        reachable = []

        if return_type["kind"] == "OBJECT":

            reachable = sorted(
                collect_reachable_types(
                    return_type["name"],
                    type_map
                )
            )

        operation = {

            #
            # Identity
            #

            "name": field["name"],

            "tokens": tokenize_name(field["name"]),

            "operation_type": operation_type,

            #
            # Descriptions
            #

            "description": field.get("description"),

            #
            # Deprecation
            #

            "deprecated": field.get(
                "isDeprecated",
                False
            ),

            "deprecation_reason": field.get(
                "deprecationReason"
            ),

            #
            # Arguments
            #

            "args": extract_args(field),

            #
            # Return metadata
            #

            "returns": {
                **return_type,
                "display": format_type(return_type)
            },

            #
            # Traversal metadata
            #

            "reachable_types": reachable
        }

        operations.append(operation)

    return operations


#
# ----------------------------
# Main Parser
# ----------------------------
#

def parse_schema(path):
    """
    Parse GraphQL introspection JSON into normalized operations.
    """

    with open(path) as f:
        data = json.load(f)

    schema = data["data"]["__schema"]

    types = schema["types"]

    type_map = build_type_map(types)

    query_name = schema["queryType"]["name"]

    mutation_type_obj = schema.get("mutationType")

    mutation_name = (
        mutation_type_obj.get("name")
        if mutation_type_obj
        else None
    )

    output = []

    #
    # Queries
    #

    query_type = type_map.get(query_name)

    if query_type:

        output.extend(
            extract_fields(
                query_type,
                type_map,
                "query"
            )
        )

    #
    # Mutations
    #

    mutation_type = type_map.get(mutation_name)

    if mutation_type:

        output.extend(
            extract_fields(
                mutation_type,
                type_map,
                "mutation"
            )
        )

    return output


#
# ----------------------------
# CLI
# ----------------------------
#

def main(path):

    output = parse_schema(path)

    print(json.dumps(output, indent=2))


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print(
            f"Usage: python {sys.argv[0]} schema.json"
        )
        sys.exit(1)

    main(sys.argv[1])
