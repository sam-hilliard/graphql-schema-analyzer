"""
parser.py

Parses GraphQL introspection schema
"""

"""
parser.py

Parses GraphQL introspection schema into normalized operations
for downstream security analysis.
"""

import json
import sys
import re


def unwrap_type(type_obj):
    """
    Recursively unwrap GraphQL introspection types.
    """

    kind = type_obj["kind"]
    name = type_obj.get("name")

    if kind == "NON_NULL":
        return f"{unwrap_type(type_obj['ofType'])}!"

    if kind == "LIST":
        return f"[{unwrap_type(type_obj['ofType'])}]"

    return name


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


def extract_fields(root_type, type_map, operation_type):
    """
    Extract GraphQL operations from Query/Mutation root types.
    """

    operations = []

    for field in root_type.get("fields", []):

        args = []

        for arg in field.get("args", []):
            args.append({
                "name": arg["name"],
                "tokens": tokenize_name(arg["name"]),
                "type": unwrap_type(arg["type"]),
                "description": arg.get("description")
            })

        operation = {
            "name": field["name"],
            "tokens": tokenize_name(field["name"]),

            "operation_type": operation_type,

            "description": field.get("description"),

            "deprecated": field.get("isDeprecated", False),
            "deprecation_reason": field.get("deprecationReason"),

            "args": args,

            "returns": unwrap_type(field["type"])
        }

        operations.append(operation)

    return operations


def parse_schema(path):
    """
    Parse introspection JSON into normalized operations list.
    """

    with open(path) as f:
        data = json.load(f)

    schema = data["data"]["__schema"]

    types = schema["types"]
    type_map = build_type_map(types)

    query_name = schema["queryType"]["name"]
    mutation_name = schema.get("mutationType", {}).get("name")

    output = []

    query_type = type_map.get(query_name)
    if query_type:
        output.extend(
            extract_fields(query_type, type_map, "query")
        )

    mutation_type = type_map.get(mutation_name)
    if mutation_type:
        output.extend(
            extract_fields(mutation_type, type_map, "mutation")
        )

    return output


def main(path):
    output = parse_schema(path)
    print(json.dumps(output, indent=2))


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} schema.json")
        sys.exit(1)

    main(sys.argv[1])
