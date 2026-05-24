import json
import sys


def unwrap_type(type_obj):
    """
    Recursively unwrap GraphQL introspection types.

    Examples:
        NON_NULL -> ID!
        LIST -> [User]
        NON_NULL(LIST(NON_NULL(User))) -> [User!]!
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


def extract_fields(root_type, type_map):
    """
    Extract operations from Query/Mutation root objects.
    """

    operations = []

    for field in root_type.get("fields", []):

        args = []

        for arg in field.get("args", []):

            args.append({
                "name": arg["name"],
                "type": unwrap_type(arg["type"]),
                "description": arg.get("description")
            })

        operation = {
            "name": field["name"],
            "description": field.get("description"),

            "deprecated": field.get("isDeprecated", False),
            "deprecation_reason": field.get("deprecationReason"),

            "args": args,

            "returns": unwrap_type(field["type"])
        }

        operations.append(operation)

    return operations


def main(path):

    with open(path) as f:
        data = json.load(f)

    schema = data["data"]["__schema"]

    types = schema["types"]

    # Improvement #1
    type_map = build_type_map(types)

    query_name = schema["queryType"]["name"]

    mutation_name = None
    if schema.get("mutationType"):
        mutation_name = schema["mutationType"]["name"]

    query_type = type_map.get(query_name)
    mutation_type = type_map.get(mutation_name)

    output = []

    if query_type:
        for op in extract_fields(query_type, type_map):
            op["operation_type"] = "query"
            output.append(op)

    if mutation_type:
        for op in extract_fields(mutation_type, type_map):
            op["operation_type"] = "mutation"
            output.append(op)

    print(json.dumps(output, indent=2))


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} schema.json")
        sys.exit(1)

    main(sys.argv[1])
