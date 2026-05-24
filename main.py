import json
import sys

from parser import parse_schema
from scorer import enrich_operations


def main(schema_path):

    #
    # Parse schema
    #

    operations = parse_schema(schema_path)

    #
    # Enrich operations
    #

    enriched = enrich_operations(operations)

    #
    # Write output
    #

    output_path = "enriched.json"

    with open(output_path, "w") as f:
        json.dump(enriched, f, indent=2)

    print(f"[+] Wrote {output_path}")


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} schema.json")
        sys.exit(1)

    main(sys.argv[1])
