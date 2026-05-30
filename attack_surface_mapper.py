#!/usr/bin/env python3

import argparse
import json
import shutil
import subprocess

from pathlib import Path

from rich.console import Console
from rich.table import Table

from patterns import categorize
import re

console = Console()


def run(cmd):
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    return result.stdout.strip()


def get_nodes(schema_path, gql_type):
    LABEL_RE = re.compile(r'label\s*=\s*"([^"]+)"')
    output = run([
        "craftql",
        "-f",
        gql_type,
        schema_path,
    ])

    nodes = []

    for line in output.splitlines():
        match = LABEL_RE.search(line)
        if not match:
            continue

        raw = match.group(1)

        # raw looks like:
        # "Activity (Object)\l\l[fields...]"

        # 1. remove Graphviz line breaks
        raw = raw.replace("\\l", " ")

        # 2. extract type name before "(Object)" / "(Enum)" etc.
        name = raw.split("(")[0].strip()

        # 3. extract kind safely
        kind = None
        kind_match = re.search(r"\(([^)]+)\)", raw)
        if kind_match:
            kind = kind_match.group(1).strip()

        if name:
            nodes.append((name, kind))

    return nodes

def incoming(schema_path, node):
    return run(
        [
            "craftql",
            "-i",
            node,
            schema_path,
        ]
    )


def outgoing(schema_path, node):
    return run(
        [
            "craftql",
            "-o",
            node,
            schema_path,
        ]
    )


def enumerate_paths(introspection, node):
    if not introspection:
        return None

    if not shutil.which("graphql-path-enum"):
        return None

    try:
        return run(
            [
                "graphql-path-enum",
                "-i",
                introspection,
                "-t",
                node,
            ]
        )

    except Exception:
        return None


def collect_findings(schema_path):
    findings = []

    gql_types = [
        "object",
        "input_object",
        "scalar",
        "enum",
    ]

    for gql_type in gql_types:

        for name, kind in get_nodes(schema_path, gql_type):

            categories = categorize(name)

            if not categories:
                continue

            findings.append(
                {
                    "name": name,
                    "type": gql_type,
                    "kind": kind,
                    "categories": categories,
                }
            )

    return findings

def print_table(findings):
    table = Table(
        title="Interesting GraphQL Surface"
    )

    table.add_column("Name")
    table.add_column("Type")
    table.add_column("Categories")

    for item in findings:
        table.add_row(
            item["name"],
            item["type"],
            ", ".join(item["categories"]),
        )

    console.print(table)


def enrich(
    schema_path,
    findings,
    introspection=None,
):
    report = []

    for item in findings:

        node = item["name"]

        console.print(
            f"[cyan]Analyzing[/cyan] {node}"
        )

        report.append(
            {
                **item,
                "incoming": incoming(
                    schema_path,
                    node,
                ),
                "outgoing": outgoing(
                    schema_path,
                    node,
                ),
                "paths": enumerate_paths(
                    introspection,
                    node,
                ),
            }
        )

    return report


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "schema",
        help="schema.graphql file",
    )

    parser.add_argument(
        "--introspection",
        help="schema.json introspection file",
    )

    parser.add_argument(
        "--report",
        default="attack_surface.json",
        help="output report path",
    )

    args = parser.parse_args()

    findings = collect_findings(
        args.schema
    )

    print_table(findings)

if __name__ == "__main__":
    main()
