#!/usr/bin/env python3
"""
manage-relationships.py -- Manage component relationships in syfter.

Syncs a CSV mapping file to the syfter component_relationships table
via the REST API. Relationships define which containers are components
of which products (e.g., an OpenStack operator container is a component
of Red Hat OpenStack Platform).

Usage:
    python3 manage-relationships.py list
    python3 manage-relationships.py sync container-relationships.csv
    python3 manage-relationships.py sync container-relationships.csv --prune

Prerequisites:
    - SYFTER_SERVER set to the syfter API endpoint
    - SYFTER_API_KEY set to an admin API key
"""

import csv
import json
import os
import sys
from urllib.parse import urlparse
from urllib.request import urlopen, Request
from urllib.error import HTTPError


def _api_url(server_url):
    parsed = urlparse(server_url)
    clean = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        clean += f":{parsed.port}"
    return clean


def api_request(server_url, method, path, body=None):
    """Make an authenticated API request to syfter."""
    url = f"{_api_url(server_url)}{path}"
    data = json.dumps(body).encode() if body else None
    req = Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")

    api_key = os.environ.get("SYFTER_API_KEY")
    if api_key:
        req.add_header("X-API-Key", api_key)

    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as e:
        resp_body = e.read().decode() if e.fp else ""
        if e.code == 409:
            return {"status": "exists", "detail": resp_body}
        elif e.code == 404:
            return {"status": "not_found", "detail": resp_body}
        raise RuntimeError(f"API {method} {path} failed ({e.code}): {resp_body}")


def load_mappings(csv_file):
    """Load relationship mappings from CSV."""
    mappings = []
    with open(csv_file, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            parent = row.get("parent_product", "").strip()
            parent_ver = row.get("parent_version", "").strip()
            component = row.get("component_product", "").strip()
            component_ver = row.get("component_version", "").strip()
            rel_type = row.get("relationship_type", "layered").strip()
            if parent and component:
                mappings.append((parent, parent_ver, component, component_ver, rel_type))
    return mappings


def list_relationships(server_url):
    """List all component relationships."""
    result = api_request(server_url, "GET", "/api/v1/relationships/")
    if isinstance(result, list):
        return result
    return result.get("relationships", result.get("items", []))


def create_relationship(server_url, parent, parent_ver, component, component_ver, rel_type):
    """Create a component relationship. Returns True if created, False if already exists."""
    body = {
        "parent_product_name": parent,
        "parent_product_version": parent_ver,
        "component_product_name": component,
        "component_product_version": component_ver,
        "relationship_type": rel_type,
    }
    result = api_request(server_url, "POST", "/api/v1/relationships/", body)
    if isinstance(result, dict) and result.get("status") == "exists":
        return False
    return True


def delete_relationship(server_url, rel_id):
    """Delete a component relationship by ID."""
    api_request(server_url, "DELETE", f"/api/v1/relationships/{rel_id}")


def cmd_list(server_url):
    """List all relationships."""
    rels = list_relationships(server_url)
    if not rels:
        print("No relationships found.")
        return

    print(f"{'ID':>5}  {'Parent':30}  {'Version':10}  {'Component':35}  {'Version':10}  {'Type'}")
    print("-" * 110)
    for r in rels:
        parent = r.get("parent_product_name", r.get("parent_product", {}).get("name", "?"))
        parent_ver = r.get("parent_product_version", r.get("parent_product", {}).get("version", "?"))
        comp = r.get("component_product_name", r.get("component_product", {}).get("name", "?"))
        comp_ver = r.get("component_product_version", r.get("component_product", {}).get("version", "?"))
        rel_type = r.get("relationship_type", "?")
        rel_id = r.get("id", "?")
        print(f"{rel_id:>5}  {parent:30}  {parent_ver:10}  {comp:35}  {comp_ver:10}  {rel_type}")


def cmd_sync(server_url, csv_file, prune=False):
    """Sync relationships from CSV to syfter."""
    mappings = load_mappings(csv_file)
    if not mappings:
        print(f"No mappings found in {csv_file}")
        return

    print(f"Syncing {len(mappings)} relationships from {csv_file}")
    created = 0
    existing = 0
    for parent, parent_ver, component, component_ver, rel_type in mappings:
        was_created = create_relationship(server_url, parent, parent_ver, component, component_ver, rel_type)
        if was_created:
            print(f"  + {parent} {parent_ver} -> {component} {component_ver} ({rel_type})")
            created += 1
        else:
            print(f"  = {parent} {parent_ver} -> {component} {component_ver} (exists)")
            existing += 1

    print(f"\nCreated: {created}, Already existed: {existing}")

    if prune:
        print("\nPruning stale relationships...")
        rels = list_relationships(server_url)
        csv_keys = set()
        for parent, parent_ver, component, component_ver, rel_type in mappings:
            csv_keys.add((parent, parent_ver, component, component_ver))

        pruned = 0
        for r in rels:
            parent = r.get("parent_product_name", r.get("parent_product", {}).get("name", ""))
            parent_ver = r.get("parent_product_version", r.get("parent_product", {}).get("version", ""))
            comp = r.get("component_product_name", r.get("component_product", {}).get("name", ""))
            comp_ver = r.get("component_product_version", r.get("component_product", {}).get("version", ""))
            key = (parent, parent_ver, comp, comp_ver)
            if key not in csv_keys:
                rel_id = r.get("id")
                print(f"  - {parent} {parent_ver} -> {comp} {comp_ver} (pruned, id={rel_id})")
                delete_relationship(server_url, rel_id)
                pruned += 1
        print(f"Pruned: {pruned}")


def main():
    server_url = os.environ.get("SYFTER_SERVER")
    if not server_url:
        sys.exit("Error: SYFTER_SERVER not set")

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 manage-relationships.py list")
        print("  python3 manage-relationships.py sync <csv-file> [--prune]")
        sys.exit(1)

    command = sys.argv[1]

    if command == "list":
        cmd_list(server_url)
    elif command == "sync":
        if len(sys.argv) < 3:
            sys.exit("Error: sync requires a CSV file argument")
        csv_file = sys.argv[2]
        prune = "--prune" in sys.argv
        cmd_sync(server_url, csv_file, prune)
    else:
        sys.exit(f"Unknown command: {command}")


if __name__ == "__main__":
    main()
