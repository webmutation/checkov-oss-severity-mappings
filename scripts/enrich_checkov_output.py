#!/usr/bin/env python3
"""
Enrich Checkov JSON output with Prisma Cloud severity levels.

This script reads Checkov JSON output from stdin, adds a 'prisma_severity' field
to each check result based on the severity mappings, and outputs the enriched
JSON to stdout.

Usage:
    checkov -o json | python enrich_checkov_output.py
    checkov -d /path/to/code -o json | python enrich_checkov_output.py > results.json
    
Environment Variables:
    CHECKOV_MAPPING_FILE: Path to severity mapping JSON file (optional)
"""

import json
import sys
import os
from pathlib import Path


def load_severity_mapping():
    """Load the severity mapping from the JSON file."""
    # Check for environment variable first
    mapping_file_str = os.environ.get('CHECKOV_MAPPING_FILE')
    
    if mapping_file_str:
        mapping_file = Path(mapping_file_str)
    else:
        # Look for mapping file relative to this script
        script_dir = Path(__file__).parent
        mapping_file = script_dir.parent / "mappings" / "checkov_severity_mapping.json"
    
    if not mapping_file.exists():
        print(
            f"Warning: Severity mapping file not found at {mapping_file}",
            file=sys.stderr
        )
        print(
            "Run 'python scripts/parse_prisma_docs.py' to generate mappings,",
            file=sys.stderr
        )
        print(
            "or set CHECKOV_MAPPING_FILE environment variable to specify a custom path.",
            file=sys.stderr
        )
        return {}
    
    try:
        with open(mapping_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading severity mapping: {e}", file=sys.stderr)
        return {}


def get_checkov_id_from_result(result):
    """Extract Checkov ID from a check result."""
    # Checkov results have a 'check_id' field
    return result.get('check_id', '')


def enrich_results(checkov_output, severity_mapping):
    """
    Enrich Checkov output with severity information.
    
    Args:
        checkov_output: Parsed Checkov JSON output
        severity_mapping: Dict mapping Checkov IDs to severities
    
    Returns:
        Enriched Checkov output
    """
    # Checkov JSON output typically has these top-level keys:
    # - results (for some formats)
    # - check_type_to_results (for comprehensive output)
    
    enriched = checkov_output.copy()
    
    # Handle results in 'results' key (older format)
    if 'results' in enriched:
        results = enriched['results']
        if isinstance(results, dict):
            for check_type, type_results in results.items():
                if isinstance(type_results, dict):
                    for status_key in ['passed_checks', 'failed_checks', 'skipped_checks']:
                        if status_key in type_results:
                            for result in type_results[status_key]:
                                checkov_id = get_checkov_id_from_result(result)
                                result['prisma_severity'] = severity_mapping.get(
                                    checkov_id, 'MEDIUM'
                                )
    
    # Handle results in 'check_type_to_results' key (newer format)
    if 'check_type_to_results' in enriched:
        for check_type, type_results in enriched['check_type_to_results'].items():
            if isinstance(type_results, dict):
                for status_key in ['passed_checks', 'failed_checks', 'skipped_checks']:
                    if status_key in type_results:
                        for result in type_results[status_key]:
                            checkov_id = get_checkov_id_from_result(result)
                            result['prisma_severity'] = severity_mapping.get(
                                checkov_id, 'MEDIUM'
                            )
    
    # Handle flat list of results (some output formats)
    if isinstance(enriched, list):
        for result in enriched:
            checkov_id = get_checkov_id_from_result(result)
            result['prisma_severity'] = severity_mapping.get(checkov_id, 'MEDIUM')
    
    return enriched


def main():
    """Main execution function."""
    # Load severity mapping
    severity_mapping = load_severity_mapping()
    
    if not severity_mapping:
        print("Warning: No severity mappings loaded. Defaulting to MEDIUM.", file=sys.stderr)
    
    # Read Checkov JSON from stdin
    try:
        checkov_output = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON input: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading input: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Enrich the output
    enriched_output = enrich_results(checkov_output, severity_mapping)
    
    # Write enriched JSON to stdout
    try:
        json.dump(enriched_output, sys.stdout, indent=2)
        print()  # Add newline at end
    except Exception as e:
        print(f"Error writing output: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
