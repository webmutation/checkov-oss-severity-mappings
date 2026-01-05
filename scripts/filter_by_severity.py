#!/usr/bin/env python3
"""
Filter Checkov results by minimum severity level.

This script reads enriched Checkov JSON output (with prisma_severity fields)
from stdin, filters results based on minimum severity level, and outputs
filtered JSON to stdout.

Usage:
    checkov -o json | python enrich_checkov_output.py | python filter_by_severity.py --min-severity HIGH
    python filter_by_severity.py --min-severity MEDIUM < enriched_results.json
"""

import json
import sys
import argparse


# Severity levels in order (lower index = higher severity)
SEVERITY_LEVELS = {
    'CRITICAL': 0,
    'HIGH': 1,
    'MEDIUM': 2,
    'LOW': 3,
    'INFO': 4,
}


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Filter Checkov results by minimum severity level'
    )
    parser.add_argument(
        '--min-severity',
        type=str,
        choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
        default='MEDIUM',
        help='Minimum severity level to include (default: MEDIUM)'
    )
    return parser.parse_args()


def meets_severity_threshold(severity, min_severity):
    """
    Check if a severity level meets the minimum threshold.
    
    Args:
        severity: The severity level to check
        min_severity: The minimum required severity level
    
    Returns:
        True if severity meets or exceeds threshold, False otherwise
    """
    severity_value = SEVERITY_LEVELS.get(severity, 999)  # Unknown = lowest priority
    min_value = SEVERITY_LEVELS.get(min_severity, 2)  # Default to MEDIUM
    
    return severity_value <= min_value


def filter_results(checkov_output, min_severity):
    """
    Filter Checkov output by minimum severity level.
    
    Args:
        checkov_output: Parsed Checkov JSON output (enriched with prisma_severity)
        min_severity: Minimum severity level to include
    
    Returns:
        Filtered Checkov output
    """
    filtered = checkov_output.copy()
    
    # Track statistics
    stats = {
        'original_failed': 0,
        'filtered_failed': 0,
    }
    
    # Handle results in 'results' key (older format)
    if 'results' in filtered:
        results = filtered['results']
        if isinstance(results, dict):
            for check_type, type_results in results.items():
                if isinstance(type_results, dict):
                    # We primarily filter failed_checks
                    if 'failed_checks' in type_results:
                        failed = type_results['failed_checks']
                        stats['original_failed'] += len(failed)
                        
                        filtered_failed = [
                            result for result in failed
                            if meets_severity_threshold(
                                result.get('prisma_severity', 'MEDIUM'),
                                min_severity
                            )
                        ]
                        
                        type_results['failed_checks'] = filtered_failed
                        stats['filtered_failed'] += len(filtered_failed)
    
    # Handle results in 'check_type_to_results' key (newer format)
    if 'check_type_to_results' in filtered:
        for check_type, type_results in filtered['check_type_to_results'].items():
            if isinstance(type_results, dict):
                # We primarily filter failed_checks
                if 'failed_checks' in type_results:
                    failed = type_results['failed_checks']
                    stats['original_failed'] += len(failed)
                    
                    filtered_failed = [
                        result for result in failed
                        if meets_severity_threshold(
                            result.get('prisma_severity', 'MEDIUM'),
                            min_severity
                        )
                    ]
                    
                    type_results['failed_checks'] = filtered_failed
                    stats['filtered_failed'] += len(filtered_failed)
    
    # Handle flat list of results (some output formats)
    if isinstance(filtered, list):
        stats['original_failed'] = len(filtered)
        filtered = [
            result for result in filtered
            if meets_severity_threshold(
                result.get('prisma_severity', 'MEDIUM'),
                min_severity
            )
        ]
        stats['filtered_failed'] = len(filtered)
    
    # Update summary if present
    if 'summary' in filtered and isinstance(filtered['summary'], dict):
        if stats['original_failed'] > 0:
            filtered['summary']['failed'] = stats['filtered_failed']
    
    # Print statistics to stderr
    if stats['original_failed'] > 0:
        print(
            f"Filtered: {stats['original_failed']} failed checks -> "
            f"{stats['filtered_failed']} (minimum severity: {min_severity})",
            file=sys.stderr
        )
    
    return filtered


def main():
    """Main execution function."""
    args = parse_args()
    
    # Read enriched Checkov JSON from stdin
    try:
        checkov_output = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON input: {e}", file=sys.stderr)
        print("Make sure input is enriched with prisma_severity fields.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading input: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Filter the output
    filtered_output = filter_results(checkov_output, args.min_severity)
    
    # Write filtered JSON to stdout
    try:
        json.dump(filtered_output, sys.stdout, indent=2)
        print()  # Add newline at end
    except Exception as e:
        print(f"Error writing output: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
