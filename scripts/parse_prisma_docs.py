#!/usr/bin/env python3
"""
Parse Prisma Cloud documentation to extract Checkov ID to severity mappings.

This script clones the hlxsites/prisma-cloud-docs repository and parses all .adoc
files in the policy reference directory to extract Checkov IDs and their corresponding
severity levels.

Output files are written to the mappings/ directory:
- checkov_severity_mapping.json: Simple {checkov_id: severity} mapping
- checkov_severity_mapping_detailed.json: Detailed mapping with metadata
- severity_mapping.py: Python module with SEVERITY_MAPPING dict
"""

import os
import re
import json
import subprocess
import sys
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# Constants
PRISMA_DOCS_REPO = "https://github.com/hlxsites/prisma-cloud-docs.git"
POLICY_REFERENCE_PATH = "docs/en/enterprise-edition/policy-reference"
MAPPINGS_DIR = Path(__file__).parent.parent / "mappings"
REPO_CLONE_DIR = Path(__file__).parent.parent / "prisma-cloud-docs"


def clone_or_update_repo() -> Path:
    """Clone or update the Prisma Cloud documentation repository."""
    print(f"Cloning/updating Prisma Cloud documentation...")
    
    if REPO_CLONE_DIR.exists():
        print(f"Repository already exists at {REPO_CLONE_DIR}, removing...")
        shutil.rmtree(REPO_CLONE_DIR)
    
    # Shallow clone to save time and space
    result = subprocess.run(
        ["git", "clone", "--depth", "1", PRISMA_DOCS_REPO, str(REPO_CLONE_DIR)],
        check=True,
        capture_output=True,
        text=True
    )
    
    # Log any warnings or messages from git
    if result.stderr:
        print(f"Git output: {result.stderr}", file=sys.stderr)
    
    print(f"Repository cloned to {REPO_CLONE_DIR}")
    return REPO_CLONE_DIR


def find_adoc_files(repo_path: Path) -> List[Path]:
    """Find all .adoc files in the policy reference directory."""
    policy_ref_path = repo_path / POLICY_REFERENCE_PATH
    
    if not policy_ref_path.exists():
        print(f"Warning: Policy reference path not found: {policy_ref_path}")
        return []
    
    adoc_files = list(policy_ref_path.rglob("*.adoc"))
    print(f"Found {len(adoc_files)} .adoc files")
    return adoc_files


def extract_checkov_ids(content: str) -> List[str]:
    """
    Extract Checkov IDs from content.
    
    Checkov IDs can appear in multiple formats:
    - [CKV_K8S_41] - in square brackets
    - |CKV_SECRET_61 - after pipe character (in tables)
    - CKV_AWS_119 or CKV3_SAST_48 - plain text
    """
    checkov_ids = []
    
    # Pattern 1: [CKV_...]
    pattern1 = r'\[CKV[^\]]+\]'
    matches1 = re.findall(pattern1, content)
    checkov_ids.extend([m.strip('[]') for m in matches1])
    
    # Pattern 2: |CKV_... (in tables)
    pattern2 = r'\|CKV[_A-Z0-9]+'
    matches2 = re.findall(pattern2, content)
    checkov_ids.extend([m.strip('|') for m in matches2])
    
    # Pattern 3: CKV_... or CKV2_... or CKV3_... in text
    # Matches: CKV_AWS_1, CKV2_AWS_1, CKV3_SAST_1, etc.
    # Optional digit after CKV allows for versioned checks (CKV2, CKV3, future versions)
    pattern3 = r'\bCKV\d?_[A-Z]+_\d+\b'
    matches3 = re.findall(pattern3, content)
    checkov_ids.extend(matches3)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_ids = []
    for cid in checkov_ids:
        if cid not in seen:
            seen.add(cid)
            unique_ids.append(cid)
    
    return unique_ids


def extract_severity(content: str) -> Optional[str]:
    """
    Extract severity from content.
    
    Severity typically appears in a table format:
    |Severity
    |HIGH
    """
    # Look for |Severity followed by |LEVEL
    pattern = r'\|Severity\s*\n\s*\|(LOW|MEDIUM|HIGH|CRITICAL|INFO|INFORMATIONAL)'
    match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
    
    if match:
        severity = match.group(1).upper()
        # Normalize INFORMATIONAL to INFO
        if severity == "INFORMATIONAL":
            severity = "INFO"
        return severity
    
    return None


def extract_prisma_policy_id(content: str) -> Optional[str]:
    """Extract Prisma Cloud Policy ID (UUID format)."""
    # Look for UUID pattern, often near "Policy ID" or in metadata
    pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    match = re.search(pattern, content, re.IGNORECASE)
    return match.group(0) if match else None


def extract_title(content: str, file_path: Path) -> str:
    """
    Extract policy title from content.
    
    Titles are typically in the first few lines, often starting with '=' or '=='
    """
    lines = content.split('\n')
    for line in lines[:20]:  # Check first 20 lines
        line = line.strip()
        if line.startswith('==') and not line.startswith('==='):
            # Remove the '==' prefix and clean up
            title = line.lstrip('=').strip()
            return title
        elif line.startswith('=') and not line.startswith('=='):
            title = line.lstrip('=').strip()
            return title
    
    # Fallback: use filename without extension
    return file_path.stem.replace('-', ' ').title()


def get_category_from_path(file_path: Path, repo_path: Path) -> str:
    """Determine the category based on file path."""
    relative_path = file_path.relative_to(repo_path)
    parts = relative_path.parts
    
    # Look for category indicators in path
    for part in parts:
        if 'kubernetes' in part.lower():
            return 'kubernetes-policies'
        elif 'aws' in part.lower():
            return 'aws-policies'
        elif 'azure' in part.lower():
            return 'azure-policies'
        elif 'gcp' in part.lower():
            return 'gcp-policies'
        elif 'docker' in part.lower():
            return 'docker-policies'
        elif 'secret' in part.lower():
            return 'secrets-policies'
        elif 'sast' in part.lower():
            return 'sast-policies'
        elif 'iac' in part.lower():
            return 'iac-policies'
    
    return 'general-policies'


def parse_adoc_file(file_path: Path, repo_path: Path) -> List[Dict]:
    """Parse a single .adoc file and extract Checkov mappings."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return []
    
    checkov_ids = extract_checkov_ids(content)
    
    if not checkov_ids:
        return []
    
    severity = extract_severity(content)
    
    if not severity:
        # Skip entries without severity
        return []
    
    prisma_id = extract_prisma_policy_id(content)
    title = extract_title(content, file_path)
    category = get_category_from_path(file_path, repo_path)
    
    # Get relative path from repo root
    try:
        source_file = str(file_path.relative_to(repo_path))
    except ValueError:
        source_file = str(file_path)
    
    results = []
    for checkov_id in checkov_ids:
        results.append({
            'checkov_id': checkov_id,
            'severity': severity,
            'prisma_cloud_policy_id': prisma_id,
            'title': title,
            'source_file': source_file,
            'category': category
        })
    
    return results


def parse_all_files(repo_path: Path) -> Tuple[Dict[str, str], List[Dict]]:
    """
    Parse all .adoc files and return both simple and detailed mappings.
    
    Returns:
        Tuple of (simple_mapping, detailed_mapping)
    """
    adoc_files = find_adoc_files(repo_path)
    
    simple_mapping = {}
    detailed_mapping = []
    
    print(f"\nParsing {len(adoc_files)} files...")
    
    for i, file_path in enumerate(adoc_files):
        if (i + 1) % 100 == 0:
            print(f"Processed {i + 1}/{len(adoc_files)} files...")
        
        results = parse_adoc_file(file_path, repo_path)
        
        for result in results:
            checkov_id = result['checkov_id']
            severity = result['severity']
            
            # Add to simple mapping (first occurrence wins)
            if checkov_id not in simple_mapping:
                simple_mapping[checkov_id] = severity
            
            # Add to detailed mapping
            detailed_mapping.append(result)
    
    print(f"Parsing complete. Found {len(simple_mapping)} unique Checkov IDs.")
    return simple_mapping, detailed_mapping


def write_simple_mapping(mapping: Dict[str, str], output_path: Path):
    """Write simple JSON mapping file."""
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(mapping, f, indent=2, sort_keys=True)
    print(f"Wrote simple mapping to {output_path} ({len(mapping)} entries)")


def write_detailed_mapping(mapping: List[Dict], output_path: Path):
    """Write detailed JSON mapping file."""
    # Sort by checkov_id for consistency
    sorted_mapping = sorted(mapping, key=lambda x: x['checkov_id'])
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(sorted_mapping, f, indent=2)
    print(f"Wrote detailed mapping to {output_path} ({len(sorted_mapping)} entries)")


def write_python_module(mapping: Dict[str, str], output_path: Path):
    """Write Python module with severity mapping."""
    lines = [
        '"""',
        'Checkov ID to Severity mapping.',
        '',
        'Auto-generated from Prisma Cloud documentation.',
        'Do not edit manually - run scripts/parse_prisma_docs.py to regenerate.',
        '"""',
        '',
        '# Severity levels',
        'CRITICAL = "CRITICAL"',
        'HIGH = "HIGH"',
        'MEDIUM = "MEDIUM"',
        'LOW = "LOW"',
        'INFO = "INFO"',
        '',
        '# Checkov ID to Severity mapping',
        'SEVERITY_MAPPING = {',
    ]
    
    # Sort by key for consistency
    for checkov_id in sorted(mapping.keys()):
        severity = mapping[checkov_id]
        lines.append(f'    "{checkov_id}": {severity},')
    
    lines.append('}')
    lines.append('')
    lines.append('')
    lines.append('def get_severity(checkov_id: str, default: str = "MEDIUM") -> str:')
    lines.append('    """')
    lines.append('    Get severity for a Checkov ID.')
    lines.append('    ')
    lines.append('    Args:')
    lines.append('        checkov_id: The Checkov check ID (e.g., "CKV_K8S_41")')
    lines.append('        default: Default severity if ID not found')
    lines.append('    ')
    lines.append('    Returns:')
    lines.append('        Severity level string')
    lines.append('    """')
    lines.append('    return SEVERITY_MAPPING.get(checkov_id, default)')
    lines.append('')
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    
    print(f"Wrote Python module to {output_path}")


def main():
    """Main execution function."""
    print("=" * 80)
    print("Checkov Severity Mapping Generator")
    print("=" * 80)
    
    # Ensure mappings directory exists
    MAPPINGS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Clone/update repository
    try:
        repo_path = clone_or_update_repo()
    except subprocess.CalledProcessError as e:
        print(f"Error cloning repository: {e}")
        sys.exit(1)
    
    # Parse all files
    simple_mapping, detailed_mapping = parse_all_files(repo_path)
    
    if not simple_mapping:
        print("\nWarning: No Checkov IDs found in documentation!")
        sys.exit(1)
    
    # Write output files
    print("\nWriting output files...")
    write_simple_mapping(
        simple_mapping,
        MAPPINGS_DIR / "checkov_severity_mapping.json"
    )
    write_detailed_mapping(
        detailed_mapping,
        MAPPINGS_DIR / "checkov_severity_mapping_detailed.json"
    )
    write_python_module(
        simple_mapping,
        MAPPINGS_DIR / "severity_mapping.py"
    )
    
    print("\n" + "=" * 80)
    print("Mapping generation complete!")
    print("=" * 80)
    
    # Print summary statistics
    print(f"\nSummary:")
    print(f"  Total Checkov IDs: {len(simple_mapping)}")
    
    # Count by severity
    severity_counts = {}
    for severity in simple_mapping.values():
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print(f"\nBy Severity:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            print(f"    {severity}: {count}")
    
    # Cleanup cloned repo
    print(f"\nCleaning up cloned repository...")
    shutil.rmtree(REPO_CLONE_DIR)
    
    print("\nDone!")


if __name__ == "__main__":
    main()
