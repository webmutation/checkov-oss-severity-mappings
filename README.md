# Checkov OSS Severity Mappings

Map open-source Checkov IaC scanner findings to Prisma Cloud severity levels (LOW, MEDIUM, HIGH, CRITICAL) for use in CI/CD pipelines.

## 🔍 Problem

The open-source version of Checkov reports all findings with severity `NONE`. This makes it difficult to:
- Prioritize security findings in CI/CD pipelines
- Set severity-based failure thresholds
- Filter critical issues from informational warnings

This repository extracts official severity classifications from Prisma Cloud's public documentation and provides easy-to-use mappings.

## 🚀 Quick Start

### Option 1: Use Pre-built Mappings (Recommended)

The simplest way to use these mappings is to reference them directly in your code:

```python
import json
import urllib.request

# Load mappings from this repository
url = "https://raw.githubusercontent.com/webmutation/chekov-oss-severity-mappings/main/mappings/checkov_severity_mapping.json"
with urllib.request.urlopen(url) as response:
    severity_map = json.loads(response.read())

# Use in your code
checkov_id = "CKV_K8S_41"
severity = severity_map.get(checkov_id, "MEDIUM")
print(f"{checkov_id} has severity: {severity}")
```

### Option 2: Enrich Checkov Output

Use the provided scripts to add severity information to Checkov's JSON output:

```bash
# Clone this repository
git clone https://github.com/webmutation/chekov-oss-severity-mappings.git
cd chekov-oss-severity-mappings

# Run Checkov and enrich output with severity
checkov -d /path/to/code -o json | python scripts/enrich_checkov_output.py > results.json

# Filter by minimum severity level
checkov -d /path/to/code -o json | \
  python scripts/enrich_checkov_output.py | \
  python scripts/filter_by_severity.py --min-severity HIGH > critical_issues.json
```

### Option 3: Use as Python Module

Import the mappings directly in your Python code:

```python
# Add mappings directory to your path or copy severity_mapping.py
from severity_mapping import get_severity, SEVERITY_MAPPING

# Get severity for a specific check
severity = get_severity("CKV_K8S_41")  # Returns "LOW"

# Use the full mapping dictionary
all_mappings = SEVERITY_MAPPING
```

### Option 4: Use Checkov Configuration File (Best for CI/CD)

Use the pre-generated `.checkov.yaml` configuration file with Checkov's native configuration support:

```bash
# Clone this repository
git clone https://github.com/webmutation/chekov-oss-severity-mappings.git
cd chekov-oss-severity-mappings

# Run Checkov with the configuration file
checkov -d /path/to/code --config-file mappings/.checkov.yaml

# Filter by severity threshold (fail only on HIGH and CRITICAL)
checkov -d /path/to/code --config-file mappings/.checkov.yaml --hard-fail-on HIGH,CRITICAL

# Or copy the config to your project root
cp mappings/.checkov.yaml /path/to/your/project/.checkov.yaml
cd /path/to/your/project
checkov -d . --config-file .checkov.yaml
```

**Note**: The `.checkov.yaml` file contains `severity-overrides` for all 1,527 Checkov IDs, allowing Checkov to use the correct severity levels natively.

## 📊 Available Mappings

This repository provides four mapping files in the `mappings/` directory:

1. **`checkov_severity_mapping.json`** - Simple key-value mapping
   ```json
   {
     "CKV_K8S_41": "LOW",
     "CKV_AWS_119": "INFO",
     "CKV_SECRET_61": "HIGH"
   }
   ```

2. **`checkov_severity_mapping_detailed.json`** - Detailed mapping with metadata
   ```json
   [
     {
       "checkov_id": "CKV_K8S_41",
       "severity": "LOW",
       "prisma_cloud_policy_id": "110b3674-1362-4d59-a721-5233965bb73d",
       "title": "Tiller (Helm v2) service is not deleted",
       "source_file": "docs/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/bc-k8s-41.adoc",
       "category": "kubernetes-policies"
     }
   ]
   ```

3. **`severity_mapping.py`** - Python module with constants and helper function
   ```python
   SEVERITY_MAPPING = {
       "CKV_K8S_41": "LOW",
       # ... more mappings
   }
   
   def get_severity(checkov_id: str, default: str = "MEDIUM") -> str:
       return SEVERITY_MAPPING.get(checkov_id, default)
   ```

4. **`.checkov.yaml`** - Checkov configuration file with severity overrides
   ```yaml
   # Checkov Configuration File
   severity-overrides:
     CKV_K8S_41: LOW
     CKV_AWS_119: INFO
     # ... 1527 total entries
   ```

## 🔧 CI/CD Integration

### GitHub Actions Example

Using the Checkov configuration file (recommended):

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  checkov:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install Checkov
        run: pip install checkov
      
      - name: Download severity mappings
        run: |
          curl -o .checkov.yaml https://raw.githubusercontent.com/webmutation/chekov-oss-severity-mappings/main/mappings/.checkov.yaml
      
      - name: Run Checkov with severity filtering
        run: |
          checkov -d . --config-file .checkov.yaml --hard-fail-on HIGH,CRITICAL --compact
```

Or using the enrichment scripts:

```yaml
name: Security Scan with Scripts

on: [push, pull_request]

jobs:
  checkov:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Clone severity mappings
        run: |
          git clone https://github.com/webmutation/chekov-oss-severity-mappings.git /tmp/mappings
      
      - name: Run Checkov with severity filtering
        run: |
          pip install checkov
          checkov -d . -o json | \
            python /tmp/mappings/scripts/enrich_checkov_output.py | \
            python /tmp/mappings/scripts/filter_by_severity.py --min-severity HIGH > results.json
      
      - name: Check for high/critical issues
        run: |
          HIGH_COUNT=$(jq '[.check_type_to_results[].failed_checks // []] | add | length' results.json)
          echo "Found $HIGH_COUNT high/critical severity issues"
          if [ "$HIGH_COUNT" -gt 0 ]; then
            echo "::error::Found $HIGH_COUNT high/critical severity issues"
            exit 1
          fi
```

### GitLab CI Example

Using the Checkov configuration file (recommended):

```yaml
security_scan:
  image: python:3.11
  before_script:
    - pip install checkov
    - git clone https://github.com/webmutation/chekov-oss-severity-mappings.git /tmp/mappings
    - cp /tmp/mappings/mappings/.checkov.yaml .
  script:
    # Run Checkov with custom severity mappings and fail on HIGH+ issues
    - checkov -d . --config-file .checkov.yaml --hard-fail-on HIGH,CRITICAL --compact
  allow_failure: false
```

Or using the enrichment scripts:

```yaml
security_scan_with_scripts:
  image: python:3.11
  script:
    - pip install checkov
    - git clone https://github.com/webmutation/chekov-oss-severity-mappings.git /tmp/mappings
    - checkov -d . -o json | 
        python /tmp/mappings/scripts/enrich_checkov_output.py |
        python /tmp/mappings/scripts/filter_by_severity.py --min-severity MEDIUM > results.json
    - cat results.json
  artifacts:
    reports:
      json: results.json
```

## 🔄 Updating Mappings

### Automatic Updates

This repository automatically updates mappings weekly via GitHub Actions. A pull request is created when changes are detected.

### Manual Update

To regenerate mappings manually:

```bash
# Clone this repository
git clone https://github.com/webmutation/chekov-oss-severity-mappings.git
cd chekov-oss-severity-mappings

# Run the parser script
python scripts/parse_prisma_docs.py

# New mappings will be generated in the mappings/ directory
```

The script will:
1. Clone the latest Prisma Cloud documentation
2. Parse all policy reference files
3. Extract Checkov IDs and severity levels
4. Generate three mapping files
5. Clean up temporary files

## 📚 Data Source

Severity mappings are extracted from the official Prisma Cloud documentation:
- **Repository**: [hlxsites/prisma-cloud-docs](https://github.com/hlxsites/prisma-cloud-docs)
- **Path**: `docs/en/enterprise-edition/policy-reference/`
- **Update Frequency**: Weekly (automated via GitHub Actions)

## 🛠️ Scripts Reference

### `scripts/parse_prisma_docs.py`

Generates severity mappings from Prisma Cloud documentation.

```bash
python scripts/parse_prisma_docs.py
```

**Output**: Creates three files in `mappings/` directory

### `scripts/enrich_checkov_output.py`

Adds `prisma_severity` field to Checkov JSON output.

```bash
checkov -o json | python scripts/enrich_checkov_output.py > enriched.json
```

**Input**: Checkov JSON from stdin  
**Output**: Enriched JSON to stdout

### `scripts/filter_by_severity.py`

Filters Checkov results by minimum severity level.

```bash
python scripts/filter_by_severity.py --min-severity HIGH < enriched.json
```

**Arguments**:
- `--min-severity`: Minimum severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)

**Input**: Enriched Checkov JSON from stdin  
**Output**: Filtered JSON to stdout

## 📦 Requirements

- **Python**: 3.7 or higher
- **Dependencies**: None (uses standard library only)
- **Checkov**: Any version that outputs JSON format

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork this repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

### Reporting Issues

If you find incorrect severity mappings:
1. Check the source documentation in [prisma-cloud-docs](https://github.com/hlxsites/prisma-cloud-docs)
2. Open an issue with the Checkov ID and expected/actual severity
3. If the documentation is correct but our parser missed it, please include the source file path

## 📄 License

This project is provided as-is for community use. Severity data is sourced from publicly available Prisma Cloud documentation.

## 🔗 Related Projects

- [Checkov](https://github.com/bridgecrewio/checkov) - Infrastructure as Code security scanner
- [Prisma Cloud](https://www.paloaltonetworks.com/prisma/cloud) - Cloud security platform
- [Prisma Cloud Docs](https://github.com/hlxsites/prisma-cloud-docs) - Official documentation source

## ⭐ Support

If this project helps you, please consider:
- Starring the repository
- Sharing it with your team
- Contributing improvements

---

**Maintained by**: [webmutation](https://github.com/webmutation)  
**Data Source**: [Prisma Cloud Documentation](https://github.com/hlxsites/prisma-cloud-docs)  
**Last Updated**: Auto-updated weekly via GitHub Actions
