# Copilot Instructions for chekov-oss-severity-mappings

## Repository Purpose

This repository contains severity mappings for Chekov OSS (Open Source Software) security and compliance checks. Chekov is a static code analysis tool for Infrastructure as Code (IaC) that scans cloud infrastructure configurations to find misconfigurations before deployment.

## Project Overview

- **Purpose**: Maintain and manage severity level mappings for Chekov security policies
- **Scope**: Define consistent severity classifications (CRITICAL, HIGH, MEDIUM, LOW, INFO) for various security and compliance checks
- **Use Case**: These mappings help organizations prioritize remediation efforts based on risk severity

## Coding Standards

### General Guidelines

- Keep the repository structure simple and maintainable
- Use clear, descriptive naming conventions
- Document any mapping rationale or special cases
- Maintain consistency with Chekov's official severity classifications

### File Organization

- Configuration files should be in standard formats (JSON, YAML, or TOML)
- Documentation should be in Markdown format
- Keep the root directory clean with only essential files

### Data Structure Guidelines

When working with severity mappings:

- **CRITICAL**: Immediate security risks, potential for data breach or system compromise
- **HIGH**: Significant security vulnerabilities that should be addressed urgently
- **MEDIUM**: Important security issues that should be remediated in a timely manner
- **LOW**: Minor security concerns or best practice violations
- **INFO**: Informational findings without direct security impact

### Quality Standards

- Ensure all mappings are valid and follow established schema
- Verify consistency across similar policy types
- Keep mappings aligned with industry security standards (CIS, NIST, etc.)
- Test any configuration changes before committing

## Development Workflow

### Making Changes

1. Review existing mappings before adding new ones
2. Ensure consistency with similar policies
3. Document the reasoning for severity assignments
4. Validate configuration syntax
5. Update documentation if needed

### Testing

- Validate JSON/YAML syntax if using structured formats
- Cross-reference with Chekov's official documentation
- Test mappings with actual Chekov scans when possible

### Documentation

- Keep README.md up to date with repository structure
- Document any special mapping rules or exceptions
- Provide examples for common use cases

## Best Practices

- **Consistency**: Maintain uniform severity levels for similar security issues
- **Accuracy**: Base severity on actual security impact, not convenience
- **Clarity**: Use clear naming and organization
- **Maintenance**: Regularly review and update mappings as Chekov evolves
- **Validation**: Always validate configuration files before committing

## Contributing

When contributing to this repository:

1. Follow the established patterns in existing files
2. Provide clear commit messages explaining mapping changes
3. Include references to relevant security standards when applicable
4. Test changes thoroughly before submitting

## Resources

- [Chekov Documentation](https://www.checkov.io/)
- [Chekov GitHub Repository](https://github.com/bridgecrewio/checkov)
- Security Standards: CIS Benchmarks, NIST, OWASP
