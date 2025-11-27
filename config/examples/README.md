# Vulnerability Threshold Configuration Examples

This directory contains example configuration files for setting vulnerability thresholds in the dependency vulnerability policies.

## Usage

Pass the configuration file to OPA using the `--data` flag:

```bash
opa eval --data policies/ \
  --data config/examples/strict-prod.json \
  --input attestations.json \
  "data.security.dependency_vulnerability.critical.allow"
```

Or include in a policy bundle:

```bash
opa build -b policies/ config/examples/strict-prod.json -o bundle.tar.gz
```

## Configuration Files

### strict-prod.json (Production)
```json
{
  "vulnerability_thresholds": {
    "critical": 0,    // No critical vulnerabilities allowed
    "high": 0,        // No high vulnerabilities allowed
    "medium": 5,      // Up to 5 medium vulnerabilities
    "low": -1         // Unlimited low vulnerabilities
  }
}
```

**Use case:** Production environments requiring strict security posture.

### relaxed-dev.json (Development)
```json
{
  "vulnerability_thresholds": {
    "critical": 2,    // Up to 2 critical vulnerabilities
    "high": 10,       // Up to 10 high vulnerabilities
    "medium": 50,     // Up to 50 medium vulnerabilities
    "low": -1         // Unlimited low vulnerabilities
  }
}
```

**Use case:** Development and testing environments where some risk is acceptable.

### unlimited.json (Testing Only)
```json
{
  "vulnerability_thresholds": {
    "critical": -1,   // Unlimited critical vulnerabilities
    "high": -1,       // Unlimited high vulnerabilities
    "medium": -1,     // Unlimited medium vulnerabilities
    "low": -1         // Unlimited low vulnerabilities
  }
}
```

**Use case:** Testing and experimentation only. Not recommended for any production use.

## Threshold Semantics

- **`0`**: No vulnerabilities of this severity allowed (zero tolerance)
- **Positive number** (e.g., `5`): Maximum number of vulnerabilities allowed
- **`-1`**: Unlimited vulnerabilities allowed (threshold disabled)

## Default Behavior

If no configuration is provided, all policies default to **zero tolerance** (`0`) for backward compatibility.
