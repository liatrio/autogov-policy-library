# Policy Configuration Examples

This directory contains example configuration files for the policy library. They
cover vulnerability thresholds and the organization settings an external adopter
overrides to use this library outside the liatrio org. All values are supplied at
runtime via `--policy-data-path` (or bundled with `opa build`) — no fork required.

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
  "vuln_thresholds": {
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
  "vuln_thresholds": {
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
  "vuln_thresholds": {
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

## Organization Configuration (external adopters)

By default the library is scoped to the liatrio org. The following top-level data
keys let any org adopt it without forking. Each defaults to the liatrio value, so
the canonical bundle is unchanged out of the box; supply your own to override.

| Key | Type | Default | Purpose |
|-----|------|---------|---------|
| `approved_owner_ids` | array of strings | `["5726618"]` | allowed GitHub org/owner IDs (provenance + metadata owner check) |
| `approved_repo_ids` | array of strings | `[]` (inert) | optional repo-ID allowlist |
| `signer_org` | string | `"liatrio"` | org slug in the Fulcio signing-cert SAN path (`.../{org}/...`) |
| `subject_prefix` | string | `"ghcr.io/liatrio/"` | required image subject (OCI ref) prefix |

See [`external-org.json`](external-org.json) for a template. Find your GitHub org
ID with `gh api orgs/<your-org> --jq .id`. Example:

```json
{
  "approved_owner_ids": ["123456789"],
  "signer_org": "your-org",
  "subject_prefix": "ghcr.io/your-org/"
}
```

```bash
autogov verify attestation --image-digest <ref> --repo <owner/repo> \
  --policy-bundle-path oci://ghcr.io/liatrio/autogov-policy-library:latest \
  --policy-data-path config/examples/external-org.json
```
