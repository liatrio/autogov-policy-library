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

## Code Scan Configuration

The code-scan policy gates SARIF (CodeQL/semgrep) attestations. It is configured
under the top-level `code_scan_thresholds` key (distinct from the policy package
name to avoid OPA conflicts). Findings are bucketed on two independent axes —
`bySecuritySeverity` (from the rule's security-severity) and `byLevel` (the SARIF
level) — each using the same `0` / `N` / `-1` threshold semantics as above.

By default the policy gates zero-tolerance on `critical`/`high` security-severity
**and** on the SARIF `error` level. The error-level gate is on so an error-severity
finding that lacks a numeric security-severity (common with semgrep/gosec and
CodeQL quality queries — it lands in the `none` security bucket) is still caught.
Lower-signal axes (medium/low/none security, and warning/note/none levels) are
disabled by default. Every override is type-checked: a wrong-typed value (e.g. a
quoted number `"0"`) is rejected and the safe default applies, so a config typo
fails closed.

| Key | Default | Purpose |
|-----|---------|---------|
| `bySecuritySeverity.{critical,high,medium,low,none}` | `0,0,-1,-1,-1` | per-security-severity thresholds |
| `byLevel.{error,warning,note,none}` | `0,-1,-1,-1` | per-SARIF-level thresholds (error gated by default) |
| `require_code_scan` | `false` | require a code-scan attestation to be present |
| `fail_on_incomplete_scan` | `true` | fail when the scanner reported an incomplete run |
| `count_suppressed` | `false` | count suppressed findings toward thresholds (needs `--include-findings`) |
| `fail_on_unreviewed_suppression` | `false` | fail if any suppressed finding is present |
| `gate_new_only` | `false` | only gate findings with baselineState new/updated (needs `--include-findings`) |
| `ignore_paths` | `[]` | glob patterns of finding locations to ignore (needs `--include-findings`) |

Finding-level filters (`count_suppressed`, `gate_new_only`, `ignore_paths`)
require embedded findings (`--include-findings`); if requested while findings are
excluded, the gate fails closed regardless of `fail_on_incomplete_scan`.

### code-scan-strict.json (Production)
Zero tolerance across all security severities and the SARIF `error` level, and
requires a code-scan attestation to be present.

### code-scan-lenient.json (Development)
Gates only `critical` security-severity; everything else disabled, presence not
required, and incomplete scans tolerated.

```bash
autogov verify attestation --image-digest <ref> --repo <owner/repo> \
  --policy-bundle-path oci://ghcr.io/liatrio/autogov-policy-library:latest \
  --policy-data-path config/examples/code-scan-strict.json
```

## Source Review Configuration

The source-review policy gates autogov source-review (PR-approval) attestations.
It is configured under the top-level `source_review_thresholds` key (distinct from
the policy package name to avoid OPA conflicts).

The gate is necessary-but-not-sufficient: meeting `min_approvals` alone never
passes while an outstanding changes-request stands or the review evidence is
incomplete. The producer always computes `distinctApprovers` at the strictest
filtering (author, stale, dismissed, changes-requested, and bot reviewers
excluded), so the per-reviewer flags can only tighten that count, never loosen
it; they also require the per-approver list (`--include-approvers`, on by
default), failing closed if a filter is requested while approvers are excluded.
Every override is type-checked: a wrong-typed value (e.g. a quoted number `"2"`)
is rejected and the safe default applies, so a config typo fails closed.

| Key | Default | Purpose |
|-----|---------|---------|
| `min_approvals` | `1` | minimum distinct qualifying approvals required |
| `require_source_review` | `false` | require a source-review attestation to be present |
| `disallow_self_approval` | `true` | exclude the PR author's own approval |
| `require_non_stale` | `true` | exclude approvals not on the PR head |
| `allow_bot_approvals` | `false` | count bot approvals toward the threshold |
| `require_codeowner_review` | `false` | require CODEOWNER review (fails closed in v0.1 — not authoritatively determinable) |
| `block_on_changes_requested` | `true` | block while any reviewer's latest state is CHANGES_REQUESTED |
| `fail_on_incomplete_review` | `true` | fail when review evidence is incomplete (no merged PR / unfetchable reviews) |

### source-review-strict.json (Production)
Two-person review: `min_approvals` of 2 and requires a source-review attestation
to be present.

### source-review-lenient.json (Development)
One approval, presence not required, and incomplete review tooling tolerated
(allows release/tag builds where the merged PR is not on the default branch).

```bash
autogov verify attestation --image-digest <ref> --repo <owner/repo> \
  --policy-bundle-path oci://ghcr.io/liatrio/autogov-policy-library:latest \
  --policy-data-path config/examples/source-review-strict.json
```

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
