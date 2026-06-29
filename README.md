# GitHub AutoGov Policy Library

[![build](https://github.com/liatrio/autogov-policy-library/actions/workflows/build.yaml/badge.svg)](https://github.com/liatrio/autogov-policy-library/actions/workflows/build.yaml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/liatrio/autogov-policy-library/badge)](https://scorecard.dev/viewer/?uri=github.com/liatrio/autogov-policy-library)
[![Release](https://img.shields.io/github/v/release/liatrio/autogov-policy-library?sort=semver)](https://github.com/liatrio/autogov-policy-library/releases)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

This repository serves as a collection of OPA Rego policies that are specifically designed for attestations created with GitHub Artifact Attestations.

## Overview

The GitHub AutoGov Policy Library provides a set of predefined policies that can be used to enforce governance and compliance rules for attestations within your GitHub repositories. These policies are written in OPA Rego language, which allows for flexible and customizable rule definitions.

These policies do not run on their own. The [autogov](https://github.com/liatrio/autogov) CLI evaluates them during verification — it loads attestation bundles, runs the OPA/Rego rules in this library, and emits a pass/fail Verification Summary Attestation (VSA) that gates a release. The CLI pulls this library as a published policy bundle, typically via the reusable [autogov-workflows](https://github.com/liatrio/autogov-workflows).

### Policy Categories

The library includes two main categories of policies:

- **Security Policies** (`policies/security/`): Validate individual attestation types (SLSA provenance, SBOM, vulnerability scans, etc.)
- **Governance Policies** (`policies/governance/`): Higher-level policies for deployment gating and workflow orchestration

The `governance` package is the aggregate entrypoint: it allows only when every
security policy below allows, and surfaces a per-policy `violations` map for
troubleshooting.

#### Shipped Policies

Each policy denies by default and allows only when it finds no violations.
Thresholds and flags marked overridable are set at runtime via
`--policy-data-path` with a JSON object under the noted key.

| Policy | Package | Gates | Key config (key → default) |
| --- | --- | --- | --- |
| Provenance | `security.provenance` | SLSA provenance present, `buildType` is the GitHub Actions workflow type, and the build owner (and optional repo) is allowlisted. | `approved_owner_ids` → liatrio org id; `approved_repo_ids` → empty (inert) |
| SBOM | `security.sbom` | A CycloneDX SBOM attestation is present. | none |
| Metadata | `security.metadata` | autogov/cosign metadata attestation present with all required sections, github-hosted runner, allowlisted owner, and a valid image/blob subject. | `approved_owner_ids` → liatrio org id; `subject_prefix` → `ghcr.io/liatrio/` |
| Certificate | `security.certificate` | Each bundle carries a non-empty Fulcio signing certificate from GitHub's Fulcio. | none (string/format checks only; full X.509 validation is not done in OPA) |
| Dependency vulnerability | `security.dependency_vulnerability.{critical,high,medium,low}` | A vulnerability-scan attestation is present and per-severity finding counts stay within threshold. | `vuln_thresholds.{critical,high,medium,low}` → `0` each (`-1` disables a bucket) |
| Scanner provenance | `security.dependency_vulnerability.scanner_provenance` | Scanner and vulnerability-DB metadata are complete and the DB is recent (within 30 days). Optional (not in the aggregate `governance` allow). | none |
| Test result | `security.test_result` | A present test-result attestation reports no more than the allowed failed tests. | `max_failed_tests` → `0`; `require_test_results` → `false` |
| Code scan | `security.code_scan` | SARIF code-scan findings stay within per-severity and per-SARIF-level thresholds. | `code_scan_thresholds`: `bySecuritySeverity.{critical,high}` → `0`, others → `-1`; `byLevel.error` → `0`, others → `-1`; `require_code_scan` → `false`; `fail_on_incomplete_scan` → `true` |
| Source review | `security.source_review` | An attested PR-approval (source-review) meets the review bar — distinct approvals, no outstanding changes-requested, optional codeowner review. | `source_review_thresholds`: `min_approvals` → `1`; `require_source_review` → `false`; `block_on_changes_requested` → `true`; `require_codeowner_review` → `false`; `fail_on_incomplete_review` → `false` |
| Dependency-vuln bypass | `security.bypass` | Authorizes the spoofable `ignore_dependency_vulnerabilities` request only when an attested source-review proves enough authorized approvals. Inert by default. | `bypass_thresholds`: `allow_dep_vuln_bypass` → `false`; `bypass_min_approvals` → `2`; `authorized_associations` → `["OWNER","MEMBER"]`; `authorized_approvers` → empty |
| VSA verification result | `governance.vsa_verification_result` | A Verification Summary Attestation reports `verificationResult: PASSED`; `FAILED`/`UNKNOWN`/missing/invalid deny. | none |

Org-specific defaults (`approved_owner_ids`, `subject_prefix`, `signer_org`) live
in `policies/shared/access` and `policies/shared/utils`; adapt them for your own org (see the
org-specific constraints note below).

#### VSA-Based Deployment Gating

The `governance/vsa_verification_result` policy enables **Verification Summary Attestation (VSA) based deployment gating**. This policy:

- Evaluates VSA bundles generated by the autogov verification tooling after policy evaluation
- Allows deployment only when `verificationResult` is `PASSED`  
- Blocks deployment for `FAILED`, `UNKNOWN`, or missing verification results
- Provides clear denial messages for troubleshooting

**Use Case**: Deploy applications only after cryptographically signed verification confirms all security and compliance policies have passed.

**Example Integration**:

```yaml
# In deployment workflow
- name: Evaluate VSA Against Policy
  run: |
    opa eval --input vsa-bundle.json \
      "data.governance.vsa_verification_result.allow"
```

This enables a **4-layer AutoGov architecture**:

1. **Build** → Generate attestations  
2. **Verify** → Validate attestations + create VSA
3. **Gate** → Evaluate VSA against deployment policy
4. **Deploy** → Release to production (if authorized)

## Using Policy Bundle in GitHub Workflows

The policy bundle (`bundle.tar.gz`) is published as a release asset. You can
download it from a GitHub Actions workflow with `gh release download` and a
token that has read access to the policy-library repo.

The job needs `contents: read` to read releases. If you authenticate with
[octo-sts](https://github.com/octo-sts/action) instead of the default
`GITHUB_TOKEN` (for example to read a bundle from a different repo), add
`id-token: write` so the action can mint a token.

```yaml
jobs:
  download-bundle:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write # only required when minting a token via octo-sts (see note below)
    steps:
      # The octo-sts step below is Liatrio-org-specific — the `scope` and
      # `identity` values reference Liatrio's trust policies. Adapt these for
      # your own org, or drop this step and use the default `GITHUB_TOKEN` /
      # your own PAT instead.
      - name: Generate Read Bundle Token
        id: generate_token
        uses: octo-sts/action@6177b4481c00308b3839969c3eca88c96a91775f # v1.0.0
        with:
          scope: liatrio # adapt for your org
          identity: autogov-infra # liatrio/.github/chainguard/autogov-infra.sts.yaml — adapt for your org

      - name: Download Policy Bundle
        env:
          GH_TOKEN: ${{ steps.generate_token.outputs.token }}
        run: |
          gh release download \
            --repo liatrio/autogov-policy-library \
            --pattern "bundle.tar.gz"
```

> **Note:** Pin actions to a commit SHA rather than a tag — a SHA is immutable.
> If you are not using octo-sts, set `GH_TOKEN: ${{ github.token }}` and remove
> the `id-token: write` permission and the token-minting step.

> **Org-specific constraints:** Some policies in this library hardcode
> Liatrio-specific values — the approved owner ID
> (`policies/shared/access/access.rego`), the `/liatrio/` Fulcio identity check
> (`policies/shared/utils/utils.rego`), and the `ghcr.io/liatrio/` subject prefix
> (`policies/security/metadata/metadata.rego`). Adapt these for your own org before
> using the affected policies.

## Getting Started

To start using the policies from this library, follow these steps:

1. Clone this repository to your local machine.
2. Install prerequisites.
3. Review the available policy files in the `policies` directory.
4. Customize the policies to fit your specific governance requirements.

### Prerequisites

```zsh
brew install make docker
```

### Makefile Commands Guide

- **`make all`**: Runs formatting, linting, checks, and tests.
- **`make eval-good`**: Runs OPA evaluation against real data.
- **`make eval-bad`**: Runs OPA evaluation against fake data.
- **`make fmt`**: Formats OPA files to fix non-compliance issues.
- **`make lint`**: Lints policies using `regal`.
- **`make check`**: Validates OPA policies.
- **`make test`**: Runs OPA unit tests.

### Attestation Guide

> (Optional) sometimes the best place to start is looking at an attestation; its contents and format are important for authoring policies.

#### Download Attestation

To download attestations from GitHub, you must [login to ghcr.io](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#authenticating-with-a-personal-access-token-classic).

```zsh
export CR_PAT=YOUR_TOKEN
echo $CR_PAT | docker login ghcr.io -u USERNAME --password-stdin
```

Now that you are authenticated, you can download the attestation.

ex:

```zsh
gh attestation download oci://ghcr.io/liatrio/autogov-workflows@sha256:efa6fcc6c8059a5fcc2c2dcdcdb83a57a7bfe480bceefbeb99d86f480a8e8aae -o liatrio
```

You now have an jsonl of the json attestation objects.

#### Parse Attestation

The downloaded attestation is base64 encoded, but we can make it human readable by piping it through jq and base64 as shown below:

```zsh
cat sha256:efa6fcc6c8059a5fcc2c2dcdcdb83a57a7bfe480bceefbeb99d86f480a8e8aae.jsonl | jq -r '.dsseEnvelope.payload' | base64 -d | jq -r
```

#### Put it all together

You can also run it all at once:

```zsh
gh attestation verify oci://ghcr.io/liatrio/autogov-workflows@sha256:efa6fcc6c8059a5fcc2c2dcdcdb83a57a7bfe480bceefbeb99d86f480a8e8aae \
  -o liatrio \
  --format json \
  --jq '.[0].attestation.bundle.dsseEnvelope.payload' \
  | base64 -d | jq
```

> Note: This will only give you the first attestation object of the bundle downloaded. You can increase the index at .[0] to get other attestation objects.

### Creating Policy

Use this [example attestation](./test/attestations.json) to help pick an object to validate. For more detailed information on authoring Rego policy, please refer to the following resources:

- [The Rego Playground - For quickly testing Rego](https://play.openpolicyagent.org)
- [OPA Policy Authoring Course](https://academy.styra.com/courses/opa-rego)

#### Standard Practices

- A new policy should have a one to one relationship with the job artifact and attestation
- A new policy should be an individual file in the policies/security folder.
- The policy file should:
  - Set violations based rules defined and only have `allow` set to true if there are no violations after evaluating all the rules
  - Check that predicateType is present in the payload (attestation bundle/list of attestations objects)
  - If predicateType is not unique, also check for subject in addition to predicateType
  - Check contents of attestation where predicateType matches

![policy](assets/img/policy.png)


#### Allow if no violations

ex:

[allow in provenance.rego](policies/security/provenance/provenance.rego#L24)

  ```rego
  default allow := false

  allow if {
    count(violations) == 0
  }
  ```

#### Check for presence of predicateType

Use Count condition to check for the presence of a predicate in the payload

ex:

[is_slsa_provenance_present in provenance.rego](policies/security/provenance/provenance.rego#L90)

  ```rego
  # Check for SLSA Provenance presence
  is_slsa_provenance_present(payload) if {
    count([obj | some obj in payload; utils.is_slsa_provenance(obj)]) > 0
  }
  ```

  > If predicateType is not unique the `is_<predicateType>` function should include a rule to check for unique subject in addition to checking predicateType

#### Check for values where predicateType matches

Use `some` to iterate through attestations and match on predicate to evaluate predicate contents

ex:

[violation rule in provenance.rego](policies/security/provenance/provenance.rego#L41)

  ```rego
  # Where predicateType is slsa provenance, the buildType should be present in the predicate
  violations contains msg if {
    some payload in utils.decoded_payload_list
    utils.is_slsa_provenance(payload)
    not payload.predicate.buildDefinition.buildType
    msg := "build type is missing"
  }
  ```

#### Complete Policy Example

A policy file will generally look like the following:

  ```rego
  package security.my_new_policy

  import data.shared.access
  import data.shared.utils
  import rego.v1

  default allow := false

  allow if {
    count(violations) == 0
  }

  violations contains msg if {
    some payload in utils.decoded_payload_list
    not payload.predicateType
    msg := "predicate type is missing"
  }

  is_slsa_provenance_present(payload) if {
    count([obj | some obj in payload; utils.is_slsa_provenance(obj)]) > 0
  }
  ```

## Check Yourself Before You Wreck Yourself

> helpful sample outputs & inputs for our specific use case and gotchas to watch out for. if you get stuck comeback here for sanity checks

### Unit Testing

When you define a function in one file/package and would like to reference it in another (like for unit testing), you **must** include the file hosting the function definition in the opa test command:

`opa test -v policies/security/sbom/sbom.rego policies/security/sbom/sbom_test.rego`

`sbom.rego` defines the function `is_cyclonedx_bom_present`, and `sbom_test.rego` calls the function.

### Understand the input data

The attestation bundle downloaded from Github is `.jsonl`

Rego cannot natively iterate over `.jsonl`

We must run the .jsonl through a `jq -s .` so we can pass a .json (list of objects) to the input of the Rego policy

Before we pass the input straight into rules logic, we parse and decode the data for each object's dsseEnvelope.payload object in the input (list of objects):

```rego

parse_payload(payload) = parsed_payload if {
    decoded_payload := base64.decode(payload)
    parsed_payload := json.unmarshal(decoded_payload)
}

decoded_payload_list := [decoded | 
  some i;
  obj := input[i]; # Iterate over the input list
  payload := obj.dsseEnvelope.payload; # Extract the payload
  base64.decode(payload, decoded_payload_raw); # Decode the base64 payload
  json.unmarshal(decoded_payload_raw, decoded) # Unmarshal the decoded payload into a JSON object
]
```

#### Refined Sample data

We now have a list of objects as the parsed payload.

```json
[
  {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [
      {
        "name": "ghcr.io/liatrio/autogov-workflows",
        "digest": {
          "sha256": "d379d8ef02ef446dc22e57e845ac7f3e5053b9398475541a8530d707511e6264"
        }
      }
    ],
    "predicateType": "https://cyclonedx.org/bom",
    "predicate": {...}
  },
  {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [
      {
        "name": "ghcr.io/liatrio/autogov-workflows",
        "digest": {
          "sha256": "d379d8ef02ef446dc22e57e845ac7f3e5053b9398475541a8530d707511e6264"
        }
      }
    ],
    "predicateType": "https://slsa.dev/provenance/v1",
    "predicate": {...}
  }
]
```

### Understand the output

> outputs should look/smell like the following

#### Expected outputs for allow policy

expected *non-passing* results for `allow` rule

If the output is `{}` the policy failed (conditions were not met). This is an intentional undefined result so that we can use the --fail flag in pipelines/workflows to block/gate the PR from being merged if there is policy failure.

expected *passing* results for `allow` rule

```json
{
  "result": [
    {
      "expressions": [
        {
          "value": true,
          "text": "data.governance.allow",
          "location": {
            "row": 1,
            "col": 1
          }
        }
      ]
    }
  ]
}
```

#### Expected outputs for violations policy

expected *non-passing* results for `violation` rule

```json
{
  "result": [
    {
      "expressions": [
        {
          "value": {
            "provenance": [],
            "sbom": [
              "cyclonedx sbom is missing"
            ]
          },
          "text": "data.governance.violations",
          "location": {
            "row": 1,
            "col": 1
          }
        }
      ]
    }
  ]
}
```

expected *passing* results for `violation` rule

```json
{
  "result": [
    {
      "expressions": [
        {
          "value": {
            "provenance": [],
            "sbom": []
          },
          "text": "data.governance.violations",
          "location": {
            "row": 1,
            "col": 1
          }
        }
      ]
    }
  ]
}
```
