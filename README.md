# GitHub AutoGov Policy Library

This repository serves as a collection of OPA Rego policies that are specifically designed for attestations created with GitHub Artifact Attestations.

## Overview

The GitHub AutoGov Policy Library provides a set of predefined policies that can be used to enforce governance and compliance rules for attestations within your GitHub repositories. These policies are written in OPA Rego language, which allows for flexible and customizable rule definitions.

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

### Creating Policy

Use this [example attestation](./test/build_provenance_and_sbom_attestations.json) to help pick an object to validate. For more detailed information on authoring Rego policy, please refer to the following resources:

- [The Rego Playground - For quickly testing Rego](https://play.openpolicyagent.org)
- [OPA Policy Authoring Course](https://academy.styra.com/courses/opa-rego)

## Contributing

Contributions to the GitHub AutoGov Policy Library are welcome! If you have any improvements or additional policies to suggest, please submit a pull request.

## Check Yourself Before Your Wreck Yourself

> helpful sample outputs & inputs for our specific use case and gotchas to watch out for. if you get stuck comeback here for sanity checks

### Unit Testing

When you define a function in one file/package and would like to reference it in another (like for unit testing), you **must** include the file hosting the function definition in the opa test command:

`opa test -v policies/security/sbom.rego policies/security/sbom_test.rego`

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
        "name": "ghcr.io/liatrio/demo-gh-autogov-workflows",
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
        "name": "ghcr.io/liatrio/demo-gh-autogov-workflows",
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
