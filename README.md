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

The input data coming from the attestations is a `.jsonl` and its base64 encoded.

Before we pass the input straight into rules logic, we parse and decode with:

```rego
some_rule if {
    parsed_payload := parse_payload(input.dsseEnvelope.payload)
    parsed_payload.predicateType == "something"
}

parse_payload(payload) := parsed_payload if {
	decoded_payload := base64.decode(payload)
	parsed_payload := json.unmarshal(decoded_payload)
}
```

#### Refined Sample data

> notice that this is not a valid json as its missing a comma. That is the true result of the parsing the payload, but we can still pass this to rules without problem.

```json
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
}
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
```

### Understand the output

If the output is `{}` something went wrong

#### Expected outputs

> outputs should look/smell like the following

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

expected *non-passing* results for `allow` rule

```json
{
  "result": [
    {
      "expressions": [
        {
          "value": false,
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
