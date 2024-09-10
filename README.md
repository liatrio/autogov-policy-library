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
