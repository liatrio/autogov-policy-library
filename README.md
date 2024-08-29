# GitHub AutoGov Policy Library

This repository serves as a collection of OPA Rego policies that are specifically designed for attestations created with GitHub Asset Action.

## Overview

The GitHub AutoGov Policy Library provides a set of predefined policies that can be used to enforce governance and compliance rules for attestations within your GitHub repositories. These policies are written in OPA Rego language, which allows for flexible and customizable rule definitions.

## Getting Started

To start using the policies from this library, follow these steps:

1. Clone this repository to your local machine.
2. Install prerequisites.
3. Review the available policies in the `policies` directory.
4. Customize the policies to fit your specific governance requirements.

## Contributing

Contributions to the GitHub AutoGov Policy Library are welcome! If you have any improvements or additional policies to suggest, please submit a pull request. Make sure to follow the contribution guidelines outlined in the `CONTRIBUTING.md` file.

### Prerequisites

```zsh
brew install make
brew install opa
```

### Testing

#### Run Tests

To run unit testing:

```zsh
make test
or
opa test policy -v
```

### Adding a New Policy

1. Review data you want run a policy against

```zsh
make parse-real
```

2. Pick the object you want to check that value for from the parse json data
3. Write a unit test for the violation policy that expects to see a violation message
   - add policy in this file `policy/security/provenance_test.rego`
4. Write a policy that will evaluate to true or false for that value
   - add policy in this file `policy/security/provenance.rego`
5. Write a violation rule that will set the message, indicating a violation
   - add policy in this file `policy/security/provenance.rego`
