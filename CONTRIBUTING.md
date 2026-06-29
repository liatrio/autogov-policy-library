# Contributing to the autogov policy library

Thank you for your interest in contributing! This repository holds the OPA/Rego
policies that the [autogov](https://github.com/liatrio/autogov) CLI evaluates
during verification. For the wider project and how these policies are consumed,
start at the [flagship repo](https://github.com/liatrio/autogov).

## Prerequisites

- [Docker](https://www.docker.com/) — the validation targets run via
  `docker compose`, so no local OPA/Regal install is required.
- [`gh`](https://cli.github.com/) and `jq` for the optional `parse` helper.

## Local development

All validation runs through the `Makefile` (each target wraps `docker compose`):

```bash
make all      # fmt + lint + check + test — run this before opening a PR
make fmt      # opa fmt (formats Rego)
make lint     # regal lint
make check    # opa check (compile/type checks)
make test     # opa unit tests
make eval-good   # evaluate policies against passing sample data
make eval-bad    # evaluate policies against failing sample data
```

## Contributing process

1. **Open an issue** describing the policy gap or bug.
2. **Create a feature branch** with a descriptive name.
3. **Add the policy and its tests** — policies should ship with `*_test.rego`
   coverage for both the allow and deny paths.
4. **Run `make all`** — formatting, lint, compile, and tests must all pass.
5. **Open a pull request** with a clear description and a linked issue.

## Policy authoring conventions

See the [Creating Policy](README.md#creating-policy) and **Standard Practices**
sections of the README for the conventions this library follows: one policy per
artifact/attestation, match on `predicateType`, set `allow` only when there are
no violations, and validate configuration fail-closed.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`,
`fix:`, `chore:`, `docs:`) — releases and changelogs are generated from the
commit history.

## Code of Conduct

This project follows the
[Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
