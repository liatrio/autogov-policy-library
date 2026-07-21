# Maintainers

This repository is part of the AutoGov project. Review and merge authority is
held by `@liatrio/tag-autogov` (see [`CODEOWNERS`](CODEOWNERS)), which currently
resolves to a single maintainer — see the review model below.

| Maintainer  | GitHub                                       | Role            |
| ----------- | -------------------------------------------- | --------------- |
| Ian Hundere | [@ianhundere](https://github.com/ianhundere) | Lead maintainer |

## Review model & SLSA source posture

This project is currently maintained by a **single maintainer**, so
`@liatrio/tag-autogov` effectively resolves to one person. Genuine two-party
review (SLSA Source **L4**) requires two trusted persons per change and is **not
met today** — it is aspirational until the project gains community co-maintainers.
The continuously enforced technical controls (branch protection, signed commits,
linear/retained history, required status checks) earn an honest **SLSA Source
L3**. AI-assisted review is used as *tooling*, not counted as a second review
party. This repo's own release verifies against the same policy it publishes;
its self-releases are not gated on a human approval that did not independently
happen, while the published bundle keeps the strict default for adopters with
real review teams.

See the [autogov](https://github.com/liatrio/autogov) repository for the project
overview and contribution guidelines.
