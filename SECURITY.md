# Security Policy

## Reporting a Vulnerability

We take the security of `autogov-policy-library` seriously. If you discover a
security vulnerability, please report it **privately** — do not open a public
issue.

**Preferred:** use GitHub's [private vulnerability reporting](https://github.com/liatrio/autogov-policy-library/security/advisories/new)
("Report a vulnerability" under the repository's **Security** tab). This keeps
the report confidential until a fix is available and a coordinated disclosure
can be made.

Please include, where possible:

- A description of the vulnerability and its impact
- Steps to reproduce (proof-of-concept, affected version/commit)
- Any known mitigations or workarounds

## What to Expect

- **Acknowledgement** of your report as soon as the maintainers are able to triage it.
- An assessment of the report and, if confirmed, a plan and timeline for a fix.
- Coordinated disclosure: we will work with you on timing and credit you in the
  advisory unless you prefer to remain anonymous.

## Supported Versions

`autogov-policy-library` is under active development. Security fixes are applied
to the latest released version. Please upgrade to the most recent release before
reporting, in case the issue is already addressed.

## Scope

This policy covers the OPA Rego policies and policy bundle published from this
repository. Vulnerabilities in third-party dependencies should be reported
upstream; if a dependency advisory affects this project, we track and remediate
it via dependency updates in CI.
