# METADATA
# scope: package
# title: Governance Policy
# description: >-
#   Aggregates security policies to ensure all checks pass:
#   - Build provenance validation
#   - SBOM attestation validation
#   - Metadata validation
# entrypoint: true
package governance

import data.security.metadata
import data.security.provenance
import data.security.sbom

import rego.v1

allow if {
	sbom.allow
	provenance.allow
	metadata.allow
}

violations := {
	"sbom": sbom.violations,
	"provenance": provenance.violations,
	"metadata": metadata.violations,
}
