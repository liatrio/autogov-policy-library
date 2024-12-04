# METADATA
# scope: package
# title: Governance Policy
# description: >-
#   Aggregates security policies to ensure all checks pass:
#   - Build provenance validation
#   - SBOM validation
#   - Metadata validation
#   - Certificate validation
# entrypoint: true
package governance

import data.security.certificate
import data.security.metadata
import data.security.provenance
import data.security.sbom

import rego.v1

allow if {
	sbom.allow
	provenance.allow
	metadata.allow
	certificate.allow
}

violations := {
	"sbom": sbom.violations,
	"provenance": provenance.violations,
	"certificate": certificate.violations,
	"metadata": metadata.violations,
}
