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
import data.security.dependency_vulnerability.critical
import data.security.dependency_vulnerability.high
import data.security.dependency_vulnerability.low
import data.security.dependency_vulnerability.medium
import data.security.metadata
import data.security.provenance
import data.security.sbom

import rego.v1

allow if {
	sbom.allow
	provenance.allow
	metadata.allow
	certificate.allow
	low.allow
	medium.allow
	high.allow
	critical.allow
}

violations := {
	"sbom": sbom.violations,
	"provenance": provenance.violations,
	"certificate": certificate.violations,
	"metadata": metadata.violations,
	"dependency_vulnerability_low": low.violations,
	"dependency_vulnerability_medium": medium.violations,
	"dependency_vulnerability_high": high.violations,
	"dependency_vulnerability_critical": critical.violations,
}
