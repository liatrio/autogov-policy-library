# METADATA
# scope: package
# title: Governance Policy
# description: >-
#   Aggregates security policies to ensure all checks pass:
#   - Build provenance validation
#   - SBOM validation
#   - Metadata validation
#   - Dependency Vulnerability validation
#   - Certificate validation
# entrypoint: true
# custom:
#  version: 0.9.3
#  path: policies/governance
#  filename: governance.rego
package governance

import data.security.certificate
import data.security.code_scan
import data.security.dependency_vulnerability.critical
import data.security.dependency_vulnerability.high
import data.security.dependency_vulnerability.low
import data.security.dependency_vulnerability.medium
import data.security.metadata
import data.security.provenance
import data.security.sbom
import data.security.source_review
import data.security.test_result

import rego.v1

allow if {
	sbom.allow
	provenance.allow
	metadata.allow
	certificate.allow
	test_result.allow
	code_scan.allow
	source_review.allow
	some x in input
	x.ignore_dependency_vulnerabilities
}

allow if {
	sbom.allow
	provenance.allow
	metadata.allow
	certificate.allow
	test_result.allow
	code_scan.allow
	source_review.allow
	not any_ignore_deps
	low.allow
	medium.allow
	high.allow
	critical.allow
}

any_ignore_deps if {
	some x in input
	x.ignore_dependency_vulnerabilities
}

violations := {
	"sbom": sbom.violations,
	"provenance": provenance.violations,
	"certificate": certificate.violations,
	"metadata": metadata.violations,
	"test_result": test_result.violations,
	"code_scan": code_scan.violations,
	"source_review": source_review.violations,
	"dependency_vulnerability_low": dependency_vulnerability_low_violations,
	"dependency_vulnerability_medium": dependency_vulnerability_medium_violations,
	"dependency_vulnerability_high": dependency_vulnerability_high_violations,
	"dependency_vulnerability_critical": dependency_vulnerability_critical_violations,
}

dependency_vulnerability_low_violations contains v if {
	not any_ignore_deps
	some v in low.violations
}

dependency_vulnerability_medium_violations contains v if {
	not any_ignore_deps
	some v in medium.violations
}

dependency_vulnerability_high_violations contains v if {
	not any_ignore_deps
	some v in high.violations
}

dependency_vulnerability_critical_violations contains v if {
	not any_ignore_deps
	some v in critical.violations
}
