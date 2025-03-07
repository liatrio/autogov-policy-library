package governance_test

import data.governance
import rego.v1

# Test all true case
test_allow_all_true if {
	violations := set()
	test_input := [{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": {"certificate": {"rawBytes": "valid-github-cert"}},
		"ignore_dependency_vulnerabilities": false,
	}]

	governance.allow with input as test_input
		with data.security.sbom.allow as true
		with data.security.provenance.allow as true
		with data.security.metadata.allow as true
		with data.security.certificate.allow as true
		with data.security.dependency_vulnerability.low.allow as true
		with data.security.dependency_vulnerability.medium.allow as true
		with data.security.dependency_vulnerability.high.allow as true
		with data.security.dependency_vulnerability.critical.allow as true
		with data.security.sbom.violations as violations
		with data.security.provenance.violations as violations
		with data.security.metadata.violations as violations
		with data.security.certificate.violations as violations
		with data.security.dependency_vulnerability.low.violations as violations
		with data.security.dependency_vulnerability.medium.violations as violations
		with data.security.dependency_vulnerability.high.violations as violations
		with data.security.dependency_vulnerability.critical.violations as violations
}

# Test all true case with ignored dependency vulnerabilities
test_allow_all_true_ignore_deps if {
	violations := set()
	dep_violations := {"some vulnerability"}
	test_input := [{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": {"certificate": {"rawBytes": "valid-github-cert"}},
		"ignore_dependency_vulnerabilities": true,
	}]

	governance.allow with input as test_input
		with data.security.sbom.allow as true
		with data.security.provenance.allow as true
		with data.security.metadata.allow as true
		with data.security.certificate.allow as true
		with data.security.dependency_vulnerability.low.allow as false
		with data.security.dependency_vulnerability.medium.allow as false
		with data.security.dependency_vulnerability.high.allow as false
		with data.security.dependency_vulnerability.critical.allow as false
		with data.security.sbom.violations as violations
		with data.security.provenance.violations as violations
		with data.security.metadata.violations as violations
		with data.security.certificate.violations as violations
		with data.security.dependency_vulnerability.low.violations as dep_violations
		with data.security.dependency_vulnerability.medium.violations as dep_violations
		with data.security.dependency_vulnerability.high.violations as dep_violations
		with data.security.dependency_vulnerability.critical.violations as dep_violations
}

# Test SBOM false case
test_allow_sbom_false if {
	sbom_violations := {"test violation"}
	other_violations := set()
	not governance.allow with data.security.sbom.violations as sbom_violations
		with data.security.provenance.violations as other_violations
		with data.security.metadata.violations as other_violations
		with data.security.dependency_vulnerability.low.violations as other_violations
		with data.security.dependency_vulnerability.medium.violations as other_violations
		with data.security.dependency_vulnerability.high.violations as other_violations
		with data.security.dependency_vulnerability.critical.violations as other_violations
}

# Test provenance false case
test_allow_provenance_false if {
	provenance_violations := {"test violation"}
	other_violations := set()
	not governance.allow with data.security.sbom.violations as other_violations
		with data.security.provenance.violations as provenance_violations
		with data.security.metadata.violations as other_violations
		with data.security.dependency_vulnerability.low.violations as other_violations
		with data.security.dependency_vulnerability.medium.violations as other_violations
		with data.security.dependency_vulnerability.high.violations as other_violations
		with data.security.dependency_vulnerability.critical.violations as other_violations
}

# Test metadata false case
test_allow_metadata_false if {
	metadata_violations := {"test violation"}
	other_violations := set()
	not governance.allow with data.security.sbom.violations as other_violations
		with data.security.provenance.violations as other_violations
		with data.security.metadata.violations as metadata_violations
		with data.security.dependency_vulnerability.low.violations as other_violations
		with data.security.dependency_vulnerability.medium.violations as other_violations
		with data.security.dependency_vulnerability.high.violations as other_violations
		with data.security.dependency_vulnerability.critical.violations as other_violations
}

# Test certificate false case
test_allow_certificate_false if {
	certificate_violations := {"test violation"}
	other_violations := set()
	not governance.allow with data.security.certificate.violations as certificate_violations
		with data.security.sbom.violations as other_violations
		with data.security.provenance.violations as other_violations
		with data.security.metadata.violations as other_violations
		with data.security.dependency_vulnerability.low.violations as other_violations
		with data.security.dependency_vulnerability.medium.violations as other_violations
		with data.security.dependency_vulnerability.high.violations as other_violations
		with data.security.dependency_vulnerability.critical.violations as other_violations
}

# Test low vulnerability false case
test_allow_low_vulnerability_false if {
	low_violations := {"test violation"}
	other_violations := set()
	not governance.allow with data.security.dependency_vulnerability.low.violations as low_violations
		with data.security.sbom.violations as other_violations
		with data.security.provenance.violations as other_violations
		with data.security.metadata.violations as other_violations
		with data.security.certificate.violations as other_violations
		with data.security.dependency_vulnerability.medium.violations as other_violations
		with data.security.dependency_vulnerability.high.violations as other_violations
		with data.security.dependency_vulnerability.critical.violations as other_violations
}

# Test medium vulnerability false case
test_allow_medium_vulnerability_false if {
	medium_violations := {"test violation"}
	other_violations := set()
	not governance.allow with data.security.dependency_vulnerability.medium.violations as medium_violations
		with data.security.sbom.violations as other_violations
		with data.security.provenance.violations as other_violations
		with data.security.metadata.violations as other_violations
		with data.security.certificate.violations as other_violations
		with data.security.dependency_vulnerability.low.violations as other_violations
		with data.security.dependency_vulnerability.high.violations as other_violations
		with data.security.dependency_vulnerability.critical.violations as other_violations
}

# Test high vulnerability false case
test_allow_high_vulnerability_false if {
	high_violations := {"test violation"}
	other_violations := set()
	not governance.allow with data.security.dependency_vulnerability.high.violations as high_violations
		with data.security.sbom.violations as other_violations
		with data.security.provenance.violations as other_violations
		with data.security.metadata.violations as other_violations
		with data.security.certificate.violations as other_violations
		with data.security.dependency_vulnerability.low.violations as other_violations
		with data.security.dependency_vulnerability.medium.violations as other_violations
		with data.security.dependency_vulnerability.critical.violations as other_violations
}

sbom_violations := {"cyclonedx sbom is missing"}

provenance_violations := {"predicate type is not correct"}

metadata_violations := {"workflow inputs are missing"}

certificate_violations := {"bundle certificate is invalid"}

dependency_vulnerability_violations_low := {"Low Vulnerabilities found."}

dependency_vulnerability_violations_medium := {"Medium Vulnerabilities found."}

dependency_vulnerability_violations_high := {"High Vulnerabilities found."}

dependency_vulnerability_violations_critical := {"Critical Vulnerabilities found."}

# Test violations reporting
test_violations_report if {
	test_input := [{
		"dsseEnvelope": {"payload": base64.encode(json.marshal({
			"predicateType": "https://example.org/other",
			"subject": [{
				"name": "ghcr.io/liatrio/demo-gh-autogov-workflows",
				"digest": {"sha256": "d379d8ef02ef446dc22e57e845ac7f3e5053b9398475541a8530d707511e6264"},
			}],
			"predicate": {},
		}))},
		"ignore_dependency_vulnerabilities": false,
	}]

	governance.violations == {
		"sbom": sbom_violations,
		"provenance": provenance_violations,
		"metadata": metadata_violations,
		"certificate": certificate_violations,
		"dependency_vulnerability_low": dependency_vulnerability_violations_low,
		"dependency_vulnerability_medium": dependency_vulnerability_violations_medium,
		"dependency_vulnerability_high": dependency_vulnerability_violations_high,
		"dependency_vulnerability_critical": dependency_vulnerability_violations_critical,
	} with input as test_input
		with data.security.sbom.violations as sbom_violations
		with data.security.provenance.violations as provenance_violations
		with data.security.metadata.violations as metadata_violations
		with data.security.certificate.violations as certificate_violations
		with data.security.dependency_vulnerability.low.violations as dependency_vulnerability_violations_low
		with data.security.dependency_vulnerability.medium.violations as dependency_vulnerability_violations_medium
		with data.security.dependency_vulnerability.high.violations as dependency_vulnerability_violations_high
		with data.security.dependency_vulnerability.critical.violations as dependency_vulnerability_violations_critical
}

# Test violations reporting with ignored dependency vulnerabilities
test_violations_report_ignore_deps if {
	test_input := [{
		"dsseEnvelope": {"payload": base64.encode(json.marshal({
			"predicateType": "https://example.org/other",
			"subject": [{
				"name": "ghcr.io/liatrio/demo-gh-autogov-workflows",
				"digest": {"sha256": "d379d8ef02ef446dc22e57e845ac7f3e5053b9398475541a8530d707511e6264"},
			}],
			"predicate": {},
		}))},
		"ignore_dependency_vulnerabilities": true,
	}]

	governance.violations == {
		"sbom": sbom_violations,
		"provenance": provenance_violations,
		"metadata": metadata_violations,
		"certificate": certificate_violations,
		"dependency_vulnerability_low": set(),
		"dependency_vulnerability_medium": set(),
		"dependency_vulnerability_high": set(),
		"dependency_vulnerability_critical": set(),
	} with input as test_input
		with data.security.sbom.violations as sbom_violations
		with data.security.provenance.violations as provenance_violations
		with data.security.metadata.violations as metadata_violations
		with data.security.certificate.violations as certificate_violations
		with data.security.dependency_vulnerability.low.violations as dependency_vulnerability_violations_low
		with data.security.dependency_vulnerability.medium.violations as dependency_vulnerability_violations_medium
		with data.security.dependency_vulnerability.high.violations as dependency_vulnerability_violations_high
		with data.security.dependency_vulnerability.critical.violations as dependency_vulnerability_violations_critical
}

# Test empty input case
test_empty_input if {
	test_input := []
	not governance.allow with input as test_input
}

# Test no violations case
test_no_violations if {
	violations := set()
	test_input := [{"ignore_dependency_vulnerabilities": false}]

	governance.violations == {
		"sbom": violations,
		"provenance": violations,
		"metadata": violations,
		"certificate": violations,
		"dependency_vulnerability_low": violations,
		"dependency_vulnerability_medium": violations,
		"dependency_vulnerability_high": violations,
		"dependency_vulnerability_critical": violations,
	} with input as test_input
		with data.security.sbom.violations as violations
		with data.security.provenance.violations as violations
		with data.security.metadata.violations as violations
		with data.security.certificate.violations as violations
		with data.security.dependency_vulnerability.low.violations as violations
		with data.security.dependency_vulnerability.medium.violations as violations
		with data.security.dependency_vulnerability.high.violations as violations
		with data.security.dependency_vulnerability.critical.violations as violations
}
