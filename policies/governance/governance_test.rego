package governance_test

import data.governance
import rego.v1

# Test all true case
test_allow_all_true if {
	violations := set()
	test_input := [{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": {"certificate": {"rawBytes": "valid-github-cert"}},
	}]

	governance.allow with input as test_input
		with data.shared.utils.is_valid_fulcio_cert as {"valid-github-cert": true}
		with data.security.sbom.violations as violations
		with data.security.provenance.violations as violations
		with data.security.metadata.violations as violations
}

# Test SBOM false case
test_allow_sbom_false if {
	sbom_violations := {"test violation"}
	other_violations := set()
	not governance.allow with data.security.sbom.violations as sbom_violations
		with data.security.provenance.violations as other_violations
		with data.security.metadata.violations as other_violations
}

# Test provenance false case
test_allow_provenance_false if {
	provenance_violations := {"test violation"}
	other_violations := set()
	not governance.allow with data.security.sbom.violations as other_violations
		with data.security.provenance.violations as provenance_violations
		with data.security.metadata.violations as other_violations
}

# Test metadata false case
test_allow_metadata_false if {
	metadata_violations := {"test violation"}
	other_violations := set()
	not governance.allow with data.security.sbom.violations as other_violations
		with data.security.provenance.violations as other_violations
		with data.security.metadata.violations as metadata_violations
}

# Test certificate false case
test_allow_certificate_false if {
	certificate_violations := {"test violation"}
	other_violations := set()
	not governance.allow with data.security.certificate.violations as certificate_violations
		with data.security.sbom.violations as other_violations
		with data.security.provenance.violations as other_violations
		with data.security.metadata.violations as other_violations
}

# Test violations reporting
test_violations_report if {
	sbom_violations := {"cyclonedx sbom is missing"}
	provenance_violations := {"predicate type is not correct"}
	metadata_violations := {"workflow inputs are missing"}
	certificate_violations := {"bundle certificate is invalid"}
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://example.org/other",
		"subject": [{
			"name": "ghcr.io/liatrio/demo-gh-autogov-workflows",
			"digest": {"sha256": "d379d8ef02ef446dc22e57e845ac7f3e5053b9398475541a8530d707511e6264"},
		}],
		"predicate": {},
	}))}}]

	governance.violations == {
		"sbom": sbom_violations,
		"provenance": provenance_violations,
		"metadata": metadata_violations,
		"certificate": certificate_violations,
	} with input as test_input
		with data.security.sbom.violations as sbom_violations
		with data.security.provenance.violations as provenance_violations
		with data.security.metadata.violations as metadata_violations
		with data.security.certificate.violations as certificate_violations
}

# Test empty input case
test_empty_input if {
	test_input := []
	not governance.allow with input as test_input
}

# Test no violations case
test_no_violations if {
	violations := set()
	governance.violations == {
		"sbom": violations,
		"provenance": violations,
		"metadata": violations,
		"certificate": violations,
	} with data.security.sbom.violations as violations
		with data.security.provenance.violations as violations
		with data.security.metadata.violations as violations
		with data.security.certificate.violations as violations
}
