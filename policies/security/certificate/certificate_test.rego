package security.certificate_test

import data.security.certificate
import rego.v1

test_valid_github_fulcio_cert if {
	# Test with valid GitHub Fulcio certificate
	test_input := [{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": {"certificate": {"rawBytes": "valid-github-cert"}},
	}]

	certificate.allow with input as test_input
		with data.shared.utils.is_valid_fulcio_cert as {"valid-github-cert": true}
}

test_empty_certificate if {
	# Test with empty certificate
	test_input := [{"verificationMaterial": {"certificate": {"rawBytes": ""}}}]

	not certificate.allow with input as test_input

	expected := {"certificate is empty"}
	certificate.violations with input as test_input == expected
}

test_empty_input if {
	# Empty input should not be allowed
	not certificate.allow with input as []
}

test_missing_certificate if {
	# Missing certificate field should not be allowed
	test_input := [{"verificationMaterial": {"certificate": {"rawBytes": null}}}]

	not certificate.allow with input as test_input

	expected := {"certificate is missing"}
	certificate.violations with input as test_input == expected
}

test_non_github_cert if {
	# Test with non-GitHub certificate
	test_input := [{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": {"certificate": {"rawBytes": "non-github-cert"}},
	}]

	expected := {"certificate is not from github fulcio"}
	certificate.violations with input as test_input == expected
}
