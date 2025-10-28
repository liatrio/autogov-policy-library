package vsa_verification_result_test

import rego.v1

import data.governance.vsa_verification_result

# Helper function to create Sigstore bundle format
sigstore_bundle(verification_result) := {
	"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
	"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/verification_summary/v1",
		"subject": [{
			"name": "ghcr.io/liatrio/example",
			"digest": {"sha256": "abc123"},
		}],
		"predicate": {
			"_type": "https://in-toto.io/Statement/v1",
			"predicateType": "https://slsa.dev/verification_summary/v1",
			"predicate": {
				"verifier": {"id": "https://github.com/liatrio/autogov-verify"},
				"timeVerified": "2024-01-01T00:00:00Z",
				"resourceUri": "ghcr.io/liatrio/example@sha256:abc123",
				"verificationResult": verification_result,
				"verifiedLevels": ["SLSA_BUILD_LEVEL_3"],
			},
		},
	}))},
}

# Test VSA verification result PASSED
test_vsa_verification_result_passed if {
	vsa_verification_result.allow with input as sigstore_bundle("PASSED")
}

# Test VSA verification result FAILED
test_vsa_verification_result_failed if {
	not vsa_verification_result.allow with input as sigstore_bundle("FAILED")
	vsa_verification_result.deny with input as sigstore_bundle("FAILED")
}

# Test VSA verification result UNKNOWN
test_vsa_verification_result_unknown if {
	not vsa_verification_result.allow with input as sigstore_bundle("UNKNOWN")
	vsa_verification_result.deny with input as sigstore_bundle("UNKNOWN")
}

# Test missing verificationResult field
test_vsa_verification_result_missing if {
	bundle := {
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"dsseEnvelope": {"payload": base64.encode(json.marshal({
			"_type": "https://in-toto.io/Statement/v1",
			"predicateType": "https://slsa.dev/verification_summary/v1",
			"predicate": {
				"_type": "https://in-toto.io/Statement/v1",
				"predicateType": "https://slsa.dev/verification_summary/v1",
				"predicate": {
					"verifier": {"id": "https://github.com/liatrio/autogov-verify"},
					"timeVerified": "2024-01-01T00:00:00Z",
				},
			},
		}))},
	}
	not vsa_verification_result.allow with input as bundle
}

# Test invalid verificationResult status
test_vsa_verification_result_invalid if {
	not vsa_verification_result.allow with input as sigstore_bundle("INVALID_STATUS")
}

# Test complete sigstore bundle structure - should pass
test_sigstore_bundle_structure_passed if {
	vsa_verification_result.allow with input as sigstore_bundle("PASSED")
}

# Test complete sigstore bundle structure - should fail
test_sigstore_bundle_structure_failed if {
	not vsa_verification_result.allow with input as sigstore_bundle("FAILED")
	vsa_verification_result.deny with input as sigstore_bundle("FAILED")
}
