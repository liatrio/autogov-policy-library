package vsa_verification_result_test

import rego.v1

import data.governance.vsa_verification_result

# Test VSA verification result PASSED
test_vsa_verification_result_passed if {
	vsa_verification_result.allow with input as {"predicate": {"verificationResult": "PASSED"}}
}

# Test VSA verification result FAILED
test_vsa_verification_result_failed if {
	not vsa_verification_result.allow with input as {"predicate": {"verificationResult": "FAILED"}}

	vsa_verification_result.deny with input as {"predicate": {"verificationResult": "FAILED"}}
}

# Test VSA verification result UNKNOWN
test_vsa_verification_result_unknown if {
	not vsa_verification_result.allow with input as {"predicate": {"verificationResult": "UNKNOWN"}}

	vsa_verification_result.deny with input as {"predicate": {"verificationResult": "UNKNOWN"}}
}

# Test missing verificationResult field
test_vsa_verification_result_missing if {
	not vsa_verification_result.allow with input as {"predicate": {}}
}

# Test invalid verificationResult status
test_vsa_verification_result_invalid if {
	not vsa_verification_result.allow with input as {"predicate": {"verificationResult": "INVALID_STATUS"}}
}

# Test complete VSA structure
test_vsa_complete_structure_passed if {
	vsa_verification_result.allow with input as {
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/verification_summary/v1",
		"subject": [{
			"uri": "ghcr.io/liatrio/example@sha256:abc123",
			"digest": {"sha256": "abc123"},
		}],
		"predicate": {
			"verifier": {"id": "https://github.com/liatrio/autogov-verify"},
			"timeVerified": "2024-01-01T00:00:00Z",
			"resourceUri": "ghcr.io/liatrio/example@sha256:abc123",
			"verificationResult": "PASSED",
			"verifiedLevels": ["SLSA_BUILD_LEVEL_3"],
		},
	}
}

# Test complete VSA structure failed
test_vsa_complete_structure_failed if {
	not vsa_verification_result.allow with input as {
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/verification_summary/v1",
		"subject": [{
			"uri": "ghcr.io/liatrio/example@sha256:def456",
			"digest": {"sha256": "def456"},
		}],
		"predicate": {
			"verifier": {"id": "https://github.com/liatrio/autogov-verify"},
			"timeVerified": "2024-01-01T00:00:00Z",
			"resourceUri": "ghcr.io/liatrio/example@sha256:def456",
			"verificationResult": "FAILED",
			"verifiedLevels": [],
		},
	}
}
