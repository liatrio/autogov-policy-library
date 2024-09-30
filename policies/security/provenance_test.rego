package security.provenance_test

import data.security.provenance
import rego.v1

# Test case for successful provenance with valid predicate, owner, and repo
test_valid_slsa_provenance if {
	test_input := [{
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://actions.github.io/buildtypes/workflow/v1",
			"internalParameters": {"github": {
				"repository_owner_id": "5726618",
				"repository_id": "845521085",
			}},
		}},
	}]
	result := provenance.allow with input as test_input
	result == true
}

# Test case for missing or invalid predicate type
test_invalid_predicate_type if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "invalid/predicate/type",
		"predicate": {},
	}))}}]
	result := provenance.allow with input as test_input
	result == false

	violations := provenance.violations with input as test_input
	"predicate type is not correct or missing" in violations
}

# Test case for invalid owner
test_invalid_owner if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://actions.github.io/buildtypes/workflow/v1",
			"internalParameters": {"github": {
				"repository_owner_id": "9999999",
				"repository_id": "845521085",
			}},
		}},
	}))}}]
	result := provenance.allow with input as test_input
	result == false

	violations := provenance.violations with input as test_input
	"owner is not correct or missing" in violations
}

# Test case for invalid repo
test_invalid_repo if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://actions.github.io/buildtypes/workflow/v1",
			"internalParameters": {"github": {
				"repository_owner_id": "5726618",
				"repository_id": "9999999",
			}},
		}},
	}))}}]
	result := provenance.allow with input as test_input
	result == false

	violations := provenance.violations with input as test_input
	"repo is not correct or missing" in violations
}

# Test case for CycloneDX BOM predicate (no checks for owner/repo)
test_valid_cyclonedx_bom if {
	test_input := [{
		"predicateType": "https://cyclonedx.org/bom",
		"predicate": {},
	}]
	result := provenance.allow with input as test_input
	result == true
}

# Test case for Cosign attestation with valid owner and repo
test_valid_cosign_attestation if {
	test_input := [{
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"predicate": {"metadata": {
			"owner": "5726618",
			"repositoryId": "849445664",
		}},
	}]
	result := provenance.allow with input as test_input
	result == true
}

test_is_slsa_provenance_true if {
	payload := {"predicateType": "https://slsa.dev/provenance/v1"}
	provenance.is_slsa_provenance(payload)
}

test_is_slsa_provenance_false if {
	payload := {"predicateType": "https://example.com/other"}

	not provenance.is_slsa_provenance(payload)
}
