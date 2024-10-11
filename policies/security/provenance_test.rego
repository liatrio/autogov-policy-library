package security.provenance_test

import data.security.provenance
import rego.v1

test_is_slsa_provenance_true if {
	payload := {"predicateType": "https://slsa.dev/provenance/v1"}
	provenance.is_slsa_provenance(payload)
}

test_is_slsa_provenance_false if {
	payload := {"predicateType": "https://example.com/other"}

	not provenance.is_slsa_provenance(payload)
}

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
	"predicate type is not correct" in violations
}

# Test case for missing predicate type
test_missing_predicate_type if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({"predicate": {}}))}}]
	result := provenance.allow with input as test_input
	result == false

	violations := provenance.violations with input as test_input
	"predicate type is missing" in violations
}

# Test case for invalid owner for SLSA build provenance
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
	"owner is not correct in build provenance" in violations
}

# Test case for invalid repo for SLSA build provenance
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
	"repository is not correct in build provenance" in violations
}

# Test case for missing repository in SLSA build provenance
test_missing_repo_id_slsa if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://actions.github.io/buildtypes/workflow/v1",
			"internalParameters": {"github": {"repository_owner_id": "5726618"}},
		}},
	}))}}]

	result := provenance.allow with input as test_input
	result == false

	violations := provenance.violations with input as test_input
	"repository is missing in build provenance" in violations
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

# Test case for metadata attestation with valid owner and repo
test_valid_metadata_attestation if {
	test_input := [{
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"predicate": {"metadata": {
			"ownerData": {"ownerId": "5726618"},
			"repositoryData": {"repositoryId": "849445664"},
		}},
	}]
	result := provenance.allow with input as test_input
	result == true
}

# Test case for metadata attestation with invalid owner and repo
test_invalid_metadata_attestation if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"predicate": {"metadata": {
			"ownerData": {"ownerId": "9999999"},
			"repositoryData": {"repositoryId": "9999999"},
		}},
	}))}}]

	result := provenance.allow with input as test_input

	result == false

	violations := provenance.violations with input as test_input

	"owner is not correct in metadata" in violations
	"repository is not correct in metadata" in violations
}

# Test case for missing workflow inputs in metadata
test_missing_workflow_inputs if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"predicate": {"metadata": {
			"workflowData": {"inputs": []},
			"ownerData": {"ownerId": "5726618"},
			"repositoryData": {"repositoryId": "849445664"},
		}},
	}))}}]

	result := provenance.allow with input as test_input
	result == false

	violations := provenance.violations with input as test_input
	"workflow inputs are missing in metadata" in violations
}

# Test case for incorrect runner environment
test_incorrect_runner_environment if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"predicate": {"metadata": {
			"runnerData": {"environment": "self-hosted"},
			"ownerData": {"ownerId": "5726618"},
			"repositoryData": {"repositoryId": "849445664"},
		}},
	}))}}]

	result := provenance.allow with input as test_input
	result == false

	violations := provenance.violations with input as test_input
	"runner environment is not github-hosted" in violations
}

# Test case for missing runner environment
test_empty_runner_environment if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"predicate": {"metadata": {
			"runnerData": {"environment": ""},
			"ownerData": {"ownerId": "5726618"},
			"repositoryData": {"repositoryId": "849445664"},
		}},
	}))}}]

	result := provenance.allow with input as test_input
	result == false

	violations := provenance.violations with input as test_input
	"runner environment is missing" in violations
}

# Test case for incorrect build type in SLSA provenance
test_incorrect_build_type if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://invalid.buildtype/v1",
			"internalParameters": {"github": {
				"repository_owner_id": "5726618",
				"repository_id": "845521085",
			}},
		}},
	}))}}]

	result := provenance.allow with input as test_input
	result == false

	violations := provenance.violations with input as test_input
	"build type is not correct" in violations
}

# Test case for missing build type in SLSA provenance
test_missing_build_type if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {"internalParameters": {"github": {
			"repository_owner_id": "5726618",
			"repository_id": "845521085",
		}}}},
	}))}}]

	result := provenance.allow with input as test_input
	result == false

	violations := provenance.violations with input as test_input
	"build type is missing" in violations
}
