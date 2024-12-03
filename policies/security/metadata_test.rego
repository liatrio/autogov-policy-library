package security.metadata_test

import data.security.metadata
import data.shared.access
import rego.v1

test_inputs_exist if {
	payload := {"predicate": {"metadata": {"workflowData": {"inputs": {"key1": "value1", "key2": "value2"}}}}}
	metadata.inputs_exist(payload)
}

test_inputs_do_not_exist if {
	payload := {"predicate": {"metadata": {"workflowData": {"inputs": {}}}}}
	not metadata.inputs_exist(payload)
}

test_predicate_type_valid_true if {
	payload := {"predicateType": "https://cosign.sigstore.dev/attestation/v1"}

	metadata.predicate_type_valid(payload)
}

test_predicate_type_valid_false if {
	payload := {"predicateType": "https://example.com/invalid"}

	not metadata.predicate_type_valid(payload)
}

test_predicate_type_missing if {
	payload := {}

	not metadata.predicate_type_valid(payload)
}

test_is_metadata_present_true if {
	test_input := [
		{
			"_type": "https://in-toto.io/Statement/v1",
			"predicateType": "https://example.org/other",
		},
		{
			"_type": "https://in-toto.io/Statement/v1",
			"predicateType": "https://cosign.sigstore.dev/attestation/v1",
			"subject": [{"name": "ghcr.io/liatrio/demo-gh-autogov-workflows"}],
		},
	]
	metadata.is_metadata_present(test_input)
}

# Test case for missing metadata predicate type of cosign attestation
test_is_metadata_present_false if {
	test_input := [
		{
			"_type": "https://in-toto.io/Statement/v1",
			"predicateType": "https://example.org/other",
		},
		{
			"_type": "https://in-toto.io/Statement/v1",
			"predicateType": "https://cosign.sigstore.dev/attestation/v1",
			"subject": [{"name": "ghcr.io/liatrio/some-other-repo"}],
		},
	]

	not metadata.is_metadata_present(test_input)
}

# Test case for metadata attestation with valid owner and repo
test_valid_metadata_attestation if {
	test_input := [{
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"subject": [{"name": "ghcr.io/liatrio/demo-gh-autogov-workflows"}],
		"predicate": {"metadata": {
			"ownerData": {"ownerId": "5726618"},
			"repositoryData": {"repositoryId": "849445664"},
		}},
	}]
	result := metadata.allow with input as test_input
	result == true
}

# Test case for missing metedata predicate type violotion message
test_missing_metadata_predicate_type if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://example.org/other",
		"subject": [{"name": "ghcr.io/liatrio/some-other-repo"}],
		"predicate": {},
	}))}}]

	result := metadata.allow with input as test_input
	result == false

	violations := metadata.violations with input as test_input
	"metadata attestation is missing" in violations
}

# Test case for metadata attestation with invalid owner and repo
test_invalid_metadata_attestation if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"subject": [{"name": "ghcr.io/liatrio/demo-gh-autogov-workflows"}],
		"predicate": {"metadata": {
			"ownerData": {"ownerId": "9999999"},
			"repositoryData": {"repositoryId": "9999999"},
		}},
	}))}}]

	result := metadata.allow with input as test_input

	result == false

	violations := metadata.violations with input as test_input

	"owner is not correct in metadata" in violations
	"repository is not correct in metadata" in violations
}

# Test case for missing workflow inputs in metadata
test_missing_workflow_inputs if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"subject": [{"name": "ghcr.io/liatrio/demo-gh-autogov-workflows"}],
		"predicate": {"metadata": {
			"workflowData": {"inputs": []},
			"ownerData": {"ownerId": "5726618"},
			"repositoryData": {"repositoryId": "849445664"},
		}},
	}))}}]

	result := metadata.allow with input as test_input
	result == false

	violations := metadata.violations with input as test_input
	"workflow inputs are missing in metadata" in violations
}

# Test case for incorrect runner environment
test_incorrect_runner_environment if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"subject": [{"name": "ghcr.io/liatrio/demo-gh-autogov-workflows"}],
		"predicate": {"metadata": {
			"runnerData": {"environment": "self-hosted"},
			"ownerData": {"ownerId": "5726618"},
			"repositoryData": {"repositoryId": "849445664"},
		}},
	}))}}]

	result := metadata.allow with input as test_input
	result == false

	violations := metadata.violations with input as test_input
	"runner environment is not github-hosted" in violations
}

# Test case for missing runner environment
test_empty_runner_environment if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"subject": [{"name": "ghcr.io/liatrio/demo-gh-autogov-workflows"}],
		"predicate": {"metadata": {
			"runnerData": {"environment": ""},
			"ownerData": {"ownerId": "5726618"},
			"repositoryData": {"repositoryId": "849445664"},
		}},
	}))}}]

	result := metadata.allow with input as test_input
	result == false

	violations := metadata.violations with input as test_input
	"runner environment is missing" in violations
}

# Test case for missing repository ID in metadata
test_missing_repository_id if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"subject": [{"name": "ghcr.io/liatrio/demo-gh-autogov-workflows"}],
		"predicate": {"metadata": {
			"runnerData": {"environment": "production"},
			"ownerData": {"ownerId": "5726618"},
			"repositoryData": {}, # Missing repositoryId
		}},
	}))}}]

	result := metadata.allow with input as test_input
	result == false

	violations := metadata.violations with input as test_input
	"repository is missing in metadata" in violations
}

# Test case for missing ownerId in metadata
test_missing_owner_id if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"subject": [{"name": "ghcr.io/liatrio/demo-gh-autogov-workflows"}],
		"predicate": {"metadata": {
			"runnerData": {"environment": "production"},
			"repositoryData": {"repositoryId": "849445664"},
			"ownerData": {}, # Missing ownerId
		}},
	}))}}]

	result := metadata.allow with input as test_input
	result == false

	violations := metadata.violations with input as test_input
	"owner is missing in metadata" in violations
}
