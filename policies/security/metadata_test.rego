package security.metadata_test

import data.security.metadata
import data.shared.access
import rego.v1

# Add this helper function at the top of the file after the imports
create_test_metadata(owner_id, runner_env, inputs) := {
	"ownerData": {"ownerId": owner_id},
	"repositoryData": {},
	"runnerData": {"environment": runner_env},
	"workflowData": {"inputs": inputs},
	"artifact": {
		"version": "1.0.0",
		"digest": "sha256:123",
		"created": "2024-03-13T00:00:00Z",
		"type": "container-image",
		"registry": "ghcr.io",
		"fullName": "ghcr.io/liatrio/demo-gh-autogov-workflows",
	},
	"jobData": {},
	"commitData": {},
	"organization": {},
	"compliance": {
		"policyRef": "https://github.com/liatrio/demo-gh-autogov-policy-library",
		"controlIds": ["liatrio-PROVENANCE-001"],
	},
	"security": {"permissions": {
		"id-token": "write",
		"attestations": "write",
		"packages": "write",
		"contents": "read",
	}},
}

# Create blob-specific test metadata
create_blob_test_metadata(owner_id, runner_env, inputs) := {
	"ownerData": {"ownerId": owner_id},
	"repositoryData": {},
	"runnerData": {"environment": runner_env},
	"workflowData": {"inputs": inputs},
	"artifact": {
		"version": "1.0.0",
		"created": "2024-03-13T00:00:00Z",
		"type": "blob",
		"path": "./artifacts/my-blob",
	},
	"jobData": {},
	"commitData": {},
	"organization": {},
	"compliance": {
		"policyRef": "https://github.com/liatrio/demo-gh-autogov-policy-library",
		"controlIds": ["liatrio-PROVENANCE-001"],
	},
	"security": {"permissions": {
		"id-token": "write",
		"attestations": "write",
		"packages": "write",
		"contents": "read",
	}},
}

# Add this helper at the top of the file
create_test_payload(predicate) := base64.encode(json.marshal({
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": "https://cosign.sigstore.dev/attestation/v1",
	"subject": [{"name": "ghcr.io/liatrio/demo-gh-autogov-workflows"}],
	"predicate": predicate,
}))

# Add these helper functions at the top with the other helpers
create_test_compliance := {
	"policyRef": "https://github.com/liatrio/demo-gh-autogov-policy-library",
	"controlIds": ["liatrio-PROVENANCE-001"],
}

create_test_security := {"permissions": {
	"id-token": "write",
	"attestations": "write",
	"packages": "write",
	"contents": "read",
}}

# Add this helper function
create_valid_metadata_predicate := {
	"artifact": {
		"version": "8532881-226",
		"digest": "sha256:7dc35cd4c54729aa57f12d9f824462ee635681e59d431558f12e69e8883154f2",
		"created": "2024-12-03T22:03:44Z",
		"type": "container-image",
		"registry": "ghcr.io",
		"fullName": "ghcr.io/liatrio/demo-gh-autogov-workflows",
	},
	"repositoryData": {},
	"ownerData": {"ownerId": "5726618"},
	"runnerData": {"environment": "github-hosted"},
	"workflowData": {"inputs": {"key1": "value1"}},
	"jobData": {
		"runNumber": "226",
		"runId": "12148901357",
		"status": "success",
		"triggeredBy": "ianhundere",
		"startedAt": "2024-12-03T22:03:44Z",
		"completedAt": "2024-12-03T22:03:44Z",
	},
	"commitData": {},
	"organization": {},
	"compliance": create_test_compliance,
	"security": create_test_security,
}

# Simplified test case
test_valid_metadata_attestation if {
	test_input := [{"dsseEnvelope": {"payload": create_test_payload(create_valid_metadata_predicate)}}]
	metadata.allow with input as test_input
}

test_inputs_exist if {
	payload := {"predicate": {"workflowData": {"inputs": {"key1": "value1", "key2": "value2"}}}}
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
	test_input := {
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"subject": [{"name": "ghcr.io/liatrio/demo-gh-autogov-workflows"}],
		"predicate": {
			"artifact": {"type": "container-image"},
			"repositoryData": {},
			"ownerData": {"ownerId": "5726618"},
		},
	}
	metadata.is_metadata_present(test_input)
}

# Test case for missing metadata predicate type of cosign attestation
test_is_metadata_present_false if {
	test_input := [{
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://example.org/other",
		"subject": [{"name": "ghcr.io/liatrio/some-other-repo"}],
	}]
	not metadata.is_metadata_present(test_input)
}

# Test missing workflow inputs
test_missing_workflow_inputs if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"subject": [{"name": "ghcr.io/liatrio/demo-gh-autogov-workflows"}],
		"predicate": {
			"workflowData": {"inputs": []},
			"ownerData": {"ownerId": "5726618"},
			"repositoryData": {},
			"artifact": {
				"type": "container-image",
				"registry": "ghcr.io",
			},
		},
	}))}}]

	result := metadata.allow with input as test_input
	result == false

	violations := metadata.violations with input as test_input
	"workflow inputs are missing in metadata" in violations
}

# Test invalid runner environment
test_incorrect_runner_environment if {
	predicate := {
		"ownerData": {"ownerId": "5726618"},
		"repositoryData": {},
		"runnerData": {"environment": "self-hosted"}, # Invalid runner environment
		"workflowData": {"inputs": {"key1": "value1"}},
		"artifact": {
			"version": "1.0.0",
			"digest": "sha256:123",
			"created": "2024-03-13T00:00:00Z",
			"type": "container-image",
			"registry": "ghcr.io",
			"fullName": "ghcr.io/liatrio/demo-gh-autogov-workflows",
		},
		"jobData": {},
		"commitData": {},
		"organization": {},
		"compliance": create_test_compliance,
		"security": create_test_security,
	}

	test_input := [{"dsseEnvelope": {"payload": create_test_payload(predicate)}}]
	not metadata.allow with input as test_input
	"invalid runner environment" in metadata.violations with input as test_input
}

# Test missing runner environment
test_empty_runner_environment if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"subject": [{"name": "ghcr.io/liatrio/demo-gh-autogov-workflows"}],
		"predicate": {
			"runnerData": {}, # Missing environment field entirely
			"ownerData": {"ownerId": "5726618"},
			"repositoryData": {},
			"workflowData": {"inputs": {"key1": "value1"}},
			"artifact": {
				"version": "1.0.0",
				"digest": "sha256:123",
				"created": "2024-03-13T00:00:00Z",
				"type": "container-image",
				"registry": "ghcr.io",
				"fullName": "ghcr.io/liatrio/demo-gh-autogov-workflows",
			},
		},
	}))}}]

	result := metadata.allow with input as test_input
	result == false

	violations := metadata.violations with input as test_input
	"runner environment is missing" in violations
}

# Test valid blob metadata
test_valid_blob_metadata if {
	test_metadata := create_blob_test_metadata("5726618", "github-hosted", {"key1": "value1"})
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"subject": [{"name": "my-blob-artifact"}],
		"predicate": test_metadata,
	}))}}]

	metadata.allow with input as test_input
}

# Test blob with incorrect artifact type
test_blob_incorrect_artifact_type if {
	test_metadata := create_test_metadata("5726618", "github-hosted", {"key1": "value1"})
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"subject": [{"name": "my-blob-artifact"}],
		"predicate": test_metadata,
	}))}}]

	not metadata.allow with input as test_input

	violations := metadata.violations with input as test_input
	"artifact type must be blob for non-image subjects" in violations
}

# Test blob with invalid name characters
test_blob_invalid_name_characters if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"subject": [{"name": "my blob@artifact"}], # Invalid characters
		"predicate": {"metadata": {
			"ownerData": {"ownerId": "5726618"},
			"repositoryData": {},
			"runnerData": {"environment": "github-hosted"},
			"workflowData": {"inputs": {"key1": "value1"}},
			"artifact": {
				"version": "1.0.0",
				"created": "2024-03-13T00:00:00Z",
				"type": "blob",
				"path": "./artifacts/my-blob",
			},
		}},
	}))}}]

	result := metadata.allow with input as test_input
	result == false

	violations := metadata.violations with input as test_input
	"blob subject name contains invalid characters" in violations
}
