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

# Test missing metadata predicate type violation
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

# Test metadata attestation with invalid owner
test_invalid_metadata_attestation if {
	predicate := {
		"ownerData": {"ownerId": "9999999"},
		"repositoryData": {},
		"runnerData": {"environment": "github-hosted"},
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
	result := metadata.allow with input as test_input
	result == false

	violations := metadata.violations with input as test_input
	"invalid owner ID" in violations
}

# Test missing owner ID
test_missing_owner_id if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"subject": [{"name": "ghcr.io/liatrio/demo-gh-autogov-workflows"}],
		"predicate": {
			"runnerData": {"environment": "github-hosted"},
			"ownerData": {},
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
	"owner is missing in metadata" in violations
}
