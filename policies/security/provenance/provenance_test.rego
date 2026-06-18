package security.provenance_test

import data.security.provenance
import data.shared.access
import data.shared.utils
import rego.v1

# Test valid SLSA provenance with correct owner
test_valid_slsa_provenance if {
	test_input := [{
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://actions.github.io/buildtypes/workflow/v1",
			"internalParameters": {"github": {"repository_owner_id": "5726618"}},
		}},
	}]
	result := provenance.allow with input as test_input
	result == true
}

# Test missing predicate type
test_missing_predicate_type if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({"predicate": {}}))}}]
	result := provenance.allow with input as test_input
	result == false

	violations := provenance.violations with input as test_input
	"predicate type is missing" in violations
}

# Test valid owner
test_valid_owner if {
	test_input := [{
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://actions.github.io/buildtypes/workflow/v1",
			"internalParameters": {"github": {"repository_owner_id": "5726618"}},
		}},
	}]

	result := provenance.allow with input as test_input
	result == true
}

# Test missing repository owner ID
test_missing_repository_owner_id if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": [{"name": "ghcr.io/liatrio/demo-gh-autogov-workflows"}],
		"predicate": {"buildDefinition": {"internalParameters": {"github": {}}}}, # Missing repository_owner_id
	}))}}]

	result := provenance.allow with input as test_input
	result == false

	violations := provenance.violations with input as test_input
	"owner is missing in build provenance" in violations
}

# Test missing SLSA provenance
test_missing_slsa_provenance if {
	test_input := [{
		"predicateType": "https://cyclonedx.org/bom",
		"predicate": {},
	}]
	result := provenance.allow with input as test_input
	result == false

	violations := provenance.violations with input as test_input
	"slsa provenance is missing" in violations
}

# Test missing build type
test_missing_build_type if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {"internalParameters": {"github": {"repository_owner_id": "5726618"}}}},
	}))}}]

	result := provenance.allow with input as test_input
	result == false

	violations := provenance.violations with input as test_input
	"build type is missing" in violations
}

# Test incorrect build type
test_incorrect_build_type if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://invalid.buildtype/v1",
			"internalParameters": {"github": {"repository_owner_id": "5726618"}},
		}},
	}))}}]

	result := provenance.allow with input as test_input
	result == false

	violations := provenance.violations with input as test_input
	"build type is not correct" in violations
}

# Test repository-id allowlist passes when configured and provenance matches
test_valid_repo if {
	test_input := [{
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://actions.github.io/buildtypes/workflow/v1",
			"internalParameters": {"github": {
				"repository_owner_id": "5726618",
				"repository_id": "944181875",
			}},
		}},
	}]
	result := provenance.allow with input as test_input
		with access.approved_repo_ids as {"944181875"}
	result == true
}

# Test repository-id allowlist denies when configured and repo not approved
test_invalid_repo if {
	test_input := [{
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://actions.github.io/buildtypes/workflow/v1",
			"internalParameters": {"github": {
				"repository_owner_id": "5726618",
				"repository_id": "9999999",
			}},
		}},
	}]
	result := provenance.allow with input as test_input
		with access.approved_repo_ids as {"944181875"}
	result == false

	violations := provenance.violations with input as test_input
		with access.approved_repo_ids as {"944181875"}
	"repository is not correct in build provenance" in violations
}

# Test repository-id presence check fires only when the allowlist is configured
test_missing_repo_id if {
	test_input := [{
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://actions.github.io/buildtypes/workflow/v1",
			"internalParameters": {"github": {"repository_owner_id": "5726618"}},
		}},
	}]
	result := provenance.allow with input as test_input
		with access.approved_repo_ids as {"944181875"}
	result == false

	violations := provenance.violations with input as test_input
		with access.approved_repo_ids as {"944181875"}
	"repository is missing in build provenance" in violations
}

# Test repository-id allowlist is inert when unconfigured (default empty set)
test_repo_id_inert_when_unconfigured if {
	test_input := [{
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://actions.github.io/buildtypes/workflow/v1",
			"internalParameters": {"github": {"repository_owner_id": "5726618"}},
		}},
	}]
	result := provenance.allow with input as test_input
	result == true
}

# Test the default owner allowlist still enforces liatrio when no override is
# supplied (behavior preservation: a non-liatrio owner is rejected).
test_default_owner_enforces_liatrio if {
	test_input := [{
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://actions.github.io/buildtypes/workflow/v1",
			"internalParameters": {"github": {"repository_owner_id": "9999999"}},
		}},
	}]
	result := provenance.allow with input as test_input
	result == false

	violations := provenance.violations with input as test_input
	"owner is not correct in build provenance" in violations
}

# Test a consumer can override the owner allowlist to approve another org.
test_owner_override_allows_other_org if {
	test_input := [{
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://actions.github.io/buildtypes/workflow/v1",
			"internalParameters": {"github": {"repository_owner_id": "12345"}},
		}},
	}]
	result := provenance.allow with input as test_input
		with access.approved_owner_ids as {"12345"}
	result == true
}

# Test the overridden owner allowlist is still an allowlist: owners outside the
# consumer's set (including the old liatrio default) are rejected.
test_owner_override_still_rejects_unapproved if {
	test_input := [{
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://actions.github.io/buildtypes/workflow/v1",
			"internalParameters": {"github": {"repository_owner_id": "5726618"}},
		}},
	}]
	result := provenance.allow with input as test_input
		with access.approved_owner_ids as {"12345"}
	result == false

	violations := provenance.violations with input as test_input
		with access.approved_owner_ids as {"12345"}
	"owner is not correct in build provenance" in violations
}
