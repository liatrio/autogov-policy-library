package security.provenance_test

import data.security.provenance
import data.shared.access
import data.shared.utils
import rego.v1

# Test valid SLSA provenance with correct owner and repo
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

# Test missing predicate type
test_missing_predicate_type if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({"predicate": {}}))}}]
	result := provenance.allow with input as test_input
	result == false

	violations := provenance.violations with input as test_input
	"predicate type is missing" in violations
}

# Test valid owner in SLSA provenance
test_valid_owner if {
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

# Test invalid owner in SLSA provenance
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

# Test valid repository in SLSA provenance
test_valid_repo if {
	test_input := [{
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://actions.github.io/buildtypes/workflow/v1",
			"internalParameters": {"github": {
				"repository_owner_id": "5726618",
				"repository_id": "849445664",
			}},
		}},
	}]

	result := provenance.allow with input as test_input
	result == true
}

# Test invalid repository in SLSA provenance
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

# Test valid owner and repository combination
test_valid_owner_repo if {
	test_input := [{
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://actions.github.io/buildtypes/workflow/v1",
			"internalParameters": {"github": {
				"repository_owner_id": "5726618", # Valid owner
				"repository_id": "849445664", # Valid repository
			}},
		}},
	}]

	result := provenance.allow with input as test_input
	result == true
}

# Test missing repository ID
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

# Test incorrect build type
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

# Test missing build type
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
