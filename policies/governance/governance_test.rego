package governance.governance_test

import data.governance
import rego.v1

# Utility function to create test input
create_test_input(predicate_type) := [{
	"_type": "https://in-toto.io/Statement/v1",
	"subject": [{
		"name": "ghcr.io/liatrio/liatrio-gh-autogov-workflows",
		"digest": {"sha256": "d379d8ef02ef446dc22e57e845ac7f3e5053b9398475541a8530d707511e6264"},
	}],
	"predicateType": predicate_type,
	"predicate": {},
}]

# Test that governance.allow is true when both sbom and provenance allow are true
test_allow_true_if_both_pass if {
	sbom_allow := true
	provenance_allow := true
	test_input := create_test_input("https://cyclonedx.org/bom")

	governance.allow with input as test_input
		with data.security.sbom.allow as sbom_allow
		with data.security.provenance.allow as provenance_allow
}

# Test that governance.allow is false when sbom fails but provenance passes
test_allow_false_if_sbom_fails if {
	sbom_allow := false
	provenance_allow := true
	test_input := create_test_input("https://cyclonedx.org/bom")

	not governance.allow with input as test_input
		with data.security.sbom.allow as sbom_allow
		with data.security.provenance.allow as provenance_allow
}

# Test that governance.allow is false when provenance fails but sbom passes
test_allow_false_if_provenance_fails if {
	sbom_allow := true
	provenance_allow := false
	test_input := create_test_input("https://cyclonedx.org/bom")

	not governance.allow with input as test_input
		with data.security.sbom.allow as sbom_allow
		with data.security.provenance.allow as provenance_allow
}

# Test that governance.allow is false when both sbom and provenance fail
test_allow_false_if_both_fail if {
	sbom_allow := false
	provenance_allow := false
	test_input := create_test_input("https://cyclonedx.org/bom")

	not governance.allow with input as test_input
		with data.security.sbom.allow as sbom_allow
		with data.security.provenance.allow as provenance_allow
}

# Test that governance.violations contains only sbom violations when provenance has no violations
test_violations_only_sbom if {
	sbom_violations := {"cyclonedx sbom is missing"}
	provenance_violations := set()
	test_input := create_test_input("https://example.org/other")

	governance.violations == {
		"sbom": sbom_violations,
		"provenance": provenance_violations,
	} with input as test_input
		with data.security.sbom.violations as sbom_violations
		with data.security.provenance.violations as provenance_violations
}

# Test that governance.violations contains only provenance violations when sbom has no violations
test_violations_only_provenance if {
	sbom_violations := set()
	provenance_violations := {"predicate type is not correct or missing"}
	test_input := create_test_input("https://slsa.dev/provenance/v1")

	governance.violations == {
		"sbom": sbom_violations,
		"provenance": provenance_violations,
	} with input as test_input
		with data.security.sbom.violations as sbom_violations
		with data.security.provenance.violations as provenance_violations
}

# Test that governance.violations contains both sbom and provenance violations
test_violations_both_sbom_and_provenance if {
	sbom_violations := {"cyclonedx sbom is missing"}
	provenance_violations := {"predicate type is not correct or missing"}
	test_input := create_test_input("https://example.org/other")

	governance.violations == {
		"sbom": sbom_violations,
		"provenance": provenance_violations,
	} with input as test_input
		with data.security.sbom.violations as sbom_violations
		with data.security.provenance.violations as provenance_violations
}

# Test that allow is false when there are no provenance attestations
test_no_provenance_attestation if {
	predicate_type := ""
	payload := base64.encode(json.marshal({"predicateType": predicate_type}))
	test_input := create_test_input(payload)
	not governance.allow with input as test_input
}

# Test that allow is false when provenance attestation is not allowed by security.provenance
test_provenance_violation_found if {
	predicate_type := "https://slsa.dev/provenance/v1"
	predicate := {"buildDefinition": {"buildType": "incorrect_build_type"}}
	payload := base64.encode(json.marshal({"predicateType": predicate_type, "predicate": predicate}))
	test_input := create_test_input(payload)
	not governance.allow with input as test_input
}

# Test that allow is false when repository is not approved
test_repository_not_approved if {
	predicate_type := "https://slsa.dev/provenance/v1"
	predicate := {"buildDefinition": {"internalParameters": {"github": {"repository_id": "unapproved_repo_id"}}}}
	payload := base64.encode(json.marshal({"predicateType": predicate_type, "predicate": predicate}))
	test_input := create_test_input(payload)
	not governance.allow with input as test_input
}

# Test that allow is false when organization is not approved
test_organization_not_approved if {
	predicate_type := "https://slsa.dev/provenance/v1"
	predicate := {"buildDefinition": {"internalParameters": {"github": {"repository_owner_id": "00000000"}}}}
	payload := base64.encode(json.marshal({"predicateType": predicate_type, "predicate": predicate}))
	test_input := create_test_input(payload)
	not governance.allow with input as test_input
}

# Test that governance.allow is false when input is empty
test_empty_input if {
	test_input := []
	not governance.allow with input as test_input
}
