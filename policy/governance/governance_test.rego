package governance.governance_test

import data.governance
import rego.v1

create_test_input(payload) := [{"Attestation": {"dsseEnvelope": {"payload": payload}}}]

test_no_provenance_attestation if {
	# Test that allow is false when there are no provenance attestations
	predicate_type := ""
	payload := base64.encode(json.marshal({"predicateType": predicate_type}))
	test_input := create_test_input(payload)
	not governance.allow with input as test_input
}

test_provenance_violation_found if {
	# Test that allow is false when provenance attestation is not allowed by security.provenance
	build_type := "incorrect_build_type"
	predicate := {"buildType": build_type}
	payload := base64.encode(json.marshal({"predicate": predicate}))
	test_input := create_test_input(payload)
	not governance.allow with input as test_input
}

test_repository_not_approved if {
	# Test that allow is false when repository is not approved
	predicate_type := "https://slsa.dev/provenance/v1"
	repository := "https://github.com/unapproved/repo"

	build_definition := {"externalParameters": {"workflow": {"repository": repository}}}
	predicate := {"buildDefinition": build_definition}
	statement := {"predicate": predicate}
	verification_result := {"statement": statement}

	payload := base64.encode(json.marshal({
		"predicateType": predicate_type,
		"verificationResult": verification_result,
	}))
	test_input := create_test_input(payload)
	not governance.allow with input as test_input
}

test_organization_not_approved if {
	# Test that allow is false when organization is not approved
	predicate_type := "https://slsa.dev/provenance/v1"
	organization := "00000000"

	verification_result := {"verifiedIdentity": {"sourceRepositoryOwnerURI": organization}}
	payload := base64.encode(json.marshal({
		"predicateType": predicate_type,
		"verificationResult": verification_result,
	}))
	test_input := create_test_input(payload)
	not governance.allow with input as test_input
}
