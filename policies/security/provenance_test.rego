package security.provenance_test

import rego.v1

allow if {
	count(violations) == 0
}

valid_payload(expected) if {
	input.dsseEnvelope.payload == base64.encode(json.marshal(expected))
}

violations[msg] if {
	# Check for incorrect build type
	build_type_url := "https://actions.github.io/buildtypes/workflow/v1"
	predicate := {"predicate": {"buildDefinition": {"buildType": build_type_url}}}
	not valid_payload(predicate)
	msg := "provenance build type is incorrect"
}

violations[msg] if {
	# Check for incorrect or missing owner
	expected_payload := {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {"internalParameters": {"github": {"repository_owner_id": "correct_owner_id"}}}},
	}
	not valid_payload(expected_payload)
	msg := "owner is not correct or missing"
}

violations[msg] if {
	# Check for incorrect or missing repository
	github := {"repository_id": "correct_repo_id"}
	internal_parameters := {"github": github}
	build_definition := {"internalParameters": internal_parameters}
	expected_payload := {"predicate": {"buildDefinition": build_definition}}
	not valid_payload(expected_payload)
	msg := "repo is not correct or missing"
}

violations[msg] if {
	# Check for incorrect predicate type
	expected_payload := {"predicateType": "https://slsa.dev/provenance/v1"}
	not valid_payload(expected_payload)
	msg := "predicate type is not correct or missing"
}

test_violation_incorrect_build_type if {
	# Test that violation message is correct when buildType is incorrect
	expected_payload := {"predicate": {"buildDefinition": {"buildType": "incorrect_build_type"}}}
	test_input := {"dsseEnvelope": {"payload": base64.encode(json.marshal(expected_payload))}}

	violations[msg] with input as test_input
	msg == "provenance build type is incorrect"
}

test_violation_incorrect_owner if {
	# Test that violation message is correct when owner is incorrect
	github := {"repository_owner_id": "0000000"}
	internal_parameters := {"github": github}
	build_definition := {"internalParameters": internal_parameters}
	expected_payload := {"predicate": {"buildDefinition": build_definition}}
	test_input := {"dsseEnvelope": {"payload": base64.encode(json.marshal(expected_payload))}}

	violations[msg] with input as test_input
	msg == "owner is not correct or missing"
}

test_violation_incorrect_repository_id if {
	# Test that violation message is correct when repository ID is incorrect
	github := {"repository_id": "0000000"}
	internal_parameters := {"github": github}
	build_definition := {"internalParameters": internal_parameters}
	expected_payload := {"predicate": {"buildDefinition": build_definition}}
	test_input := {"dsseEnvelope": {"payload": base64.encode(json.marshal(expected_payload))}}

	violations[msg] with input as test_input
	msg == "repo is not correct or missing"
}

test_violation_incorrect_predicate_type if {
	# Test that violation message is correct when predicate type is incorrect
	expected_payload := {"predicateType": "incorrect_predicate_type"}
	test_input := {"dsseEnvelope": {"payload": base64.encode(json.marshal(expected_payload))}}
	violations[msg] with input as test_input
	msg == "predicate type is not correct or missing"
}
