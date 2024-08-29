package security.provenance

# Define a safe allow rule
allow {
    count(violations) == 0
}

# Define a safe violations rule
violations[msg] {
    input := {"dsseEnvelope": {"payload": base64.encode(json.marshal({"predicate": {"buildType": "incorrect_build_type"}}))}}
    msg := "provenance build type is incorrect"
}

# Test that allow is false when buildType is incorrect
test_fail_incorrect_buildType {
    input := {"dsseEnvelope": {"payload": base64.encode(json.marshal({"predicate": {"buildType": "incorrect_build_type"}}))}}
    not allow with input as input
}

# Test that violation message is correct when buildType is incorrect
test_violation_incorrect_buildType {
    input := {"dsseEnvelope": {"payload": base64.encode(json.marshal({"predicate": {"buildType": "incorrect_build_type"}}))}}
    violations[msg] with input as input
    msg == "provenance build type is incorrect"
}

# Test that violation message is correct when Owner is incorrect
test_violation_incorrect_owner {
    input := {
        "dsseEnvelope": {
            "payload": base64.encode(json.marshal({
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {
                    "buildDefinition": {
                        "internalParameters": {
                            "github": {
                                "repository_owner_id": "0000000"
                            }
                        }
                    }
                }
            }))
        }
    }

    violations[msg] with input as input
    msg == "owner is not correct or missing"
}

# Test that violation message is correct when repository ID is invalid
test_violation_invalid_repositoryID {
    input := {
        "dsseEnvelope": {
            "payload": base64.encode(json.marshal({
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {
                    "buildDefinition": {
                        "internalParameters": {
                            "github": {
                                "repository_id": "0000000"
                            }
                        }
                    }
                }
            }))
        }
    }

    violations[msg] with input as input
    msg == "repo is not correct or missing"
}

# Test that violation message is correct when predicate type is incorrect
test_violation_incorrect_predicate_type {
    input := {"dsseEnvelope": {"payload": base64.encode(json.marshal({"predicateType": "incorrect_predicate_type"}))}}
    violations[msg] with input as input
    msg == "predicate type is not correct or missing"
}

