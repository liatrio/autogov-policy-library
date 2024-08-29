package governance

import data.governance.allow

# Test that allow is false when there are no provenance attestations
test_no_provenance_attestation {
    input := [
        {
            "Attestation": {
                "dsseEnvelope": {
                    "payload": base64.encode(json.marshal({"predicateType": "https://slsa.dev/provenance/v1"}))
                }
            }
        }
    ]
    not allow with input as input
}

# Test that allow is false when provenance attestation is not allowed by security.provenance
test_provenance_violation_found {
    input := [
        {
            "Attestation": {
                "dsseEnvelope": {
                    "payload": base64.encode(json.marshal({"predicate": {"buildType": "incorrect_build_type"}}))
                }
            }
        }
    ]
    not allow with input as input
}

# Test that allow is false when repository is not approved
test_repository_not_approved {
    input := [
        {
            "Attestation": {
                "dsseEnvelope": {
                    "payload": base64.encode(json.marshal({
                        "predicateType": "https://slsa.dev/provenance/v1",
                        "verificationResult": {
                            "statement": {
                                "predicate": {
                                    "buildDefinition": {
                                        "externalParameters": {
                                            "workflow": {
                                                "repository": "https://github.com/unapproved/repo"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }))
                }
            }
        }
    ]
    not allow with input as input
}

# Test that allow is false when organization is not approved
test_organization_not_approved {
    input := [
        {
            "Attestation": {
                "dsseEnvelope": {
                    "payload": base64.encode(json.marshal({
                        "predicateType": "https://slsa.dev/provenance/v1",
                        "verificationResult": {
                            "verifiedIdentity": {
                                "sourceRepositoryOwnerURI": "https://github.com/unapproved/org"
                            }
                        }
                    }))
                }
            }
        }
    ]
    not allow with input as input
}