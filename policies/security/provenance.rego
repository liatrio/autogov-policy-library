package security.provenance

import rego.v1

# liatrio
approved_owner_ids := {"5726618"}

# [demo-gh-autogov-workflows, demo-gh-autogov-caller-workflow]
approved_repo_ids := {"845521085", "849445664"}

default allow := false

# Top-level allow rule - iterates over all inputs and ensures no violations
allow if {
	count(violations) == 0
}

# we need to update the expected input to be a list of json objects
# for input we have a list of encoded objects where at the key dsseEnvelope.payload is base64 encoded

parse_payload(payload) := parsed_payload if {
	decoded_payload := base64.decode(payload)
	parsed_payload := json.unmarshal(decoded_payload)
}

decoded_payload_list := [decoded |
	some obj in input
	payload := obj.dsseEnvelope.payload
	decoded_payload_raw := base64.decode(payload)
	decoded := json.unmarshal(decoded_payload_raw)
]

# Iterate through all inputs and collect violations
violations contains msg if {
	some payload in decoded_payload_list
	not predicate_type_valid(payload)
	msg := "predicate type is not correct or missing"
}

violations contains msg if {
	some payload in decoded_payload_list
	not build_type_valid(payload)
	msg := "build type is not correct or missing"
}

violations contains msg if {
	some payload in decoded_payload_list
	payload.predicateType == "https://slsa.dev/provenance/v1"
	not owner_valid(payload, approved_owner_ids)
	msg := "owner is not correct or missing"
}

violations contains msg if {
	some payload in decoded_payload_list
	payload.predicateType == "https://slsa.dev/provenance/v1"
	not repo_valid(payload, approved_repo_ids)
	msg := "repo is not correct or missing"
}

# Validation rules

predicate_type_valid(payload) if {
	is_slsa_provenance(payload)
}

predicate_type_valid(payload) if {
	is_cyclonedx_bom(payload)
}

predicate_type_valid(payload) if {
	is_cosign_attestation(payload)
}

build_type_valid(payload) if {
	is_slsa_provenance(payload)
	payload.predicate.buildDefinition.buildType == "https://actions.github.io/buildtypes/workflow/v1"
}

build_type_valid(payload) if {
	not is_slsa_provenance(payload)
	not payload.predicate.buildDefinition.buildType
}

owner_valid(payload, approved_owner_ids) if {
	is_slsa_provenance(payload)
	payload.predicate.buildDefinition.internalParameters.github.repository_owner_id in approved_owner_ids
}

owner_valid(payload, approved_owner_ids) if {
	is_cosign_attestation(payload)
	payload.predicate.metadata.owner in approved_owner_ids
}

owner_valid(payload, _) if {
	is_cyclonedx_bom(payload)
}

repo_valid(payload, approved_repo_ids) if {
	is_slsa_provenance(payload)
	payload.predicate.buildDefinition.internalParameters.github.repository_id in approved_repo_ids
}

repo_valid(payload, approved_repo_ids) if {
	is_cosign_attestation(payload)
	payload.predicate.metadata.repositoryId in approved_repo_ids
}

repo_valid(payload, _) if {
	is_cyclonedx_bom(payload)
}

# Helper functions to identify types
is_slsa_provenance(payload) if {
	payload.predicateType == "https://slsa.dev/provenance/v1"
}

is_cyclonedx_bom(payload) if {
	payload.predicateType == "https://cyclonedx.org/bom"
}

is_cosign_attestation(payload) if {
	payload.predicateType == "https://cosign.sigstore.dev/attestation/v1"
}
