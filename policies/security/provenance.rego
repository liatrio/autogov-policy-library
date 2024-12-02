package security.provenance

import rego.v1

# [liatrio]
approved_owner_ids := {"5726618"}

default allow := false

# Top-level allow rule - iterates over JSON input to ensure no violations
allow if {
	count(violations) == 0
}

# Helper function to decode, unmarshal, and base64 decode the list of payloads from the dsseEnvelope key
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

# Helper functions to identify predicate types
is_slsa_provenance(payload) if {
	payload.predicateType == "https://slsa.dev/provenance/v1"
}

is_cyclonedx_bom(payload) if {
	payload.predicateType == "https://cyclonedx.org/bom"
}

is_cosign_attestation(payload) if {
	payload.predicateType == "https://cosign.sigstore.dev/attestation/v1"
}

# Helper functions to check for missing or incorrect Owner/Repository IDs

invalid_owner_id(payload, approved_owner_ids) if {
	is_slsa_provenance(payload)
	not payload.predicate.buildDefinition.internalParameters.github.repository_owner_id in approved_owner_ids
}

invalid_owner_id(payload, approved_owner_ids) if {
	is_cosign_attestation(payload)
	not payload.predicate.metadata.ownerData.ownerId in approved_owner_ids
}

# Iterate through JSON and collect violations
violations contains msg if {
	some payload in decoded_payload_list
	not payload.predicateType
	msg := "predicate type is missing"
}

violations contains msg if {
	some payload in decoded_payload_list
	not predicate_type_valid(payload)
	msg := "predicate type is not correct"
}

violations contains msg if {
	some payload in decoded_payload_list
	is_slsa_provenance(payload)
	not payload.predicate.buildDefinition.buildType
	msg := "build type is missing"
}

violations contains msg if {
	some payload in decoded_payload_list
	not build_type_valid(payload)
	msg := "build type is not correct"
}

violations contains msg if {
	some payload in decoded_payload_list
	is_slsa_provenance(payload)
	not payload.predicate.buildDefinition.internalParameters.github.repository_owner_id in approved_owner_ids
	msg := "owner is not correct in build provenance"
}

violations contains msg if {
	some payload in decoded_payload_list
	is_cosign_attestation(payload)
	not payload.predicate.metadata.ownerData.ownerId in approved_owner_ids
	msg := "owner is not correct in metadata"
}

violations contains msg if {
	some payload in decoded_payload_list
	is_slsa_provenance(payload)
	not payload.predicate.buildDefinition.internalParameters.github.repository_id
	msg := "repository is missing in build provenance"
}

violations contains msg if {
	some payload in decoded_payload_list
	is_cosign_attestation(payload)
	not payload.predicate.metadata.repositoryData.repositoryId
	msg := "repository is missing in metadata"
}

violations contains msg if {
	some payload in decoded_payload_list
	is_slsa_provenance(payload)
	not payload.predicate.buildDefinition.internalParameters.github.repository_owner_id
	msg := "owner is missing in build provenance"
}

violations contains msg if {
	some payload in decoded_payload_list
	is_cosign_attestation(payload)
	not payload.predicate.metadata.ownerData.ownerId
	msg := "owner is missing in metadata"
}

violations contains msg if {
	some payload in decoded_payload_list
	payload.predicate.metadata.runnerData.environment != "github-hosted"
	msg := "runner environment is not github-hosted"
}

violations contains msg if {
	some payload in decoded_payload_list
	is_cosign_attestation(payload)
	payload.predicate.metadata.runnerData.environment == ""
	msg := "runner environment is missing"
}

violations contains msg if {
	some payload in decoded_payload_list
	is_cosign_attestation(payload)
	not inputs_exist(payload)
	msg := "workflow inputs are missing in metadata"
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

inputs_exist(payload) if {
	payload.predicate.metadata.workflowData.inputs
	count(payload.predicate.metadata.workflowData.inputs) > 0
}

owner_repo_valid(payload, approved_owner_ids) if {
	owner_valid(payload, approved_owner_ids)
}

owner_valid(payload, approved_owner_ids) if {
	is_slsa_provenance(payload)
	payload.predicate.buildDefinition.internalParameters.github.repository_owner_id in approved_owner_ids
}

owner_valid(payload, approved_owner_ids) if {
	is_cosign_attestation(payload)
	payload.predicate.metadata.ownerData.ownerId in approved_owner_ids
}

owner_valid(payload, _) if {
	is_cyclonedx_bom(payload)
}

repo_valid(payload) if {
	is_slsa_provenance(payload)
}

repo_valid(payload) if {
	is_cosign_attestation(payload)
}

repo_valid(payload, _) if {
	is_cyclonedx_bom(payload)
}
