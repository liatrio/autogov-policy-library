package security.metadata

import rego.v1

import data.shared.access
import data.shared.utils

default allow := false

# Top-level allow rule - iterates over JSON input to ensure no violations
allow if {
	count(violations) == 0
}

# Validation rules
inputs_exist(payload) if {
	payload.predicate.metadata.workflowData.inputs
	count(payload.predicate.metadata.workflowData.inputs) > 0
}

predicate_type_valid(payload) if {
	utils.is_cosign_attestation(payload)
}

is_metadata_present(payload) if {
	count([obj | some obj in payload; obj.predicateType == "https://cosign.sigstore.dev/attestation/v1"]) > 0
	count([obj | some obj in payload; obj.subject[0].name == "ghcr.io/liatrio/demo-gh-autogov-workflows"]) > 0
}

# Iterate through JSON and collect violations
violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	not payload.predicate.metadata.repositoryData.repositoryId
	msg := "repository is missing in metadata"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	not payload.predicate.metadata.repositoryData.repositoryId in access.approved_repo_ids
	msg := "repository is not correct in metadata"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	not payload.predicate.metadata.ownerData.ownerId
	msg := "owner is missing in metadata"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	not payload.predicate.metadata.ownerData.ownerId in access.approved_owner_ids
	msg := "owner is not correct in metadata"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	payload.predicate.metadata.runnerData.environment == ""
	msg := "runner environment is missing"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	payload.predicate.metadata.runnerData.environment != "github-hosted"
	msg := "runner environment is not github-hosted"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	not inputs_exist(payload)
	msg := "workflow inputs are missing in metadata"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	not is_metadata_present(payload)
	msg := "metadata attestation is missing"
}