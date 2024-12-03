package security.provenance

import rego.v1

import data.shared.access
import data.shared.utils

default allow := false

# Top-level allow rule - iterates over JSON input to ensure no violations
allow if {
	count(violations) == 0
}

# Iterate through JSON and collect violations
violations contains msg if {
	some payload in utils.decoded_payload_list
	not payload.predicateType
	msg := "predicate type is missing"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	not predicate_type_valid(payload)
	msg := "predicate type is not correct"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_slsa_provenance(payload)
	not payload.predicate.buildDefinition.buildType
	msg := "build type is missing"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	not build_type_valid(payload)
	msg := "build type is not correct"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_slsa_provenance(payload)
	not payload.predicate.buildDefinition.internalParameters.github.repository_id in access.approved_repo_ids
	msg := "repository is not correct in build provenance"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_slsa_provenance(payload)
	not payload.predicate.buildDefinition.internalParameters.github.repository_owner_id in access.approved_owner_ids
	msg := "owner is not correct in build provenance"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_slsa_provenance(payload)
	not payload.predicate.buildDefinition.internalParameters.github.repository_id
	msg := "repository is missing in build provenance"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_slsa_provenance(payload)
	not payload.predicate.buildDefinition.internalParameters.github.repository_owner_id
	msg := "owner is missing in build provenance"
}

# Validation rules
predicate_type_valid(payload) if {
	utils.is_slsa_provenance(payload)
}

build_type_valid(payload) if {
	utils.is_slsa_provenance(payload)
	payload.predicate.buildDefinition.buildType == "https://actions.github.io/buildtypes/workflow/v1"
}

build_type_valid(payload) if {
	not utils.is_slsa_provenance(payload)
	not payload.predicate.buildDefinition.buildType
}
