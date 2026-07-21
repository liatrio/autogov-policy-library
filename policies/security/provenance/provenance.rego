# METADATA
# scope: package
# title: Provenance Policy
# description: Verifies SLSA provenance attestation requirements
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
# schemas:
# - input: schema["provenance-schema"]
# custom:
#  control_number: 1
#  version: 1.0.1
#  path: policies/security
#  filename: provenance.rego
#  irm_control_ids: [LIATRIO-PROVENANCE-001]
package security.provenance

import data.shared.access
import data.shared.utils
import rego.v1

default allow := false

# Top-level allow rule - checks for violations
allow if {
	count(violations) == 0
}

# Iterate through JSON and collect violations
violations contains msg if {
	not is_slsa_provenance_present(input)
	not is_slsa_provenance_present(utils.decoded_payload_list)
	msg := "slsa provenance is missing"
}

violations contains msg if {
	msg := "predicate type is missing"
	some payload in utils.decoded_payload_list
	not payload.predicateType
}

violations contains msg if {
	msg := "build type is missing"
	some payload in utils.decoded_payload_list
	utils.is_slsa_provenance(payload)
	not payload.predicate.buildDefinition.buildType
}

violations contains msg if {
	msg := "build type is not correct"
	some payload in utils.decoded_payload_list
	utils.is_slsa_provenance(payload)
	not build_type_valid(payload)
}

violations contains msg if {
	msg := "owner is not correct in build provenance"
	some payload in utils.decoded_payload_list
	utils.is_slsa_provenance(payload)
	not payload.predicate.buildDefinition.internalParameters.github.repository_owner_id in access.approved_owner_ids
}

violations contains msg if {
	msg := "owner is missing in build provenance"
	some payload in utils.decoded_payload_list
	utils.is_slsa_provenance(payload)
	not payload.predicate.buildDefinition.internalParameters.github.repository_owner_id
}

# Repository-id allowlist (inert unless a consumer configures
# access.approved_repo_ids). Mirrors the owner-id checks above.
violations contains msg if {
	msg := "repository is not correct in build provenance"
	count(access.approved_repo_ids) > 0
	some payload in utils.decoded_payload_list
	utils.is_slsa_provenance(payload)
	not payload.predicate.buildDefinition.internalParameters.github.repository_id in access.approved_repo_ids
}

violations contains msg if {
	msg := "repository is missing in build provenance"
	count(access.approved_repo_ids) > 0
	some payload in utils.decoded_payload_list
	utils.is_slsa_provenance(payload)
	not payload.predicate.buildDefinition.internalParameters.github.repository_id
}

# Validation rules
build_type_valid(payload) if {
	utils.is_slsa_provenance(payload)
	payload.predicate.buildDefinition.buildType == "https://actions.github.io/buildtypes/workflow/v1"
}

# Check for SLSA Provenance presence
is_slsa_provenance_present(payload) if {
	count([obj | some obj in payload; utils.is_slsa_provenance(obj)]) > 0
}
