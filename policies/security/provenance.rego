# METADATA
# scope: package
# title: Provenance Policy
# description: Verifies SLSA provenance attestation requirements
# authors:
# - Autogov Team <autogov@liatrio.com>
# schemas:
# - input: schema["provenance-schema"]
# custom:
#  control_number: 1
#  version: 0.6.3
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
