package security.provenance

import rego.v1

# Liatrio
approved_owner_ids := {"5726618"}

# [liatrio/tag-automated-governance-github-attestations-beta-v0.0.1]
approved_repo_ids := {"845521085"}

is_slsa_provenance(parsed_payload) if {
	parsed_payload.predicateType == "https://slsa.dev/provenance/v1"
}

is_cyclonedx_bom(parsed_payload) if {
	parsed_payload.predicateType == "https://cyclonedx.org/bom"
}

default allow := false

allow if {
	count(violations) == 0
}

violations contains msg if {
	parsed_payload := parse_payload(input.dsseEnvelope.payload)
	not predicate_type_valid(parsed_payload)
	msg := "predicate type is not correct or missing"
}

violations contains msg if {
	parsed_payload := parse_payload(input.dsseEnvelope.payload)
	not build_type_valid(parsed_payload)
	msg := "build type is not correct or missing"
}

violations contains msg if {
	parsed_payload := parse_payload(input.dsseEnvelope.payload)
	not owner_valid(parsed_payload, approved_owner_ids)
	msg := "owner is not correct or missing"
}

violations contains msg if {
	parsed_payload := parse_payload(input.dsseEnvelope.payload)
	not repo_valid(parsed_payload, approved_repo_ids)
	msg := "repo is not correct or missing"
}

parse_payload(payload) := parsed_payload if {
	decoded_payload := base64.decode(payload)
	parsed_payload := json.unmarshal(decoded_payload)
}

predicate_type_valid(parsed_payload) if {
	is_slsa_provenance(parsed_payload)
}

predicate_type_valid(parsed_payload) if {
	is_cyclonedx_bom(parsed_payload)
}

build_type_valid(parsed_payload) if {
	is_slsa_provenance(parsed_payload)
	parsed_payload.predicate.buildDefinition.buildType == "https://actions.github.io/buildtypes/workflow/v1"
}

build_type_valid(parsed_payload) if {
	not is_slsa_provenance(parsed_payload)
	not parsed_payload.predicate.buildDefinition.buildType
}

owner_valid(parsed_payload, approved_owner_ids) if {
	is_slsa_provenance(parsed_payload)
	parsed_payload.predicate.buildDefinition.internalParameters.github.repository_owner_id in approved_owner_ids
}

owner_valid(parsed_payload, _) if {
	is_cyclonedx_bom(parsed_payload)
}

repo_valid(parsed_payload, approved_repo_ids) if {
	is_slsa_provenance(parsed_payload)
	parsed_payload.predicate.buildDefinition.internalParameters.github.repository_id in approved_repo_ids
}

repo_valid(parsed_payload, _) if {
	is_cyclonedx_bom(parsed_payload)
}
