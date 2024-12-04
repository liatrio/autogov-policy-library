# METADATA
# scope: package
# title: Metadata Policy
# description: Verifies metadata attestation requirements for images and blobs
# authors:
# - Autogov Team https://github.com/orgs/liatrio/teams/tag-autogov
# schemas:
# - input: schema["metadata-schema"]
# custom:
#  control_number: 3
#  version: 0.6.3
#  path: policies/security
#  filename: metadata.rego
#  irm_control_ids: [LIATRIO-METADATA-003]
package security.metadata

import data.shared.access
import data.shared.utils
import rego.v1

default allow := false

# Top-level allow rule - iterates over JSON input to ensure no violations
allow if {
	count(violations) == 0
}

# Validation rules
inputs_exist(payload) if {
	payload.predicate.workflowData.inputs
	count(payload.predicate.workflowData.inputs) > 0
}

predicate_type_valid(payload) if {
	utils.is_cosign_attestation(payload)
}

is_metadata_present(payload) if {
	utils.is_cosign_attestation(payload)
	payload.predicate
	payload.predicate.artifact
	payload.predicate.repositoryData
	payload.predicate.ownerData
}

is_image_subject(payload) if {
	startswith(payload.subject[0].name, "ghcr.io/")
}

# Common violations for both images and blobs
violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	is_metadata_present(payload)
	not payload.predicate.artifact
	msg := "artifact metadata is missing"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	is_metadata_present(payload)
	not payload.predicate.repositoryData.repositoryId
	msg := "repository is missing in metadata"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	is_metadata_present(payload)
	not payload.predicate.ownerData.ownerId
	msg := "owner is missing in metadata"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	is_metadata_present(payload)
	not payload.predicate.runnerData.environment
	msg := "runner environment is missing"
}

# Artifact-specific validations
violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	is_metadata_present(payload)
	not payload.predicate.artifact.type
	msg := "artifact type is missing"
}

# Type-specific artifact validations
violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	is_image_subject(payload)
	payload.predicate.artifact.type != "container-image"
	msg := "artifact type must be container-image for image subjects"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	not is_image_subject(payload)
	payload.predicate.artifact.type != "blob"
	msg := "artifact type must be blob for non-image subjects"
}

# Image-specific violations
violations contains msg if {
	some payload in utils.decoded_payload_list
	is_image_subject(payload)
	not startswith(payload.subject[0].name, "ghcr.io/liatrio/")
	msg := "image subject name must be under ghcr.io/liatrio/"
}

# Blob-specific violations
violations contains msg if {
	some payload in utils.decoded_payload_list
	not is_image_subject(payload)
	not regex.match(`^[a-zA-Z0-9_-]+$`, payload.subject[0].name)
	msg := "blob subject name contains invalid characters"
}

# Required fields validation
violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	is_metadata_present(payload)
	not inputs_exist(payload)
	msg := "workflow inputs are missing in metadata"
}

# Required metadata sections validation
violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	is_metadata_present(payload)
	required_sections := {
		"artifact",
		"repositoryData",
		"ownerData",
		"runnerData",
		"workflowData",
		"jobData",
		"commitData",
		"organization",
		"compliance",
		"security",
	}
	some section in required_sections
	not payload.predicate[section]
	msg := sprintf("%s section is missing in metadata", [section])
}

# Additional validation for path/digest exclusivity
violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	payload.predicate.artifact.type == "blob"
	payload.predicate.artifact.digest
	msg := "artifact.digest should not be present for blob type"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	payload.predicate.artifact.type == "container-image"
	payload.predicate.artifact.path
	msg := "artifact.path should not be present for container-image type"
}

# Compliance validations
violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	is_metadata_present(payload)
	not payload.predicate.compliance.policyRef
	msg := "compliance.policyRef is missing in metadata"
}

violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	is_metadata_present(payload)
	not payload.predicate.compliance.controlIds
	msg := "compliance.controlIds is missing in metadata"
}

# Security permissions validations
violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	is_metadata_present(payload)
	required_permissions := {
		"id-token",
		"attestations",
		"packages",
		"contents",
	}
	some perm in required_permissions
	not payload.predicate.security.permissions[perm]
	msg := sprintf("security.permissions.%s is missing in metadata", [perm])
}

# Metadata attestation validation
violations contains msg if {
	attestations := [payload |
		some payload in utils.decoded_payload_list
		utils.is_cosign_attestation(payload)
		is_metadata_present(payload)
	]
	count(attestations) == 0
	msg := "metadata attestation is missing"
}

# Add this rule to validate runner environment
violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	is_metadata_present(payload)
	payload.predicate.runnerData.environment != "github-hosted"
	msg := "invalid runner environment"
}

# Add this rule to validate owner and repository IDs
violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_cosign_attestation(payload)
	is_metadata_present(payload)
	not payload.predicate.ownerData.ownerId in access.approved_owner_ids
	msg := "invalid owner ID"
}
