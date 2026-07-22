# METADATA
# scope: package
# title: Metadata Policy
# description: Verifies metadata attestation requirements for images and blobs
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
# schemas:
# - input: schema["metadata-schema"]
# custom:
#  control_number: 3
#  version: 1.0.4
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

# Helper to check if payload is a metadata attestation (new or legacy format)
is_metadata_attestation(payload) if {
	utils.is_autogov_metadata(payload)
}

is_metadata_attestation(payload) if {
	utils.is_cosign_attestation(payload)
}

predicate_type_valid(payload) if {
	is_metadata_attestation(payload)
}

is_metadata_present(payload) if {
	is_metadata_attestation(payload)
	payload.predicate
	payload.predicate.artifact
	payload.predicate.repositoryData
	payload.predicate.ownerData
}

is_image_subject(payload) if {
	startswith(payload.subject[0].name, "ghcr.io/")
}

# Guard against attestations with no (or empty) subject name. Rego's
# negation-as-failure means an absent payload.subject[0].name makes both the
# image-prefix and blob-regex violation rule bodies undefined, so neither
# fires and the gate fails open. This rule closes that gap.
has_subject_name(payload) if {
	is_array(payload.subject)
	count(payload.subject) > 0
	is_string(payload.subject[0].name)
	count(payload.subject[0].name) > 0
}

# Common violations for both images and blobs
violations contains msg if {
	msg := "attestation subject with a name is missing"
	some payload in utils.decoded_payload_list
	is_metadata_attestation(payload)
	not has_subject_name(payload)
}

violations contains msg if {
	msg := "artifact metadata is missing"
	some payload in utils.decoded_payload_list
	is_metadata_attestation(payload)
	is_metadata_present(payload)
	not payload.predicate.artifact
}

violations contains msg if {
	msg := "owner is missing in metadata"
	some payload in utils.decoded_payload_list
	is_metadata_attestation(payload)
	is_metadata_present(payload)
	not payload.predicate.ownerData.ownerId
}

violations contains msg if {
	msg := "runner environment is missing"
	some payload in utils.decoded_payload_list
	is_metadata_attestation(payload)
	is_metadata_present(payload)
	not payload.predicate.runnerData.environment
}

# Artifact-specific validations
violations contains msg if {
	msg := "artifact type is missing"
	some payload in utils.decoded_payload_list
	is_metadata_attestation(payload)
	is_metadata_present(payload)
	not payload.predicate.artifact.type
}

# Type-specific artifact validations
violations contains msg if {
	msg := "artifact type must be container-image for image subjects"
	some payload in utils.decoded_payload_list
	is_metadata_attestation(payload)
	is_image_subject(payload)
	payload.predicate.artifact.type != "container-image"
}

violations contains msg if {
	msg := "artifact type must be blob for non-image subjects"
	some payload in utils.decoded_payload_list
	is_metadata_attestation(payload)
	not is_image_subject(payload)
	payload.predicate.artifact.type != "blob"
}

# Image-specific violations
violations contains msg if {
	msg := sprintf("image subject name must be under %s", [access.subject_prefix])
	some payload in utils.decoded_payload_list
	is_image_subject(payload)
	not startswith(payload.subject[0].name, access.subject_prefix)
}

# Blob-specific violations
violations contains msg if {
	msg := "blob subject name contains invalid characters"
	some payload in utils.decoded_payload_list
	not is_image_subject(payload)
	not regex.match(`^[a-zA-Z0-9_.-]+$`, payload.subject[0].name)
}

# Required fields validation
violations contains msg if {
	msg := "workflow inputs are missing in metadata"
	some payload in utils.decoded_payload_list
	is_metadata_attestation(payload)
	is_metadata_present(payload)
	not inputs_exist(payload)
}

# Required metadata sections validation
violations contains msg if {
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
	some payload in utils.decoded_payload_list
	is_metadata_attestation(payload)
	is_metadata_present(payload)
	some section in required_sections
	not payload.predicate[section]
	msg := sprintf("%s section is missing in metadata", [section])
}

# Additional validation for path/digest exclusivity
violations contains msg if {
	msg := "artifact.digest should not be present for blob type"
	some payload in utils.decoded_payload_list
	is_metadata_attestation(payload)
	payload.predicate.artifact.type == "blob"
	payload.predicate.artifact.digest
}

violations contains msg if {
	msg := "artifact.path should not be present for container-image type"
	some payload in utils.decoded_payload_list
	is_metadata_attestation(payload)
	payload.predicate.artifact.type == "container-image"
	payload.predicate.artifact.path
}

# Compliance validations
violations contains msg if {
	msg := "compliance.policyRef is missing in metadata"
	some payload in utils.decoded_payload_list
	is_metadata_attestation(payload)
	is_metadata_present(payload)
	not payload.predicate.compliance.policyRef
}

violations contains msg if {
	msg := "compliance.controlIds is missing in metadata"
	some payload in utils.decoded_payload_list
	is_metadata_attestation(payload)
	is_metadata_present(payload)
	not payload.predicate.compliance.controlIds
}

# Security permissions validations
violations contains msg if {
	required_permissions := {
		"id-token",
		"attestations",
		"packages",
		"contents",
	}
	some payload in utils.decoded_payload_list
	is_metadata_attestation(payload)
	is_metadata_present(payload)
	some perm in required_permissions
	not payload.predicate.security.permissions[perm]
	msg := sprintf("security.permissions.%s is missing in metadata", [perm])
}

# Metadata attestation validation
violations contains msg if {
	attestations := [payload |
		some payload in utils.decoded_payload_list
		is_metadata_attestation(payload)
		is_metadata_present(payload)
	]
	count(attestations) == 0
	msg := "metadata attestation is missing"
}

# Add this rule to validate runner environment
violations contains msg if {
	msg := "invalid runner environment"
	some payload in utils.decoded_payload_list
	is_metadata_attestation(payload)
	is_metadata_present(payload)
	payload.predicate.runnerData.environment != "github-hosted"
}

# Add this rule to validate owner ID
violations contains msg if {
	msg := "invalid owner ID"
	some payload in utils.decoded_payload_list
	is_metadata_attestation(payload)
	is_metadata_present(payload)
	not payload.predicate.ownerData.ownerId in access.approved_owner_ids
}
