# METADATA
# scope: package
# title: Source Level Policy
# description: Gates a minimum source-control posture (SLSA Source level) from the source-review technicalControls.
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
# custom:
#  version: 0.22.2
#  path: policies/security/source_level
#  filename: source_level.rego
package security.source_level

import data.security.source_review_common as common
import data.shared.utils
import data.source_level_config
import rego.v1

default allow := false

allow if {
	count(violations) == 0
}

# source-review attestations present in the input. The source-control posture is
# carried on the same source-review predicate (predicate.technicalControls), so
# this gate reads the same attestations the source_review gate does.
sr_payloads := [payload |
	some payload in utils.decoded_payload_list
	utils.is_source_review(payload)
]

# NOTE: every predicate field a violation rule below reads MUST also be
# type-checked by common.technical_controls_valid (or common.continuity_recorded's
# own is_string guard). The gate is not re-validated against the JSON schema at
# eval time, so an unchecked field would read UNDEFINED and silently skip its leg
# (fail-open). When adding a leg that reads a new field, extend
# technical_controls_valid and the malformed-field coupling test.

# Violation: the policy configuration itself is malformed (a provided override has
# the wrong type, or an unknown/misspelled key). Fails CLOSED so a config typo
# cannot silently revert the gate to a looser default. UNCONDITIONAL (like
# source_review's config_errors violation): when the gate is inert no override is
# normally present, so this stays quiet; once an operator supplies any override it
# is validated.
violations contains msg if {
	some err in source_level_config.config_errors
	msg := sprintf("source-level configuration is invalid: %s", [err])
}

# Everything below is gated on the inert master switch: with
# require_min_source_posture=false (the default) the gate raises no posture
# violation, so it ships fully INERT and no current consumer breaks.

# Violation: posture required but no source-review attestation present (the posture
# is carried on the source-review predicate, so a missing attestation means the
# posture is undeterminable -> fail closed).
violations contains msg if {
	source_level_config.require_min_source_posture
	count(sr_payloads) == 0
	msg := "source-level: source-review attestation is missing"
}

# Violation: a present source-review predicate carries no technicalControls. The
# posture is undeterminable without it -> fail closed (REQUIRED only when enabled,
# so the gate stays inert for predicates lacking it).
violations contains msg if {
	source_level_config.require_min_source_posture
	some payload in sr_payloads
	not common.has_technical_controls(payload)
	msg := "source-level: source-review predicate records no technicalControls"
}

# Violation: technicalControls is present but malformed (a field the gate depends
# on is missing or mistyped). The predicate is not re-validated against the schema
# at eval time, so this fails CLOSED — a non-conforming signed predicate cannot
# slip the gate via an undefined lookup.
violations contains msg if {
	source_level_config.require_min_source_posture
	some payload in sr_payloads
	common.has_technical_controls(payload)
	not common.technical_controls_valid(payload)
	msg := "source-level: technicalControls is malformed (missing or mistyped posture fields)"
}

# Violation: the technical-control posture does not meet L3 (force-push blocked,
# >=1 required status check, retained history, an AUTHORITATIVE+narrow bypass
# list). Only evaluated over a well-formed technicalControls so the message is
# about the posture, not a malformed predicate.
violations contains msg if {
	source_level_config.require_min_source_posture
	some payload in sr_payloads
	common.has_technical_controls(payload)
	common.technical_controls_valid(payload)
	not common.meets_l3_posture(payload)
	msg := concat("", [
		"source-level: technical controls do not meet the L3 posture ",
		"(force-push, status checks, retained history, authoritative narrow bypass)",
	])
}

# Violation: continuity is required (default) but not proven. Continuity holds only
# when continuityComplete==true AND continuityStartRevision is a non-empty string
# (controls continuously enforced from a start revision); a false/absent
# continuityComplete OR an empty start is UNDETERMINED and must not satisfy the
# L3-continuity leg -> fail closed. Governed by require_continuity (default true).
violations contains msg if {
	source_level_config.require_min_source_posture
	source_level_config.require_continuity
	some payload in sr_payloads
	common.has_technical_controls(payload)
	common.technical_controls_valid(payload)
	not common.continuity_recorded(payload)
	msg := "source-level: continuity not proven: continuityStartRevision empty/undetermined or continuityComplete is false"
}

# Violation: signed commits are required (opt-in) but requiredSignatures is not
# set. The verifier does NOT demand signatures for L3, so this leg is off by
# default and only fires when require_signed_commits is enabled.
violations contains msg if {
	source_level_config.require_min_source_posture
	source_level_config.require_signed_commits
	some payload in sr_payloads
	common.has_technical_controls(payload)
	common.technical_controls_valid(payload)
	payload.predicate.technicalControls.requiredSignatures != true
	msg := "source-level: signed commits are required but requiredSignatures is not set"
}
