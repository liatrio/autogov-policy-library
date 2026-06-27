# METADATA
# scope: package
# title: Source Level Configuration
# description: Source-control posture (SLSA Source level) gating thresholds and flags with overridable defaults.
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
# custom:
#  version: 0.21.0
#  path: policies/source_level_config
#  filename: source_level_config.rego
package source_level_config

import rego.v1

# Resolved configuration for the source-level (source-control posture) gating
# policy. Override at runtime via --policy-data-path with JSON under the key
# "source_level_thresholds" (DISTINCT from this package name to avoid OPA v1
# conflicts between external data and the Rego package path).
#
# This gate enforces a MINIMUM source-control posture derived from the
# source-review attestation's technicalControls — mirroring the verifier's
# promotion logic (autogov pkg/source/review.go ComputeSourceLevelFromControls).
# It ships fully INERT: with require_min_source_posture=false (the default) no
# violation is ever raised, so no current consumer breaks.
#
# Every override is VALIDATED. A wrong-typed value (e.g. a string for a boolean
# flag), an array that contains a non-string, OR an unknown/misspelled key name is
# reported in config_errors, and the gate DENIES when config_errors is non-empty —
# so a config typo fails closed rather than silently reverting to a looser default.
# An ABSENT (correctly-spelled) key falls back to the documented default below.
# regal ignore:unresolved-reference
_cfg := data.source_level_thresholds

# --- flags ---

# Master switch. The whole gate is inert until this is true: with the default,
# the source-control posture is never checked, so an artifact whose source-review
# attestation lacks technicalControls (or carries a weaker posture) still passes.
# When true the gate fails CLOSED — a missing attestation, missing/malformed
# technicalControls, or an unmet posture leg denies.
default require_min_source_posture := false

require_min_source_posture := _cfg.require_min_source_posture if {
	is_boolean(_cfg.require_min_source_posture)
}

# Require continuity to be recorded (continuityStartRevision != "") as part of the
# L3 posture. Default true: L3 in the verifier requires recorded continuity, so a
# consumer enabling the posture gate gets the verifier's full L3 bar. An empty
# continuityStartRevision is UNDETERMINED and never satisfies this leg (fail
# closed). Set false to gate on the technical controls alone (continuity aside).
default require_continuity := true

require_continuity := _cfg.require_continuity if {
	is_boolean(_cfg.require_continuity)
}

# Require commit signatures (requiredSignatures) as part of the posture. Default
# false: the verifier does NOT require signed commits for L3 (it is surfaced only
# as the ORG_SOURCE_SIGNED_COMMITS annotation), so this gate mirrors that and
# leaves signatures opt-in. Set true to additionally demand requiredSignatures.
default require_signed_commits := false

require_signed_commits := _cfg.require_signed_commits if {
	is_boolean(_cfg.require_signed_commits)
}

# --- narrow-bypass allowlist ---

# Bypass actors that count as "narrow" (allowlisted). Mirrors the verifier's
# allowedBypass argument: a recorded bypass actor is matched on its "<Type>:<ID>"
# (the formatted entry is "<Type>:<ID>:<Mode>", so the trailing ":<Mode>" is
# dropped before matching). An EMPTY bypass list (no bypass at all) is always
# narrow; with a non-empty bypass list, EVERY actor's Type:ID must be in this
# allowlist or the posture leg fails. Default empty so the only narrow posture is
# "no bypass actors at all" — the strictest, safest interpretation when an operator
# supplies no allowlist (matches the verifier called with a nil allowedBypass).
default allowed_bypass_actors := set()

allowed_bypass_actors := {a | some a in _cfg.allowed_bypass_actors} if {
	_valid_str_array(_cfg.allowed_bypass_actors)
}

# --- config validation (provided-but-invalid overrides fail closed) ---

# _bool_keys lists every flag that must be a boolean when provided.
_bool_keys := {
	"require_min_source_posture",
	"require_continuity",
	"require_signed_commits",
}

# _array_keys must be arrays-of-strings when provided.
_array_keys := {"allowed_bypass_actors"}

# _allowed_keys is every recognized override key; any other key is a typo.
_allowed_keys := _bool_keys | _array_keys

# _valid_str_array is true for an array whose every element is a string.
_valid_str_array(v) if {
	is_array(v)
	every e in v {
		is_string(e)
	}
}

# config_errors reports every PROVIDED source_level_thresholds override that has
# the wrong type. The gate denies when this is non-empty, so a config typo fails
# CLOSED instead of silently reverting to a looser default. An absent key is fine
# (it falls back to its documented default).
config_errors contains "source_level_thresholds must be an object" if {
	_cfg
	not is_object(_cfg)
}

config_errors contains msg if {
	is_object(_cfg)
	some k in _bool_keys
	k in object.keys(_cfg)
	not is_boolean(_cfg[k])
	msg := sprintf("%s must be a boolean", [k])
}

config_errors contains msg if {
	is_object(_cfg)
	some k in _array_keys
	k in object.keys(_cfg)
	not _valid_str_array(_cfg[k])
	msg := sprintf("%s must be an array of strings", [k])
}

# unknown/misspelled key -> fail closed (a typo'd key would otherwise be ignored,
# silently keeping the looser default instead of the operator's intended value).
config_errors contains msg if {
	is_object(_cfg)
	some k in object.keys(_cfg)
	not k in _allowed_keys
	msg := sprintf("unknown config key: %s", [k])
}
