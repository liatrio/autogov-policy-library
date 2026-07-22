# METADATA
# scope: package
# title: Source Review Configuration
# description: Source-review (PR-approval) gating thresholds and flags with overridable defaults.
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
# custom:
#  version: 1.0.5
#  path: policies/source_review_config
#  filename: source_review_config.rego
package source_review_config

import rego.v1

# Resolved configuration for the source-review gating policy.
# Override at runtime via --policy-data-path with JSON under the key
# "source_review_thresholds" (DISTINCT from this package name to avoid OPA v1
# conflicts between external data and the Rego package path).
#
# Every override is VALIDATED. A wrong-typed value (e.g. a quoted number "2", or a
# string for a boolean flag), an out-of-range min_approvals (negative or
# fractional), OR an unknown/misspelled key name (e.g. `min_aprovals`) is reported
# in config_errors, and the gate DENIES when config_errors is non-empty — so a
# config typo fails closed rather than silently reverting to a looser default. An
# ABSENT (correctly-spelled) key falls back to the documented default below.
#
# The per-reviewer flags (disallow_self_approval / require_non_stale /
# allow_bot_approvals / require_codeowner_review) can only TIGHTEN gating. The
# producer already computes summary.distinctApprovers at the strictest filtering
# (author, stale, dismissed, changes-requested, and bot reviewers excluded), so
# these flags never loosen that floor; they additionally require the per-approver
# list to be present (see source_review_common.recompute_required).
# regal ignore:unresolved-reference
_cfg := data.source_review_thresholds

# --- approval thresholds ---

# Minimum number of distinct qualifying approvals required. Default 1 (inert-ish
# day-one, non-breaking); the strict preset ships 2 (two-person review).
default min_approvals := 1

min_approvals := _cfg.min_approvals if {
	_valid_count(_cfg.min_approvals)
}

# --- flags ---

# Whether a source-review attestation must be present. Default false so the
# policy is inert for artifacts without one.
default require_source_review := false

require_source_review := _cfg.require_source_review if {
	is_boolean(_cfg.require_source_review)
}

# Exclude the PR author's own approval. Default true. (The producer already
# excludes self-approval; this flag drives per-approver recompute requirements
# and documents intent — it cannot loosen the producer's exclusion.)
default disallow_self_approval := true

disallow_self_approval := _cfg.disallow_self_approval if {
	is_boolean(_cfg.disallow_self_approval)
}

# Exclude stale approvals (approval not on the PR head). Default true.
default require_non_stale := true

require_non_stale := _cfg.require_non_stale if {
	is_boolean(_cfg.require_non_stale)
}

# Count bot approvals toward the threshold. Default false (humans only).
default allow_bot_approvals := false

allow_bot_approvals := _cfg.allow_bot_approvals if {
	is_boolean(_cfg.allow_bot_approvals)
}

# Require CODEOWNER review. Default false: REST-only cannot authoritatively
# determine CODEOWNERS, so codeownerReviewMet is null and turning this on fails
# closed on every attestation until a future version adds the needed evidence.
default require_codeowner_review := false

require_codeowner_review := _cfg.require_codeowner_review if {
	is_boolean(_cfg.require_codeowner_review)
}

# Block when any reviewer's latest opinionated state is CHANGES_REQUESTED,
# regardless of approval count. Default true (necessary-but-not-sufficient
# gate: approvals alone never pass while a change request stands).
default block_on_changes_requested := true

block_on_changes_requested := _cfg.block_on_changes_requested if {
	is_boolean(_cfg.block_on_changes_requested)
}

# Fail when the review evidence could not be fully gathered
# (reviewToolingComplete=false). Default false to match require_source_review's
# inert default, so the gate ships fully inert; enforcing consumers set both true.
# (Per-approver and codeowner incompleteness guards are NOT governed by this flag;
# they always fire.)
default fail_on_incomplete_review := false

fail_on_incomplete_review := _cfg.fail_on_incomplete_review if {
	is_boolean(_cfg.fail_on_incomplete_review)
}

# RFC3339 cutoff for grandfathering. Default "" (inert): no revision is
# grandfathered, so enabling the gate behaves identically to before this key.
# When set, a revision whose pullRequest.mergedAt is BEFORE this instant has its
# approval-count violation suppressed, so enabling the gate does not retroactively
# fail commits merged before adoption. A standing changes-request still blocks
# regardless (a hard block, never grandfathered). A non-empty value that is not a
# parseable RFC3339 date is a config_error (fail closed — a typo cannot silently
# disable grandfathering or, worse, be read as an open window).
default enforced_since := ""

enforced_since := _cfg.enforced_since if {
	_valid_rfc3339(_cfg.enforced_since)
}

# Author associations that a qualifying approver must carry. Default empty so the
# gate is inert: with no entries the allowlist check never fires. When non-empty
# (e.g. ["OWNER", "MEMBER"]) at least one qualifying approver's association must be
# in the set, else the gate denies.
default required_approver_associations := set()

required_approver_associations := {a | some a in _cfg.required_approver_associations} if {
	_valid_str_array(_cfg.required_approver_associations)
}

# --- config validation (provided-but-invalid overrides fail closed) ---

# _bool_keys lists every flag that must be a boolean when provided.
_bool_keys := {
	"require_source_review",
	"disallow_self_approval",
	"require_non_stale",
	"allow_bot_approvals",
	"require_codeowner_review",
	"block_on_changes_requested",
	"fail_on_incomplete_review",
}

# _string_keys must be strings when provided.
_string_keys := {"enforced_since"}

# _array_keys must be arrays-of-strings when provided.
_array_keys := {"required_approver_associations"}

# _allowed_keys is every recognized override key; any other key is a typo.
_allowed_keys := (({"min_approvals"} | _bool_keys) | _string_keys) | _array_keys

# _valid_count is true for a non-negative integer.
_valid_count(v) if {
	is_number(v)
	v >= 0
	v == floor(v)
}

# _valid_rfc3339 is true for the empty string (inert default) or a parseable
# RFC3339 timestamp. A non-empty unparseable value is rejected so a typo cannot
# silently disable grandfathering.
_valid_rfc3339("")

_valid_rfc3339(v) if {
	is_string(v)
	_ := time.parse_rfc3339_ns(v)
}

# _valid_str_array is true for an array whose every element is a string.
_valid_str_array(v) if {
	is_array(v)
	every e in v {
		is_string(e)
	}
}

# config_errors reports every PROVIDED source_review_thresholds override that has
# the wrong type or is out of range. The gate denies when this is non-empty, so a
# config typo fails CLOSED instead of silently reverting to a looser default. An
# absent key is fine (it falls back to its documented default).
config_errors contains "source_review_thresholds must be an object" if {
	_cfg
	not is_object(_cfg)
}

config_errors contains "min_approvals must be a non-negative integer" if {
	is_object(_cfg)
	"min_approvals" in object.keys(_cfg)
	not _valid_count(_cfg.min_approvals)
}

config_errors contains msg if {
	is_object(_cfg)
	some k in _bool_keys
	k in object.keys(_cfg)
	not is_boolean(_cfg[k])
	msg := sprintf("%s must be a boolean", [k])
}

config_errors contains "enforced_since must be an RFC3339 date string" if {
	is_object(_cfg)
	"enforced_since" in object.keys(_cfg)
	not _valid_rfc3339(_cfg.enforced_since)
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
