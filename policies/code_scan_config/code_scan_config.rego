# METADATA
# scope: package
# title: Code Scan Configuration
# description: Code-scan gating thresholds and flags with overridable defaults.
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
# custom:
#  version: 0.1.0
#  path: policies/code_scan_config
#  filename: code_scan_config.rego
package code_scan_config

import rego.v1

# Resolved configuration for the code-scan gating policy.
# Override at runtime via --policy-data-path with JSON under the key
# "code_scan_thresholds" (DISTINCT from this package name to avoid OPA v1
# conflicts between external data and the Rego package path).
#
# Threshold values (per security-severity bucket and per SARIF level):
#   0  = zero tolerance (no finding of that bucket allowed)
#   N  = allow up to N findings
#   -1 = unlimited (disable that bucket's check)
#
# Every override is TYPE-CHECKED: a value of the wrong type (e.g. a quoted
# number "0", or a string for a boolean flag) or an out-of-range threshold (an
# integer below -1) is reported in config_errors, and the gate DENIES when
# config_errors is non-empty — so a config typo fails closed rather than silently
# reverting to a looser default or disabling a gate. An ABSENT key falls back to
# the documented default. Threshold values: 0 = zero tolerance, N = allow up to N,
# -1 = disabled; only integers >= -1 are valid.
#
# Defaults gate zero-tolerance on critical/high security-severity AND on the
# SARIF "error" level. The error-level gate is on by default so that an
# error-severity finding lacking a numeric security-severity (common with
# semgrep/gosec and CodeQL quality queries — it lands in the "none" security
# bucket) is still caught. Lower-signal axes (medium/low/none security, and the
# warning/note/none levels) are disabled by default.
# regal ignore:unresolved-reference
_cfg := data.code_scan_thresholds

# --- security-severity bucket thresholds ---

default sev_critical := 0

sev_critical := _cfg.bySecuritySeverity.critical if {
	_valid_threshold(_cfg.bySecuritySeverity.critical)
}

default sev_high := 0

sev_high := _cfg.bySecuritySeverity.high if {
	_valid_threshold(_cfg.bySecuritySeverity.high)
}

default sev_medium := -1

sev_medium := _cfg.bySecuritySeverity.medium if {
	_valid_threshold(_cfg.bySecuritySeverity.medium)
}

default sev_low := -1

sev_low := _cfg.bySecuritySeverity.low if {
	_valid_threshold(_cfg.bySecuritySeverity.low)
}

default sev_none := -1

sev_none := _cfg.bySecuritySeverity.none if {
	_valid_threshold(_cfg.bySecuritySeverity.none)
}

# --- SARIF level thresholds (error gated by default; rest disabled) ---

default level_error := 0

level_error := _cfg.byLevel.error if {
	_valid_threshold(_cfg.byLevel.error)
}

default level_warning := -1

level_warning := _cfg.byLevel.warning if {
	_valid_threshold(_cfg.byLevel.warning)
}

default level_note := -1

level_note := _cfg.byLevel.note if {
	_valid_threshold(_cfg.byLevel.note)
}

default level_none := -1

level_none := _cfg.byLevel.none if {
	_valid_threshold(_cfg.byLevel.none)
}

# --- flags ---

# Whether a code-scan attestation must be present. Default false so the policy is
# inert for artifacts without a code scan.
default require_code_scan := false

require_code_scan := _cfg.require_code_scan if {
	is_boolean(_cfg.require_code_scan)
}

# Fail when the scanner reported an incomplete run. Default true. (The separate
# finding-level incompleteness guard — filters requested but findings excluded —
# is NOT governed by this flag; it always fires.)
default fail_on_incomplete_scan := true

fail_on_incomplete_scan := _cfg.fail_on_incomplete_scan if {
	is_boolean(_cfg.fail_on_incomplete_scan)
}

# Count suppressed findings toward thresholds. Default false (honor suppressions).
default count_suppressed := false

count_suppressed := _cfg.count_suppressed if {
	is_boolean(_cfg.count_suppressed)
}

# Treat any suppressed finding as a violation. Default false. (The predicate
# records that a finding was suppressed, not whether the suppression was
# reviewed, so this gates on presence of suppressions.)
default fail_on_unreviewed_suppression := false

fail_on_unreviewed_suppression := _cfg.fail_on_unreviewed_suppression if {
	is_boolean(_cfg.fail_on_unreviewed_suppression)
}

# Only gate findings whose baselineState is new or updated. Default false.
default gate_new_only := false

gate_new_only := _cfg.gate_new_only if {
	is_boolean(_cfg.gate_new_only)
}

# Glob patterns for finding locations to ignore. Default empty.
default ignore_paths := []

ignore_paths := _cfg.ignore_paths if {
	is_array(_cfg.ignore_paths)
}

# --- config validation (provided-but-invalid overrides fail closed) ---

# _sev_buckets / _level_buckets / _bool_keys enumerate the overridable keys.
_sev_buckets := {"critical", "high", "medium", "low", "none"}

_level_buckets := {"error", "warning", "note", "none"}

_bool_keys := {
	"require_code_scan",
	"fail_on_incomplete_scan",
	"count_suppressed",
	"fail_on_unreviewed_suppression",
	"gate_new_only",
}

# _valid_threshold is true for an integer >= -1 (0 = zero tolerance, N = allow up
# to N, -1 = disabled). A value below -1 would silently disable a bucket.
_valid_threshold(v) if {
	is_number(v)
	v >= -1
	v == floor(v)
}

# config_errors reports every PROVIDED code_scan_thresholds override that has the
# wrong type or is out of range. The gate denies when this is non-empty, so a
# config typo fails CLOSED instead of silently reverting to a looser default (or
# disabling a bucket via a stray negative). An absent key falls back to its
# documented default.
config_errors contains "code_scan_thresholds must be an object" if {
	_cfg
	not is_object(_cfg)
}

config_errors contains "bySecuritySeverity must be an object" if {
	is_object(_cfg)
	"bySecuritySeverity" in object.keys(_cfg)
	not is_object(_cfg.bySecuritySeverity)
}

config_errors contains msg if {
	is_object(_cfg)
	is_object(_cfg.bySecuritySeverity)
	some k in _sev_buckets
	k in object.keys(_cfg.bySecuritySeverity)
	not _valid_threshold(_cfg.bySecuritySeverity[k])
	msg := sprintf("bySecuritySeverity.%s must be an integer >= -1", [k])
}

config_errors contains "byLevel must be an object" if {
	is_object(_cfg)
	"byLevel" in object.keys(_cfg)
	not is_object(_cfg.byLevel)
}

config_errors contains msg if {
	is_object(_cfg)
	is_object(_cfg.byLevel)
	some k in _level_buckets
	k in object.keys(_cfg.byLevel)
	not _valid_threshold(_cfg.byLevel[k])
	msg := sprintf("byLevel.%s must be an integer >= -1", [k])
}

config_errors contains msg if {
	is_object(_cfg)
	some k in _bool_keys
	k in object.keys(_cfg)
	not is_boolean(_cfg[k])
	msg := sprintf("%s must be a boolean", [k])
}

config_errors contains "ignore_paths must be an array" if {
	is_object(_cfg)
	"ignore_paths" in object.keys(_cfg)
	not is_array(_cfg.ignore_paths)
}

config_errors contains msg if {
	is_object(_cfg)
	is_array(_cfg.ignore_paths)
	some i, p in _cfg.ignore_paths
	not is_string(p)
	msg := sprintf("ignore_paths[%d] must be a string", [i])
}
