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
# number "0", or a string for a boolean flag) is rejected and the safe default
# is used instead, so a config typo fails closed rather than silently disabling
# a gate.
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
	is_number(_cfg.bySecuritySeverity.critical)
}

default sev_high := 0

sev_high := _cfg.bySecuritySeverity.high if {
	is_number(_cfg.bySecuritySeverity.high)
}

default sev_medium := -1

sev_medium := _cfg.bySecuritySeverity.medium if {
	is_number(_cfg.bySecuritySeverity.medium)
}

default sev_low := -1

sev_low := _cfg.bySecuritySeverity.low if {
	is_number(_cfg.bySecuritySeverity.low)
}

default sev_none := -1

sev_none := _cfg.bySecuritySeverity.none if {
	is_number(_cfg.bySecuritySeverity.none)
}

# --- SARIF level thresholds (error gated by default; rest disabled) ---

default level_error := 0

level_error := _cfg.byLevel.error if {
	is_number(_cfg.byLevel.error)
}

default level_warning := -1

level_warning := _cfg.byLevel.warning if {
	is_number(_cfg.byLevel.warning)
}

default level_note := -1

level_note := _cfg.byLevel.note if {
	is_number(_cfg.byLevel.note)
}

default level_none := -1

level_none := _cfg.byLevel.none if {
	is_number(_cfg.byLevel.none)
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
