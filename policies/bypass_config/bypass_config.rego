# METADATA
# scope: package
# title: Dependency-Vulnerability Bypass Configuration
# description: Authorization thresholds/flags for the attested dependency-vulnerability bypass.
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
# custom:
#  version: 0.19.0
#  path: policies/bypass_config
#  filename: bypass_config.rego
package bypass_config

import rego.v1

# Resolved configuration for the attested dependency-vulnerability bypass.
# Override at runtime via --policy-data-path with JSON under the key
# "bypass_thresholds" (DISTINCT from this package name to avoid OPA v1 conflicts
# between external data and the Rego package path).
#
# Every override is VALIDATED. A wrong-typed value, an out-of-range
# bypass_min_approvals (zero, negative, or fractional), an array that contains a
# non-string, OR an unknown/misspelled key is reported in config_errors. The
# bypass refuses to authorize while config_errors is non-empty — so a config typo
# fails CLOSED rather than silently weakening the gate. An ABSENT (correctly
# spelled) key falls back to the documented default below.
# regal ignore:unresolved-reference
_cfg := data.bypass_thresholds

# --- flags / thresholds ---

# Master switch. The whole capability is inert until this is true: with the
# default, the raw ignore_dependency_vulnerabilities request flag never authorizes
# a bypass, so dependency-vulnerability gates always enforce.
default allow_dep_vuln_bypass := false

allow_dep_vuln_bypass := _cfg.allow_dep_vuln_bypass if {
	is_boolean(_cfg.allow_dep_vuln_bypass)
}

# Distinct authorized approvals required to honor a bypass. Default 2
# (higher-stakes than an ordinary merge — two-person authorization).
default bypass_min_approvals := 2

bypass_min_approvals := _cfg.bypass_min_approvals if {
	_valid_min_approvals(_cfg.bypass_min_approvals)
}

# Author associations that count as authorized to approve a bypass.
default authorized_associations := ["OWNER", "MEMBER"]

authorized_associations := _cfg.authorized_associations if {
	_valid_str_array(_cfg.authorized_associations)
}

# Optional explicit login allowlist (OR-ed with authorized_associations).
default authorized_approvers := []

authorized_approvers := _cfg.authorized_approvers if {
	_valid_str_array(_cfg.authorized_approvers)
}

# --- config validation (provided-but-invalid overrides fail closed) ---

# _valid_min_approvals is true for a POSITIVE integer (>= 1). Zero is rejected:
# authorized_approvals(payload) >= 0 is always true, so a zero threshold would
# authorize a bypass with no approvals at all. The capability is disabled via
# allow_dep_vuln_bypass=false, never via a zero threshold.
_valid_min_approvals(v) if {
	is_number(v)
	v >= 1
	v == floor(v)
}

# _valid_str_array is true for an array whose every element is a string.
_valid_str_array(v) if {
	is_array(v)
	every e in v {
		is_string(e)
	}
}

# _array_keys must be arrays-of-strings when provided.
_array_keys := {"authorized_associations", "authorized_approvers"}

# _allowed_keys is every recognized override key; any other key is a typo.
_allowed_keys := {"allow_dep_vuln_bypass", "bypass_min_approvals"} | _array_keys

config_errors contains "bypass_thresholds must be an object" if {
	_cfg
	not is_object(_cfg)
}

config_errors contains "allow_dep_vuln_bypass must be a boolean" if {
	is_object(_cfg)
	"allow_dep_vuln_bypass" in object.keys(_cfg)
	not is_boolean(_cfg.allow_dep_vuln_bypass)
}

config_errors contains "bypass_min_approvals must be a positive integer (>= 1)" if {
	is_object(_cfg)
	"bypass_min_approvals" in object.keys(_cfg)
	not _valid_min_approvals(_cfg.bypass_min_approvals)
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
