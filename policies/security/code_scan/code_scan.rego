# METADATA
# scope: package
# title: Code Scan Policy
# description: Gates autogov code-scan (SARIF) attestations against configurable per-severity and per-level thresholds.
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
# custom:
#  version: 0.21.0
#  path: policies/security/code_scan
#  filename: code_scan.rego
package security.code_scan

import data.code_scan_config
import data.security.code_scan_common as common
import data.shared.utils
import rego.v1

default allow := false

allow if {
	count(violations) == 0
}

# code-scan attestations present in the input.
cs_payloads := [payload |
	some payload in utils.decoded_payload_list
	utils.is_code_scan(payload)
]

# threshold maps keyed by bucket/level; -1 disables a check.
sev_thresholds := {
	"critical": code_scan_config.sev_critical,
	"high": code_scan_config.sev_high,
	"medium": code_scan_config.sev_medium,
	"low": code_scan_config.sev_low,
	"none": code_scan_config.sev_none,
}

level_thresholds := {
	"error": code_scan_config.level_error,
	"warning": code_scan_config.level_warning,
	"note": code_scan_config.level_note,
	"none": code_scan_config.level_none,
}

# Violation: the policy configuration itself is malformed (a provided override has
# the wrong type or an out-of-range threshold). Fails CLOSED so a config typo
# cannot silently revert a gate to a looser default or disable a bucket.
violations contains msg if {
	some err in code_scan_config.config_errors
	msg := sprintf("code-scan configuration is invalid: %s", [err])
}

# Violation: presence required but no code-scan attestation present.
violations contains msg if {
	code_scan_config.require_code_scan
	count(cs_payloads) == 0
	msg := "code-scan attestation is missing"
}

# Violation: a present code-scan predicate is malformed (missing or mistyped
# fields the gate depends on). The predicate is not re-validated against the
# schema at eval time, so this fails CLOSED — a non-conforming signed predicate
# cannot slip a threshold via an undefined lookup.
violations contains msg if {
	some payload in cs_payloads
	not common.structurally_valid(payload)
	msg := "code-scan predicate is malformed (missing or mistyped summary/invocation fields)"
}

# Violation: the scanner reported an incomplete run.
violations contains msg if {
	code_scan_config.fail_on_incomplete_scan == true
	some payload in cs_payloads
	payload.predicate.invocation.executionSuccessful == false
	msg := "code-scan reports an incomplete scan (invocation.executionSuccessful=false)"
}

# Violation: finding-level gating was requested (count_suppressed / gate_new_only
# / ignore_paths) but the attestation does not embed findings, so the summary
# cannot honor those filters. ALWAYS fires (never a silent no-op) — decoupled
# from fail_on_incomplete_scan, which governs scanner-run completeness, not the
# contradiction of requesting per-finding gating without per-finding data.
violations contains msg if {
	common.recompute_required == true
	some payload in cs_payloads
	not common.can_recompute(payload)
	msg := concat("", [
		"code-scan gating needs per-finding data ",
		"(count_suppressed/gate_new_only/ignore_paths) but findings are excluded; ",
		"regenerate with --include-findings",
	])
}

# Violation: a security-severity bucket exceeds its threshold.
violations contains msg if {
	some payload in cs_payloads
	some bucket, threshold in sev_thresholds
	threshold >= 0
	n := common.effective_sev(payload, bucket)
	n > threshold
	msg := sprintf("code-scan: %d %s security-severity finding(s) exceed threshold of %d", [n, bucket, threshold])
}

# Violation: a SARIF level bucket exceeds its threshold.
violations contains msg if {
	some payload in cs_payloads
	some level, threshold in level_thresholds
	threshold >= 0
	n := common.effective_level(payload, level)
	n > threshold
	msg := sprintf("code-scan: %d %s-level finding(s) exceed threshold of %d", [n, level, threshold])
}

# Violation: suppressed findings present and suppressions are not permitted.
violations contains msg if {
	code_scan_config.fail_on_unreviewed_suppression == true
	some payload in cs_payloads
	suppressed := payload.predicate.summary.suppressed
	suppressed > 0
	msg := sprintf("code-scan: %d suppressed finding(s) present; suppressions are not permitted", [suppressed])
}
