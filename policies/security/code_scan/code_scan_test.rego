package security.code_scan_test

import data.security.code_scan
import data.shared.utils
import rego.v1

# --- builders ---

sev(c, h, m, l, n) := {"critical": c, "high": h, "medium": m, "low": l, "none": n, "total": (((c + h) + m) + l) + n}

lvl(e, w, no, nn) := {"error": e, "warning": w, "note": no, "none": nn, "total": ((e + w) + no) + nn}

_env(predicate) := {"dsseEnvelope": {"payload": base64.encode(json.marshal({
	"predicateType": "https://autogov.dev/attestation/code-scan/v0.1",
	"predicate": predicate,
}))}}

# summary-only attestation (findings excluded — the default producer mode).
cs_summary(by_sev, by_level, suppressed) := [_env({
	"tools": [{"name": "CodeQL"}],
	"summary": {"bySecuritySeverity": by_sev, "byLevel": by_level, "suppressed": suppressed},
	"configuration": [],
	"invocation": {"executionSuccessful": true},
	"findingsIncluded": false,
	"truncated": true,
	"resultCount": ((((by_sev.critical + by_sev.high) + by_sev.medium) + by_sev.low) + by_sev.none) + suppressed,
})]

# findings-embedded attestation (authoritative results[]).
cs_findings(findings) := [_env({
	"tools": [{"name": "CodeQL"}],
	"summary": {"bySecuritySeverity": sev(0, 0, 0, 0, 0), "byLevel": lvl(0, 0, 0, 0), "suppressed": 0},
	"configuration": [],
	"invocation": {"executionSuccessful": true},
	"findingsIncluded": true,
	"truncated": false,
	"resultCount": count(findings),
	"results": findings,
})]

finding(rule, level, sevlevel, baseline, suppressed, finding_uri) := {
	"ruleId": rule,
	"level": level,
	"securitySeverityLevel": sevlevel,
	"baselineState": baseline,
	"suppressed": suppressed,
	"location": {"uri": finding_uri},
}

# Patch a valid predicate AFTER the arithmetic builders run so invalid operands
# cannot make the fixture undefined before the policy sees them.
_valid_predicate := predicate if {
	payload := utils.has_envelope(cs_summary(sev(0, 0, 0, 0, 0), lvl(0, 0, 0, 0), 0)[0])
	predicate := payload.predicate
}

_count_paths := [
	"/summary/suppressed",
	"/resultCount",
	"/summary/bySecuritySeverity/critical",
	"/summary/bySecuritySeverity/high",
	"/summary/bySecuritySeverity/medium",
	"/summary/bySecuritySeverity/low",
	"/summary/bySecuritySeverity/none",
	"/summary/byLevel/error",
	"/summary/byLevel/warning",
	"/summary/byLevel/note",
	"/summary/byLevel/none",
]

_malformed_msg := "code-scan predicate is malformed (missing or mistyped summary/invocation fields)"

_disabled_thresholds := {
	"bySecuritySeverity": {"critical": -1, "high": -1, "medium": -1, "low": -1, "none": -1},
	"byLevel": {"error": -1, "warning": -1, "note": -1, "none": -1},
}

test_all_scan_counts_reject_invalid_values_in_both_producer_paths if {
	every included in [true, false] {
		every thresholds in [{}, _disabled_thresholds] {
			cfg := object.union(thresholds, {"fail_on_unreviewed_suppression": true})
			every path in _count_paths {
				every value in [-1, 0.5, "bad", null, true, false, [], {}] {
					predicate := json.patch(_valid_predicate, [
						{"op": "replace", "path": path, "value": value},
						{"op": "replace", "path": "/findingsIncluded", "value": included},
						{"op": "replace", "path": "/truncated", "value": false},
						{"op": "add", "path": "/results", "value": []},
					])
					inp := [_env(predicate)]

					# regal ignore:unresolved-reference
					not code_scan.allow with input as inp with data.code_scan_thresholds as cfg

					# regal ignore:unresolved-reference
					msgs := code_scan.violations with input as inp with data.code_scan_thresholds as cfg
					msgs == {_malformed_msg}
				}
			}
		}
	}
}

test_all_scan_counts_are_required_in_both_producer_paths if {
	every included in [true, false] {
		every path in _count_paths {
			predicate := json.patch(_valid_predicate, [
				{"op": "remove", "path": path},
				{"op": "replace", "path": "/findingsIncluded", "value": included},
				{"op": "replace", "path": "/truncated", "value": false},
				{"op": "add", "path": "/results", "value": []},
			])
			inp := [_env(predicate)]
			not code_scan.allow with input as inp
			msgs := code_scan.violations with input as inp
			msgs == {_malformed_msg}
		}
	}
}

test_decimal_scan_counts_and_thresholds_format_cleanly if {
	# Both summary totals are 30, plus 7 suppressed findings = 37 results.
	inp := cs_summary(sev(2.0, 4.0, 6.0, 8.0, 10.0), lvl(3.0, 5.0, 9.0, 13.0), 7.0)
	cfg := {
		"bySecuritySeverity": {"critical": 1.0, "high": 3.0, "medium": 5.0, "low": 7.0, "none": 9.0},
		"byLevel": {"error": 2.0, "warning": 4.0, "note": 8.0, "none": 12.0},
		"fail_on_unreviewed_suppression": true,
	}

	# regal ignore:unresolved-reference
	not code_scan.allow with input as inp with data.code_scan_thresholds as cfg

	# regal ignore:unresolved-reference
	msgs := code_scan.violations with input as inp with data.code_scan_thresholds as cfg
	msgs == {
		"code-scan: 2 critical security-severity finding(s) exceed threshold of 1",
		"code-scan: 4 high security-severity finding(s) exceed threshold of 3",
		"code-scan: 6 medium security-severity finding(s) exceed threshold of 5",
		"code-scan: 8 low security-severity finding(s) exceed threshold of 7",
		"code-scan: 10 none security-severity finding(s) exceed threshold of 9",
		"code-scan: 3 error-level finding(s) exceed threshold of 2",
		"code-scan: 5 warning-level finding(s) exceed threshold of 4",
		"code-scan: 9 note-level finding(s) exceed threshold of 8",
		"code-scan: 13 none-level finding(s) exceed threshold of 12",
		"code-scan: 7 suppressed finding(s) present; suppressions are not permitted",
	}

	# regal ignore:unresolved-reference
	code_scan.allow with input as inp with data.code_scan_thresholds as _disabled_thresholds
}

test_decimal_scan_counts_at_threshold_allow if {
	payload := utils.has_envelope(cs_summary(sev(1.0, 1.0, 1.0, 1.0, 1.0), lvl(2.0, 1.0, 1.0, 1.0), 1.0)[0])

	# Preserve a decimal-form resultCount as well as all decimal summary counts.
	base := object.union(payload.predicate, {"resultCount": 6.0})
	embedded := object.union(base, {
		"findingsIncluded": true,
		"truncated": false,
		"results": [
			finding("r1", "error", "critical", "new", false, "src/a.js"),
			finding("r2", "error", "high", "new", false, "src/b.js"),
			finding("r3", "warning", "medium", "new", false, "src/c.js"),
			finding("r4", "note", "low", "new", false, "src/d.js"),
			finding("r5", "none", "none", "new", false, "src/e.js"),
			finding("r6", "error", "critical", "new", true, "src/f.js"),
		],
	})
	cfg := {
		"bySecuritySeverity": {"critical": 1.0, "high": 1.0, "medium": 1.0, "low": 1.0, "none": 1.0},
		"byLevel": {"error": 2.0, "warning": 1.0, "note": 1.0, "none": 1.0},
	}

	every predicate in [base, embedded] {
		inp := [_env(predicate)]

		# regal ignore:unresolved-reference
		code_scan.allow with input as inp with data.code_scan_thresholds as cfg

		# regal ignore:unresolved-reference
		msgs := code_scan.violations with input as inp with data.code_scan_thresholds as cfg
		msgs == set()
	}
}

test_recomputed_scan_counts_retain_filters_and_decimal_thresholds if {
	findings := [
		finding("r1", "error", "critical", "new", false, "src/a.js"),
		finding("r2", "error", "critical", "updated", false, "src/b.js"),
		finding("r3", "error", "critical", "new", true, "src/c.js"),
		finding("r4", "error", "critical", "unchanged", false, "src/d.js"),
		finding("r5", "error", "critical", "new", false, "test/a.js"),
	]
	cfg := {
		"bySecuritySeverity": {"critical": 1.0},
		"byLevel": {"error": 1.0},
		"gate_new_only": true,
		"ignore_paths": ["test/**"],
	}
	inp := cs_findings(findings)

	# regal ignore:unresolved-reference
	not code_scan.allow with input as inp with data.code_scan_thresholds as cfg

	# regal ignore:unresolved-reference
	msgs := code_scan.violations with input as inp with data.code_scan_thresholds as cfg
	msgs == {
		"code-scan: 2 critical security-severity finding(s) exceed threshold of 1",
		"code-scan: 2 error-level finding(s) exceed threshold of 1",
	}
}

# --- presence / inertness ---

test_inert_when_absent if {
	code_scan.allow with input as []
}

test_inert_for_other_predicate if {
	code_scan.allow with input as [_env_other]
}

_env_other := {"dsseEnvelope": {"payload": base64.encode(json.marshal({
	"predicateType": "https://example.org/other",
	"predicate": {},
}))}}

test_require_present_violation if {
	cfg := {"require_code_scan": true}
	msg := "code-scan attestation is missing"

	# regal ignore:unresolved-reference
	not code_scan.allow with input as [] with data.code_scan_thresholds as cfg

	# regal ignore:unresolved-reference
	msg in code_scan.violations with input as [] with data.code_scan_thresholds as cfg
}

# --- summary-mode gating (default config: critical=0, high=0, rest disabled) ---

test_clean_summary_passes if {
	code_scan.allow with input as cs_summary(sev(0, 0, 0, 0, 0), lvl(0, 0, 0, 0), 0)
}

test_critical_fails_default if {
	not code_scan.allow with input as cs_summary(sev(1, 0, 0, 0, 0), lvl(1, 0, 0, 0), 0)
}

test_high_fails_default if {
	not code_scan.allow with input as cs_summary(sev(0, 1, 0, 0, 0), lvl(0, 1, 0, 0), 0)
}

test_medium_low_none_pass_default if {
	code_scan.allow with input as cs_summary(sev(0, 0, 3, 5, 2), lvl(0, 0, 0, 0), 0)
}

test_error_level_gated_by_default if {
	not code_scan.allow with input as cs_summary(sev(0, 0, 0, 0, 0), lvl(1, 0, 0, 0), 0)
}

test_warning_note_none_levels_disabled_by_default if {
	code_scan.allow with input as cs_summary(sev(0, 0, 0, 0, 0), lvl(0, 9, 9, 9), 0)
}

# a fail finding with no numeric security-severity lands in (sev none, level
# error); the default error-level gate must still catch it.
test_error_level_no_severity_gated_by_default if {
	not code_scan.allow with input as cs_summary(sev(0, 0, 0, 0, 5), lvl(5, 0, 0, 0), 0)
}

# --- threshold overrides ---

test_critical_threshold_override_allows if {
	inp := cs_summary(sev(3, 0, 0, 0, 0), lvl(0, 0, 0, 0), 0)
	cfg := {"bySecuritySeverity": {"critical": 5}}

	# regal ignore:unresolved-reference
	code_scan.allow with input as inp with data.code_scan_thresholds as cfg
}

test_critical_threshold_override_exceeded if {
	inp := cs_summary(sev(6, 0, 0, 0, 0), lvl(0, 0, 0, 0), 0)
	cfg := {"bySecuritySeverity": {"critical": 5}}

	# regal ignore:unresolved-reference
	not code_scan.allow with input as inp with data.code_scan_thresholds as cfg
}

test_bylevel_override_gates_error if {
	inp := cs_summary(sev(0, 0, 0, 0, 0), lvl(2, 0, 0, 0), 0)
	cfg := {"byLevel": {"error": 0}}

	# regal ignore:unresolved-reference
	not code_scan.allow with input as inp with data.code_scan_thresholds as cfg
}

# --- incomplete scan ---

test_incomplete_scan_fails if {
	att := [_env({
		"tools": [{"name": "CodeQL"}],
		"summary": {"bySecuritySeverity": sev(0, 0, 0, 0, 0), "byLevel": lvl(0, 0, 0, 0), "suppressed": 0},
		"configuration": [],
		"invocation": {"executionSuccessful": false},
		"findingsIncluded": false,
		"truncated": true,
		"resultCount": 0,
	})]
	not code_scan.allow with input as att
}

# --- recompute-required without findings -> incompleteness violation ---

test_count_suppressed_without_findings_is_incomplete if {
	inp := cs_summary(sev(0, 0, 0, 0, 0), lvl(0, 0, 0, 0), 1)
	cfg := {"count_suppressed": true}

	# regal ignore:unresolved-reference
	not code_scan.allow with input as inp with data.code_scan_thresholds as cfg
}

# --- recompute mode over results[] ---

test_suppressed_excluded_by_default if {
	# the only critical is suppressed; default config excludes it
	f := [finding("r1", "error", "critical", "new", true, "src/a.js")]
	code_scan.allow with input as cs_findings(f)
}

test_count_suppressed_includes_suppressed if {
	f := [finding("r1", "error", "critical", "new", true, "src/a.js")]
	cfg := {"count_suppressed": true}

	# regal ignore:unresolved-reference
	not code_scan.allow with input as cs_findings(f) with data.code_scan_thresholds as cfg
}

test_ignore_paths_filters_finding if {
	f := [finding("r1", "error", "critical", "new", false, "test/a_test.js")]
	cfg := {"ignore_paths": ["test/**"]}

	# regal ignore:unresolved-reference
	code_scan.allow with input as cs_findings(f) with data.code_scan_thresholds as cfg
}

test_gate_new_only_skips_unchanged if {
	f := [finding("r1", "error", "critical", "unchanged", false, "src/a.js")]
	cfg := {"gate_new_only": true}

	# regal ignore:unresolved-reference
	code_scan.allow with input as cs_findings(f) with data.code_scan_thresholds as cfg
}

test_gate_new_only_catches_new if {
	f := [finding("r1", "error", "critical", "new", false, "src/a.js")]
	cfg := {"gate_new_only": true}

	# regal ignore:unresolved-reference
	not code_scan.allow with input as cs_findings(f) with data.code_scan_thresholds as cfg
}

# --- suppression policy ---

test_fail_on_unreviewed_suppression if {
	inp := cs_summary(sev(0, 0, 0, 0, 0), lvl(0, 0, 0, 0), 2)
	cfg := {"fail_on_unreviewed_suppression": true}

	# regal ignore:unresolved-reference
	not code_scan.allow with input as inp with data.code_scan_thresholds as cfg
}

test_suppressions_allowed_by_default if {
	code_scan.allow with input as cs_summary(sev(0, 0, 0, 0, 0), lvl(0, 0, 0, 0), 2)
}

# --- fail-closed on malformed / mistyped input ---

# a signed predicate missing the bySecuritySeverity object must not slip the gate
# via an undefined lookup.
test_malformed_missing_sev_bucket_fails_closed if {
	att := [_env({
		"tools": [{"name": "CodeQL"}],
		"summary": {"byLevel": lvl(10, 0, 0, 0), "suppressed": 0},
		"configuration": [],
		"invocation": {"executionSuccessful": true},
		"findingsIncluded": false,
		"truncated": true,
		"resultCount": 10,
	})]
	not code_scan.allow with input as att
}

# a missing invocation must read as incomplete (fail closed), not success.
test_malformed_missing_invocation_fails_closed if {
	att := [_env({
		"tools": [{"name": "CodeQL"}],
		"summary": {"bySecuritySeverity": sev(0, 0, 0, 0, 0), "byLevel": lvl(0, 0, 0, 0), "suppressed": 0},
		"configuration": [],
		"findingsIncluded": false,
		"truncated": true,
		"resultCount": 0,
	})]
	not code_scan.allow with input as att
}

# a quoted (string) threshold is rejected and the safe default is used.
test_string_threshold_fails_closed if {
	inp := cs_summary(sev(3, 0, 0, 0, 0), lvl(0, 0, 0, 0), 0)
	cfg := {"bySecuritySeverity": {"critical": "0"}}

	# regal ignore:unresolved-reference
	not code_scan.allow with input as inp with data.code_scan_thresholds as cfg
}

# the finding-level incompleteness guard fires regardless of fail_on_incomplete_scan.
test_count_suppressed_incomplete_even_when_foic_false if {
	inp := cs_summary(sev(0, 0, 0, 0, 0), lvl(0, 0, 0, 0), 3)
	cfg := {"count_suppressed": true, "fail_on_incomplete_scan": false}

	# regal ignore:unresolved-reference
	not code_scan.allow with input as inp with data.code_scan_thresholds as cfg
}

# --- config validation (provided-but-invalid overrides fail closed) ---

# a negative-but-not-(-1) threshold would silently disable the bucket -> rejected.
test_negative_threshold_fails_closed if {
	inp := cs_summary(sev(0, 0, 0, 0, 0), lvl(0, 0, 0, 0), 0)
	cfg := {"bySecuritySeverity": {"critical": -5}}

	# regal ignore:unresolved-reference
	not code_scan.allow with input as inp with data.code_scan_thresholds as cfg
}

# -1 (the documented "disabled" sentinel) is valid -> not a config error.
test_minus_one_threshold_is_valid if {
	inp := cs_summary(sev(3, 0, 0, 0, 0), lvl(0, 0, 0, 0), 0)
	cfg := {"bySecuritySeverity": {"critical": -1}}

	# regal ignore:unresolved-reference
	code_scan.allow with input as inp with data.code_scan_thresholds as cfg
}

# a fractional threshold is rejected.
test_fractional_threshold_fails_closed if {
	inp := cs_summary(sev(0, 0, 0, 0, 0), lvl(0, 0, 0, 0), 0)
	cfg := {"byLevel": {"error": 1.5}}

	# regal ignore:unresolved-reference
	not code_scan.allow with input as inp with data.code_scan_thresholds as cfg
}

# a wrong-typed boolean flag is a config error -> fail closed (the require_code_scan
# typo would otherwise silently revert to the looser default false).
test_bool_flag_typo_fails_closed if {
	inp := cs_summary(sev(0, 0, 0, 0, 0), lvl(0, 0, 0, 0), 0)
	cfg := {"require_code_scan": "true"}

	# regal ignore:unresolved-reference
	not code_scan.allow with input as inp with data.code_scan_thresholds as cfg
}

# ignore_paths must be an array of strings.
test_ignore_paths_wrong_type_fails_closed if {
	inp := cs_summary(sev(0, 0, 0, 0, 0), lvl(0, 0, 0, 0), 0)
	cfg := {"ignore_paths": "test/**"}

	# regal ignore:unresolved-reference
	not code_scan.allow with input as inp with data.code_scan_thresholds as cfg
}

# a wrong-typed bucket object is a config error.
test_bysev_not_object_fails_closed if {
	inp := cs_summary(sev(0, 0, 0, 0, 0), lvl(0, 0, 0, 0), 0)
	cfg := {"bySecuritySeverity": "nope"}

	# regal ignore:unresolved-reference
	not code_scan.allow with input as inp with data.code_scan_thresholds as cfg
}

# M2: an unknown/misspelled top-level key fails closed (would otherwise be
# silently ignored, keeping the looser default instead of the operator's intent).
test_unknown_config_key_fails_closed if {
	inp := cs_summary(sev(0, 0, 0, 0, 0), lvl(0, 0, 0, 0), 0)
	cfg := {"require_code_scn": true}

	# regal ignore:unresolved-reference
	not code_scan.allow with input as inp with data.code_scan_thresholds as cfg
}

# M2: an unknown/misspelled bucket key fails closed (a typo'd `medum`/`critcal`
# would otherwise leave that bucket at its default, silently un-gating).
test_unknown_bucket_key_fails_closed if {
	inp := cs_summary(sev(0, 0, 0, 0, 0), lvl(0, 0, 0, 0), 0)
	cfg := {"bySecuritySeverity": {"critcal": 0}}

	# regal ignore:unresolved-reference
	not code_scan.allow with input as inp with data.code_scan_thresholds as cfg
}
