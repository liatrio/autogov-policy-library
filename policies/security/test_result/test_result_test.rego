package security.test_result_test

import data.security.test_result
import rego.v1

# build an input list containing one in-toto test-result attestation with the
# given failed-test identifiers.
tr_input(failed) := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
	"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
	"predicate": {
		"result": "FAILED",
		"passedTests": ["ok1", "ok2"],
		"warnedTests": [],
		"failedTests": failed,
	},
}))}}]

test_passes_when_no_failures if {
	test_result.allow with input as tr_input([])
}

test_fails_on_default_zero_tolerance if {
	inp := tr_input(["pkg.TestA"])
	not test_result.allow with input as inp
	"test-result reports 1 failed test(s), exceeds threshold of 0" in test_result.violations with input as inp
}

test_threshold_override_allows if {
	# regal ignore:unresolved-reference
	test_result.allow with input as tr_input(["t1", "t2"]) with data.max_failed_tests as 3
}

test_threshold_override_exceeded if {
	# regal ignore:unresolved-reference
	not test_result.allow with input as tr_input(["t1", "t2", "t3", "t4"]) with data.max_failed_tests as 3
}

# A missing test-result attestation is inert by default.
test_missing_not_required_passes if {
	test_result.allow with input as []
}

# ...but can be required via data.
test_missing_required_violation if {
	# regal ignore:unresolved-reference
	not test_result.allow with input as [] with data.require_test_results as true

	# regal ignore:unresolved-reference
	"test-result attestation is missing" in test_result.violations with input as [] with data.require_test_results as true
}

# --- config-validation + structural (fail-closed) tests ---

# a quoted "0" threshold with a failing-test attestation -> deny (it would
# otherwise slip the count gate: OPA orders a number below a string, so 1 > "0"
# is false). NO unknown-key test here: test_result reads two independent top-level
# data keys, so there is no enclosing object to detect a typo against (AC2).
test_quoted_max_failed_fails_closed if {
	# regal ignore:unresolved-reference
	not test_result.allow with input as tr_input(["pkg.TestA"]) with data.max_failed_tests as "0"
}

# out-of-range (-1) or fractional (1.5) max_failed_tests -> deny.
test_out_of_range_max_failed_fails_closed if {
	# regal ignore:unresolved-reference
	not test_result.allow with input as tr_input(["pkg.TestA"]) with data.max_failed_tests as -1

	# regal ignore:unresolved-reference
	not test_result.allow with input as tr_input(["pkg.TestA"]) with data.max_failed_tests as 1.5
}

# a quoted require_test_results flag is a config error -> deny.
test_quoted_require_flag_fails_closed if {
	# regal ignore:unresolved-reference
	not test_result.allow with input as tr_input([]) with data.require_test_results as "true"
}

# a present test-result predicate whose failedTests is not an array -> deny
# (count() over a non-array would otherwise error or miscount).
test_malformed_test_predicate_fails_closed if {
	bad := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
		"predicate": {
			"result": "FAILED",
			"failedTests": "pkg.TestA",
		},
	}))}}]
	not test_result.allow with input as bad

	"test-result predicate is malformed (failedTests is not an array)" in test_result.violations with input as bad
}

test_non_array_failed_tests_have_only_malformed_diagnostic if {
	every value in ["pkg.TestA", 1, -1, 0.5, null, true, false, {}, {"test": "pkg.TestA"}] {
		inp := tr_input(value)
		not test_result.allow with input as inp
		msgs := test_result.violations with input as inp
		msgs == {"test-result predicate is malformed (failedTests is not an array)"}
	}
}

test_missing_failed_tests_have_only_malformed_diagnostic if {
	inp := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
		"predicate": {"result": "FAILED"},
	}))}}]
	not test_result.allow with input as inp
	msgs := test_result.violations with input as inp
	msgs == {"test-result predicate is malformed (failedTests is not an array)"}
}

test_invalid_max_overrides_preserve_config_and_count_diagnostics if {
	inp := tr_input(["pkg.TestA"])
	every value in ["0", -1, 0.5, true, false, [], {}] {
		# regal ignore:unresolved-reference
		not test_result.allow with input as inp with data.max_failed_tests as value

		# regal ignore:unresolved-reference
		msgs := test_result.violations with input as inp with data.max_failed_tests as value
		msgs == {
			"test-result configuration is invalid: max_failed_tests must be a non-negative integer",
			"test-result reports 1 failed test(s), exceeds threshold of 0",
		}
	}
}

test_decimal_max_override_formats_cleanly if {
	inp := tr_input(["t1", "t2", "t3"])

	# regal ignore:unresolved-reference
	not test_result.allow with input as inp with data.max_failed_tests as 2.0

	# regal ignore:unresolved-reference
	msgs := test_result.violations with input as inp with data.max_failed_tests as 2.0
	msgs == {"test-result reports 3 failed test(s), exceeds threshold of 2"}

	# regal ignore:unresolved-reference
	test_result.allow with input as tr_input(["t1", "t2"]) with data.max_failed_tests as 2.0

	# regal ignore:unresolved-reference
	test_result.allow with input as tr_input([]) with data.max_failed_tests as 0.0
}

test_null_overrides_preserve_defaults if {
	# regal ignore:unresolved-reference
	test_result.allow with input as tr_input([]) with data.max_failed_tests as null with data.require_test_results as null

	# regal ignore:unresolved-reference
	test_result.allow with input as [] with data.max_failed_tests as null with data.require_test_results as null

	inp := tr_input(["t1"])

	# regal ignore:unresolved-reference
	msgs := test_result.violations with input as inp with data.max_failed_tests as null
	msgs == {"test-result reports 1 failed test(s), exceeds threshold of 0"}
}

# a numeric, in-range override still allows (regression: no config error fires).
test_valid_overrides_still_allow if {
	# regal ignore:unresolved-reference
	test_result.allow with input as tr_input(["t1", "t2"]) with data.max_failed_tests as 3
}
