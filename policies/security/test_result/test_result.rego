# METADATA
# scope: package
# title: Test Result Policy
# description: Gates in-toto test-result attestations against a configurable failed-test threshold.
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
# custom:
#  version: 1.0.3
#  path: policies/security/test_result
#  filename: test_result.rego
package security.test_result

import data.shared.utils
import rego.v1

default allow := false

allow if {
	count(violations) == 0
}

# Maximum number of failed tests tolerated. Defaults to 0 (zero tolerance).
# Override at runtime via --policy-data-path with JSON: {"max_failed_tests": N}.
# An invalid override (quoted "0", negative, or fractional) falls back to the
# default AND is surfaced in config_errors, so the gate denies on the config error
# rather than running with the silently-reverted default. Mirrors
# source_review_config / bypass_config.
# regal ignore:unresolved-reference
_max_failed := data.max_failed_tests

default max_failed_tests := 0

max_failed_tests := _max_failed if {
	_valid_max(_max_failed)
}

# Whether a test-result attestation must be present. Defaults to false so the
# policy is inert for artifacts without tests. Override via --policy-data-path
# with JSON: {"require_test_results": true}. A non-boolean override (e.g. "true")
# falls back to the default and is surfaced in config_errors.
# regal ignore:unresolved-reference
_require := data.require_test_results

default require_test_results := false

require_test_results := _require if {
	is_boolean(_require)
}

result_present if {
	some payload in utils.decoded_payload_list
	utils.is_test_result(payload)
}

# --- config validation (provided-but-invalid overrides fail closed) ---

# _valid_max is true for a non-negative integer. Rejects strings (quoted "0"),
# fractions, and negatives — these would otherwise slip the count gate (OPA orders
# a number below a string, so failed > "0" is false).
_valid_max(v) if {
	is_number(v)
	v >= 0
	v == floor(v)
}

# config_errors reports each PROVIDED test-result override that has the wrong type
# or is out of range. The gate denies when this is non-empty, so a config typo
# fails CLOSED instead of silently reverting to the looser default. Unlike the
# namespaced vuln_thresholds object, test config is TWO independent top-level data
# keys, so there is no enclosing object to enumerate for unknown-key detection
# (it would false-positive on every other gate's config keys in the same
# --policy-data-path document); only type/range validation of the two known keys
# is in scope. Each rule guards on != null so an absent key never emits an error
# (inert).
config_errors contains "max_failed_tests must be a non-negative integer" if {
	_max_failed != null
	not _valid_max(_max_failed)
}

config_errors contains "require_test_results must be a boolean" if {
	_require != null
	not is_boolean(_require)
}

# structurally_valid is true only when the predicate carries the field the gate
# reads, with the right type. The gate consumes a signed-but-otherwise-untrusted
# predicate and is NOT re-validated against the schema at eval time. count() over
# a non-array failedTests errors (a number) or miscounts (a string counts chars),
# so the gate fires a violation when this is false — a malformed predicate fails
# CLOSED rather than erroring or slipping the count rule.
structurally_valid(payload) if {
	is_array(payload.predicate.failedTests)
}

# Violation: the policy configuration itself is malformed (a provided override has
# the wrong type or is out of range). Fails CLOSED so a config typo cannot
# silently revert the gate to a looser default.
violations contains msg if {
	some err in config_errors
	msg := sprintf("test-result configuration is invalid: %s", [err])
}

# Violation: a present test-result predicate is malformed (failedTests is not an
# array). Guards the count rule below — count() over a non-array would otherwise
# error or miscount, so this denies instead.
violations contains msg if {
	msg := "test-result predicate is malformed (failedTests is not an array)"
	some payload in utils.decoded_payload_list
	utils.is_test_result(payload)
	not structurally_valid(payload)
}

# Violation: a present, structurally-valid test-result attestation reports more
# failed tests than tolerated.
violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_test_result(payload)
	structurally_valid(payload)
	failed := count(payload.predicate.failedTests)
	failed > max_failed_tests
	msg := sprintf("test-result reports %d failed test(s), exceeds threshold of %d", [failed, max_failed_tests])
}

# Violation: presence is required but no test-result attestation is present.
violations contains msg if {
	require_test_results
	not result_present
	msg := "test-result attestation is missing"
}
