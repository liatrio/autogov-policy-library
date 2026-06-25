# METADATA
# scope: package
# title: Test Result Policy
# description: Gates in-toto test-result attestations against a configurable failed-test threshold.
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
# custom:
#  version: 0.20.0
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
# regal ignore:unresolved-reference
_max_failed := data.max_failed_tests

default max_failed_tests := 0

max_failed_tests := _max_failed if {
	_max_failed != null
}

# Whether a test-result attestation must be present. Defaults to false so the
# policy is inert for artifacts without tests. Override via --policy-data-path
# with JSON: {"require_test_results": true}.
# regal ignore:unresolved-reference
_require := data.require_test_results

default require_test_results := false

require_test_results := _require if {
	_require != null
}

result_present if {
	some payload in utils.decoded_payload_list
	utils.is_test_result(payload)
}

# Violation: a present test-result attestation reports more failed tests than tolerated.
violations contains msg if {
	some payload in utils.decoded_payload_list
	utils.is_test_result(payload)
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
