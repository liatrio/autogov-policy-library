package source_review_config_test

import data.source_review_config
import rego.v1

# regression: the SHIPPED default min_approvals must be 1, not 0. The pre-launch
# admin-merge window temporarily relaxed this to 0 so 0-approval releases passed;
# this test locks the restored default so a future accidental relax back to 0
# (which would silently disable the approval-count gate for every consumer that
# does not override it) fails the suite.
test_shipped_default_min_approvals_is_one if {
	source_review_config.min_approvals == 1
}

# a valid override still resolves (the default-assertion above does not pin the
# value when an operator explicitly configures it).
test_min_approvals_override_resolves if {
	# regal ignore:unresolved-reference
	n := source_review_config.min_approvals with data.source_review_thresholds as {"min_approvals": 2}
	n == 2
}

# --- zero_approval_merger_allowlist ---

# inert default: an empty/unset allowlist resolves to the empty set.
test_zero_approval_merger_allowlist_default_empty if {
	count(source_review_config.zero_approval_merger_allowlist) == 0
}

# a valid populated allowlist resolves to the expected set.
test_zero_approval_merger_allowlist_override_resolves if {
	cfg := {"zero_approval_merger_allowlist": [138915, 42]}

	# regal ignore:unresolved-reference
	s := source_review_config.zero_approval_merger_allowlist with data.source_review_thresholds as cfg
	s == {138915, 42}
}

# regression lock: 0 must NEVER be accepted into the allowlist. 0 is this same
# feature's own sentinel for "mergedById absent/unfetchable" (source_review.rego)
# -- a populated allowlist containing 0 would silently match every absent-merger
# payload, defeating the gate entirely. This was a confirmed, reproducible bypass
# during review; _valid_int_array must require e > 0, not e >= 0.
test_zero_approval_merger_allowlist_rejects_zero if {
	cfg := {"zero_approval_merger_allowlist": [0]}

	# regal ignore:unresolved-reference
	errs := source_review_config.config_errors with data.source_review_thresholds as cfg
	msg := "zero_approval_merger_allowlist must be an array of positive integers"
	msg in errs
}

# a negative integer entry is rejected the same way.
test_zero_approval_merger_allowlist_rejects_negative if {
	cfg := {"zero_approval_merger_allowlist": [-1]}

	# regal ignore:unresolved-reference
	errs := source_review_config.config_errors with data.source_review_thresholds as cfg
	msg := "zero_approval_merger_allowlist must be an array of positive integers"
	msg in errs
}

# a fractional (float) entry is rejected the same way.
test_zero_approval_merger_allowlist_rejects_float if {
	cfg := {"zero_approval_merger_allowlist": [1.5]}

	# regal ignore:unresolved-reference
	errs := source_review_config.config_errors with data.source_review_thresholds as cfg
	msg := "zero_approval_merger_allowlist must be an array of positive integers"
	msg in errs
}
