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
