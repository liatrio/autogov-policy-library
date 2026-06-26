package source_review_config_test

import data.source_review_config
import rego.v1

# regression: the SHIPPED default min_approvals is temporarily 0 for the pre-launch
# admin-merge window so 0-approval releases pass; this test locks the relaxed
# default so an accidental flip back to 1 (which would re-break consumers that do
# not override it) fails the suite. The post-launch flip-back to 1 lands as a
# releasable fix that also restores this guard to == 1.
test_shipped_default_min_approvals_is_zero if {
	source_review_config.min_approvals == 0
}

# a valid override still resolves (the default-assertion above does not pin the
# value when an operator explicitly configures it).
test_min_approvals_override_resolves if {
	# regal ignore:unresolved-reference
	n := source_review_config.min_approvals with data.source_review_thresholds as {"min_approvals": 2}
	n == 2
}
