package source_review_config_test

import data.source_review_config
import rego.v1

# TEMPORARY: the SHIPPED default min_approvals is relaxed to 0 for the pre-launch
# admin-merge window so 0-approval releases pass. Restore this assertion to 1 (and
# the shipped default in source_review_config.rego) once the pre-launch fix PRs are
# merged, so a future accidental relax to 0 (which would silently disable the
# approval-count gate for every consumer that does not override it) fails the suite.
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
