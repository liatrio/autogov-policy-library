package security.source_review_test

import data.security.source_review
import rego.v1

# --- historical pass-2 bypass: full-stack regression lock ---

# regression: pass-2's validator accepted 0 into zero_approval_merger_allowlist,
# colliding with this policy's absent-merger sentinel (object.get(..., 0)) -- a
# populated allowlist containing 0 silently matched every unrecorded merger,
# defeating the gate. Proven at the full policy-API level (allow/violations): a
# min_approvals:0 payload with NO merger recorded at all, under
# zero_approval_merger_allowlist:[0], must still deny.
test_zero_approval_merger_allowlist_zero_regression_full_stack_denies if {
	inp := sr_approvers([], 0, true)
	cfg := {"min_approvals": 0, "zero_approval_merger_allowlist": [0]}
	msg := "source-review configuration is invalid: zero_approval_merger_allowlist must be an array of positive integers"

	# regal ignore:unresolved-reference
	msg in source_review.violations with input as inp with data.source_review_thresholds as cfg
}

# regression: unlike the sibling distinct-approval-count violation, this one is
# NOT grandfathered by enforced_since. mergedAt here predates a cutoff that would
# satisfy _grandfathered's own condition -- yet the violation fires identically
# with or without that cutoff configured.
test_zero_approval_merger_not_grandfathered_by_enforced_since if {
	inp := [_env({
		"sourceRepository": "https://github.com/liatrio/autogov",
		"sourceRevision": "abc123",
		"pullRequest": {"number": 1, "mergedAt": "2026-05-01T00:00:00Z"},
		"summary": _summary(0, 0),
		"approversIncluded": true,
		"approvers": [],
		"configuration": [],
		"reviewToolingComplete": true,
	})]
	msg := "source-review: merger identity is absent (mergedById missing) and not on the zero-approval-merger allowlist"
	cfg_no_cutoff := {"min_approvals": 0, "zero_approval_merger_allowlist": [138915]}

	# regal ignore:unresolved-reference
	msg in source_review.violations with input as inp with data.source_review_thresholds as cfg_no_cutoff

	# enforced_since set after mergedAt: fires identically -- no grandfathering.
	cfg_with_cutoff := {
		"min_approvals": 0,
		"enforced_since": "2026-06-01T00:00:00Z",
		"zero_approval_merger_allowlist": [138915],
	}

	# regal ignore:unresolved-reference
	msg in source_review.violations with input as inp with data.source_review_thresholds as cfg_with_cutoff
}
