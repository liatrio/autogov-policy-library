package security.source_review_test

import data.security.source_review
import rego.v1

# --- zero_approval_merger_allowlist gate ---

# like sr_merged but also carries pullRequest.mergedById, for the
# zero-approval-merger allowlist tests.
sr_merged_by(approvers, changes, merged_by_id) := sr_merged_by_with_status(approvers, changes, merged_by_id, true)

sr_merged_by_with_status(approvers, changes, merged_by_id, review_complete) := [_env({
	"sourceRepository": "https://github.com/liatrio/autogov",
	"sourceRevision": "abc123",
	"pullRequest": {"number": 1, "mergedAt": "2026-06-15T00:00:00Z", "mergedById": merged_by_id},
	"summary": _summary(_strict(approvers), changes),
	"approversIncluded": true,
	"approvers": approvers,
	"configuration": [],
	"reviewToolingComplete": review_complete,
})]

# realistic producer-fetch-failure shape: pullRequest present (mergedAt/number)
# but mergedById key entirely absent -- distinct from "no pullRequest at all".
sr_merged_no_merged_by_key(approvers, changes) := [_env({
	"sourceRepository": "https://github.com/liatrio/autogov",
	"sourceRevision": "abc123",
	"pullRequest": {"number": 1, "mergedAt": "2026-06-15T00:00:00Z"},
	"summary": _summary(_strict(approvers), changes),
	"approversIncluded": true,
	"approvers": approvers,
	"configuration": [],
	"reviewToolingComplete": true,
})]

# inert by default: an empty (unset) allowlist never fires, regardless of
# mergedById.
test_zero_approval_merger_inert_by_default if {
	inp := sr_merged_by([], 0, 999)
	cfg := {"min_approvals": 0}

	# regal ignore:unresolved-reference
	source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# allowlisted merger: mergedById present and listed -> no violation.
test_zero_approval_merger_allowlisted_passes if {
	inp := sr_merged_by([], 0, 138915)
	cfg := {"min_approvals": 0, "zero_approval_merger_allowlist": [138915]}

	# regal ignore:unresolved-reference
	source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# non-allowlisted merger: mergedById present but not listed -> deny, fail closed.
test_zero_approval_merger_not_listed_fails_closed if {
	inp := sr_merged_by([], 0, 42)
	cfg := {"min_approvals": 0, "zero_approval_merger_allowlist": [138915]}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg

	msg := "source-review: merger 42 is not on the zero-approval-merger allowlist"

	# regal ignore:unresolved-reference
	msg in source_review.violations with input as inp with data.source_review_thresholds as cfg
}

test_zero_approval_merger_reviewed_non_allowlisted_passes if {
	inp := sr_merged_by([_ok], 0, 42)
	cfg := {"min_approvals": 0, "zero_approval_merger_allowlist": [138915]}

	# regal ignore:unresolved-reference
	source_review.allow with input as inp with data.source_review_thresholds as cfg
}

test_zero_approval_merger_reviewed_empty_pull_request_still_requires_allowlist if {
	inp := [_env({
		"sourceRepository": "https://github.com/liatrio/autogov",
		"sourceRevision": "abc123",
		"pullRequest": {},
		"summary": _summary(1, 0),
		"approversIncluded": true,
		"approvers": [_ok],
		"configuration": [],
		"reviewToolingComplete": true,
	})]
	cfg := {"min_approvals": 0, "zero_approval_merger_allowlist": [138915]}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg

	msg := "source-review: merger identity is absent (mergedById missing) and not on the zero-approval-merger allowlist"

	# regal ignore:unresolved-reference
	msg in source_review.violations with input as inp with data.source_review_thresholds as cfg
}

test_zero_approval_merger_reviewed_missing_pull_request_number_still_requires_allowlist if {
	inp := [_env({
		"sourceRepository": "https://github.com/liatrio/autogov",
		"sourceRevision": "abc123",
		"pullRequest": {"mergedAt": "2026-06-15T00:00:00Z"},
		"summary": _summary(1, 0),
		"approversIncluded": true,
		"approvers": [_ok],
		"configuration": [],
		"reviewToolingComplete": true,
	})]
	cfg := {"min_approvals": 0, "zero_approval_merger_allowlist": [138915]}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg

	msg := "source-review: merger identity is absent (mergedById missing) and not on the zero-approval-merger allowlist"

	# regal ignore:unresolved-reference
	msg in source_review.violations with input as inp with data.source_review_thresholds as cfg
}

test_zero_approval_merger_reviewed_missing_pull_request_merged_at_still_requires_allowlist if {
	inp := [_env({
		"sourceRepository": "https://github.com/liatrio/autogov",
		"sourceRevision": "abc123",
		"pullRequest": {"number": 1},
		"summary": _summary(1, 0),
		"approversIncluded": true,
		"approvers": [_ok],
		"configuration": [],
		"reviewToolingComplete": true,
	})]
	cfg := {"min_approvals": 0, "zero_approval_merger_allowlist": [138915]}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg

	msg := "source-review: merger identity is absent (mergedById missing) and not on the zero-approval-merger allowlist"

	# regal ignore:unresolved-reference
	msg in source_review.violations with input as inp with data.source_review_thresholds as cfg
}

test_zero_approval_merger_reviewed_missing_identity_passes if {
	inp := sr_merged_no_merged_by_key([_ok], 0)
	cfg := {"min_approvals": 0, "zero_approval_merger_allowlist": [138915]}

	# regal ignore:unresolved-reference
	source_review.allow with input as inp with data.source_review_thresholds as cfg
}

test_zero_approval_merger_reviewed_without_pull_request_fails_closed if {
	inp := sr_approvers([_ok], 0, true)
	cfg := {"min_approvals": 0, "zero_approval_merger_allowlist": [138915]}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg

	msg := "source-review: merger identity is absent (mergedById missing) and not on the zero-approval-merger allowlist"

	# regal ignore:unresolved-reference
	msg in source_review.violations with input as inp with data.source_review_thresholds as cfg
}

test_zero_approval_merger_incomplete_review_still_requires_allowlisted_merger if {
	inp := sr_merged_by_with_status([_ok], 0, 42, false)
	cfg := {"min_approvals": 0, "zero_approval_merger_allowlist": [138915]}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg

	msg := "source-review: merger 42 is not on the zero-approval-merger allowlist"

	# regal ignore:unresolved-reference
	msg in source_review.violations with input as inp with data.source_review_thresholds as cfg
}

test_zero_approval_merger_unqualified_reviews_still_require_allowlisted_merger if {
	cfg := {"min_approvals": 0, "zero_approval_merger_allowlist": [138915]}
	msg := "source-review: merger 42 is not on the zero-approval-merger allowlist"

	every approvers in [[_stale], [_bot], [_stale, _bot]] {
		inp := sr_merged_by(approvers, 0, 42)

		# regal ignore:unresolved-reference
		not source_review.allow with input as inp with data.source_review_thresholds as cfg

		# regal ignore:unresolved-reference
		msg in source_review.violations with input as inp with data.source_review_thresholds as cfg
	}
}

test_zero_approval_merger_reviewed_path_preserves_association_gate if {
	inp := sr_merged_by([_assoc_approver("alice", "CONTRIBUTOR")], 0, 42)
	cfg := {
		"min_approvals": 0,
		"required_approver_associations": ["OWNER"],
		"zero_approval_merger_allowlist": [138915],
	}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg

	msg := "source-review: no approver association in the required allowlist"

	# regal ignore:unresolved-reference
	msg in source_review.violations with input as inp with data.source_review_thresholds as cfg
}

# absent merger identity (no pullRequest object at all): fail closed.
test_zero_approval_merger_absent_no_pull_request_fails_closed if {
	inp := sr_approvers([], 0, true)
	cfg := {"min_approvals": 0, "zero_approval_merger_allowlist": [138915]}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg

	msg := "source-review: merger identity is absent (mergedById missing) and not on the zero-approval-merger allowlist"

	# regal ignore:unresolved-reference
	msg in source_review.violations with input as inp with data.source_review_thresholds as cfg
}

# realistic fetch-failure shape: pullRequest present (mergedAt/number) but
# mergedById key entirely absent -- exercised at the violation/message layer, not
# only via structurally_valid.
test_zero_approval_merger_missing_merged_by_key_fails_closed if {
	inp := sr_merged_no_merged_by_key([], 0)
	cfg := {"min_approvals": 0, "zero_approval_merger_allowlist": [138915]}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg

	msg := "source-review: merger identity is absent (mergedById missing) and not on the zero-approval-merger allowlist"

	# regal ignore:unresolved-reference
	msg in source_review.violations with input as inp with data.source_review_thresholds as cfg
}

# non-zero min_approvals: this violation never fires, even with a populated
# allowlist and a not-listed merger -- distinct from the general
# min-approvals-unmet violation, which is unaffected.
test_zero_approval_merger_never_fires_when_min_approvals_nonzero if {
	inp := sr_merged_by([_ok], 0, 42)
	cfg := {"min_approvals": 1, "zero_approval_merger_allowlist": [138915]}

	# regal ignore:unresolved-reference
	source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# a forged non-numeric mergedById (e.g. a string) produces a clean, non-garbled
# message -- never a Go/OPA "%!d(string=...)" format artifact. (The malformed-
# predicate violation also fires independently via structurally_valid; both are
# expected to be present.)
test_zero_approval_merger_non_numeric_produces_clean_message if {
	bad := [_env({
		"sourceRepository": "https://github.com/liatrio/autogov",
		"sourceRevision": "abc123",
		"pullRequest": {"number": 1, "mergedAt": "2026-06-15T00:00:00Z", "mergedById": "138915"},
		"summary": _summary(1, 0),
		"approversIncluded": true,
		"approvers": [_ok],
		"configuration": [],
		"reviewToolingComplete": true,
	})]
	cfg := {"min_approvals": 0, "zero_approval_merger_allowlist": [138915]}

	# regal ignore:unresolved-reference
	not source_review.allow with input as bad with data.source_review_thresholds as cfg

	# regal ignore:unresolved-reference
	msgs := source_review.violations with input as bad with data.source_review_thresholds as cfg

	clean_msg := "source-review: mergedById is not numeric (\"138915\"), not on the zero-approval-merger allowlist"
	clean_msg in msgs

	every m in msgs {
		not contains(m, "%!d")
	}
}
