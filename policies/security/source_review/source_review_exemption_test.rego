package security.source_review_test

import data.security.source_review
import rego.v1

_exemption_config := {"min_approvals": 0, "zero_approval_merger_allowlist": [138915]}

_exemption_predicate := {
	"sourceRepository": "https://github.com/liatrio/autogov",
	"sourceRevision": "abc123",
	"pullRequest": {"number": 1, "mergedAt": "2026-06-15T00:00:00Z", "mergedById": 42},
	"summary": _summary(1, 0),
	"approversIncluded": true,
	"approvers": [_ok],
	"configuration": [],
	"reviewToolingComplete": true,
}

_unlisted_merger_msg := "source-review: merger 42 is not on the zero-approval-merger allowlist"

test_reviewed_exemption_rejects_invalid_merged_pr_fields if {
	invalid_fields := array.concat(
		[{"number": n} | some n in [0, -1, 1.5, "1", null, true]],
		[{"mergedAt": t} | some t in ["", "not-a-date", 1, null, true]],
	)
	every fields in invalid_fields {
		pr := object.union(_exemption_predicate.pullRequest, fields)
		inp := [_env(object.union(_exemption_predicate, {"pullRequest": pr}))]

		# regal ignore:unresolved-reference
		not source_review.allow with input as inp with data.source_review_thresholds as _exemption_config

		# regal ignore:unresolved-reference
		violations := source_review.violations with input as inp with data.source_review_thresholds as _exemption_config
		_unlisted_merger_msg in violations
	}
}

test_reviewed_exemption_requires_summary_and_reviewer_support if {
	cases := [
		{"summary": _summary(1, 0), "approvers": []},
		{"summary": _summary(1, 0), "approvers": [_stale]},
		{"summary": _summary(1, 0), "approvers": [_bot]},
		{"summary": _summary(1, 0), "approvers": [_stale, _bot]},
		{"summary": _summary(0, 0), "approvers": [_ok]},
	]
	every fields in cases {
		inp := [_env(object.union(_exemption_predicate, fields))]

		# regal ignore:unresolved-reference
		not source_review.allow with input as inp with data.source_review_thresholds as _exemption_config

		# regal ignore:unresolved-reference
		violations := source_review.violations with input as inp with data.source_review_thresholds as _exemption_config
		_unlisted_merger_msg in violations
	}
}

test_reviewed_exemption_summary_only_requires_explicit_filter_opt_out if {
	pred := object.union(object.remove(_exemption_predicate, {"approvers"}), {"approversIncluded": false})
	inp := [_env(pred)]

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as _exemption_config

	cfg := object.union(_exemption_config, _summary_config)

	# regal ignore:unresolved-reference
	source_review.allow with input as inp with data.source_review_thresholds as cfg
}

test_reviewed_exemption_preserves_changes_requested_gate if {
	inp := [_env(object.union(_exemption_predicate, {"summary": _summary(1, 1)}))]

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as _exemption_config

	# Prove the denial comes from the standing review request, not the merger gate.
	# regal ignore:unresolved-reference
	violations := source_review.violations with input as inp with data.source_review_thresholds as _exemption_config
	count(violations) > 0
	not _unlisted_merger_msg in violations
	cfg := object.union(_exemption_config, {"block_on_changes_requested": false})

	# regal ignore:unresolved-reference
	source_review.allow with input as inp with data.source_review_thresholds as cfg
}

test_reviewed_exemption_preserves_codeowner_gate if {
	inp := [_env(_exemption_predicate)]
	cfg := object.union(_exemption_config, {"require_codeowner_review": true})

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg

	# regal ignore:unresolved-reference
	source_review.allow with input as inp with data.source_review_thresholds as _exemption_config
}
