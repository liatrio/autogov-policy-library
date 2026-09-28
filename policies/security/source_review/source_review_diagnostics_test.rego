package security.source_review_test

import data.security.source_review
import rego.v1

# a forged non-numeric changesRequested (e.g. a string) produces a clean,
# non-garbled message -- never a Go/OPA "%!d(string=...)" format artifact.
# _changes_requested_present fails closed on ANY non-numeric type by design (not
# by Rego ordering accident -- see its own doc comment), so the forged string
# still satisfies it and the violation fires; only the message differs. (The
# malformed-predicate violation also fires independently via structurally_valid;
# both are expected to be present.)
test_changes_requested_non_numeric_produces_clean_message if {
	bad := [_env({
		"sourceRepository": "https://github.com/liatrio/autogov",
		"sourceRevision": "abc123",
		"summary": {
			"approvals": 1,
			"distinctApprovers": 1,
			"changesRequested": "bad",
			"requiredApprovals": 0,
			"requirementMet": true,
			"selfApprovalExcluded": false,
			"codeownerReviewMet": null,
		},
		"approversIncluded": true,
		"approvers": [_ok],
		"configuration": [],
		"reviewToolingComplete": true,
	})]

	# regal ignore:unresolved-reference
	not source_review.allow with input as bad

	# regal ignore:unresolved-reference
	msgs := source_review.violations with input as bad

	clean_msg := "source-review: changesRequested is not numeric (\"bad\"), treating as an outstanding review"
	clean_msg in msgs

	every m in msgs {
		not contains(m, "%!d")
	}
}

# regression: this violation's own protection against a forged non-numeric
# distinctApprovers must not be an accident of comparison ordering. Before this
# fix, Rego's total value ordering (strings rank above numbers) made a bare
# `n < min_approvals` comparison always false for a forged string, so THIS RULE
# never fired for such input -- it relied entirely on the separate
# malformed-predicate violation (structurally_valid) to deny overall `allow`.
# _insufficient_approvals now fails closed on ANY non-numeric type by design
# (not by ordering accident), closing that gap for good. Exercised via the
# summary-only (approversIncluded:false) path, where effective_distinct returns
# the raw forged value directly. (The malformed-predicate violation also fires
# independently via structurally_valid; both are expected to be present.)
test_distinct_approvals_non_numeric_fails_closed if {
	bad := [_env({
		"sourceRepository": "https://github.com/liatrio/autogov",
		"sourceRevision": "abc123",
		"summary": {
			"approvals": 0,
			"distinctApprovers": "bad",
			"changesRequested": 0,
			"requiredApprovals": 0,
			"requirementMet": true,
			"selfApprovalExcluded": false,
			"codeownerReviewMet": null,
		},
		"approversIncluded": false,
		"configuration": [],
		"reviewToolingComplete": true,
	})]
	cfg := {"min_approvals": 1}

	# regal ignore:unresolved-reference
	not source_review.allow with input as bad with data.source_review_thresholds as cfg

	# regal ignore:unresolved-reference
	msgs := source_review.violations with input as bad with data.source_review_thresholds as cfg

	clean_msg := "source-review: distinct approval count is not numeric (\"bad\"), need at least 1"
	clean_msg in msgs

	every m in msgs {
		not contains(m, "%!d")
	}
}

test_fractional_distinct_reports_invalid_whole_count_both_paths if {
	cases := [
		{"included": true, "distinct": 0.5, "min": 1, "approvers": [_ok]},
		{"included": false, "distinct": 0.5, "min": 1, "approvers": [_ok]},
		{"included": true, "distinct": 2.5, "min": 2, "approvers": [_ok, _ok2]},
		{"included": false, "distinct": 2.5, "min": 2, "approvers": [_ok, _ok2]},
		{"included": true, "distinct": 1.5, "min": 0, "approvers": [_ok]},
		{"included": false, "distinct": 1.5, "min": 0, "approvers": [_ok]},
	]
	every tc in cases {
		predicate := json.patch(_base_pred, [
			{"op": "replace", "path": "/approversIncluded", "value": tc.included},
			{"op": "replace", "path": "/approvers", "value": tc.approvers},
			{"op": "replace", "path": "/summary/distinctApprovers", "value": tc.distinct},
		])
		inp := [_env(predicate)]
		cfg := object.union(_summary_config, {"min_approvals": tc.min})

		# regal ignore:unresolved-reference
		not source_review.allow with input as inp with data.source_review_thresholds as cfg

		# regal ignore:unresolved-reference
		msgs := source_review.violations with input as inp with data.source_review_thresholds as cfg
		msg := sprintf(
			"source-review: distinct approval count %v is not a non-negative whole number, need at least %d",
			[tc.distinct, floor(tc.min)],
		)
		msgs == {_malformed_msg, msg}
	}
}

test_fractional_distinct_1_5_min_1_approvers_included_reports_exact_diagnostic if {
	predicate := json.patch(_base_pred, [
		{"op": "replace", "path": "/approversIncluded", "value": true},
		{"op": "replace", "path": "/approvers", "value": [_ok]},
		{"op": "replace", "path": "/summary/distinctApprovers", "value": 1.5},
	])
	inp := [_env(predicate)]
	cfg := object.union(_summary_config, {"min_approvals": 1})

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg

	# regal ignore:unresolved-reference
	msgs := source_review.violations with input as inp with data.source_review_thresholds as cfg
	msgs == {
		_malformed_msg,
		"source-review: distinct approval count 1.5 is not a non-negative whole number, need at least 1",
	}
}

test_fractional_distinct_1_5_min_1_summary_only_reports_exact_diagnostic if {
	predicate := json.patch(_base_pred, [
		{"op": "replace", "path": "/approversIncluded", "value": false},
		{"op": "replace", "path": "/approvers", "value": [_ok]},
		{"op": "replace", "path": "/summary/distinctApprovers", "value": 1.5},
	])
	inp := [_env(predicate)]
	cfg := object.union(_summary_config, {"min_approvals": 1})

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg

	# regal ignore:unresolved-reference
	msgs := source_review.violations with input as inp with data.source_review_thresholds as cfg
	msgs == {
		_malformed_msg,
		"source-review: distinct approval count 1.5 is not a non-negative whole number, need at least 1",
	}
}

test_fractional_distinct_1_5_min_2_approvers_included_reports_exact_diagnostic if {
	predicate := json.patch(_base_pred, [
		{"op": "replace", "path": "/approversIncluded", "value": true},
		{"op": "replace", "path": "/approvers", "value": [_ok, _ok2]},
		{"op": "replace", "path": "/summary/distinctApprovers", "value": 1.5},
	])
	inp := [_env(predicate)]
	cfg := object.union(_summary_config, {"min_approvals": 2})

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg

	# regal ignore:unresolved-reference
	msgs := source_review.violations with input as inp with data.source_review_thresholds as cfg
	msgs == {
		_malformed_msg,
		"source-review: distinct approval count 1.5 is not a non-negative whole number, need at least 2",
	}
}

test_fractional_distinct_1_5_min_2_summary_only_reports_exact_diagnostic if {
	predicate := json.patch(_base_pred, [
		{"op": "replace", "path": "/approversIncluded", "value": false},
		{"op": "replace", "path": "/approvers", "value": [_ok, _ok2]},
		{"op": "replace", "path": "/summary/distinctApprovers", "value": 1.5},
	])
	inp := [_env(predicate)]
	cfg := object.union(_summary_config, {"min_approvals": 2})

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg

	# regal ignore:unresolved-reference
	msgs := source_review.violations with input as inp with data.source_review_thresholds as cfg
	msgs == {
		_malformed_msg,
		"source-review: distinct approval count 1.5 is not a non-negative whole number, need at least 2",
	}
}

test_fractional_distinct_diagnostic_suppressed_when_incomplete if {
	cfg := object.union(_summary_config, {
		"min_approvals": 0,
		"fail_on_incomplete_review": false,
	})
	every included in [true, false] {
		predicate := json.patch(_base_pred, [
			{"op": "replace", "path": "/approversIncluded", "value": included},
			{"op": "replace", "path": "/summary/distinctApprovers", "value": 1.5},
			{"op": "replace", "path": "/reviewToolingComplete", "value": false},
		])
		inp := [_env(predicate)]

		# regal ignore:unresolved-reference
		not source_review.allow with input as inp with data.source_review_thresholds as cfg

		# regal ignore:unresolved-reference
		msgs := source_review.violations with input as inp with data.source_review_thresholds as cfg
		msgs == {_malformed_msg}
	}
}

test_fractional_distinct_diagnostic_suppressed_when_grandfathered if {
	cfg := object.union(_summary_config, {
		"min_approvals": 0,
		"enforced_since": "2026-06-01T00:00:00Z",
	})
	every included in [true, false] {
		predicate := json.patch(_base_pred, [
			{"op": "replace", "path": "/approversIncluded", "value": included},
			{"op": "replace", "path": "/summary/distinctApprovers", "value": 1.5},
			{
				"op": "add",
				"path": "/pullRequest",
				"value": {"number": 1, "mergedAt": "2026-05-01T00:00:00Z"},
			},
		])
		inp := [_env(predicate)]

		# regal ignore:unresolved-reference
		not source_review.allow with input as inp with data.source_review_thresholds as cfg

		# regal ignore:unresolved-reference
		msgs := source_review.violations with input as inp with data.source_review_thresholds as cfg
		msgs == {_malformed_msg}
	}
}

# defense-in-depth: a distinct-approval count is a legitimate value even when
# JSON/Rego represents it as a whole-number float (e.g. 1.0 -- JSON does not
# distinguish int from float). is_number(n) alone would not catch this: Go's %d
# verb rejects a float64 even when it is integer-valued, garbling identically to
# a forged string ("%!d(float64=1)"). Exercised via the summary-only path so
# effective_distinct returns the raw value, and with distinct min_approvals/n
# values so an argument-order regression in the message format would be caught.
test_distinct_approvals_whole_number_float_formats_cleanly if {
	bad := [_env({
		"sourceRepository": "https://github.com/liatrio/autogov",
		"sourceRevision": "abc123",
		"summary": {
			"approvals": 1,
			"distinctApprovers": 1.0,
			"changesRequested": 0,
			"requiredApprovals": 0,
			"requirementMet": true,
			"selfApprovalExcluded": false,
			"codeownerReviewMet": null,
		},
		"approversIncluded": false,
		"configuration": [],
		"reviewToolingComplete": true,
	})]
	cfg := {"min_approvals": 2}

	# regal ignore:unresolved-reference
	not source_review.allow with input as bad with data.source_review_thresholds as cfg

	# regal ignore:unresolved-reference
	msgs := source_review.violations with input as bad with data.source_review_thresholds as cfg

	clean_msg := "source-review: 1 distinct approval(s), need at least 2"
	clean_msg in msgs

	every m in msgs {
		not contains(m, "%!d")
	}
}

# defense-in-depth: same float-representation hazard for changesRequested (see
# test_distinct_approvals_whole_number_float_formats_cleanly above).
test_changes_requested_whole_number_float_formats_cleanly if {
	bad := [_env({
		"sourceRepository": "https://github.com/liatrio/autogov",
		"sourceRevision": "abc123",
		"summary": {
			"approvals": 1,
			"distinctApprovers": 1,
			"changesRequested": 2.0,
			"requiredApprovals": 0,
			"requirementMet": true,
			"selfApprovalExcluded": false,
			"codeownerReviewMet": null,
		},
		"approversIncluded": true,
		"approvers": [_ok],
		"configuration": [],
		"reviewToolingComplete": true,
	})]

	# regal ignore:unresolved-reference
	not source_review.allow with input as bad

	# regal ignore:unresolved-reference
	msgs := source_review.violations with input as bad

	clean_msg := "source-review: 2 outstanding changes-requested review(s)"
	clean_msg in msgs

	every m in msgs {
		not contains(m, "%!d")
	}
}

# regression: null and boolean are the two forgeable types Rego's total value
# ordering ranks BELOW numbers (unlike strings/arrays/objects, which rank
# above), so a bare `n > 0` would silently -- and wrongly -- treat a forged
# `changesRequested: null` as "no changes requested" and skip this violation
# entirely, relying solely on the separate malformed-predicate violation
# (structurally_valid) to deny overall `allow`. _changes_requested_present
# closes this for every non-numeric type by design, not by ordering luck.
test_changes_requested_null_fails_closed if {
	bad := [_env({
		"sourceRepository": "https://github.com/liatrio/autogov",
		"sourceRevision": "abc123",
		"summary": {
			"approvals": 1,
			"distinctApprovers": 1,
			"changesRequested": null,
			"requiredApprovals": 0,
			"requirementMet": true,
			"selfApprovalExcluded": false,
			"codeownerReviewMet": null,
		},
		"approversIncluded": true,
		"approvers": [_ok],
		"configuration": [],
		"reviewToolingComplete": true,
	})]

	# regal ignore:unresolved-reference
	not source_review.allow with input as bad

	# regal ignore:unresolved-reference
	msgs := source_review.violations with input as bad

	clean_msg := "source-review: changesRequested is not numeric (\"null\"), treating as an outstanding review"
	clean_msg in msgs
}

# regression: same ordering-accident class as the null case above, for a forged
# boolean changesRequested (`true > 0` and `false > 0` both evaluate false in
# Rego).
test_changes_requested_boolean_fails_closed if {
	bad := [_env({
		"sourceRepository": "https://github.com/liatrio/autogov",
		"sourceRevision": "abc123",
		"summary": {
			"approvals": 1,
			"distinctApprovers": 1,
			"changesRequested": true,
			"requiredApprovals": 0,
			"requirementMet": true,
			"selfApprovalExcluded": false,
			"codeownerReviewMet": null,
		},
		"approversIncluded": true,
		"approvers": [_ok],
		"configuration": [],
		"reviewToolingComplete": true,
	})]

	# regal ignore:unresolved-reference
	not source_review.allow with input as bad

	# regal ignore:unresolved-reference
	msgs := source_review.violations with input as bad

	clean_msg := "source-review: changesRequested is not numeric (\"true\"), treating as an outstanding review"
	clean_msg in msgs
}

# regression: a whole-number-float min_approvals (e.g. 2.0 -- a legitimate,
# _valid_count-accepted config override, not a forged predicate) must not
# garble the message's "need at least %d" clause. floor(min_approvals) is
# applied at every %d call site regardless of n's own shape.
test_distinct_approvals_float_min_approvals_formats_cleanly if {
	bad := [_env({
		"sourceRepository": "https://github.com/liatrio/autogov",
		"sourceRevision": "abc123",
		"summary": _summary(0, 0),
		"approversIncluded": true,
		"approvers": [],
		"configuration": [],
		"reviewToolingComplete": true,
	})]
	cfg := {"min_approvals": 2.0}

	# regal ignore:unresolved-reference
	not source_review.allow with input as bad with data.source_review_thresholds as cfg

	# regal ignore:unresolved-reference
	msgs := source_review.violations with input as bad with data.source_review_thresholds as cfg

	clean_msg := "source-review: 0 distinct approval(s), need at least 2"
	clean_msg in msgs

	every m in msgs {
		not contains(m, "%!d")
	}
}

# regression: a whole-number-float mergedById (e.g. 138915.0) must format
# cleanly, mirroring the same hazard already fixed for the distinct-approval and
# changes-requested messages above -- _zero_approval_merger_msg is the helper
# they were both written to mirror, so it must not itself regress.
test_zero_approval_merger_whole_number_float_formats_cleanly if {
	bad := [_env({
		"sourceRepository": "https://github.com/liatrio/autogov",
		"sourceRevision": "abc123",
		"pullRequest": {"number": 1, "mergedAt": "2026-06-15T00:00:00Z", "mergedById": 999999.0},
		"summary": _summary(0, 0),
		"approversIncluded": true,
		"approvers": [],
		"configuration": [],
		"reviewToolingComplete": true,
	})]
	cfg := {"min_approvals": 0, "zero_approval_merger_allowlist": [138915]}

	# regal ignore:unresolved-reference
	not source_review.allow with input as bad with data.source_review_thresholds as cfg

	# regal ignore:unresolved-reference
	msgs := source_review.violations with input as bad with data.source_review_thresholds as cfg

	clean_msg := "source-review: merger 999999 is not on the zero-approval-merger allowlist"
	clean_msg in msgs

	every m in msgs {
		not contains(m, "%!d")
	}
}

# malformed (non-object) pullRequest fails closed via structurally_valid rather
# than silently passing the zero-approval-merger gate.
test_zero_approval_merger_non_object_pull_request_fails_closed if {
	bad := [_env({
		"sourceRepository": "https://github.com/liatrio/autogov",
		"sourceRevision": "abc123",
		"pullRequest": "not-an-object",
		"summary": _summary(1, 0),
		"approversIncluded": true,
		"approvers": [_ok],
		"configuration": [],
		"reviewToolingComplete": true,
	})]
	cfg := {"min_approvals": 0, "zero_approval_merger_allowlist": [138915]}

	# regal ignore:unresolved-reference
	not source_review.allow with input as bad with data.source_review_thresholds as cfg

	msg := "source-review predicate is malformed (missing or mistyped summary, approvers, or top-level fields)"

	# regal ignore:unresolved-reference
	msg in source_review.violations with input as bad with data.source_review_thresholds as cfg
}
