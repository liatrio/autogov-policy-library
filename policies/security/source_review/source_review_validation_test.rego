package security.source_review_test

import data.security.source_review
import rego.v1

# --- malformed -> fail closed ---

test_malformed_predicate_fails_closed if {
	bad := [_env({
		"sourceRepository": "https://github.com/liatrio/autogov",
		"sourceRevision": "abc123",
		"summary": {
			"approvals": 1,
			"distinctApprovers": "1",
			"changesRequested": 0,
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
	not source_review.allow with input as bad
}

# coupling guard: corrupting ANY field a gate rule reads must trip the malformed
# denial. If a new gate rule reads a new predicate field, add it to
# common.structurally_valid AND to the patch list here. A valid base must allow;
# every corrupted variant must deny.
_base_pred := {
	"sourceRepository": "https://github.com/liatrio/autogov",
	"sourceRevision": "abc123",
	"summary": _summary(1, 0),
	"approversIncluded": true,
	"approvers": [_ok],
	"configuration": [],
	"reviewToolingComplete": true,
}

# Disable the filters that require embedded reviewers so both producer paths
# expose the same count diagnostics in the malformed-count matrix.
_summary_config := {
	"disallow_self_approval": false,
	"require_non_stale": false,
	"allow_bot_approvals": true,
}

_malformed_msg := "source-review predicate is malformed (missing or mistyped summary, approvers, or top-level fields)"

test_non_numeric_distinct_preserved_in_both_producer_paths if {
	cases := [
		{"value": "bad", "rendered": "\"bad\""},
		{"value": null, "rendered": "\"null\""},
		{"value": true, "rendered": "\"true\""},
		{"value": false, "rendered": "\"false\""},
		{"value": [], "rendered": "\"[]\""},
		{"value": {}, "rendered": "\"{}\""},
	]
	every included in [true, false] {
		every tc in cases {
			predicate := json.patch(_base_pred, [
				{"op": "replace", "path": "/summary/distinctApprovers", "value": tc.value},
				{"op": "replace", "path": "/approversIncluded", "value": included},
			])
			inp := [_env(predicate)]

			# regal ignore:unresolved-reference
			not source_review.allow with input as inp with data.source_review_thresholds as _summary_config

			# regal ignore:unresolved-reference
			msgs := source_review.violations with input as inp with data.source_review_thresholds as _summary_config
			diagnostic := concat("", [
				"source-review: distinct approval count is not numeric (",
				tc.rendered,
				"), need at least 1",
			])
			msgs == {_malformed_msg, diagnostic}
		}
	}
}

test_all_source_counts_reject_invalid_values if {
	cases := [
		{"value": -1, "diagnostics": {
			"distinctApprovers": "source-review: distinct approval count -1 is not a non-negative whole number, need at least 1",
		}},
		{"value": 0.5, "diagnostics": {
			"distinctApprovers": concat("", [
				"source-review: distinct approval count 0.5 is not a non-negative whole number, ",
				"need at least 1",
			]),
			"changesRequested": concat("", [
				"source-review: changesRequested value 0.5 is not a non-negative whole number, ",
				"treating as an outstanding review",
			]),
		}},
		{"value": "bad", "diagnostics": {
			"distinctApprovers": "source-review: distinct approval count is not numeric (\"bad\"), need at least 1",
			"changesRequested": "source-review: changesRequested is not numeric (\"bad\"), treating as an outstanding review",
		}},
		{"value": null, "diagnostics": {
			"distinctApprovers": "source-review: distinct approval count is not numeric (\"null\"), need at least 1",
			"changesRequested": "source-review: changesRequested is not numeric (\"null\"), treating as an outstanding review",
		}},
		{"value": true, "diagnostics": {
			"distinctApprovers": "source-review: distinct approval count is not numeric (\"true\"), need at least 1",
			"changesRequested": "source-review: changesRequested is not numeric (\"true\"), treating as an outstanding review",
		}},
		{"value": false, "diagnostics": {
			"distinctApprovers": "source-review: distinct approval count is not numeric (\"false\"), need at least 1",
			"changesRequested": "source-review: changesRequested is not numeric (\"false\"), treating as an outstanding review",
		}},
		{"value": [], "diagnostics": {
			"distinctApprovers": "source-review: distinct approval count is not numeric (\"[]\"), need at least 1",
			"changesRequested": "source-review: changesRequested is not numeric (\"[]\"), treating as an outstanding review",
		}},
		{"value": {}, "diagnostics": {
			"distinctApprovers": "source-review: distinct approval count is not numeric (\"{}\"), need at least 1",
			"changesRequested": "source-review: changesRequested is not numeric (\"{}\"), treating as an outstanding review",
		}},
	]
	every included in [true, false] {
		every field in ["approvals", "distinctApprovers", "changesRequested", "requiredApprovals"] {
			every tc in cases {
				predicate := json.patch(_base_pred, [
					{"op": "replace", "path": ["summary", field], "value": tc.value},
					{"op": "replace", "path": "/approversIncluded", "value": included},
				])
				inp := [_env(predicate)]

				# regal ignore:unresolved-reference
				not source_review.allow with input as inp with data.source_review_thresholds as _summary_config

				# regal ignore:unresolved-reference
				msgs := source_review.violations with input as inp with data.source_review_thresholds as _summary_config
				expected := {_malformed_msg} | {msg | msg := tc.diagnostics[field]}
				msgs == expected
			}
		}
	}
}

test_all_source_counts_are_required if {
	every included in [true, false] {
		every field in ["approvals", "distinctApprovers", "changesRequested", "requiredApprovals"] {
			predicate := json.patch(_base_pred, [
				{"op": "remove", "path": ["summary", field]},
				{"op": "replace", "path": "/approversIncluded", "value": included},
			])
			inp := [_env(predicate)]

			# regal ignore:unresolved-reference
			not source_review.allow with input as inp with data.source_review_thresholds as _summary_config

			# regal ignore:unresolved-reference
			msgs := source_review.violations with input as inp with data.source_review_thresholds as _summary_config
			msgs == {_malformed_msg}
		}
	}
}

test_decimal_source_counts_and_minimum_in_both_producer_paths if {
	cfg := object.union(_summary_config, {"min_approvals": 2.0})
	every included in [true, false] {
		predicate := json.patch(_base_pred, [
			{"op": "replace", "path": "/summary/approvals", "value": 1.0},
			{"op": "replace", "path": "/summary/distinctApprovers", "value": 1.0},
			{"op": "replace", "path": "/summary/changesRequested", "value": 0.0},
			{"op": "replace", "path": "/summary/requiredApprovals", "value": 0.0},
			{"op": "replace", "path": "/approversIncluded", "value": included},
		])
		inp := [_env(predicate)]

		# regal ignore:unresolved-reference
		source_review.allow with input as inp with data.source_review_thresholds as _summary_config

		# regal ignore:unresolved-reference
		not source_review.allow with input as inp with data.source_review_thresholds as cfg

		# regal ignore:unresolved-reference
		msgs := source_review.violations with input as inp with data.source_review_thresholds as cfg
		msgs == {"source-review: 1 distinct approval(s), need at least 2"}
	}
}

test_numeric_summary_still_constrained_by_reviewer_count_and_filters if {
	cases := [
		{"approvers": [_ok], "distinct": 10, "cfg": {"min_approvals": 2}},
		{"approvers": [_ok, _stale, _bot], "distinct": 3, "cfg": {"min_approvals": 2}},
		{"approvers": [_ok, _stale, _bot], "distinct": 1, "cfg": {
			"min_approvals": 2,
			"require_non_stale": false,
			"allow_bot_approvals": true,
		}},
	]
	every tc in cases {
		predicate := json.patch(_base_pred, [
			{"op": "replace", "path": "/summary/distinctApprovers", "value": tc.distinct},
			{"op": "replace", "path": "/approvers", "value": tc.approvers},
		])
		inp := [_env(predicate)]

		# regal ignore:unresolved-reference
		not source_review.allow with input as inp with data.source_review_thresholds as tc.cfg

		# regal ignore:unresolved-reference
		msgs := source_review.violations with input as inp with data.source_review_thresholds as tc.cfg
		msgs == {"source-review: 1 distinct approval(s), need at least 2"}
	}
}

test_invalid_minimum_overrides_have_exact_policy_diagnostic if {
	inp := [_env(_base_pred)]
	every value in [-1, 0.5, "0", null, true, false, [], {}] {
		cfg := {"min_approvals": value}

		# regal ignore:unresolved-reference
		not source_review.allow with input as inp with data.source_review_thresholds as cfg

		# regal ignore:unresolved-reference
		msgs := source_review.violations with input as inp with data.source_review_thresholds as cfg
		msgs == {"source-review configuration is invalid: min_approvals must be a non-negative integer"}
	}
}

test_zero_minimum_and_positive_decimal_merger_id_allow if {
	inp := sr_merged_by([], 0, 42.0)
	cfg := {"min_approvals": 0.0, "zero_approval_merger_allowlist": [42.0]}

	# regal ignore:unresolved-reference
	source_review.allow with input as inp with data.source_review_thresholds as cfg

	# regal ignore:unresolved-reference
	msgs := source_review.violations with input as inp with data.source_review_thresholds as cfg
	msgs == set()
}

test_malformed_field_coupling if {
	source_review.allow with input as [_env(_base_pred)]

	patches := [
		[{"op": "remove", "path": "/summary/approvals"}],
		[{"op": "replace", "path": "/summary/distinctApprovers", "value": "x"}],
		[{"op": "remove", "path": "/summary/distinctApprovers"}],
		[{"op": "replace", "path": "/summary/changesRequested", "value": "x"}],
		[{"op": "remove", "path": "/summary/changesRequested"}],
		[{"op": "replace", "path": "/summary/requiredApprovals", "value": "x"}],
		[{"op": "replace", "path": "/summary/requirementMet", "value": 1}],
		[{"op": "replace", "path": "/summary/selfApprovalExcluded", "value": 1}],
		[{"op": "remove", "path": "/summary/codeownerReviewMet"}],
		[{"op": "replace", "path": "/summary/codeownerReviewMet", "value": "x"}],
		[{"op": "replace", "path": "/approversIncluded", "value": "x"}],
		[{"op": "remove", "path": "/approversIncluded"}],
		[{"op": "replace", "path": "/reviewToolingComplete", "value": "x"}],
		[{"op": "remove", "path": "/reviewToolingComplete"}],
		[{"op": "replace", "path": "/approvers/0/stale", "value": "x"}],
		[{"op": "replace", "path": "/approvers/0/isBot", "value": "x"}],
		[{"op": "add", "path": "/pullRequest", "value": "not-an-object"}],
		[{"op": "add", "path": "/pullRequest", "value": {"number": 1, "mergedById": "bad"}}],
		[{"op": "add", "path": "/pullRequest", "value": {"number": 1, "mergedById": -1}}],
		[{"op": "add", "path": "/pullRequest", "value": {"number": 1, "mergedById": 1.5}}],
		[{"op": "add", "path": "/pullRequest", "value": {"number": 1, "mergedById": true}}],
	]
	every patch in patches {
		bad := json.patch(_base_pred, patch)
		not source_review.allow with input as [_env(bad)]
	}
}

# an approver missing its stale/isBot booleans is malformed -> fail closed.
test_malformed_approver_fails_closed if {
	bad := [_env({
		"sourceRepository": "https://github.com/liatrio/autogov",
		"sourceRevision": "abc123",
		"summary": _summary(1, 0),
		"approversIncluded": true,
		"approvers": [{"login": "alice"}],
		"configuration": [],
		"reviewToolingComplete": true,
	})]
	not source_review.allow with input as bad
}

# type-coerced config (quoted number) is a config error -> fail closed, rather
# than silently reverting to a looser default.
test_string_threshold_fails_closed if {
	inp := sr_approvers([_ok], 0, true)
	cfg := {"min_approvals": "5"}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# a wrong-typed boolean flag is a config error -> fail closed.
test_bool_flag_typo_fails_closed if {
	inp := sr_approvers([_ok], 0, true)
	cfg := {"require_codeowner_review": "true"}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# a negative min_approvals would silently disable the threshold -> rejected.
test_negative_min_approvals_fails_closed if {
	inp := sr_approvers([], 0, true)
	cfg := {"min_approvals": -1}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# a fractional min_approvals is rejected.
test_fractional_min_approvals_fails_closed if {
	inp := sr_approvers([_ok], 0, true)
	cfg := {"min_approvals": 1.5}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# M2: an unknown/misspelled key fails closed. The operator intended min_approvals:2
# but typo'd it; without the unknown-key guard the gate silently keeps the default 1
# and the single approval passes. With the guard it denies.
test_unknown_config_key_fails_closed if {
	inp := sr_approvers([_ok], 0, true)
	cfg := {"min_aprovals": 2}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# L3: a forged negative count is rejected by structurally_valid (would otherwise
# slip the changes-requested block: changesRequested -1 > 0 is false).
test_forged_negative_count_fails_closed if {
	bad := [_env({
		"sourceRepository": "https://github.com/liatrio/autogov",
		"sourceRevision": "abc123",
		"summary": {
			"approvals": 1,
			"distinctApprovers": 1,
			"changesRequested": -1,
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
	not source_review.allow with input as bad
}
