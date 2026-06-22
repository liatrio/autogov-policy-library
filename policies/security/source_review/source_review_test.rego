package security.source_review_test

import data.security.source_review
import rego.v1

# --- builders ---

_env(predicate) := {"dsseEnvelope": {"payload": base64.encode(json.marshal({
	"predicateType": "https://autogov.dev/attestation/source-review/v0.1",
	"predicate": predicate,
}))}}

approver(login, stale, isbot) := {
	"login": login,
	"association": "MEMBER",
	"stale": stale,
	"isBot": isbot,
}

# strict distinct count the producer would emit (not stale, not bot).
_strict(approvers) := count([a |
	some a in approvers
	a.stale == false
	a.isBot == false
])

_summary(distinct, changes) := {
	"approvals": distinct,
	"distinctApprovers": distinct,
	"changesRequested": changes,
	"requiredApprovals": 0,
	"requirementMet": true,
	"selfApprovalExcluded": false,
	"codeownerReviewMet": null,
}

# summary-only attestation (approvers excluded — the producer's degrade path).
sr_summary(distinct, changes, complete) := [_env({
	"sourceRepository": "https://github.com/liatrio/autogov",
	"sourceRevision": "abc123",
	"summary": _summary(distinct, changes),
	"approversIncluded": false,
	"configuration": [],
	"reviewToolingComplete": complete,
})]

# attestation with the per-approver list embedded (the default producer mode).
sr_approvers(approvers, changes, complete) := [_env({
	"sourceRepository": "https://github.com/liatrio/autogov",
	"sourceRevision": "abc123",
	"summary": _summary(_strict(approvers), changes),
	"approversIncluded": true,
	"approvers": approvers,
	"configuration": [],
	"reviewToolingComplete": complete,
})]

_ok := approver("alice", false, false)

_ok2 := approver("bob", false, false)

_stale := approver("carol", true, false)

_bot := approver("ci[bot]", false, true)

# --- presence / inertness ---

test_inert_when_absent if {
	source_review.allow with input as []
}

test_inert_for_other_predicate if {
	source_review.allow with input as [_env_other]
}

_env_other := {"dsseEnvelope": {"payload": base64.encode(json.marshal({
	"predicateType": "https://example.org/other",
	"predicate": {},
}))}}

test_require_present_violation if {
	cfg := {"require_source_review": true}

	# regal ignore:unresolved-reference
	not source_review.allow with input as [] with data.source_review_thresholds as cfg

	msg := "source-review attestation is missing"

	# regal ignore:unresolved-reference
	msg in source_review.violations with input as [] with data.source_review_thresholds as cfg
}

# --- min approvals ---

test_clean_passes if {
	source_review.allow with input as sr_approvers([_ok], 0, true)
}

test_zero_approvals_fails_default if {
	not source_review.allow with input as sr_approvers([], 0, true)
}

test_min_approvals_override_fails if {
	inp := sr_approvers([_ok], 0, true)
	cfg := {"min_approvals": 2}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg
}

test_min_approvals_override_passes if {
	inp := sr_approvers([_ok, _ok2], 0, true)
	cfg := {"min_approvals": 2}

	# regal ignore:unresolved-reference
	source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# admin-merge style: tooling complete but zero qualifying approvals -> a
# DEFINITIVE fail (not incompleteness), even if incomplete-review is tolerated.
test_zero_approvals_fails_even_if_incomplete_tolerated if {
	inp := sr_approvers([], 0, true)
	cfg := {"fail_on_incomplete_review": false}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# --- changes requested (necessary-but-not-sufficient) ---

test_changes_requested_blocks_despite_approvals if {
	not source_review.allow with input as sr_approvers([_ok, _ok2], 1, true)
}

test_changes_requested_can_be_disabled if {
	inp := sr_approvers([_ok], 1, true)
	cfg := {"block_on_changes_requested": false}

	# regal ignore:unresolved-reference
	source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# a standing change-request blocks even when incomplete-review evidence is
# tolerated: changesRequested > 0 is never an incompleteness artifact.
test_changes_requested_blocks_even_when_incomplete_tolerated if {
	inp := sr_approvers([], 5, false)
	cfg := {"fail_on_incomplete_review": false}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# --- incompleteness ---

test_incomplete_fails_default if {
	not source_review.allow with input as sr_approvers([_ok], 0, false)
}

test_incomplete_tolerated_when_disabled if {
	inp := sr_approvers([], 0, false)
	cfg := {"fail_on_incomplete_review": false}

	# regal ignore:unresolved-reference
	source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# --- degrade-to-summary / can_recompute ---

# default per-reviewer filters are active, so a summary-only attestation cannot
# be verified -> incompleteness, fail closed (even though distinct=1 >= min 1).
test_summary_only_fails_closed_by_default if {
	not source_review.allow with input as sr_summary(1, 0, true)
}

# disabling every per-reviewer filter lets the gate trust the strict summary.
test_summary_only_passes_when_filters_disabled if {
	inp := sr_summary(1, 0, true)
	cfg := {
		"disallow_self_approval": false,
		"require_non_stale": false,
		"allow_bot_approvals": true,
		"require_codeowner_review": false,
	}

	# regal ignore:unresolved-reference
	source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# --- self / stale / bot via recompute ---

test_stale_and_bot_excluded_from_distinct if {
	# only alice qualifies; carol is stale, ci[bot] is a bot -> distinct 1 < 2.
	inp := sr_approvers([_ok, _stale, _bot], 0, true)
	cfg := {"min_approvals": 2}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# never-loosen: disabling require_non_stale cannot lift the count above the
# producer's strict floor (min of recompute and summary).
test_disabling_filter_cannot_loosen_below_floor if {
	inp := sr_approvers([_ok, _stale], 0, true)
	cfg := {"min_approvals": 2, "require_non_stale": false}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# --- codeowner (tri-state null) ---

test_codeowner_required_null_fails_closed if {
	inp := sr_approvers([_ok], 0, true)
	cfg := {"require_codeowner_review": true}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg
}

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
