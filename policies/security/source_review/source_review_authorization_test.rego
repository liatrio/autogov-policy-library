package security.source_review_test

import data.security.source_review
import rego.v1

# --- required_approver_associations allowlist ---

# an approver with a configurable association (else like approver/3).
_assoc_approver(login, association) := {
	"login": login,
	"association": association,
	"stale": false,
	"isBot": false,
}

# inert by default: an empty allowlist never fires, even for an unusual association.
test_assoc_allowlist_inert_by_default if {
	source_review.allow with input as sr_approvers([_assoc_approver("alice", "CONTRIBUTOR")], 0, true)
}

# a qualifying approver whose association is in the allowlist passes.
test_assoc_allowlist_passes if {
	inp := sr_approvers([_assoc_approver("alice", "OWNER")], 0, true)
	cfg := {"required_approver_associations": ["OWNER", "MEMBER"]}

	# regal ignore:unresolved-reference
	source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# no qualifying approver's association is in the allowlist -> deny.
test_assoc_allowlist_fails_when_none_match if {
	inp := sr_approvers([_assoc_approver("alice", "CONTRIBUTOR")], 0, true)
	cfg := {"required_approver_associations": ["OWNER", "MEMBER"]}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg

	msg := "source-review: no approver association in the required allowlist"

	# regal ignore:unresolved-reference
	msg in source_review.violations with input as inp with data.source_review_thresholds as cfg
}

# a stale/bot approver does not satisfy the allowlist (qualifying approvers only).
test_assoc_allowlist_ignores_stale_and_bot if {
	approvers := [
		{"login": "carol", "association": "OWNER", "stale": true, "isBot": false},
		{"login": "ci[bot]", "association": "OWNER", "stale": false, "isBot": true},
	]
	cfg := {"required_approver_associations": ["OWNER"]}

	# regal ignore:unresolved-reference
	not source_review.allow with input as sr_approvers(approvers, 0, true) with data.source_review_thresholds as cfg
}

# fail closed when approvers[] is not authoritative: associations cannot be verified,
# so a non-empty allowlist cannot be satisfied (even with per-reviewer filters off).
test_assoc_allowlist_summary_only_fails_closed if {
	inp := sr_summary(1, 0, true)
	cfg := {
		"required_approver_associations": ["OWNER"],
		"disallow_self_approval": false,
		"require_non_stale": false,
		"allow_bot_approvals": true,
		"require_codeowner_review": false,
	}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# a forged non-string association does not satisfy the allowlist (is_string guard).
test_assoc_allowlist_non_string_association_fails_closed if {
	approvers := [{"login": "alice", "association": 42, "stale": false, "isBot": false}]
	cfg := {"required_approver_associations": ["OWNER"]}

	# regal ignore:unresolved-reference
	not source_review.allow with input as sr_approvers(approvers, 0, true) with data.source_review_thresholds as cfg
}

# a non-string entry in the allowlist is a config error -> fail closed.
test_assoc_allowlist_non_string_config_fails_closed if {
	inp := sr_approvers([_assoc_approver("alice", "OWNER")], 0, true)
	cfg := {"required_approver_associations": ["OWNER", 5]}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# like sr_approvers but carries a merged PR with the given mergedAt, for
# enforced_since grandfathering tests.
sr_merged(approvers, changes, merged_at) := [_env({
	"sourceRepository": "https://github.com/liatrio/autogov",
	"sourceRevision": "abc123",
	"pullRequest": {"number": 1, "mergedAt": merged_at},
	"summary": _summary(_strict(approvers), changes),
	"approversIncluded": true,
	"approvers": approvers,
	"configuration": [],
	"reviewToolingComplete": true,
})]

# --- enforced_since grandfathering ---

# inert by default: with no enforced_since, a zero-approval merge still fails (no
# grandfathering), so current behavior is unchanged.
test_enforced_since_inert_by_default if {
	inp := sr_merged([], 0, "2020-01-01T00:00:00Z")
	cfg := {"min_approvals": 1}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# a revision merged BEFORE the cutoff is grandfathered: the count violation is
# suppressed even though zero approvals < min 1.
test_enforced_since_grandfathers_pre_cutoff if {
	inp := sr_merged([], 0, "2026-05-01T00:00:00Z")
	cfg := {"enforced_since": "2026-06-01T00:00:00Z"}

	# regal ignore:unresolved-reference
	source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# a revision merged AFTER the cutoff is enforced: the count violation fires.
test_enforced_since_enforces_post_cutoff if {
	inp := sr_merged([], 0, "2026-06-15T00:00:00Z")
	cfg := {"min_approvals": 1, "enforced_since": "2026-06-01T00:00:00Z"}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# a standing changes-request is a HARD block: it still denies even for a revision
# merged before the cutoff (grandfathering never lifts a change request). ZERO
# qualifying approvals + a standing changes-request + merged before the cutoff: the
# count violation IS grandfathered (absent) but the changes-request still blocks, so
# this proves the block fires WHILE grandfathering actively suppresses the count.
test_enforced_since_changes_requested_still_blocks if {
	inp := sr_merged([], 1, "2026-05-01T00:00:00Z")
	cfg := {"enforced_since": "2026-06-01T00:00:00Z"}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg

	# grandfathered: the approval-count violation is suppressed.
	count_msg := "source-review: 0 distinct approval(s), need at least 1"

	# regal ignore:unresolved-reference
	not count_msg in source_review.violations with input as inp with data.source_review_thresholds as cfg

	# but the standing changes-request still blocks.
	cr_msg := "source-review: 1 outstanding changes-requested review(s)"

	# regal ignore:unresolved-reference
	cr_msg in source_review.violations with input as inp with data.source_review_thresholds as cfg
}

# strict-before boundary: mergedAt EXACTLY equal to enforced_since is NOT
# grandfathered (the cutoff is a strict <, so the instant the gate takes effect is
# enforced). zero approvals -> the count violation fires.
test_enforced_since_boundary_equal_not_grandfathered if {
	inp := sr_merged([], 0, "2026-06-01T00:00:00Z")
	cfg := {"min_approvals": 1, "enforced_since": "2026-06-01T00:00:00Z"}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# defense-in-depth: a mergedAt of JSON null is not a string, so it cannot prove a
# pre-cutoff merge -> NOT grandfathered (is_string guard), zero approvals denies.
test_enforced_since_null_merged_at_fails_closed if {
	inp := sr_merged([], 0, null)
	cfg := {"min_approvals": 1, "enforced_since": "2026-06-01T00:00:00Z"}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# defense-in-depth: a numeric mergedAt (e.g. a forged epoch) is not a string, so it
# cannot prove a pre-cutoff merge -> NOT grandfathered (is_string guard), zero
# approvals denies.
test_enforced_since_numeric_merged_at_fails_closed if {
	inp := sr_merged([], 0, 1748736000)
	cfg := {"min_approvals": 1, "enforced_since": "2026-06-01T00:00:00Z"}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# fail closed when there is no merged PR / mergedAt: an absent timestamp can never
# be proven before the cutoff, so a zero-approval merge is NOT grandfathered.
test_enforced_since_missing_merged_at_fails_closed if {
	inp := sr_approvers([], 0, true)
	cfg := {"min_approvals": 1, "enforced_since": "2026-06-01T00:00:00Z"}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg
}

# an invalid (unparseable) enforced_since is a config error -> fail closed, rather
# than silently disabling grandfathering or being read as an open window.
test_enforced_since_invalid_date_fails_closed if {
	inp := sr_merged([_ok], 0, "2026-05-01T00:00:00Z")
	cfg := {"enforced_since": "last-tuesday"}

	# regal ignore:unresolved-reference
	not source_review.allow with input as inp with data.source_review_thresholds as cfg

	msg := "source-review configuration is invalid: enforced_since must be an RFC3339 date string"

	# regal ignore:unresolved-reference
	msg in source_review.violations with input as inp with data.source_review_thresholds as cfg
}
