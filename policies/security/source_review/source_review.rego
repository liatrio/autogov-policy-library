# METADATA
# scope: package
# title: Source Review Policy
# description: Gates autogov source-review (PR-approval) attestations against a configurable review bar.
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
# custom:
#  version: 0.1.0
#  path: policies/security/source_review
#  filename: source_review.rego
package security.source_review

import data.security.source_review_common as common
import data.shared.utils
import data.source_review_config
import rego.v1

default allow := false

allow if {
	count(violations) == 0
}

# source-review attestations present in the input.
sr_payloads := [payload |
	some payload in utils.decoded_payload_list
	utils.is_source_review(payload)
]

# Violation: presence required but no source-review attestation present.
violations contains msg if {
	source_review_config.require_source_review
	count(sr_payloads) == 0
	msg := "source-review attestation is missing"
}

# Violation: a present source-review predicate is malformed (missing or mistyped
# fields the gate depends on). The predicate is not re-validated against the
# schema at eval time, so this fails CLOSED — a non-conforming signed predicate
# cannot slip the gate via an undefined lookup.
violations contains msg if {
	some payload in sr_payloads
	not common.structurally_valid(payload)
	msg := "source-review predicate is malformed (missing or mistyped summary fields)"
}

# Violation: the review evidence could not be fully gathered (no merged PR — a
# direct push or the ListPullRequestsWithCommit default-branch quirk — or reviews
# were unfetchable). Governed by fail_on_incomplete_review (default true).
violations contains msg if {
	source_review_config.fail_on_incomplete_review == true
	some payload in sr_payloads
	payload.predicate.reviewToolingComplete == false
	msg := "source-review reports incomplete review tooling (reviewToolingComplete=false)"
}

# Violation: per-reviewer gating was requested (disallow_self_approval /
# require_non_stale / allow_bot_approvals=false / require_codeowner_review) but the
# attestation does not embed approvers[], so the summary cannot be verified under
# those filters. ALWAYS fires (never a silent no-op) — decoupled from
# fail_on_incomplete_review, which governs review-evidence completeness, not the
# contradiction of requesting per-approver gating without per-approver data.
violations contains msg if {
	common.recompute_required == true
	some payload in sr_payloads
	not common.can_recompute(payload)
	msg := concat("", [
		"source-review gating needs per-approver data ",
		"(disallow_self_approval/require_non_stale/allow_bot_approvals/require_codeowner_review) ",
		"but approvers are excluded; regenerate with --include-approvers",
	])
}

# Violation: fewer distinct qualifying approvals than required. Only evaluated
# when the review tooling is complete; otherwise the count is untrustworthy and
# the incompleteness violation governs (so a release/tag build is not falsely
# hard-failed on a zero count). Pass/fail derives ONLY from the numeric count,
# never from a self-asserted requirementMet/selfApprovalExcluded boolean.
violations contains msg if {
	some payload in sr_payloads
	common.review_complete(payload)
	n := common.effective_distinct(payload)
	n < source_review_config.min_approvals
	msg := sprintf("source-review: %d distinct approval(s), need at least %d", [n, source_review_config.min_approvals])
}

# Violation: an outstanding CHANGES_REQUESTED review blocks regardless of the
# approval count (necessary-but-not-sufficient). NOT guarded by review
# completeness: the producer emits changesRequested > 0 only when reviews were
# actually fetched, so a positive count is never an incompleteness artifact and
# must block even when incomplete-review evidence is otherwise tolerated
# (fail_on_incomplete_review=false). Bot/self requests are already excluded by the
# producer; a later dismissal clears it.
violations contains msg if {
	source_review_config.block_on_changes_requested == true
	some payload in sr_payloads
	n := payload.predicate.summary.changesRequested
	n > 0
	msg := sprintf("source-review: %d outstanding changes-requested review(s)", [n])
}

# Violation: CODEOWNER review required but not met or not determinable. Decoupled
# from fail_on_incomplete_review so it cannot be regressed by that flag. Because
# codeownerReviewMet is tri-state and REST-only leaves it null, turning this on
# fails closed until a future version can authoritatively determine it.
violations contains msg if {
	source_review_config.require_codeowner_review == true
	some payload in sr_payloads
	payload.predicate.summary.codeownerReviewMet != true
	msg := "source-review: codeowner review is required but not met or not determinable"
}
