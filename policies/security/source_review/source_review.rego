# METADATA
# scope: package
# title: Source Review Policy
# description: Gates autogov source-review (PR-approval) attestations against a configurable review bar.
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
# custom:
#  version: 0.22.2
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

# NOTE: every predicate field a violation rule below reads MUST also be
# type-checked by common.structurally_valid. The gate is not re-validated against
# the JSON schema at eval time, so an unchecked field would read UNDEFINED and
# silently skip its gate (fail-open). When adding a rule that reads a new field,
# extend structurally_valid and the malformed-field coupling test.

# Violation: the policy configuration itself is malformed (a provided override has
# the wrong type or is out of range). Fails CLOSED so a config typo cannot
# silently revert a gate to a looser default.
violations contains msg if {
	some err in source_review_config.config_errors
	msg := sprintf("source-review configuration is invalid: %s", [err])
}

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
	msg := "source-review predicate is malformed (missing or mistyped summary, approvers, or top-level fields)"
}

# Violation: the review evidence could not be fully gathered (no merged PR — a
# direct push or the ListPullRequestsWithCommit default-branch quirk — or reviews
# were unfetchable). Governed by fail_on_incomplete_review (default false).
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
# Suppressed for a revision merged before enforced_since (grandfathered) so
# enabling the gate does not retroactively fail pre-adoption commits.
violations contains msg if {
	some payload in sr_payloads
	common.review_complete(payload)
	not _grandfathered(payload)
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

# Violation: a required-approver-association allowlist is enforced but no qualifying
# approver carries an association in it. Inert by default (empty set => never fires).
# Fails CLOSED when approvers[] is not authoritative (approversIncluded=false): the
# associations cannot be verified, so the allowlist cannot be satisfied. Copies the
# bypass policy's authorized-by-association handling: a qualifying approver is
# non-stale, non-bot, with a string association in the set.
violations contains msg if {
	count(source_review_config.required_approver_associations) > 0
	some payload in sr_payloads
	not _assoc_satisfied(payload)
	msg := "source-review: no approver association in the required allowlist"
}

# _grandfathered is true when enforced_since is set AND this revision's merged PR
# closed strictly before it, so its approval-count violation is suppressed.
# Fails CLOSED (no grandfathering) when enforced_since is "", when pullRequest /
# mergedAt is absent, or when mergedAt is not a parseable RFC3339 string — a
# missing or forged timestamp can never open the window. enforced_since is already
# validated as RFC3339 (config_errors blocks otherwise). The changes-requested
# block is intentionally NOT guarded by this, so it stands regardless.
_grandfathered(payload) if {
	source_review_config.enforced_since != ""
	merged := object.get(payload.predicate, ["pullRequest", "mergedAt"], "")
	is_string(merged)
	merged != ""
	time.parse_rfc3339_ns(merged) < time.parse_rfc3339_ns(source_review_config.enforced_since)
}

# _assoc_satisfied is true when approvers[] is authoritative AND some qualifying
# (non-stale, non-bot) approver's string association is in the allowlist. The
# is_string guard fails closed: structurally_valid does not type-check association,
# so a forged non-string association is simply not matched.
_assoc_satisfied(payload) if {
	common.can_recompute(payload)
	some a in object.get(payload.predicate, "approvers", [])
	not a.stale
	not a.isBot
	is_string(a.association)
	a.association in source_review_config.required_approver_associations
}
