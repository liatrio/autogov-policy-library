# METADATA
# scope: package
# title: Source Review Common Helpers
# description: Shared helpers for source-review gating — recompute over approvers[] or degrade to the summary.
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
package security.source_review_common

import data.source_review_config
import rego.v1

# can_recompute is true when approvers[] is authoritative — the producer embedded
# the per-approver list (approversIncluded). Only then may the policy recompute /
# verify the distinct-approver count over approvers[]; otherwise it must use the
# producer's summary count.
can_recompute(payload) if {
	payload.predicate.approversIncluded == true
}

# recompute_required is true when a per-reviewer filter is active and therefore
# needs the per-approver list to verify, rather than trusting the producer's
# summary at face value. With the safe defaults (disallow_self_approval=true,
# require_non_stale=true, allow_bot_approvals=false, require_codeowner_review=false)
# this is true, so the degrade-to-summary path (approversIncluded=false) fails
# closed unless an operator explicitly disables per-reviewer verification.
recompute_required if {
	source_review_config.disallow_self_approval
}

recompute_required if {
	source_review_config.require_non_stale
}

recompute_required if {
	not source_review_config.allow_bot_approvals
}

recompute_required if {
	source_review_config.require_codeowner_review
}

# review_complete is true when the producer fully gathered the review evidence.
# When false the counts are untrustworthy and the gate defers to the
# incompleteness violation rather than firing the count-based checks.
review_complete(payload) if {
	payload.predicate.reviewToolingComplete == true
}

# recompute_distinct counts the qualifying approvers in approvers[] under the
# configured filters. The PR author is already absent from approvers[] (the
# producer excludes self), so self-approval can never be re-added here.
recompute_distinct(payload) := count([a |
	some a in object.get(payload.predicate, "approvers", [])
	_qualifies(a)
])

_qualifies(a) if {
	not _stale_excluded(a)
	not _bot_excluded(a)
}

_stale_excluded(a) if {
	source_review_config.require_non_stale
	a.stale == true
}

_bot_excluded(a) if {
	not source_review_config.allow_bot_approvals
	a.isBot == true
}

# effective_distinct returns the distinct-approver count to gate on. When
# approvers[] is authoritative it recomputes and takes the MINIMUM of the
# recomputed count and the producer's strict summary count — so a policy can only
# tighten the producer's floor, never loosen it. When approvers[] is absent it
# falls back to the producer's strict summary count (the summary is always
# computed at the strictest filtering, so it is a safe floor; a per-reviewer
# filter requested without approvers[] raises the recompute incompleteness
# violation elsewhere rather than silently trusting the wrong number).
#
# In v0.1 the recompute equals the strict summary, so the min() is purely an
# INFLATION CROSS-CHECK — it catches a (buggy/forged) producer that reports a
# higher distinctApprovers than its own approvers[] supports — not a tightening.
# Do NOT "simplify" it to summary.distinctApprovers: that re-opens that cross-check
# and the v0.2 path where a tightening filter recomputes below the summary.
effective_distinct(payload) := min([recompute_distinct(payload), payload.predicate.summary.distinctApprovers]) if {
	can_recompute(payload)
} else := payload.predicate.summary.distinctApprovers

# structurally_valid is true only when the predicate carries every field the gate
# relies on, with the right type. The gate consumes a signed-but-otherwise-
# untrusted predicate and is NOT re-validated against the schema at eval time, so
# a missing/mistyped field would otherwise make a lookup UNDEFINED and silently
# skip a gate (fail-open). The policy fires a violation when this is false, so a
# malformed predicate fails CLOSED.
structurally_valid(payload) if {
	s := payload.predicate.summary
	is_number(s.approvals)
	is_number(s.distinctApprovers)
	is_number(s.changesRequested)
	is_number(s.requiredApprovals)
	is_boolean(s.requirementMet)
	is_boolean(s.selfApprovalExcluded)
	_codeowner_typed(s)
	is_boolean(payload.predicate.approversIncluded)
	is_boolean(payload.predicate.reviewToolingComplete)
	every a in object.get(payload.predicate, "approvers", []) {
		is_boolean(a.stale)
		is_boolean(a.isBot)
	}
}

# codeownerReviewMet is tri-state: boolean or JSON null (not determinable).
_codeowner_typed(s) if is_boolean(s.codeownerReviewMet)

_codeowner_typed(s) if is_null(s.codeownerReviewMet)
