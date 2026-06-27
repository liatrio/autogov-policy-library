# METADATA
# scope: package
# title: Source Review Common Helpers
# description: Shared helpers for source-review gating — recompute over approvers[] or degrade to the summary.
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
package security.source_review_common

import data.source_level_config
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

	# counts must be non-negative — a forged negative (e.g. changesRequested: -1)
	# would otherwise pass is_number and slip the count-based gates (n > 0 false).
	_non_negative_int(s.approvals)
	_non_negative_int(s.distinctApprovers)
	_non_negative_int(s.changesRequested)
	_non_negative_int(s.requiredApprovals)
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

# _non_negative_int is true for an integer >= 0 (the valid range for every count).
_non_negative_int(v) if {
	is_number(v)
	v >= 0
	v == floor(v)
}

# codeownerReviewMet is tri-state: boolean or JSON null (not determinable).
_codeowner_typed(s) if is_boolean(s.codeownerReviewMet)

_codeowner_typed(s) if is_null(s.codeownerReviewMet)

# --- source-level (source-control posture) helpers ---
#
# These mirror the verifier's promotion logic (autogov pkg/source/review.go
# ComputeSourceLevelFromControls) so the source_level gate can ENFORCE the same
# L3 posture the verifier would PROMOTE to. They read predicate.technicalControls
# (an object SIBLING of summary) and predicate.continuityStartRevision (a string
# sibling of technicalControls — NOT inside it).

# has_technical_controls is true when the predicate carries a technicalControls
# object. The source_level gate REQUIRES it (fail closed) when enabled; the
# source_review gate does not (so it stays inert for predicates lacking it).
has_technical_controls(payload) if is_object(payload.predicate.technicalControls)

# technical_controls_valid type-checks every technicalControls field the posture
# gate relies on, WHEN PRESENT. The predicate is signed-but-otherwise-untrusted
# and is NOT re-validated against the schema at eval time, so a missing/mistyped
# field would make a lookup UNDEFINED and silently skip a leg (fail open). The gate
# fires a violation when this is false, so a malformed technicalControls fails
# CLOSED. continuityStartRevision is a sibling string and is checked here too.
#
# continuityComplete (v0.2) is checked ONLY WHEN PRESENT: a v0.1 bundle omits it
# entirely (and continuity_recorded's `== true` then reads undefined -> the
# continuity leg fails closed elsewhere), while a v0.2 bundle that carries a
# MISTYPED continuityComplete (e.g. a string) is malformed and must fail here so the
# field/typecheck coupling the source_level NOTE mandates holds.
technical_controls_valid(payload) if {
	tc := payload.predicate.technicalControls
	is_boolean(tc.forcePushBlocked)
	is_boolean(tc.requiredLinearHistory)
	is_boolean(tc.deletionBlocked)
	is_boolean(tc.requiredSignatures)
	is_boolean(tc.bypassActorsComplete)
	_string_array(tc.requiredStatusChecks)
	_string_array(tc.bypassActors)
	is_string(payload.predicate.continuityStartRevision)
	_continuity_complete_typed(tc)
}

# _continuity_complete_typed accepts a technicalControls that either OMITS
# continuityComplete (v0.1) or carries it as a boolean (v0.2). A present-but-mistyped
# value (string/number/null) fails -> malformed -> fail closed.
_continuity_complete_typed(tc) if not _has_key(tc, "continuityComplete")

_continuity_complete_typed(tc) if is_boolean(tc.continuityComplete)

# _has_key reports whether object o has key k (object.get with a sentinel default).
_has_key(o, k) if object.get(o, k, null) != null

_has_key(o, k) if {
	object.get(o, k, "__absent__") == null # key present with an explicit null value
}

# _string_array is true for an array whose every element is a string.
_string_array(v) if {
	is_array(v)
	every e in v {
		is_string(e)
	}
}

# meets_l3_posture mirrors ComputeSourceLevelFromControls' controlsMet:
#   forcePushBlocked AND count(requiredStatusChecks) > 0
#   AND (requiredLinearHistory OR deletionBlocked)
#   AND bypassActorsComplete == true AND every bypass actor is narrow.
# FAIL CLOSED: bypassActorsComplete != true means the bypass posture is UNKNOWN
# (an empty bypassActors with complete=false is UNKNOWN, not "none"), so the leg
# fails. requiredSignatures is NOT part of L3 here (the verifier surfaces it only
# as an annotation); the require_signed_commits flag layers it on separately.
meets_l3_posture(payload) if {
	tc := payload.predicate.technicalControls
	tc.forcePushBlocked == true
	count(tc.requiredStatusChecks) > 0
	_retained_history(tc)
	tc.bypassActorsComplete == true
	narrow_bypass(tc.bypassActors)
}

_retained_history(tc) if tc.requiredLinearHistory == true

_retained_history(tc) if tc.deletionBlocked == true

# narrow_bypass mirrors bypassActorsAllNarrow: an empty list (no bypass at all) is
# narrow; otherwise EVERY recorded actor's "<Type>:<ID>" (the formatted entry is
# "<Type>:<ID>:<Mode>", so the trailing ":<Mode>" is dropped) must be in the
# configured allowed_bypass_actors allowlist. With the default empty allowlist the
# only narrow posture is "no bypass actors", matching the verifier called with a
# nil allowedBypass. An unrecognized actor fails the leg (no L3).
narrow_bypass(actors) if count(actors) == 0

narrow_bypass(actors) if {
	count(actors) > 0
	every a in actors {
		_actor_allowed(a)
	}
}

# _actor_allowed strips the trailing ":<Mode>" segment (matching the verifier's
# LastIndex(":") split) and checks the remaining "<Type>:<ID>" against the
# allowlist. is_string guards fail closed: a non-string actor cannot match.
_actor_allowed(a) if {
	is_string(a)
	_type_id(a) in source_level_config.allowed_bypass_actors
}

# _type_id drops the trailing ":<Mode>" suffix when present, else returns the whole
# string (mirrors strings.LastIndex(actor, ":") in the verifier).
_type_id(a) := substring(a, 0, i) if {
	i := _last_colon(a)
	i >= 0
} else := a

# _last_colon returns the index of the last ":" in s, or -1 when absent.
_last_colon(s) := i if {
	idxs := [n | some n in numbers.range(0, count(s) - 1); substring(s, n, 1) == ":"]
	count(idxs) > 0
	i := idxs[count(idxs) - 1]
} else := -1

# continuity_recorded is true ONLY when the producer ASSERTS a proven no-gap
# window: technicalControls.continuityComplete == true AND continuityStartRevision
# is a non-empty string. This mirrors the verifier's fail-closed
# `tc.ContinuityComplete && TrimSpace(start) != ""` (autogov pkg/source/review.go).
#
# A non-empty start alone is NOT enough: a v0.1 bundle has no continuityComplete
# field (lookup UNDEFINED -> this rule is undefined -> the continuity violation
# fires), and a v0.2 bundle that could not prove the window sets
# continuityComplete=false (and an empty start). Either way continuity stays
# UNDETERMINED and the L3-continuity leg fails closed -> the gate is DORMANT until
# a genuine proof lands.
continuity_recorded(payload) if {
	payload.predicate.technicalControls.continuityComplete == true
	rev := payload.predicate.continuityStartRevision
	is_string(rev)
	trim_space(rev) != ""
}
