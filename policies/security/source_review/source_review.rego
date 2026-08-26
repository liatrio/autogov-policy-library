# METADATA
# scope: package
# title: Source Review Policy
# description: Gates autogov source-review (PR-approval) attestations against a configurable review bar.
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
# custom:
#  version: 1.1.5
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
	msg := "source-review predicate is malformed (missing or mistyped summary, approvers, or top-level fields)"
	some payload in sr_payloads
	not common.structurally_valid(payload)
}

# Violation: the review evidence could not be fully gathered (no merged PR — a
# direct push or the ListPullRequestsWithCommit default-branch quirk — or reviews
# were unfetchable). Governed by fail_on_incomplete_review (default false).
violations contains msg if {
	msg := "source-review reports incomplete review tooling (reviewToolingComplete=false)"
	source_review_config.fail_on_incomplete_review == true
	some payload in sr_payloads
	payload.predicate.reviewToolingComplete == false
}

# Violation: per-reviewer gating was requested (disallow_self_approval /
# require_non_stale / allow_bot_approvals=false / require_codeowner_review) but the
# attestation does not embed approvers[], so the summary cannot be verified under
# those filters. ALWAYS fires (never a silent no-op) — decoupled from
# fail_on_incomplete_review, which governs review-evidence completeness, not the
# contradiction of requesting per-approver gating without per-approver data.
violations contains msg if {
	msg := concat("", [
		"source-review gating needs per-approver data ",
		"(disallow_self_approval/require_non_stale/allow_bot_approvals/require_codeowner_review) ",
		"but approvers are excluded; regenerate with --include-approvers",
	])
	common.recompute_required == true
	some payload in sr_payloads
	not common.can_recompute(payload)
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
	_insufficient_approvals(n, source_review_config.min_approvals)
	msg := _distinct_approval_msg(n, source_review_config.min_approvals)
}

# Violation: an outstanding CHANGES_REQUESTED review blocks regardless of the
# approval count (necessary-but-not-sufficient). NOT guarded by review
# completeness: the producer emits changesRequested > 0 only when reviews were
# actually fetched, so a positive count is never an incompleteness artifact and
# must block even when incomplete-review evidence is otherwise tolerated
# (fail_on_incomplete_review=false). Bot/self requests are already excluded by the
# producer; a later dismissal clears it. Gated by _changes_requested_present, not
# a bare `n > 0`: Rego's total ordering only ranks strings (and arrays/objects)
# above numbers, not null/booleans, so a forged `changesRequested: null` or
# `true` would silently fail `n > 0` and skip this violation -- the same
# ordering-accident class _insufficient_approvals guards against below. A forged
# non-numeric value of ANY type must always count as present.
violations contains msg if {
	source_review_config.block_on_changes_requested == true
	some payload in sr_payloads
	n := payload.predicate.summary.changesRequested
	_changes_requested_present(n)
	msg := _changes_requested_msg(n)
}

# Violation: CODEOWNER review required but not met or not determinable. Decoupled
# from fail_on_incomplete_review so it cannot be regressed by that flag. Because
# codeownerReviewMet is tri-state and REST-only leaves it null, turning this on
# fails closed until a future version can authoritatively determine it.
violations contains msg if {
	msg := "source-review: codeowner review is required but not met or not determinable"
	source_review_config.require_codeowner_review == true
	some payload in sr_payloads
	payload.predicate.summary.codeownerReviewMet != true
}

# Violation: a required-approver-association allowlist is enforced but no qualifying
# approver carries an association in it. Inert by default (empty set => never fires).
# Fails CLOSED when approvers[] is not authoritative (approversIncluded=false): the
# associations cannot be verified, so the allowlist cannot be satisfied. Copies the
# bypass policy's authorized-by-association handling: a qualifying approver is
# non-stale, non-bot, with a string association in the set.
violations contains msg if {
	msg := "source-review: no approver association in the required allowlist"
	count(source_review_config.required_approver_associations) > 0
	some payload in sr_payloads
	not _assoc_satisfied(payload)
}

# Violation: min_approvals is configured as 0 (a zero-approval-authorized build,
# e.g. a release's own self-verify) but the actual merger is not on the
# zero_approval_merger_allowlist. Inert by default: with an empty allowlist (the
# default) this never fires regardless of mergedById, so the gate ships opt-in per
# repo (count(...) > 0 guard). Once populated, fires when mergedById is
# absent/zero (the producer's supplemental GET failed, or no merger was ever
# recorded) OR present but not listed -- either way an unauthorized zero-approval
# merge fails closed. The ambiguity between "fetch failed" and "genuinely absent"
# is an accepted risk (see config/examples/README.md), not engineered around here.
#
# Intentionally NOT grandfathered / enforced_since-exempted: this evaluates the
# CURRENT policy configuration against the CURRENT merger identity at
# verification time, rather than retroactively re-litigating historical merges
# the way the approval-count violation above is, so no exemption window applies.
#
# Scope: the design assumes human User-type mergers (the release-bot,
# Integration:801323, is out of scope -- it doesn't merge via the 0-approval
# self-verify path today). This rule only checks a numeric mergedById; it does
# NOT itself enforce merger type.
violations contains msg if {
	source_review_config.min_approvals == 0
	count(source_review_config.zero_approval_merger_allowlist) > 0
	some payload in sr_payloads
	merger_id := object.get(payload.predicate, ["pullRequest", "mergedById"], 0)
	not merger_id in source_review_config.zero_approval_merger_allowlist
	present := object.get(payload.predicate, ["pullRequest", "mergedById"], null) != null
	msg := _zero_approval_merger_msg(merger_id, present)
}

# _insufficient_approvals decides whether the distinct-approval-count violation
# above should fire. A forged non-numeric n (e.g. a string) ALWAYS counts as
# insufficient: Rego's total value ordering ranks strings above numbers, so a
# bare `n < min_approvals` comparison would silently (and accidentally) evaluate
# to false for a forged string, letting it slip past the gate by ordering
# accident rather than by design.
_insufficient_approvals(n, min_approvals) if {
	is_number(n)
	n < min_approvals
}

_insufficient_approvals(n, _) if {
	not is_number(n)
}

# _clean_int is true for a value that formats safely with a %d verb: numeric,
# non-negative, and whole-valued. is_number(n) ALONE is not enough: JSON (and
# Rego) does not distinguish int from float, so a whole-number value written
# with a decimal point (e.g. 1.0, however it arrived -- a forged predicate or an
# honest producer/JSON round-trip) is still a Go float64 under the hood, and %d
# garbles it as "%!d(float64=1)" exactly like a non-numeric string does. n ==
# floor(n) confirms it is whole-valued; the %d call site must then format
# floor(n) (not the raw n) to get a clean result -- floor() re-derives the
# number in a representation %d accepts. n >= 0 rejects a forged negative count
# (e.g. -5), which would otherwise format "cleanly" but nonsensically -- every
# quantity this predicate guards (approval counts, review counts, user IDs) is
# inherently non-negative, matching common._non_negative_int's convention.
_clean_int(n) if {
	is_number(n)
	n >= 0
	n == floor(n)
}

# _changes_requested_present decides whether the changes-requested violation
# above should fire. A forged non-numeric n (of ANY type -- string, null,
# boolean, array, object) ALWAYS counts as present: Rego's total value ordering
# only ranks strings/arrays/objects above numbers, NOT null/booleans, so a bare
# `n > 0` comparison would silently (and accidentally) evaluate to false for a
# forged `null` or `true`, letting it slip past the gate by ordering accident
# rather than by design -- the same class _insufficient_approvals guards below.
_changes_requested_present(n) if {
	is_number(n)
	n > 0
}

_changes_requested_present(n) if {
	not is_number(n)
}

# _distinct_approval_msg builds a clear, non-garbled message for the
# distinct-approval-count violation above, mirroring _zero_approval_merger_msg's
# style below. min_approvals is always a validated, non-negative number (never a
# forged string -- source_review_config's own validation rejects a non-numeric
# override and falls back to the default), but config validation permits a
# whole-number float (e.g. 2.0), so it is defensively floored at every %d call
# site below, same as n. n itself gets a three-way split so the message never
# claims a numeric value "is not numeric": _clean_int(n) formats cleanly;
# is_number(n) but not _clean_int(n) (negative or fractional) says so precisely;
# not is_number(n) is the true not-numeric case.
_distinct_approval_msg(n, min_approvals) := msg if {
	_clean_int(n)
	msg := sprintf("source-review: %d distinct approval(s), need at least %d", [floor(n), floor(min_approvals)])
}

_distinct_approval_msg(n, min_approvals) := msg if {
	is_number(n)
	not _clean_int(n)
	msg := sprintf(
		"source-review: distinct approval count %v is not a non-negative whole number, need at least %d",
		[n, floor(min_approvals)],
	)
}

_distinct_approval_msg(n, min_approvals) := msg if {
	not is_number(n)
	msg := sprintf(
		"source-review: distinct approval count is not numeric (%q), need at least %d",
		[n, floor(min_approvals)],
	)
}

# _changes_requested_msg builds a clear, non-garbled message for the
# changes-requested violation above, mirroring _zero_approval_merger_msg's style
# below. Same three-way split as _distinct_approval_msg, for the same reason.
_changes_requested_msg(n) := msg if {
	_clean_int(n)
	msg := sprintf("source-review: %d outstanding changes-requested review(s)", [floor(n)])
}

_changes_requested_msg(n) := msg if {
	is_number(n)
	not _clean_int(n)
	msg := sprintf(
		"source-review: changesRequested value %v is not a non-negative whole number, treating as an outstanding review",
		[n],
	)
}

_changes_requested_msg(n) := msg if {
	not is_number(n)
	msg := sprintf("source-review: changesRequested is not numeric (%q), treating as an outstanding review", [n])
}

# _zero_approval_merger_msg builds a clear, non-garbled message for the violation
# above, on the same three-way split as _distinct_approval_msg /
# _changes_requested_msg (this is the helper they were written to mirror --
# gated on _clean_int, not bare is_number, so a whole-number-float mergedById
# such as 138915.0 gets floor()'d instead of garbling %d exactly like the other
# two would have without that guard). Distinguishes "absent" from "present but
# literally 0" via the `present` flag, best-effort (mergedById:0 is not
# producer-reachable today -- Go's omitempty never emits a literal 0 -- but the
# field is structurally valid per _non_negative_int, so this is worth getting
# right for a forged/future input). merger_id == 0 is a plain numeric equality
# check (true for both the int 0 and the float 0.0), so it is unaffected by and
# checked ahead of the _clean_int split below.
_zero_approval_merger_msg(merger_id, _) := msg if {
	merger_id != 0
	_clean_int(merger_id)
	msg := sprintf("source-review: merger %d is not on the zero-approval-merger allowlist", [floor(merger_id)])
}

_zero_approval_merger_msg(merger_id, true) := msg if {
	merger_id == 0
	msg := "source-review: mergedById is 0 (present but zero) and not on the zero-approval-merger allowlist"
}

_zero_approval_merger_msg(merger_id, false) := msg if {
	merger_id == 0
	msg := "source-review: merger identity is absent (mergedById missing) and not on the zero-approval-merger allowlist"
}

_zero_approval_merger_msg(merger_id, _) := msg if {
	merger_id != 0
	is_number(merger_id)
	not _clean_int(merger_id)
	msg := sprintf(
		"source-review: mergedById %v is not a non-negative whole number, not on the zero-approval-merger allowlist",
		[merger_id],
	)
}

_zero_approval_merger_msg(merger_id, _) := msg if {
	not is_number(merger_id)
	msg := sprintf("source-review: mergedById is not numeric (%q), not on the zero-approval-merger allowlist", [merger_id])
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
