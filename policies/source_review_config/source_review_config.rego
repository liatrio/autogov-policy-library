# METADATA
# scope: package
# title: Source Review Configuration
# description: Source-review (PR-approval) gating thresholds and flags with overridable defaults.
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
# custom:
#  version: 0.1.0
#  path: policies/source_review_config
#  filename: source_review_config.rego
package source_review_config

import rego.v1

# Resolved configuration for the source-review gating policy.
# Override at runtime via --policy-data-path with JSON under the key
# "source_review_thresholds" (DISTINCT from this package name to avoid OPA v1
# conflicts between external data and the Rego package path).
#
# Every override is TYPE-CHECKED: a value of the wrong type (e.g. a quoted
# number "2", or a string for a boolean flag) is rejected and the safe default
# is used instead, so a config typo fails closed rather than silently disabling
# a gate.
#
# The per-reviewer flags (disallow_self_approval / require_non_stale /
# allow_bot_approvals / require_codeowner_review) can only TIGHTEN gating. The
# producer already computes summary.distinctApprovers at the strictest filtering
# (author, stale, dismissed, changes-requested, and bot reviewers excluded), so
# these flags never loosen that floor; they additionally require the per-approver
# list to be present (see source_review_common.recompute_required).
# regal ignore:unresolved-reference
_cfg := data.source_review_thresholds

# --- approval thresholds ---

# Minimum number of distinct qualifying approvals required. Default 1 (inert-ish
# day-one, non-breaking); the strict preset ships 2 (two-person review).
default min_approvals := 1

min_approvals := _cfg.min_approvals if {
	is_number(_cfg.min_approvals)
}

# --- flags ---

# Whether a source-review attestation must be present. Default false so the
# policy is inert for artifacts without one.
default require_source_review := false

require_source_review := _cfg.require_source_review if {
	is_boolean(_cfg.require_source_review)
}

# Exclude the PR author's own approval. Default true. (The producer already
# excludes self-approval; this flag drives per-approver recompute requirements
# and documents intent — it cannot loosen the producer's exclusion.)
default disallow_self_approval := true

disallow_self_approval := _cfg.disallow_self_approval if {
	is_boolean(_cfg.disallow_self_approval)
}

# Exclude stale approvals (approval not on the PR head). Default true.
default require_non_stale := true

require_non_stale := _cfg.require_non_stale if {
	is_boolean(_cfg.require_non_stale)
}

# Count bot approvals toward the threshold. Default false (humans only).
default allow_bot_approvals := false

allow_bot_approvals := _cfg.allow_bot_approvals if {
	is_boolean(_cfg.allow_bot_approvals)
}

# Require CODEOWNER review. Default false: REST-only cannot authoritatively
# determine CODEOWNERS, so codeownerReviewMet is null and turning this on fails
# closed on every attestation until a future version adds the needed evidence.
default require_codeowner_review := false

require_codeowner_review := _cfg.require_codeowner_review if {
	is_boolean(_cfg.require_codeowner_review)
}

# Block when any reviewer's latest opinionated state is CHANGES_REQUESTED,
# regardless of approval count. Default true (necessary-but-not-sufficient
# gate: approvals alone never pass while a change request stands).
default block_on_changes_requested := true

block_on_changes_requested := _cfg.block_on_changes_requested if {
	is_boolean(_cfg.block_on_changes_requested)
}

# Fail when the review evidence could not be fully gathered
# (reviewToolingComplete=false). Default true. (The separate per-approver and
# codeowner incompleteness guards are NOT governed by this flag; they always fire.)
default fail_on_incomplete_review := true

fail_on_incomplete_review := _cfg.fail_on_incomplete_review if {
	is_boolean(_cfg.fail_on_incomplete_review)
}
