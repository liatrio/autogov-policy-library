# METADATA
# scope: package
# title: Dependency-Vulnerability Bypass Authorization
# description: Authorizes the dependency-vulnerability bypass when an attested source-review approves it.
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
# custom:
#  version: 0.20.0
#  path: policies/security/bypass
#  filename: bypass.rego
package security.bypass

import data.bypass_config
import data.security.source_review_common as common
import data.shared.utils
import rego.v1

# source-review attestations present in the input.
sr_payloads := [payload |
	some payload in utils.decoded_payload_list
	utils.is_source_review(payload)
]

# requested is the opt-in trigger: the raw (unauthenticated) request flag on the
# verify input. It expresses INTENT to bypass; authorization is separate and lives
# in dep_vuln_authorized.
requested if {
	some x in input
	x.ignore_dependency_vulnerabilities
}

# dep_vuln_authorized is true only when an attested source-review proves the bypass
# was approved by enough authorized reviewers. It fails CLOSED on bad config, a
# missing/malformed/incomplete source-review, or too few authorized approvals — so
# the raw request flag can never skip the dependency-vulnerability gate on its own.
default dep_vuln_authorized := false

dep_vuln_authorized if {
	# bad config never authorizes (also surfaced as a blocking violation below)
	count(bypass_config.config_errors) == 0

	# capability must be explicitly enabled (inert by default)
	bypass_config.allow_dep_vuln_bypass

	# evidence: a structurally-valid, recomputable, complete source-review
	some payload in sr_payloads
	common.structurally_valid(payload)

	# approversIncluded==true — else a forged approversIncluded=false could embed
	# approvers[] the producer claims it did not include; this closes that.
	common.can_recompute(payload)

	# incomplete evidence never authorizes
	payload.predicate.reviewToolingComplete == true

	# enough distinct, authorized, non-stale, non-bot approvals
	authorized_approvals(payload) >= bypass_config.bypass_min_approvals
}

# authorized_approvals is the distinct-approver count to gate on. It counts DISTINCT
# authorized logins (a duplicated approvers[] entry can never inflate the count) and
# takes the MINIMUM with the producer's strict summary.distinctApprovers — the same
# inflation cross-check security.source_review_common.effective_distinct applies, so
# a padded approvers[] can only ever tighten, never loosen, the count. Keyed on
# login: an approver with no string login is simply not counted (fail closed).
# summary.distinctApprovers is type-checked by structurally_valid, a precondition of
# dep_vuln_authorized above.
authorized_approvals(payload) := min([
	count({a.login |
		some a in object.get(payload.predicate, "approvers", [])
		not a.stale
		not a.isBot
		is_string(a.login)
		_authorized(a)
	}),
	payload.predicate.summary.distinctApprovers,
])

# _authorized: an approver is authorized by association OR by explicit login.
# Defensive is_string guards — structurally_valid does NOT type-check
# association/login, and `in` over a missing/mistyped value fails closed (the
# approver is simply not counted) rather than erroring.
_authorized(a) if {
	is_string(a.association)
	a.association in bypass_config.authorized_associations
}

_authorized(a) if {
	is_string(a.login)
	a.login in bypass_config.authorized_approvers
}

# --- gate hook wired into governance ---

# violations carries ONLY the malformed-config-when-requested message. The
# authorization decision lives in dep_vuln_authorized, never here.
#
# Inverted-polarity divergence from source_review.rego's UNCONDITIONAL config_errors
# violation: the bypass is opt-in, so an unconditional config-error violation would
# turn a bypass_thresholds typo into a repo-wide outage for artifacts that never
# request a bypass. So gate it on bypass_requested. It cannot fail open: when no
# bypass is requested, config validity is irrelevant (the dep-vuln gate enforces
# regardless); when one IS requested, dep_vuln_authorized already requires
# config_errors==0, so a malformed config never honors the bypass — surfacing it
# just makes the fail-closed decision visible and blocking until the config is fixed.
violations contains msg if {
	requested
	some err in bypass_config.config_errors
	msg := sprintf("dependency-vulnerability bypass configuration is invalid: %s", [err])
}

default allow := false

allow if {
	count(violations) == 0
}
