package security.bypass_test

import data.security.bypass
import rego.v1

# --- builders ---

_env(predicate) := {"dsseEnvelope": {"payload": base64.encode(json.marshal({
	"predicateType": "https://autogov.dev/attestation/source-review/v0.1",
	"predicate": predicate,
}))}}

# an approver with configurable login / association / stale / isBot
approver(login, association, stale, isbot) := {
	"login": login,
	"association": association,
	"stale": stale,
	"isBot": isbot,
}

# strict distinct count the producer would emit (not stale, not bot).
_strict(approvers) := count([a |
	some a in approvers
	a.stale == false
	a.isBot == false
])

_summary(distinct) := {
	"approvals": distinct,
	"distinctApprovers": distinct,
	"changesRequested": 0,
	"requiredApprovals": 0,
	"requirementMet": true,
	"selfApprovalExcluded": false,
	"codeownerReviewMet": null,
}

# source-review attestation input with approvers[] embedded.
sr(approvers, included, complete) := [_env({
	"sourceRepository": "https://github.com/liatrio/autogov",
	"sourceRevision": "abc123",
	"summary": _summary(_strict(approvers)),
	"approversIncluded": included,
	"approvers": approvers,
	"reviewToolingComplete": complete,
})]

# arbitrary-predicate input (for malformed-predicate cases).
sr_raw(predicate) := [_env(predicate)]

# feature enabled, min 2, default associations (OWNER/MEMBER).
_enabled := {"allow_dep_vuln_bypass": true, "bypass_min_approvals": 2}

# two authorized (OWNER/MEMBER), non-stale, non-bot approvers.
_two_authorized := [
	approver("alice", "OWNER", false, false),
	approver("bob", "MEMBER", false, false),
]

# --- dep_vuln_authorized: authorized happy path (the feature) ---

test_authorized_two_owner_member_approvals if {
	inp := sr(_two_authorized, true, true)

	# regal ignore:unresolved-reference
	bypass.dep_vuln_authorized with input as inp with data.bypass_thresholds as _enabled
}

# login-allowlist path is OR-ed with associations.
test_authorized_via_login_allowlist if {
	inp := sr([approver("carol", "CONTRIBUTOR", false, false)], true, true)
	cfg := {"allow_dep_vuln_bypass": true, "bypass_min_approvals": 1, "authorized_approvers": ["carol"]}

	# regal ignore:unresolved-reference
	bypass.dep_vuln_authorized with input as inp with data.bypass_thresholds as cfg
}

# --- inert / fail-closed ---

# feature off (default, no config) -> never authorizes, even with enough approvals.
test_inert_when_feature_off if {
	not bypass.dep_vuln_authorized with input as sr(_two_authorized, true, true)
}

# no source-review attestation present -> nothing to authorize against.
test_no_attestation_not_authorized if {
	inp := [{"ignore_dependency_vulnerabilities": true}]

	# regal ignore:unresolved-reference
	not bypass.dep_vuln_authorized with input as inp with data.bypass_thresholds as _enabled
}

# --- under-authorization ---

test_under_count_not_authorized if {
	inp := sr([approver("alice", "OWNER", false, false)], true, true)

	# regal ignore:unresolved-reference
	not bypass.dep_vuln_authorized with input as inp with data.bypass_thresholds as _enabled
}

test_wrong_association_not_counted if {
	inp := sr([approver("a", "CONTRIBUTOR", false, false), approver("b", "NONE", false, false)], true, true)

	# regal ignore:unresolved-reference
	not bypass.dep_vuln_authorized with input as inp with data.bypass_thresholds as _enabled
}

test_bot_approver_not_counted if {
	inp := sr([approver("alice", "OWNER", false, false), approver("bot", "MEMBER", false, true)], true, true)

	# regal ignore:unresolved-reference
	not bypass.dep_vuln_authorized with input as inp with data.bypass_thresholds as _enabled
}

test_stale_approver_not_counted if {
	inp := sr([approver("alice", "OWNER", false, false), approver("bob", "MEMBER", true, false)], true, true)

	# regal ignore:unresolved-reference
	not bypass.dep_vuln_authorized with input as inp with data.bypass_thresholds as _enabled
}

# approversIncluded=false fails closed even if approvers[] is embedded (a forged
# predicate could claim it did not include them yet embed counted approvers).
test_approvers_not_included_fails_closed if {
	inp := sr(_two_authorized, false, true)

	# regal ignore:unresolved-reference
	not bypass.dep_vuln_authorized with input as inp with data.bypass_thresholds as _enabled
}

# incomplete review evidence never authorizes.
test_incomplete_review_not_authorized if {
	inp := sr(_two_authorized, true, false)

	# regal ignore:unresolved-reference
	not bypass.dep_vuln_authorized with input as inp with data.bypass_thresholds as _enabled
}

# malformed predicate (summary.approvals is a string) -> structurally_valid denies.
test_malformed_predicate_not_authorized if {
	inp := sr_raw({
		"sourceRepository": "https://github.com/liatrio/autogov",
		"sourceRevision": "abc123",
		"summary": {
			"approvals": "2",
			"distinctApprovers": 2,
			"changesRequested": 0,
			"requiredApprovals": 0,
			"requirementMet": true,
			"selfApprovalExcluded": false,
			"codeownerReviewMet": null,
		},
		"approversIncluded": true,
		"approvers": _two_authorized,
		"reviewToolingComplete": true,
	})

	# regal ignore:unresolved-reference
	not bypass.dep_vuln_authorized with input as inp with data.bypass_thresholds as _enabled
}

# a non-string association is not counted (the `in` check fails closed via the
# is_string guard); structurally_valid does NOT type-check association, so the
# attestation is otherwise valid — proving the guard is what closes it.
test_non_string_association_not_counted if {
	approvers := [
		{"login": "alice", "association": 42, "stale": false, "isBot": false},
		{"login": "bob", "association": 7, "stale": false, "isBot": false},
	]

	# regal ignore:unresolved-reference
	not bypass.dep_vuln_authorized with input as sr(approvers, true, true) with data.bypass_thresholds as _enabled
}

# --- config validation fails closed ---

test_unknown_config_key_not_authorized if {
	cfg := {"allow_dep_vuln_bypass": true, "bypass_min_aprovals": 2}

	# regal ignore:unresolved-reference
	not bypass.dep_vuln_authorized with input as sr(_two_authorized, true, true) with data.bypass_thresholds as cfg
}

test_wrong_typed_config_not_authorized if {
	cfg := {"allow_dep_vuln_bypass": "true", "bypass_min_approvals": 2}

	# regal ignore:unresolved-reference
	not bypass.dep_vuln_authorized with input as sr(_two_authorized, true, true) with data.bypass_thresholds as cfg
}

test_negative_min_approvals_not_authorized if {
	cfg := {"allow_dep_vuln_bypass": true, "bypass_min_approvals": -1}

	# regal ignore:unresolved-reference
	not bypass.dep_vuln_authorized with input as sr(_two_authorized, true, true) with data.bypass_thresholds as cfg
}

test_non_string_array_config_not_authorized if {
	cfg := {"allow_dep_vuln_bypass": true, "bypass_min_approvals": 1, "authorized_associations": ["OWNER", 5]}

	# regal ignore:unresolved-reference
	not bypass.dep_vuln_authorized with input as sr(_two_authorized, true, true) with data.bypass_thresholds as cfg
}

# --- violations / allow (the gate hook) ---

# malformed config + bypass requested -> a blocking violation, allow false.
test_violation_on_malformed_config_when_requested if {
	inp := [{"ignore_dependency_vulnerabilities": true}]
	cfg := {"bypass_min_aprovals": 2}

	# regal ignore:unresolved-reference
	count(bypass.violations) > 0 with input as inp with data.bypass_thresholds as cfg

	# regal ignore:unresolved-reference
	not bypass.allow with input as inp with data.bypass_thresholds as cfg
}

# malformed config but NO bypass requested -> no violation, allow true (opt-in).
test_no_violation_when_not_requested if {
	inp := [{"ignore_dependency_vulnerabilities": false}]
	cfg := {"bypass_min_aprovals": 2}

	# regal ignore:unresolved-reference
	count(bypass.violations) == 0 with input as inp with data.bypass_thresholds as cfg

	# regal ignore:unresolved-reference
	bypass.allow with input as inp with data.bypass_thresholds as cfg
}

# clean config + bypass requested -> no violation, allow true (no effect on its
# own; the authorization decision lives in dep_vuln_authorized, not violations).
test_no_violation_on_clean_config_when_requested if {
	inp := [{"ignore_dependency_vulnerabilities": true}]

	# regal ignore:unresolved-reference
	count(bypass.violations) == 0 with input as inp with data.bypass_thresholds as _enabled

	# regal ignore:unresolved-reference
	bypass.allow with input as inp with data.bypass_thresholds as _enabled
}

# --- distinct-approver counting / inflation cross-check ---

# a duplicated approver login counts ONCE — a single identity listed twice cannot
# clear a two-person bar. sr() builds summary.distinctApprovers from the array
# length (2 here — an inflated summary), yet the distinct-login count + min() floor
# both reject it. Before the distinct fix this authorized (count([alice,alice])=2).
test_duplicate_login_counted_once if {
	dup := [approver("alice", "OWNER", false, false), approver("alice", "OWNER", false, false)]

	# regal ignore:unresolved-reference
	not bypass.dep_vuln_authorized with input as sr(dup, true, true) with data.bypass_thresholds as _enabled
}

# an HONEST summary (distinctApprovers=1) with a padded approvers[] (alice listed
# twice) must not authorize a min-2 bypass — the inflation cross-check floors the
# recomputed count against the producer's strict summary, mirroring the v0.1
# source_review gate (which blocks the identical payload).
test_honest_summary_padded_approvers_not_authorized if {
	pred := {
		"sourceRepository": "https://github.com/liatrio/autogov",
		"sourceRevision": "abc123",
		"summary": _summary(1),
		"approversIncluded": true,
		"approvers": [approver("alice", "OWNER", false, false), approver("alice", "OWNER", false, false)],
		"reviewToolingComplete": true,
	}

	# regal ignore:unresolved-reference
	not bypass.dep_vuln_authorized with input as sr_raw(pred) with data.bypass_thresholds as _enabled
}

# an approver authorized BY ASSOCIATION but carrying a non-string login (e.g. a
# forged numeric login) is NOT counted toward the distinct bar. structurally_valid
# does not type-check login, so the input reaches authorized_approvals; the
# is_string(a.login) guard on the count comprehension drops it (fail closed).
# Without the guard, two distinct numeric keys (1, 2) would clear a min-2 bypass.
test_non_string_login_by_association_not_counted if {
	numeric := [approver(1, "OWNER", false, false), approver(2, "MEMBER", false, false)]

	# regal ignore:unresolved-reference
	not bypass.dep_vuln_authorized with input as sr(numeric, true, true) with data.bypass_thresholds as _enabled
}

# --- min_approvals must be positive ---

# bypass_min_approvals: 0 is rejected (a zero-approval bypass is nonsensical) -> not
# authorized even with valid approvals, and surfaces as a config error when a bypass
# is requested. Disabling the capability is done via allow_dep_vuln_bypass=false.
test_zero_min_approvals_rejected if {
	cfg := {"allow_dep_vuln_bypass": true, "bypass_min_approvals": 0}
	inp := [{"ignore_dependency_vulnerabilities": true}]

	# regal ignore:unresolved-reference
	not bypass.dep_vuln_authorized with input as sr(_two_authorized, true, true) with data.bypass_thresholds as cfg

	# regal ignore:unresolved-reference
	count(bypass.violations) > 0 with input as inp with data.bypass_thresholds as cfg
}

# a fractional bypass_min_approvals is out of range -> config error -> not authorized.
test_fractional_min_approvals_not_authorized if {
	cfg := {"allow_dep_vuln_bypass": true, "bypass_min_approvals": 1.5}

	# regal ignore:unresolved-reference
	not bypass.dep_vuln_authorized with input as sr(_two_authorized, true, true) with data.bypass_thresholds as cfg
}
