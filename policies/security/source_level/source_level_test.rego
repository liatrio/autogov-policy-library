package security.source_level_test

import data.security.source_level
import rego.v1

# --- builders ---

# _env wraps a predicate as a v0.2 source-review attestation (the current producer
# output). is_source_review accepts both v0.1 and v0.2; _env_v01 below exercises the
# legacy type for backward acceptance.
_env(predicate) := {"dsseEnvelope": {"payload": base64.encode(json.marshal({
	"predicateType": "https://autogov.dev/attestation/source-review/v0.2",
	"predicate": predicate,
}))}}

_env_v01(predicate) := {"dsseEnvelope": {"payload": base64.encode(json.marshal({
	"predicateType": "https://autogov.dev/attestation/source-review/v0.1",
	"predicate": predicate,
}))}}

# a technicalControls object that MEETS the L3 posture: force-push blocked, one
# required status check, retained history (linear), an authoritative empty bypass
# list, signatures on, and a PROVEN continuity window (continuityComplete=true).
# continuityStartRevision is a sibling of technicalControls.
_tc_l3 := {
	"forcePushBlocked": true,
	"requiredLinearHistory": true,
	"deletionBlocked": false,
	"requiredSignatures": true,
	"requiredStatusChecks": ["build"],
	"bypassActors": [],
	"bypassActorsComplete": true,
	"continuityComplete": true,
}

# a full L3 source-review predicate (controls + recorded continuity).
_pred(tc, continuity) := {
	"sourceRepository": "https://github.com/liatrio/autogov",
	"sourceRevision": "abc123",
	"technicalControls": tc,
	"continuityStartRevision": continuity,
}

# a source-review predicate WITHOUT technicalControls (the pre-posture producer, or
# a predicate that records no controls).
_pred_no_tc := {
	"sourceRepository": "https://github.com/liatrio/autogov",
	"sourceRevision": "abc123",
}

# enable the gate (master switch on).
_on := {"require_min_source_posture": true}

# a clean L3 input: meets the posture and records continuity.
_l3_input := [_env(_pred(_tc_l3, "startrev"))]

# --- inertness (default off) ---

# default off: a predicate with NO posture still passes (no violation).
test_inert_when_absent if {
	source_level.allow with input as []
}

test_inert_for_other_predicate if {
	source_level.allow with input as [_env_other]
}

_env_other := {"dsseEnvelope": {"payload": base64.encode(json.marshal({
	"predicateType": "https://example.org/other",
	"predicate": {},
}))}}

# default off: even a predicate with a WEAK posture passes while the gate is inert.
test_inert_with_weak_posture if {
	weak := json.patch(_tc_l3, [{"op": "replace", "path": "/forcePushBlocked", "value": false}])
	source_level.allow with input as [_env(_pred(weak, "startrev"))]
}

# default off: even a predicate lacking technicalControls entirely passes.
test_inert_when_no_technical_controls if {
	source_level.allow with input as [_env(_pred_no_tc)]
}

# --- enabled: L3 posture pass ---

test_l3_posture_passes_when_enabled if {
	# regal ignore:unresolved-reference
	source_level.allow with input as _l3_input with data.source_level_thresholds as _on
}

# deletion-blocked (instead of linear history) also satisfies retained history.
test_l3_passes_with_deletion_blocked_history if {
	tc := json.patch(_tc_l3, [
		{"op": "replace", "path": "/requiredLinearHistory", "value": false},
		{"op": "replace", "path": "/deletionBlocked", "value": true},
	])

	# regal ignore:unresolved-reference
	source_level.allow with input as [_env(_pred(tc, "startrev"))] with data.source_level_thresholds as _on
}

# --- enabled: presence / technicalControls required (fail closed) ---

test_missing_attestation_fails_closed if {
	# regal ignore:unresolved-reference
	not source_level.allow with input as [] with data.source_level_thresholds as _on

	msg := "source-level: source-review attestation is missing"

	# regal ignore:unresolved-reference
	msg in source_level.violations with input as [] with data.source_level_thresholds as _on
}

test_missing_technical_controls_fails_closed if {
	inp := [_env(_pred_no_tc)]

	# regal ignore:unresolved-reference
	not source_level.allow with input as inp with data.source_level_thresholds as _on

	msg := "source-level: source-review predicate records no technicalControls"

	# regal ignore:unresolved-reference
	msg in source_level.violations with input as inp with data.source_level_thresholds as _on
}

# --- enabled: each posture leg fails ---

test_force_push_not_blocked_fails if {
	tc := json.patch(_tc_l3, [{"op": "replace", "path": "/forcePushBlocked", "value": false}])

	# regal ignore:unresolved-reference
	not source_level.allow with input as [_env(_pred(tc, "startrev"))] with data.source_level_thresholds as _on
}

test_no_status_checks_fails if {
	tc := json.patch(_tc_l3, [{"op": "replace", "path": "/requiredStatusChecks", "value": []}])

	# regal ignore:unresolved-reference
	not source_level.allow with input as [_env(_pred(tc, "startrev"))] with data.source_level_thresholds as _on
}

test_no_retained_history_fails if {
	tc := json.patch(_tc_l3, [
		{"op": "replace", "path": "/requiredLinearHistory", "value": false},
		{"op": "replace", "path": "/deletionBlocked", "value": false},
	])

	# regal ignore:unresolved-reference
	not source_level.allow with input as [_env(_pred(tc, "startrev"))] with data.source_level_thresholds as _on
}

# --- enabled: bypass fail-closed (the KEY rule) ---

# bypassActorsComplete==false means the bypass posture is UNKNOWN, even with an
# EMPTY bypassActors -> the leg must fail (UNKNOWN is not "none").
test_bypass_incomplete_empty_actors_fails_closed if {
	tc := json.patch(_tc_l3, [{"op": "replace", "path": "/bypassActorsComplete", "value": false}])
	inp := [_env(_pred(tc, "startrev"))]

	# regal ignore:unresolved-reference
	not source_level.allow with input as inp with data.source_level_thresholds as _on

	msg := concat("", [
		"source-level: technical controls do not meet the L3 posture ",
		"(force-push, status checks, retained history, authoritative narrow bypass)",
	])

	# regal ignore:unresolved-reference
	msg in source_level.violations with input as inp with data.source_level_thresholds as _on
}

# a non-empty bypass list with an actor NOT on the (empty default) allowlist is not
# narrow -> the leg fails.
test_bypass_actor_not_allowlisted_fails if {
	tc := json.patch(_tc_l3, [{"op": "replace", "path": "/bypassActors", "value": ["Team:7:always"]}])

	# regal ignore:unresolved-reference
	not source_level.allow with input as [_env(_pred(tc, "startrev"))] with data.source_level_thresholds as _on
}

# a bypass actor whose Type:ID IS on the allowlist is narrow -> passes. The entry
# is "<Type>:<ID>:<Mode>"; the trailing ":<Mode>" is dropped before matching.
test_bypass_actor_allowlisted_passes if {
	tc := json.patch(_tc_l3, [{"op": "replace", "path": "/bypassActors", "value": ["Team:7:always"]}])
	cfg := {"require_min_source_posture": true, "allowed_bypass_actors": ["Team:7"]}

	# regal ignore:unresolved-reference
	source_level.allow with input as [_env(_pred(tc, "startrev"))] with data.source_level_thresholds as cfg
}

# one allowlisted + one NOT allowlisted -> not narrow (every actor must match).
test_bypass_mixed_actors_fails if {
	actors := ["Team:7:always", "User:99:pull_request"]
	tc := json.patch(_tc_l3, [{"op": "replace", "path": "/bypassActors", "value": actors}])
	cfg := {"require_min_source_posture": true, "allowed_bypass_actors": ["Team:7"]}

	# regal ignore:unresolved-reference
	not source_level.allow with input as [_env(_pred(tc, "startrev"))] with data.source_level_thresholds as cfg
}

# the verifier ALWAYS strips after the last ":" (it expects "<Type>:<ID>:<Mode>"),
# so a recorded "RepositoryRole:5:always" matches the allowlisted "RepositoryRole:5".
test_bypass_actor_three_segment_matches if {
	tc := json.patch(_tc_l3, [{"op": "replace", "path": "/bypassActors", "value": ["RepositoryRole:5:always"]}])
	cfg := {"require_min_source_posture": true, "allowed_bypass_actors": ["RepositoryRole:5"]}

	# regal ignore:unresolved-reference
	source_level.allow with input as [_env(_pred(tc, "startrev"))] with data.source_level_thresholds as cfg
}

# --- enabled: continuity fail-closed (the KEY rule) ---

# an empty continuityStartRevision is UNDETERMINED and must NOT satisfy the
# continuity leg -> fail closed.
test_empty_continuity_fails_closed if {
	inp := [_env(_pred(_tc_l3, ""))]

	# regal ignore:unresolved-reference
	not source_level.allow with input as inp with data.source_level_thresholds as _on

	msg := "source-level: continuity is required but continuityStartRevision is empty or undetermined"

	# regal ignore:unresolved-reference
	msg in source_level.violations with input as inp with data.source_level_thresholds as _on
}

# a whitespace-only continuityStartRevision is also UNDETERMINED -> fail closed.
test_whitespace_continuity_fails_closed if {
	# regal ignore:unresolved-reference
	not source_level.allow with input as [_env(_pred(_tc_l3, "   "))] with data.source_level_thresholds as _on
}

# continuity can be turned OFF: the same empty-continuity input passes when
# require_continuity=false (gate on the technical controls alone).
test_continuity_can_be_disabled if {
	cfg := {"require_min_source_posture": true, "require_continuity": false}

	# regal ignore:unresolved-reference
	source_level.allow with input as [_env(_pred(_tc_l3, ""))] with data.source_level_thresholds as cfg
}

# FAIL-CLOSED (v0.2): continuityComplete=false with a NON-EMPTY start revision must
# NOT satisfy continuity. A populated start is meaningless without the proven-window
# assertion (mirrors the verifier's tc.ContinuityComplete && start != "").
test_continuity_incomplete_fails_closed if {
	tc := json.patch(_tc_l3, [{"op": "replace", "path": "/continuityComplete", "value": false}])

	# regal ignore:unresolved-reference
	not source_level.allow with input as [_env(_pred(tc, "startrev"))] with data.source_level_thresholds as _on

	msg := "source-level: continuity is required but continuityStartRevision is empty or undetermined"

	# regal ignore:unresolved-reference
	msg in source_level.violations with input as [_env(_pred(tc, "startrev"))] with data.source_level_thresholds as _on
}

# FAIL-CLOSED (v0.1 bundle): a legacy predicate has NO continuityComplete field, so
# continuity is UNDETERMINED -> the continuity leg fails even with a start revision.
# This keeps the L3 claim DORMANT for every already-published v0.1 bundle.
test_v01_bundle_continuity_fails_closed if {
	tc := json.patch(_tc_l3, [{"op": "remove", "path": "/continuityComplete"}])

	# regal ignore:unresolved-reference
	not source_level.allow with input as [_env_v01(_pred(tc, "startrev"))] with data.source_level_thresholds as _on
}

# a v0.1 bundle is still RECOGNIZED as source-review (is_source_review accepts both
# types): with continuity disabled it passes on the technical controls alone, which
# proves the v0.1 predicate type is gated (not silently ignored).
test_v01_bundle_recognized_when_continuity_off if {
	tc := json.patch(_tc_l3, [{"op": "remove", "path": "/continuityComplete"}])
	cfg := {"require_min_source_posture": true, "require_continuity": false}

	# regal ignore:unresolved-reference
	source_level.allow with input as [_env_v01(_pred(tc, "startrev"))] with data.source_level_thresholds as cfg
}

# v0.2 full proof (continuityComplete=true + start) passes the continuity leg.
test_v02_full_continuity_proof_passes if {
	# regal ignore:unresolved-reference
	source_level.allow with input as _l3_input with data.source_level_thresholds as _on
}

# --- enabled: signed-commits opt-in leg ---

# off by default: an L3 posture without signatures passes (signatures not required).
test_signed_commits_not_required_by_default if {
	tc := json.patch(_tc_l3, [{"op": "replace", "path": "/requiredSignatures", "value": false}])

	# regal ignore:unresolved-reference
	source_level.allow with input as [_env(_pred(tc, "startrev"))] with data.source_level_thresholds as _on
}

# opt-in: with require_signed_commits=true, a posture lacking signatures fails.
test_signed_commits_required_fails_when_unsigned if {
	tc := json.patch(_tc_l3, [{"op": "replace", "path": "/requiredSignatures", "value": false}])
	cfg := {"require_min_source_posture": true, "require_signed_commits": true}

	# regal ignore:unresolved-reference
	not source_level.allow with input as [_env(_pred(tc, "startrev"))] with data.source_level_thresholds as cfg
}

# opt-in: with signatures present and required, it passes.
test_signed_commits_required_passes_when_signed if {
	cfg := {"require_min_source_posture": true, "require_signed_commits": true}

	# regal ignore:unresolved-reference
	source_level.allow with input as _l3_input with data.source_level_thresholds as cfg
}

# --- enabled: malformed technicalControls -> fail closed (structural coupling) ---

# corrupting ANY technicalControls field the gate reads (or continuityStartRevision)
# must trip the malformed denial. A valid base must pass; every corrupted variant
# must deny. If a new leg reads a new field, add it to common.technical_controls_valid
# AND to the patch list here.
test_malformed_technical_controls_coupling if {
	# regal ignore:unresolved-reference
	source_level.allow with input as _l3_input with data.source_level_thresholds as _on

	patches := [
		[{"op": "replace", "path": "/technicalControls/forcePushBlocked", "value": "x"}],
		[{"op": "remove", "path": "/technicalControls/forcePushBlocked"}],
		[{"op": "replace", "path": "/technicalControls/requiredLinearHistory", "value": 1}],
		[{"op": "remove", "path": "/technicalControls/requiredLinearHistory"}],
		[{"op": "replace", "path": "/technicalControls/deletionBlocked", "value": "x"}],
		[{"op": "remove", "path": "/technicalControls/deletionBlocked"}],
		[{"op": "replace", "path": "/technicalControls/requiredSignatures", "value": "x"}],
		[{"op": "remove", "path": "/technicalControls/requiredSignatures"}],
		[{"op": "replace", "path": "/technicalControls/bypassActorsComplete", "value": "x"}],
		[{"op": "remove", "path": "/technicalControls/bypassActorsComplete"}],
		[{"op": "replace", "path": "/technicalControls/requiredStatusChecks", "value": "x"}],
		[{"op": "replace", "path": "/technicalControls/requiredStatusChecks", "value": [1]}],
		[{"op": "remove", "path": "/technicalControls/requiredStatusChecks"}],
		[{"op": "replace", "path": "/technicalControls/bypassActors", "value": "x"}],
		[{"op": "replace", "path": "/technicalControls/bypassActors", "value": [2]}],
		[{"op": "remove", "path": "/technicalControls/bypassActors"}],
		# continuityComplete (v0.2): a MISTYPED value is malformed -> fail closed.
		# (REMOVING it is valid for v0.1 and is NOT in this list — it's covered by the
		# v0.1 continuity-fails-closed test instead.)
		[{"op": "replace", "path": "/technicalControls/continuityComplete", "value": "x"}],
		[{"op": "replace", "path": "/technicalControls/continuityComplete", "value": 1}],
		[{"op": "replace", "path": "/continuityStartRevision", "value": 5}],
		[{"op": "remove", "path": "/continuityStartRevision"}],
	]
	every patch in patches {
		bad := json.patch(_pred(_tc_l3, "startrev"), patch)

		# regal ignore:unresolved-reference
		not source_level.allow with input as [_env(bad)] with data.source_level_thresholds as _on
	}
}

# the malformed denial carries the malformed message (not a posture message), so a
# corrupted predicate is reported as malformed rather than silently slipping a leg.
test_malformed_emits_malformed_message if {
	patch := [{"op": "replace", "path": "/technicalControls/forcePushBlocked", "value": "x"}]
	bad := json.patch(_pred(_tc_l3, "startrev"), patch)
	inp := [_env(bad)]

	msg := "source-level: technicalControls is malformed (missing or mistyped posture fields)"

	# regal ignore:unresolved-reference
	msg in source_level.violations with input as inp with data.source_level_thresholds as _on
}

# --- enabled: config fails closed ---

# a wrong-typed flag is a config error -> fail closed (even an L3 input denies).
test_bad_config_fails_closed if {
	cfg := {"require_min_source_posture": "true"}

	# regal ignore:unresolved-reference
	not source_level.allow with input as _l3_input with data.source_level_thresholds as cfg
}

# an unknown/misspelled key fails closed.
test_unknown_config_key_fails_closed if {
	cfg := {"require_min_source_posture": true, "alowed_bypass_actors": ["Team:7"]}

	# regal ignore:unresolved-reference
	not source_level.allow with input as _l3_input with data.source_level_thresholds as cfg
}
