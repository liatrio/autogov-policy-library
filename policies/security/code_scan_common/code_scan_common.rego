# METADATA
# scope: package
# title: Code Scan Common Helpers
# description: Shared helpers for code-scan gating — recompute over results[] or degrade to the summary.
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
package security.code_scan_common

import data.code_scan_config
import rego.v1

# can_recompute is true when results[] is authoritative — every fail-kind finding
# is present (findingsIncluded) and none were dropped (not truncated). Only then
# may the policy count over results[]; otherwise it must use the summary counts.
can_recompute(payload) if {
	payload.predicate.findingsIncluded == true
	not payload.predicate.truncated
}

# recompute_required is true when the configured filters need per-finding data
# the summary cannot provide (suppressed inclusion, baseline filtering, or path
# ignores). When required but results[] is unavailable, the gate is incomplete.
recompute_required if {
	code_scan_config.count_suppressed
}

recompute_required if {
	code_scan_config.gate_new_only
}

recompute_required if {
	count(code_scan_config.ignore_paths) > 0
}

# gateable returns the findings eligible for gating after suppression, baseline,
# and path filters. Only meaningful when can_recompute(payload) holds.
gateable(payload) := [f |
	some f in payload.predicate.results
	_eligible(f)
]

_eligible(f) if {
	not _suppressed_excluded(f)
	not _baseline_excluded(f)
	not _path_ignored(f)
}

_suppressed_excluded(f) if {
	f.suppressed == true
	not code_scan_config.count_suppressed
}

_baseline_excluded(f) if {
	code_scan_config.gate_new_only
	not f.baselineState in {"new", "updated"}
}

_path_ignored(f) if {
	some pattern in code_scan_config.ignore_paths
	glob.match(pattern, ["/"], f.location.uri)
}

# count_sev / count_level recompute a bucket over the gateable findings.
count_sev(payload, bucket) := count([f |
	some f in gateable(payload)
	f.securitySeverityLevel == bucket
])

count_level(payload, level) := count([f |
	some f in gateable(payload)
	f.level == level
])

# effective_sev / effective_level return the count to gate on: recomputed over
# results[] when authoritative, else the summary bucket. The summary excludes
# suppressed findings and reflects no path/baseline filtering, which is why
# recompute_required + not can_recompute raises an incompleteness violation
# elsewhere rather than silently gating on the wrong number.
effective_sev(payload, bucket) := count_sev(payload, bucket) if {
	can_recompute(payload)
} else := payload.predicate.summary.bySecuritySeverity[bucket]

effective_level(payload, level) := count_level(payload, level) if {
	can_recompute(payload)
} else := payload.predicate.summary.byLevel[level]

# structurally_valid is true only when the predicate carries every field the gate
# relies on, with the right type. The gate consumes a signed-but-otherwise-
# untrusted predicate and is NOT re-validated against the schema at eval time, so
# a missing/mistyped field would otherwise make a threshold lookup UNDEFINED and
# silently skip that gate (fail-open). The policy fires a violation when this is
# false, so a malformed predicate fails CLOSED.
structurally_valid(payload) if {
	s := payload.predicate.summary
	is_number(s.suppressed)
	is_boolean(payload.predicate.invocation.executionSuccessful)
	is_boolean(payload.predicate.findingsIncluded)
	is_boolean(payload.predicate.truncated)
	is_number(payload.predicate.resultCount)
	every k in {"critical", "high", "medium", "low", "none"} {
		is_number(s.bySecuritySeverity[k])
	}
	every k in {"error", "warning", "note", "none"} {
		is_number(s.byLevel[k])
	}
}
