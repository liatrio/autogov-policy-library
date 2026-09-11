# METADATA
# scope: package
# title: Code Scan Common Helpers
# description: Shared helpers for code-scan gating — recompute over results[] or degrade to the summary.
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
package security.code_scan_common

import data.code_scan_config
import data.shared.utils
import rego.v1

# Recompute only after checking the authoritative claim against the raw findings.
# Contradictions must retain summary diagnostics instead of counting an empty or
# partial results container as a complete scan.
can_recompute(payload) if {
	_claims_authoritative_results(payload)
	_complete_results(payload)
}

_claims_authoritative_results(payload) if {
	payload.predicate.findingsIncluded == true
	payload.predicate.truncated == false
}

# The producer omits empty results. Explicit non-arrays are malformed even when
# counts are zero. Check raw cardinality before any configured finding filters;
# summary axes count unsuppressed findings, while resultCount includes all of them.
_complete_results(payload) if {
	_counts_valid(payload)
	results := object.get(payload.predicate, "results", [])
	is_array(results)
	n := count(results)
	n == payload.predicate.resultCount
	s := payload.predicate.summary
	severity := s.bySecuritySeverity
	sum([severity.critical, severity.high, severity.medium, severity.low, severity.none]) + s.suppressed <= n
	level := s.byLevel
	sum([level.error, level.warning, level.note, level.none]) + s.suppressed <= n
}

_invalid_authoritative_results(payload) if {
	_claims_authoritative_results(payload)
	not _complete_results(payload)
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
	_counts_valid(payload)
	is_boolean(payload.predicate.invocation.executionSuccessful)
	is_boolean(payload.predicate.findingsIncluded)
	is_boolean(payload.predicate.truncated)
	not _invalid_authoritative_results(payload)
}

_counts_valid(payload) if {
	s := payload.predicate.summary
	utils.is_non_negative_int(s.suppressed)
	utils.is_non_negative_int(payload.predicate.resultCount)
	every k in {"critical", "high", "medium", "low", "none"} {
		utils.is_non_negative_int(s.bySecuritySeverity[k])
	}
	every k in {"error", "warning", "note", "none"} {
		utils.is_non_negative_int(s.byLevel[k])
	}
}
