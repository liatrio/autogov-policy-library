package governance_test

import data.governance
import rego.v1

# Test all true case
test_allow_all_true if {
	violations := set()
	test_input := [{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": {"certificate": {"rawBytes": "valid-github-cert"}},
		"ignore_dependency_vulnerabilities": false,
	}]

	governance.allow with input as test_input
		with data.security.sbom.allow as true
		with data.security.provenance.allow as true
		with data.security.metadata.allow as true
		with data.security.certificate.allow as true
		with data.security.dependency_vulnerability.low.allow as true
		with data.security.dependency_vulnerability.medium.allow as true
		with data.security.dependency_vulnerability.high.allow as true
		with data.security.dependency_vulnerability.critical.allow as true
		with data.security.sbom.violations as violations
		with data.security.provenance.violations as violations
		with data.security.metadata.violations as violations
		with data.security.certificate.violations as violations
		with data.security.dependency_vulnerability.low.violations as violations
		with data.security.dependency_vulnerability.medium.violations as violations
		with data.security.dependency_vulnerability.high.violations as violations
		with data.security.dependency_vulnerability.critical.violations as violations
}

# Test all true case with ignored dependency vulnerabilities
test_allow_all_true_ignore_deps if {
	violations := set()
	dep_violations := {"some vulnerability"}
	test_input := [{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": {"certificate": {"rawBytes": "valid-github-cert"}},
		"ignore_dependency_vulnerabilities": true,
	}]

	governance.allow with input as test_input
		with data.security.sbom.allow as true
		with data.security.provenance.allow as true
		with data.security.metadata.allow as true
		with data.security.certificate.allow as true
		with data.security.dependency_vulnerability.low.allow as false
		with data.security.dependency_vulnerability.medium.allow as false
		with data.security.dependency_vulnerability.high.allow as false
		with data.security.dependency_vulnerability.critical.allow as false
		with data.security.sbom.violations as violations
		with data.security.provenance.violations as violations
		with data.security.metadata.violations as violations
		with data.security.certificate.violations as violations
		with data.security.dependency_vulnerability.low.violations as dep_violations
		with data.security.dependency_vulnerability.medium.violations as dep_violations
		with data.security.dependency_vulnerability.high.violations as dep_violations
		with data.security.dependency_vulnerability.critical.violations as dep_violations
		with data.security.bypass.dep_vuln_authorized as true
		with data.security.bypass.allow as true
}

# An ignore_dependency_vulnerabilities flag WITHOUT attested authorization must NOT
# allow when the dep-vuln gates fail — the spoofable-bypass fix.
test_no_allow_unauthorized_ignore_deps if {
	violations := set()
	dep_violations := {"some vulnerability"}
	test_input := [{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": {"certificate": {"rawBytes": "valid-github-cert"}},
		"ignore_dependency_vulnerabilities": true,
	}]

	not governance.allow with input as test_input
		with data.security.sbom.allow as true
		with data.security.provenance.allow as true
		with data.security.metadata.allow as true
		with data.security.certificate.allow as true
		with data.security.dependency_vulnerability.low.allow as false
		with data.security.dependency_vulnerability.medium.allow as false
		with data.security.dependency_vulnerability.high.allow as false
		with data.security.dependency_vulnerability.critical.allow as false
		with data.security.sbom.violations as violations
		with data.security.provenance.violations as violations
		with data.security.metadata.violations as violations
		with data.security.certificate.violations as violations
		with data.security.dependency_vulnerability.low.violations as dep_violations
		with data.security.dependency_vulnerability.medium.violations as dep_violations
		with data.security.dependency_vulnerability.high.violations as dep_violations
		with data.security.dependency_vulnerability.critical.violations as dep_violations
		with data.security.bypass.dep_vuln_authorized as false
}

# Test SBOM false case
test_allow_sbom_false if {
	sbom_violations := {"test violation"}
	other_violations := set()
	not governance.allow with data.security.sbom.violations as sbom_violations
		with data.security.provenance.violations as other_violations
		with data.security.metadata.violations as other_violations
		with data.security.dependency_vulnerability.low.violations as other_violations
		with data.security.dependency_vulnerability.medium.violations as other_violations
		with data.security.dependency_vulnerability.high.violations as other_violations
		with data.security.dependency_vulnerability.critical.violations as other_violations
}

# Test provenance false case
test_allow_provenance_false if {
	provenance_violations := {"test violation"}
	other_violations := set()
	not governance.allow with data.security.sbom.violations as other_violations
		with data.security.provenance.violations as provenance_violations
		with data.security.metadata.violations as other_violations
		with data.security.dependency_vulnerability.low.violations as other_violations
		with data.security.dependency_vulnerability.medium.violations as other_violations
		with data.security.dependency_vulnerability.high.violations as other_violations
		with data.security.dependency_vulnerability.critical.violations as other_violations
}

# Test metadata false case
test_allow_metadata_false if {
	metadata_violations := {"test violation"}
	other_violations := set()
	not governance.allow with data.security.sbom.violations as other_violations
		with data.security.provenance.violations as other_violations
		with data.security.metadata.violations as metadata_violations
		with data.security.dependency_vulnerability.low.violations as other_violations
		with data.security.dependency_vulnerability.medium.violations as other_violations
		with data.security.dependency_vulnerability.high.violations as other_violations
		with data.security.dependency_vulnerability.critical.violations as other_violations
}

# Test certificate false case
test_allow_certificate_false if {
	certificate_violations := {"test violation"}
	other_violations := set()
	not governance.allow with data.security.certificate.violations as certificate_violations
		with data.security.sbom.violations as other_violations
		with data.security.provenance.violations as other_violations
		with data.security.metadata.violations as other_violations
		with data.security.dependency_vulnerability.low.violations as other_violations
		with data.security.dependency_vulnerability.medium.violations as other_violations
		with data.security.dependency_vulnerability.high.violations as other_violations
		with data.security.dependency_vulnerability.critical.violations as other_violations
}

# Test low vulnerability false case
test_allow_low_vulnerability_false if {
	low_violations := {"test violation"}
	other_violations := set()
	not governance.allow with data.security.dependency_vulnerability.low.violations as low_violations
		with data.security.sbom.violations as other_violations
		with data.security.provenance.violations as other_violations
		with data.security.metadata.violations as other_violations
		with data.security.certificate.violations as other_violations
		with data.security.dependency_vulnerability.medium.violations as other_violations
		with data.security.dependency_vulnerability.high.violations as other_violations
		with data.security.dependency_vulnerability.critical.violations as other_violations
}

# Test medium vulnerability false case
test_allow_medium_vulnerability_false if {
	medium_violations := {"test violation"}
	other_violations := set()
	not governance.allow with data.security.dependency_vulnerability.medium.violations as medium_violations
		with data.security.sbom.violations as other_violations
		with data.security.provenance.violations as other_violations
		with data.security.metadata.violations as other_violations
		with data.security.certificate.violations as other_violations
		with data.security.dependency_vulnerability.low.violations as other_violations
		with data.security.dependency_vulnerability.high.violations as other_violations
		with data.security.dependency_vulnerability.critical.violations as other_violations
}

# Test high vulnerability false case
test_allow_high_vulnerability_false if {
	high_violations := {"test violation"}
	other_violations := set()
	not governance.allow with data.security.dependency_vulnerability.high.violations as high_violations
		with data.security.sbom.violations as other_violations
		with data.security.provenance.violations as other_violations
		with data.security.metadata.violations as other_violations
		with data.security.certificate.violations as other_violations
		with data.security.dependency_vulnerability.low.violations as other_violations
		with data.security.dependency_vulnerability.medium.violations as other_violations
		with data.security.dependency_vulnerability.critical.violations as other_violations
}

sbom_violations := {"cyclonedx sbom is missing"}

provenance_violations := {"predicate type is not correct"}

metadata_violations := {"workflow inputs are missing"}

certificate_violations := {"bundle certificate is invalid"}

dependency_vulnerability_violations_low := {"Low Vulnerabilities found."}

dependency_vulnerability_violations_medium := {"Medium Vulnerabilities found."}

dependency_vulnerability_violations_high := {"High Vulnerabilities found."}

dependency_vulnerability_violations_critical := {"Critical Vulnerabilities found."}

# Test violations reporting
test_violations_report if {
	test_input := [{
		"dsseEnvelope": {"payload": base64.encode(json.marshal({
			"predicateType": "https://example.org/other",
			"subject": [{
				"name": "ghcr.io/liatrio/demo-gh-autogov-workflows",
				"digest": {"sha256": "d379d8ef02ef446dc22e57e845ac7f3e5053b9398475541a8530d707511e6264"},
			}],
			"predicate": {},
		}))},
		"ignore_dependency_vulnerabilities": false,
	}]

	governance.violations == {
		"sbom": sbom_violations,
		"provenance": provenance_violations,
		"metadata": metadata_violations,
		"certificate": certificate_violations,
		"test_result": set(),
		"code_scan": set(),
		"source_review": set(),
		"source_level": set(),
		"bypass": set(),
		"dependency_vulnerability_low": dependency_vulnerability_violations_low,
		"dependency_vulnerability_medium": dependency_vulnerability_violations_medium,
		"dependency_vulnerability_high": dependency_vulnerability_violations_high,
		"dependency_vulnerability_critical": dependency_vulnerability_violations_critical,
	}
		with input as test_input
		with data.security.sbom.violations as sbom_violations
		with data.security.provenance.violations as provenance_violations
		with data.security.metadata.violations as metadata_violations
		with data.security.certificate.violations as certificate_violations
		with data.security.dependency_vulnerability.low.violations as dependency_vulnerability_violations_low
		with data.security.dependency_vulnerability.medium.violations as dependency_vulnerability_violations_medium
		with data.security.dependency_vulnerability.high.violations as dependency_vulnerability_violations_high
		with data.security.dependency_vulnerability.critical.violations as dependency_vulnerability_violations_critical
}

# Violations reporting with an UNAUTHORIZED ignore_dependency_vulnerabilities flag:
# the bare flag no longer suppresses the dep-vuln buckets (the v0.2 fix), so they
# surface the underlying violations. bypass is empty (no malformed config).
test_violations_report_ignore_deps_unauthorized if {
	test_input := [{
		"dsseEnvelope": {"payload": base64.encode(json.marshal({
			"predicateType": "https://example.org/other",
			"subject": [{
				"name": "ghcr.io/liatrio/demo-gh-autogov-workflows",
				"digest": {"sha256": "d379d8ef02ef446dc22e57e845ac7f3e5053b9398475541a8530d707511e6264"},
			}],
			"predicate": {},
		}))},
		"ignore_dependency_vulnerabilities": true,
	}]

	governance.violations == {
		"sbom": sbom_violations,
		"provenance": provenance_violations,
		"metadata": metadata_violations,
		"certificate": certificate_violations,
		"test_result": set(),
		"code_scan": set(),
		"source_review": set(),
		"source_level": set(),
		"bypass": set(),
		"dependency_vulnerability_low": dependency_vulnerability_violations_low,
		"dependency_vulnerability_medium": dependency_vulnerability_violations_medium,
		"dependency_vulnerability_high": dependency_vulnerability_violations_high,
		"dependency_vulnerability_critical": dependency_vulnerability_violations_critical,
	}
		with input as test_input
		with data.security.sbom.violations as sbom_violations
		with data.security.provenance.violations as provenance_violations
		with data.security.metadata.violations as metadata_violations
		with data.security.certificate.violations as certificate_violations
		with data.security.dependency_vulnerability.low.violations as dependency_vulnerability_violations_low
		with data.security.dependency_vulnerability.medium.violations as dependency_vulnerability_violations_medium
		with data.security.dependency_vulnerability.high.violations as dependency_vulnerability_violations_high
		with data.security.dependency_vulnerability.critical.violations as dependency_vulnerability_violations_critical
}

# Violations reporting with an AUTHORIZED bypass: the dep-vuln buckets are
# suppressed (the feature) — but ONLY because the bypass is attested-authorized
# (mocked dep_vuln_authorized), not because of the bare flag.
test_violations_report_ignore_deps_authorized if {
	test_input := [{
		"dsseEnvelope": {"payload": base64.encode(json.marshal({
			"predicateType": "https://example.org/other",
			"subject": [{
				"name": "ghcr.io/liatrio/demo-gh-autogov-workflows",
				"digest": {"sha256": "d379d8ef02ef446dc22e57e845ac7f3e5053b9398475541a8530d707511e6264"},
			}],
			"predicate": {},
		}))},
		"ignore_dependency_vulnerabilities": true,
	}]

	governance.violations == {
		"sbom": sbom_violations,
		"provenance": provenance_violations,
		"metadata": metadata_violations,
		"certificate": certificate_violations,
		"test_result": set(),
		"code_scan": set(),
		"source_review": set(),
		"source_level": set(),
		"bypass": set(),
		"dependency_vulnerability_low": set(),
		"dependency_vulnerability_medium": set(),
		"dependency_vulnerability_high": set(),
		"dependency_vulnerability_critical": set(),
	}
		with input as test_input
		with data.security.bypass.dep_vuln_authorized as true
		with data.security.sbom.violations as sbom_violations
		with data.security.provenance.violations as provenance_violations
		with data.security.metadata.violations as metadata_violations
		with data.security.certificate.violations as certificate_violations
		with data.security.dependency_vulnerability.low.violations as dependency_vulnerability_violations_low
		with data.security.dependency_vulnerability.medium.violations as dependency_vulnerability_violations_medium
		with data.security.dependency_vulnerability.high.violations as dependency_vulnerability_violations_high
		with data.security.dependency_vulnerability.critical.violations as dependency_vulnerability_violations_critical
}

# Test empty input case
test_empty_input if {
	test_input := []
	not governance.allow with input as test_input
}

# A bypass REQUESTED with a malformed bypass config surfaces a blocking violation
# AND is not allowed even when every other gate is clean — proving bypass.allow
# blocks both allow rules and the config error fails closed visibly.
test_bypass_malformed_config_when_requested_blocks if {
	test_input := [{"ignore_dependency_vulnerabilities": true}]
	bad_cfg := {"bypass_min_aprovals": 2}

	# regal ignore:unresolved-reference
	result := governance.violations with input as test_input with data.bypass_thresholds as bad_cfg
	count(result.bypass) > 0

	# regal ignore:unresolved-reference
	not governance.allow with input as test_input with data.bypass_thresholds as bad_cfg
		with data.security.sbom.allow as true
		with data.security.provenance.allow as true
		with data.security.metadata.allow as true
		with data.security.certificate.allow as true
		with data.security.test_result.allow as true
		with data.security.code_scan.allow as true
		with data.security.source_review.allow as true
		with data.security.source_level.allow as true
		with data.security.dependency_vulnerability.low.allow as true
		with data.security.dependency_vulnerability.medium.allow as true
		with data.security.dependency_vulnerability.high.allow as true
		with data.security.dependency_vulnerability.critical.allow as true
}

# The SAME malformed config but with NO bypass requested adds no bypass surface
# (the gate is opt-in) — the dep-vuln gate enforces normally regardless of config
# validity, so a bypass_thresholds typo is never a repo-wide outage.
test_bypass_malformed_config_not_requested_no_surface if {
	test_input := [{"ignore_dependency_vulnerabilities": false}]
	bad_cfg := {"bypass_min_aprovals": 2}

	# regal ignore:unresolved-reference
	result := governance.violations with input as test_input with data.bypass_thresholds as bad_cfg
	result.bypass == set()
}

# the source-level posture gate is wired into the aggregate but ships INERT: a
# source-review attestation with a WEAK posture (force-push not blocked) and no
# source_level_thresholds override raises no source_level surface and does not
# block, so the aggregate behaves exactly as before the gate was added.
test_source_level_inert_in_aggregate if {
	weak := {"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://autogov.dev/attestation/source-review/v0.2",
		"predicate": {
			"technicalControls": {"forcePushBlocked": false},
			"continuityStartRevision": "",
		},
	}))}}
	test_input := [weak]

	# regal ignore:unresolved-reference
	result := governance.violations with input as test_input
	result.source_level == set()
}

# once a consumer ENABLES the posture gate, a weak posture blocks the aggregate
# (source_level.allow is false), proving the gate is effective when opted in.
test_source_level_blocks_aggregate_when_enabled if {
	weak := {"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"predicateType": "https://autogov.dev/attestation/source-review/v0.2",
		"predicate": {
			"technicalControls": {
				"forcePushBlocked": false,
				"requiredLinearHistory": true,
				"deletionBlocked": false,
				"requiredSignatures": false,
				"requiredStatusChecks": ["build"],
				"bypassActors": [],
				"bypassActorsComplete": true,
			},
			"continuityStartRevision": "startrev",
		},
	}))}}
	test_input := [weak]
	cfg := {"require_min_source_posture": true}

	# regal ignore:unresolved-reference
	not governance.allow with input as test_input with data.source_level_thresholds as cfg
		with data.security.sbom.allow as true
		with data.security.provenance.allow as true
		with data.security.metadata.allow as true
		with data.security.certificate.allow as true
		with data.security.test_result.allow as true
		with data.security.code_scan.allow as true
		with data.security.source_review.allow as true
		with data.security.dependency_vulnerability.low.allow as true
		with data.security.dependency_vulnerability.medium.allow as true
		with data.security.dependency_vulnerability.high.allow as true
		with data.security.dependency_vulnerability.critical.allow as true
}

# Test no violations case
test_no_violations if {
	violations := set()
	test_input := [{"ignore_dependency_vulnerabilities": false}]

	governance.violations == {
		"sbom": violations,
		"provenance": violations,
		"metadata": violations,
		"certificate": violations,
		"test_result": violations,
		"code_scan": violations,
		"source_review": violations,
		"source_level": violations,
		"bypass": violations,
		"dependency_vulnerability_low": violations,
		"dependency_vulnerability_medium": violations,
		"dependency_vulnerability_high": violations,
		"dependency_vulnerability_critical": violations,
	}
		with input as test_input
		with data.security.sbom.violations as violations
		with data.security.provenance.violations as violations
		with data.security.metadata.violations as violations
		with data.security.certificate.violations as violations
		with data.security.dependency_vulnerability.low.violations as violations
		with data.security.dependency_vulnerability.medium.violations as violations
		with data.security.dependency_vulnerability.high.violations as violations
		with data.security.dependency_vulnerability.critical.violations as violations
}
