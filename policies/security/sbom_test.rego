package security.sbom_test

import rego.v1

import data.security.sbom

test_is_cyclonedx_bom_present_true if {
	parsed_payload := [
		{
			"_type": "https://in-toto.io/Statement/v1",
			"predicateType": "https://example.org/other",
		},
		{
			"_type": "https://in-toto.io/Statement/v1",
			"predicateType": "https://cyclonedx.org/bom",
		},
	]
	sbom.is_cyclonedx_bom_present(parsed_payload)
}

test_is_cyclonedx_bom_present_false if {
	parsed_payload := [{
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://example.org/other",
	}]
	not sbom.is_cyclonedx_bom_present(parsed_payload)
}

test_allow_true if {
	test_input := [
		{"dsseEnvelope": {"payload": base64.encode(json.marshal({
			"_type": "https://in-toto.io/Statement/v1",
			"predicateType": "https://example.org/other",
		}))}},
		{"dsseEnvelope": {"payload": base64.encode(json.marshal({
			"_type": "https://in-toto.io/Statement/v1",
			"predicateType": "https://cyclonedx.org/bom",
		}))}},
	]
	sbom.allow with input as test_input
}

test_allow_false if {
	test_input := [{"dsseEnvelope": {"payload": base64.encode(json.marshal({
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://example.org/other",
	}))}}]
	not sbom.allow with input as test_input
}

test_no_violations if {
	test_input := [
		{"dsseEnvelope": {"payload": base64.encode(json.marshal({
			"_type": "https://in-toto.io/Statement/v1",
			"predicateType": "https://example.org/other",
		}))}},
		{"dsseEnvelope": {"payload": base64.encode(json.marshal({
			"_type": "https://in-toto.io/Statement/v1",
			"predicateType": "https://cyclonedx.org/bom",
		}))}},
	]
	sbom.allow with input as test_input
}

# Test case for violations rule when CycloneDX SBOM is missing
test_violations if {
	test_input := [{
		"_type": "https://in-toto.io/Statement/v1",
		"dsseEnvelope": {"payload": base64.encode(json.marshal({
			"_type": "https://in-toto.io/Statement/v1",
			"predicateType": "https://example.org/other",
		}))},
	}]
	count(sbom.violations) > 0 with input as test_input
}

# Test case for malformed input
test_malformed_input if {
	test_input := [{"dsseEnvelope": {"payload": "not-base64-encoded"}}]
	not sbom.allow with input as test_input

	violations := sbom.violations with input as test_input
	"cyclonedx sbom is missing" in violations
}
