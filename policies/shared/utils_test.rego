package shared.utils_test

import rego.v1

import data.shared.utils

# Test payload decoding
test_decoded_payload_list if {
	test_input := [
		{"dsseEnvelope": {"payload": base64.encode("{\"key\":\"value1\"}")}},
		{"dsseEnvelope": {"payload": base64.encode("{\"key\":\"value2\"}")}},
	]

	# Expected decoded payloads
	expected := [{"key": "value1"}, {"key": "value2"}]

	# Decode and unmarshal payloads
	decoded_payload_list := [decoded |
		some obj in test_input
		payload := obj.dsseEnvelope.payload
		decoded_payload_raw := base64.decode(payload)
		decoded := json.unmarshal(decoded_payload_raw)
	]

	# Assert that decoded_payload_list matches expected
	decoded_payload_list == expected
}

# Test SLSA provenance identification
test_is_slsa_provenance_true if {
	payload := {"predicateType": "https://slsa.dev/provenance/v1"}
	utils.is_slsa_provenance(payload)
}

# Test invalid SLSA provenance
test_is_slsa_provenance_false if {
	payload := {"predicateType": "https://example.com/other"}

	not utils.is_slsa_provenance(payload)
}

# Test Cosign attestation identification
test_is_cosign_attestation_true if {
	payload := {"predicateType": "https://cosign.sigstore.dev/attestation/v1"}
	utils.is_cosign_attestation(payload)
}

# Test invalid Cosign attestation
test_is_cosign_attestation_false if {
	payload := {"predicateType": "https://example.com/other"}

	not utils.is_cosign_attestation(payload)
}

# Test CycloneDX BOM identification
test_is_cyclonedx_bom_true if {
	payload := {"predicateType": "https://cyclonedx.org/bom"}
	utils.is_cyclonedx_bom(payload)
}

# Test invalid CycloneDX BOM
test_is_cyclonedx_bom_false if {
	payload := {"predicateType": "https://example.com/other"}
	not utils.is_cyclonedx_bom(payload)
}
