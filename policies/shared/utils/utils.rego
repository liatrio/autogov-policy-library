package shared.utils

import data.shared.access
import rego.v1

decoded_payload_list := [decoded |
	some attestation in input
	decoded := has_envelope(attestation)
]

has_envelope(obj) := json.unmarshal(base64.decode(obj.dsseEnvelope.payload)) if {
	obj.dsseEnvelope
} else := obj

# Helper functions to identify predicate types
# is_autogov_metadata checks for the custom autogov metadata predicate type
is_autogov_metadata(payload) if {
	payload.predicateType == "https://autogov.dev/attestation/metadata/v1"
}

# is_cosign_attestation checks for legacy Cosign custom attestation type
# Note: Kept for backward compatibility during transition period
# New attestations should use is_autogov_metadata() instead
is_cosign_attestation(payload) if {
	payload.predicateType == "https://cosign.sigstore.dev/attestation/v1"
}

is_slsa_provenance(payload) if {
	payload.predicateType == "https://slsa.dev/provenance/v1"
}

is_cyclonedx_bom(payload) if {
	payload.predicateType == "https://cyclonedx.org/bom"
}

is_dep_vulnerability_scan(payload) if {
	payload.predicateType == "https://in-toto.io/attestation/vulns/v0.2"
}

is_test_result(payload) if {
	payload.predicateType == "https://in-toto.io/attestation/test-result/v0.1"
}

# Helper function to validate Fulcio certificates
is_valid_fulcio_cert(raw) := valid if {
	is_string(raw)
	count(raw) > 0
	cert_bytes := base64.decode(raw)

	contains(cert_bytes, "GitHub, Inc.")
	contains(cert_bytes, "Fulcio Intermediate l2")
	contains(cert_bytes, "github-hosted")
	contains(cert_bytes, "token.actions.githubusercontent.com")
	contains(cert_bytes, sprintf("/%s/", [access.signer_org]))
	contains(cert_bytes, ".github/workflows")

	valid := true
} else := false

# Helper function to remove prefix from string
remove_prefix(str, prefix) := trimmed if {
	startswith(str, prefix)
	trimmed := substring(str, count(prefix), -1)
}

# Helper function to remove suffix from string
remove_suffix(str, suffix) := trimmed if {
	endswith(str, suffix)
	trimmed := substring(str, 0, count(str) - count(suffix))
}
