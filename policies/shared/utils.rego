package shared.utils

import rego.v1
import data.shared.access

decoded_payload_list := [decoded |
	some attestation in input
	decoded := has_envelope(attestation)
]

has_envelope(obj) := json.unmarshal(base64.decode(obj.dsseEnvelope.payload)) if {
	obj.dsseEnvelope
} else := obj

# Helper functions to identify predicate types
is_cosign_attestation(payload) if {
	payload.predicateType == "https://cosign.sigstore.dev/attestation/v1"
}

is_slsa_provenance(payload) if {
	payload.predicateType == "https://slsa.dev/provenance/v1"
}

is_cyclonedx_bom(payload) if {
	payload.predicateType == "https://cyclonedx.org/bom"
}
