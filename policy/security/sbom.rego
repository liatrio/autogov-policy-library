package security.sbom

import rego.v1

default allow := false

allow if {
	count(violations) == 0
}

violations contains msg if {
	parsed_payload := parse_payload(input.dsseEnvelope.payload)
	not predicate_type_valid(parsed_payload)
	msg := "sbom predicate type is not correct"
}

parse_payload(payload) := parsed_payload if {
	decoded_payload := base64.decode(payload)
	parsed_payload := json.unmarshal(decoded_payload)
}

predicate_type_valid(parsed_payload) if {
	parsed_payload.predicateType == "https://cyclonedx.org/bom"
}
