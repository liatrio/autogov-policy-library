package security.sbom

import rego.v1

# of the objects in input, there must some object that has predicateType of value https://cyclonedx.org/bom

default allow := false

allow if {
	count(violations) == 0
}

# we need to update the expected input to be a list of json objects
# for input we have a list of encoded objects where at the key dsseEnvelope.payload is base64 encoded

parse_payload(payload) := parsed_payload if {
	decoded_payload := base64.decode(payload)
	parsed_payload := json.unmarshal(decoded_payload)
}

decoded_payload_list := [decoded |
	some obj in input
	payload := obj.dsseEnvelope.payload
	decoded_payload_raw := base64.decode(payload)
	decoded := json.unmarshal(decoded_payload_raw)
]

violations contains msg if {
	not is_cyclonedx_bom_present(decoded_payload_list)
	msg := "cyclonedx sbom is missing"
}

is_cyclonedx_bom_present(payload) if {
	count([obj | some obj in payload; obj.predicateType == "https://cyclonedx.org/bom"]) > 0
}
