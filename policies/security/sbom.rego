package security.sbom

import rego.v1

# of the objects in input, there must some object that has predicateType of value https://cyclonedx.org/bom

default allow = false

allow if {
	count(violations) == 0
}

violations contains msg if {
	parsed_payload := parse_payload(input.dsseEnvelope.payload)
	not is_cyclonedx_bom_present(parsed_payload)
	msg := "cyclonedx sbom is missing"
}

parse_payload(payload) = parsed_payload if {
	decoded_payload := base64.decode(payload)
	parsed_payload := json.unmarshal(decoded_payload)
}

is_cyclonedx_bom_present(parsed_payload) if {
    some key
    key == "predicateType"
    parsed_payload[key]== "https://cyclonedx.org/bom"
}
