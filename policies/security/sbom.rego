package security.sbom

import rego.v1

import data.shared.utils

# of the objects in input, there must some object that has predicateType of value https://cyclonedx.org/bom

default allow := false

allow if {
	count(violations) == 0
}

violations contains msg if {
	not is_cyclonedx_bom_present(utils.decoded_payload_list)
	msg := "cyclonedx sbom is missing"
}

is_cyclonedx_bom_present(payload) if {
	count([obj | some obj in payload; obj.predicateType == "https://cyclonedx.org/bom"]) > 0
}
