package security.sbom

import data.shared.utils
import rego.v1

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
	count([obj | some obj in payload; utils.is_cyclonedx_bom(obj)]) > 0
}
