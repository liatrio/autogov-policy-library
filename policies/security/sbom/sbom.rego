# METADATA
# scope: package
# title: SBOM Policy
# description: Verifies presence of CycloneDX SBOM attestation
# authors:
# - AutoGov Team https://github.com/orgs/liatrio/teams/tag-autogov
# schemas:
# - input: schema["sbom-schema"]
# custom:
#  control_number: 2
#  version: 0.20.3
#  path: policies/security
#  filename: sbom.rego
#  irm_control_ids: [LIATRIO-SBOM-002]
package security.sbom

import data.shared.utils
import rego.v1

default allow := false

allow if {
	count(violations) == 0
}

violations contains msg if {
	not is_cyclonedx_bom_present(input)
	not is_cyclonedx_bom_present(utils.decoded_payload_list)
	msg := "cyclonedx sbom is missing"
}

# Check for CycloneDX BOM presence
is_cyclonedx_bom_present(payload) if {
	count([obj | some obj in payload; utils.is_cyclonedx_bom(obj)]) > 0
}
