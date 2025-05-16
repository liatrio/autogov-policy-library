# METADATA
# scope: package
# title: Certificate Policy
# description: >-
#   Validates certificates in Sigstore bundles to ensure they are from trusted sources.
#   NOTE: Full X.509 certificate validation is not currently possible in OPA.
#   This policy only performs basic format/string validation.
#   See: https://github.com/open-policy-agent/opa/issues/6268
# authors:
# - Autogov Team https://github.com/orgs/liatrio/teams/tag-autogov
# schemas:
# - input: schema["bundle-schema"]
# custom:
#  control_number: 4
#  version: 0.6.7
#  path: policies/security
#  filename: certificate.rego
#  irm_control_ids: [LIATRIO-CERT-004]
package security.certificate

import data.shared.utils
import rego.v1

default allow := false

allow if {
	count(violations) == 0
}

violations contains msg if {
	count(input) == 0
	msg := "certificate is missing"
}

violations contains msg if {
	some bundle in input
	not is_string(bundle.verificationMaterial.certificate.rawBytes)
	msg := "certificate is missing"
}

violations contains msg if {
	some bundle in input
	cert := bundle.verificationMaterial.certificate.rawBytes
	is_string(cert)
	count(cert) == 0
	msg := "certificate is empty"
}

violations contains msg if {
	some bundle in input
	cert := bundle.verificationMaterial.certificate.rawBytes
	is_string(cert)
	count(cert) > 0
	not utils.is_valid_fulcio_cert(cert)
	msg := "certificate is not from github fulcio"
}
