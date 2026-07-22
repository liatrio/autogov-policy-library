# METADATA
# scope: package
# title: VSA Verification Result
# description: This policy will verify the result status of the VSA
# authors:
# - Liatrio <info@liatrio.com>
# schemas:
#   - input: schema["vsa-schema"]
# custom:
#  control_number: 8
#  version: 1.1.0
#  path: policies/governance
#  filename: vsa_verification_result.rego
package governance.vsa_verification_result

import data.shared.utils
import rego.v1

default allow := false

# Allow only if at least one VSA payload is present and every VSA payload
# present is PASSED
allow if {
	count(vsa_payloads) > 0
	every payload in vsa_payloads {
		payload.predicate.predicate.verificationResult == "PASSED"
	}
}

# Extract all VSA payloads from the array of Sigstore bundles/attestations
vsa_payloads := [payload |
	some payload in utils.decoded_payload_list
	utils.is_vsa(payload)
]

# Deny if no VSA attestation is present at all
deny contains msg if {
	count(vsa_payloads) == 0
	msg := "VSA attestation is missing"
}

# Deny if a VSA attestation is missing verification result
deny contains msg if {
	some payload in vsa_payloads
	not payload.predicate.predicate.verificationResult
	msg := "VSA attestation is missing predicate.predicate.verificationResult"
}

# Deny if a VSA verification result is FAILED
deny contains msg if {
	some payload in vsa_payloads
	payload.predicate.predicate.verificationResult == "FAILED"
	msg := "VSA verification result indicates FAILED status"
}

# Deny if a VSA verification result is UNKNOWN
deny contains msg if {
	some payload in vsa_payloads
	payload.predicate.predicate.verificationResult == "UNKNOWN"
	msg := "VSA verification result indicates UNKNOWN status"
}

# Deny if a VSA verification result is invalid
deny contains msg if {
	some payload in vsa_payloads
	result := payload.predicate.predicate.verificationResult
	result
	not result in {"PASSED", "FAILED", "UNKNOWN"}
	msg := sprintf("VSA verification result has invalid status: %s", [result])
}
