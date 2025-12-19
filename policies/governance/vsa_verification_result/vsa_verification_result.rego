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
#  version: 0.9.3
#  path: policies/governance
#  filename: vsa_verification_result.rego
package governance.vsa_verification_result

import data.shared.utils
import rego.v1

# Extract VSA payload from Sigstore bundle using shared utility
vsa_payload := utils.has_envelope(input)

# Get verification result from nested structure
verification_result := vsa_payload.predicate.predicate.verificationResult

# Allow if VSA verification result is PASSED
allow if {
	verification_result == "PASSED"
}

# Deny if VSA attestation is missing verification result
deny contains msg if {
	not verification_result
	msg := "VSA attestation is missing predicate.predicate.verificationResult"
}

# Deny if VSA verification result is FAILED
deny contains msg if {
	verification_result == "FAILED"
	msg := "VSA verification result indicates FAILED status"
}

# Deny if VSA verification result is UNKNOWN
deny contains msg if {
	verification_result == "UNKNOWN"
	msg := "VSA verification result indicates UNKNOWN status"
}

# Deny if VSA verification result is invalid
deny contains msg if {
	verification_result
	not verification_result in {"PASSED", "FAILED", "UNKNOWN"}
	msg := sprintf("VSA verification result has invalid status: %s", [verification_result])
}
