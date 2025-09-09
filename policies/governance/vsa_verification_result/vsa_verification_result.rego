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
#  version: 0.7.1
#  path: policies/governance
#  filename: vsa_verification_result.rego
package governance.vsa_verification_result

import rego.v1

# Default allow is false
default allow := false

# Allow if VSA verification result is PASSED
allow if {
	input.predicate.verificationResult == "PASSED"
}

# Deny if VSA attestation is missing predicate.verificationResult
deny contains msg if {
	not input.predicate.verificationResult
	msg := "VSA attestation is missing predicate.verificationResult"
}

# Deny if VSA verification result is FAILED
deny contains msg if {
	input.predicate.verificationResult == "FAILED"
	msg := "VSA verification result indicates FAILED status"
}

# Deny if VSA verification result is UNKNOWN
deny contains msg if {
	input.predicate.verificationResult == "UNKNOWN"
	msg := "VSA verification result indicates UNKNOWN status"
}

# Deny if VSA verification result is invalid
deny contains msg if {
	not input.predicate.verificationResult in {"PASSED", "FAILED", "UNKNOWN"}
	msg := sprintf("VSA verification result has invalid status: %s", [input.predicate.verificationResult])
}
