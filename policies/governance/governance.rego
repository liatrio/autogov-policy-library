package governance

import data.security.metadata
import data.security.provenance
import data.security.sbom

import rego.v1

# Aggregates policy to ensure all security checks pass:
# - Build provenance validation
# - SBOM attestation validation
# - Metadata validation
allow if {
	sbom.allow
	provenance.allow
	metadata.allow
}

violations := {
	"sbom": sbom.violations,
	"provenance": provenance.violations,
	"metadata": metadata.violations,
}
