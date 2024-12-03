package governance

import data.security.provenance
import data.security.sbom
import data.security.metadata

import rego.v1

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
