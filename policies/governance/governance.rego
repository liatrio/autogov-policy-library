package governance

import data.security.provenance
import data.security.sbom

import rego.v1

allow if {
	sbom.allow
	provenance.allow
}

violations := {
	"sbom": sbom.violations,
	"provenance": provenance.violations,
}
