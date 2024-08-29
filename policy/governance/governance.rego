package governance

import rego.v1

import data.security.provenance
import data.security.sbom

default allow := false

all_passed if {
	provenance_results := {res | some i in provenance.violations; res := provenance.violations[i]}

	every result in provenance_results {
		result == true
	}
}
