package governance

import data.security.provenance
import rego.v1

default allow := false

all_passed if {
	provenance_results := {res | some res in provenance.violations}
	every result in provenance_results {
		result == true
	}
}
