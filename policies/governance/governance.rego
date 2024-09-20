package governance

import data.security.provenance
import data.security.sbom
import rego.v1

allow if {
    data.security.sbom.allow
    data.security.provenance.allow
}

violations = {
    "sbom":  data.security.sbom.violations,
    "provenance": data.security.provenance.violations,
}
