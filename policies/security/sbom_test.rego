package security.sbom_test

import rego.v1

import data.security.sbom

test_is_cyclonedx_bom_present_true if {
    parsed_payload := {"predicateType": "https://cyclonedx.org/bom"}
    sbom.is_cyclonedx_bom_present(parsed_payload)
}

test_is_cyclonedx_bom_present_false if {
    parsed_payload := {"predicateType": "https://example.org/other"}
    not sbom.is_cyclonedx_bom_present(parsed_payload)
}

test_allow_true if {
    test_input := {
        "dsseEnvelope": {
            "payload": base64.encode(json.marshal({"predicateType": "https://cyclonedx.org/bom"}))
        }
    }
    sbom.allow with input as test_input
}

test_allow_false if {
    test_input := {
        "dsseEnvelope": {
            "payload": base64.encode(json.marshal({"predicateType": "https://example.org/other"}))
        }
    }
    not sbom.allow with input as test_input
}

test_no_violations if {
    test_input := {
        "dsseEnvelope": {
            "payload": base64.encode(json.marshal({"predicateType": "https://cyclonedx.org/bom"}))
        }
    }
    count(sbom.violations) == 0 with input as test_input
}

test_violation_message if {
    test_input := {
        "dsseEnvelope": {
            "payload": base64.encode(json.marshal({"predicateType": "https://example.org/other"}))
        }
    }
    sbom.violations[_] == "cyclonedx sbom is missing" with input as test_input
}