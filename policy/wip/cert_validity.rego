package attestation.slsa1

default allow = false

allow {
    payload := input.verificationMaterial.certificate.rawBytes
    decoded_payload := base64.decode(payload)
    parsed_payload := json.unmarshal(decoded_payload)
    cert_raw := parsed_payload
    cert_pem := base64.decode(cert_raw)
    cert_info := parse_cert(cert_pem)

    valid_certificate(cert_info)
}

valid_certificate(cert_info) {
    cert_info.issuer == "O=GitHub, Inc., CN=Fulcio Intermediate l2"
    cert_info.subject_alternative_name == "https://github.com/liatrio/tag-automated-governance-github-attestations-beta-v0.0.1/.github/workflows/build.yaml@refs/heads/main"
}

parse_cert(cert_pem) = {
    "issuer": issuer,
    "subject_alternative_name": san
} {
    issuer := regex.find_n("Issuer: (.*)", cert_pem, 1)[0]
    san := regex.find_n("X509v3 Subject Alternative Name: critical\n *URI:(.*)", cert_pem, 1)[0]
}