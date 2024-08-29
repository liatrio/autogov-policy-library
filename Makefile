.PHONY: parse-fake
parse-fake:
	cat test/sigstore_bundle_fake.jsonl | jq -r '.dsseEnvelope.payload' | base64 -d | jq -r

.PHONY: parse-real
parse-real:
	cat test/sigstore_bundle_real.jsonl | jq -r '.dsseEnvelope.payload' | base64 -d | jq -r

.PHONY: test
test:
	opa test policy -v