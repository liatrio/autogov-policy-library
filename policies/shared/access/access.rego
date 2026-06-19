package shared.access

import rego.v1

# Org configuration with liatrio defaults that an external adopter can override
# at runtime via --policy-data-path. Each value reads a top-level data key
# (mirroring the vuln_thresholds idiom) so external data never conflicts with
# these rules under OPA v1. When a key is absent the liatrio default applies, so
# the canonical bundle behaves exactly as before out of the box.

# Approved GitHub repository owner IDs (string org IDs). Override with JSON:
# {"approved_owner_ids": ["<org-id>", ...]}. Defaults to the liatrio org.
# [liatrio]
# regal ignore:unresolved-reference
_owner_ids := data.approved_owner_ids

default approved_owner_ids := {"5726618"}

approved_owner_ids := {id | some id in _owner_ids} if {
	_owner_ids != null
}

# Approved GitHub repository IDs (string repo IDs). Override with JSON:
# {"approved_repo_ids": ["<repo-id>", ...]}. Defaults to empty (inert).
# regal ignore:unresolved-reference
_repo_ids := data.approved_repo_ids

default approved_repo_ids := set()

approved_repo_ids := {id | some id in _repo_ids} if {
	_repo_ids != null
}

# Org slug embedded in the Fulcio signing-cert SAN path (".../{org}/..."). Override
# with JSON: {"signer_org": "<org-slug>"}. Defaults to liatrio.
# [liatrio]
# regal ignore:unresolved-reference
_signer_org := data.signer_org

default signer_org := "liatrio"

signer_org := _signer_org if {
	_signer_org != null
}

# Required image subject (OCI reference) prefix. Override with JSON:
# {"subject_prefix": "ghcr.io/<org>/"}. Defaults to ghcr.io/liatrio/.
# [liatrio]
# regal ignore:unresolved-reference
_subject_prefix := data.subject_prefix

default subject_prefix := "ghcr.io/liatrio/"

subject_prefix := _subject_prefix if {
	_subject_prefix != null
}
