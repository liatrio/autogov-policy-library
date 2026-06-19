package shared.access_test

import rego.v1

import data.shared.access

# Test owner IDs are strings in a set
test_approved_owner_ids_type if {
	is_set(access.approved_owner_ids)
	all_strings := {v | some v in access.approved_owner_ids; is_string(v)}
	count(all_strings) == count(access.approved_owner_ids)
}

# Test the owner allowlist defaults to the liatrio org (behavior preservation)
test_approved_owner_ids_default if {
	access.approved_owner_ids == {"5726618"}
}

# Test a consumer can override the owner allowlist
test_approved_owner_ids_override if {
	ids := access.approved_owner_ids with access.approved_owner_ids as {"12345"}
	ids == {"12345"}
}

# Test a consumer can override the owner allowlist at runtime via --policy-data-path
test_approved_owner_ids_data_override if {
	# regal ignore:unresolved-reference
	ids := access.approved_owner_ids with data.approved_owner_ids as ["999", "1000"]
	ids == {"999", "1000"}
}

# Test repository IDs are strings in a set (defaults to empty)
test_approved_repo_ids_type if {
	is_set(access.approved_repo_ids)
	all_strings := {v | some v in access.approved_repo_ids; is_string(v)}
	count(all_strings) == count(access.approved_repo_ids)
}

# Test the repo allowlist can be supplied at runtime via --policy-data-path
test_approved_repo_ids_data_override if {
	# regal ignore:unresolved-reference
	ids := access.approved_repo_ids with data.approved_repo_ids as ["42"]
	ids == {"42"}
}

# Test the signer org defaults to liatrio and is overridable via --policy-data-path
test_signer_org_default if {
	access.signer_org == "liatrio"
}

test_signer_org_data_override if {
	# regal ignore:unresolved-reference
	org := access.signer_org with data.signer_org as "my-org"
	org == "my-org"
}

# Test the image subject prefix defaults to ghcr.io/liatrio/ and is overridable
test_subject_prefix_default if {
	access.subject_prefix == "ghcr.io/liatrio/"
}

test_subject_prefix_data_override if {
	# regal ignore:unresolved-reference
	prefix := access.subject_prefix with data.subject_prefix as "ghcr.io/my-org/"
	prefix == "ghcr.io/my-org/"
}
