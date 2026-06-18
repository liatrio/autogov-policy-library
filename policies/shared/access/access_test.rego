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

# Test repository IDs are strings in a set (defaults to empty)
test_approved_repo_ids_type if {
	is_set(access.approved_repo_ids)
	all_strings := {v | some v in access.approved_repo_ids; is_string(v)}
	count(all_strings) == count(access.approved_repo_ids)
}
