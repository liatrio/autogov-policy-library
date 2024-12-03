package shared.access_test

import rego.v1

import data.shared.access

test_approved_owner_ids_type if {
	is_set(access.approved_owner_ids)
	all_strings := {v | some v in access.approved_owner_ids; is_string(v)}
	count(all_strings) == count(access.approved_owner_ids)
}

test_approved_repo_ids_type if {
	is_set(access.approved_repo_ids)
	all_strings := {v | some v in access.approved_repo_ids; is_string(v)}
	count(all_strings) == count(access.approved_repo_ids)
}
