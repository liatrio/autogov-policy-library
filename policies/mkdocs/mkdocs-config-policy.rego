package mkdocs.mkdocs_config_policy

import rego.v1

default allow := false


# Allow only if there are no violations
allow if {
    count(violations) == 0
}

violations[msg] if {
    not is_site_name_present
    msg := "site_name is missing"
}

violations[msg] if {
    not is_site_url_present
    msg := "site_url is missing"
}

violations[msg] if {
    not is_repo_url_present
    msg := "repo_url is missing"
}

violations[msg] if {
    not is_edit_uri_present
    msg := "edit_uri is missing"
}

# Helper rules to check for presence of keys

is_site_name_present if {
    input.site_name
}

is_site_url_present if {
    input.site_url
}

is_repo_url_present if {
    input.repo_url
}

is_edit_uri_present if {
    input.edit_uri
}
