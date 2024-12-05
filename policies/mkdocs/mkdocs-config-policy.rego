package mkdocs.mkdocs_config_policy

import rego.v1

default allow := false

# Allow only if there are no violations
allow if {
    count(violations) == 0
}

violations[msg] if {
    not is_site_name_present
    msg := "The site_name is missing or is empty within the mkdocs.yml file. Example: site_name: 'Chaos Engineering'."
}

violations[msg] if {
    not is_site_url_present
    msg := "The site_url is missing or is empty within the mkdocs.yml file. Example: site_url: 'https://chaos-engineering.liatr.io/'."
}

violations[msg] if {
    not is_repo_url_present
    msg := "The repo_url is missing or is empty within the mkdocs.yml file. Example: repo_url: 'https://github.com/liatrio/chaos-engineering'."
}

violations[msg] if {
    not is_edit_uri_present
    msg := "The edit_uri is missing or is empty within the mkdocs.yml file. Example: edit_uri: 'edit/main/docs'."
}

# Helper rules to check for presence of keys and non-empty values

is_site_name_present if {
    input.site_name != ""
}

is_site_url_present if {
    input.site_url != ""
}

is_repo_url_present if {
    input.repo_url != ""
}

is_edit_uri_present if {
    input.edit_uri != ""
}
