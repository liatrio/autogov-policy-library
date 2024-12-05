package mkdocs.mkdocs_config_policy_test

import rego.v1

import data.mkdocs.mkdocs_config_policy

# Test helper functions

## is_site_name_present
test_is_site_name_present_true if {
    test_input := {
        "site_name": "Example Site",
    }
    result := mkdocs_config_policy.is_site_name_present with input as test_input
    result == true
}

test_is_site_name_present_false_missing if {
    test_input := {
    }
    not mkdocs_config_policy.is_site_name_present with input as test_input
}

test_is_site_name_present_false_empty if {
    test_input := {
        "site_name": "",
    }
    not mkdocs_config_policy.is_site_name_present with input as test_input
}

## is_site_url_present

test_is_site_url_present_true if {
    test_input := {
        "site_url": "https://example.com",
    }
    is_site_url_present := mkdocs_config_policy.is_site_url_present with input as test_input
    is_site_url_present == true
}

test_is_site_url_present_false_missing if {
    test_input := {
    }
    not mkdocs_config_policy.is_site_url_present with input as test_input
}

test_is_site_url_present_false_empty if {
    test_input := {
        "site_url": "",
    }
    not mkdocs_config_policy.is_site_url_present with input as test_input
}

## is_repo_url_present

test_is_repo_url_present_true if {
    test_input := {
        "repo_url": "https://github.com/example/repo",
    }
    is_repo_url_present := mkdocs_config_policy.is_repo_url_present with input as test_input
    is_repo_url_present == true
}

test_is_repo_url_present_false_missing if {
    test_input := {
    }
    not mkdocs_config_policy.is_repo_url_present with input as test_input
}

test_is_repo_url_present_false_empty if {
    test_input := {
        "repo_url": "",
    }
    not mkdocs_config_policy.is_repo_url_present with input as test_input
}

## is_edit_uri_present

test_is_edit_uri_present_true if {
    test_input := {
        "edit_uri": "edit/main/docs",
    }
    is_edit_uri_present := mkdocs_config_policy.is_edit_uri_present with input as test_input
    is_edit_uri_present == true
}

test_is_edit_uri_present_false_missing if {
    test_input := {
    }
    not mkdocs_config_policy.is_edit_uri_present with input as test_input
}

test_is_edit_uri_present_false_empty if {
    test_input := {
        "edit_uri": "",
    }
    not mkdocs_config_policy.is_edit_uri_present with input as test_input
}

# Test violation messages

test_allow_no_violations if {
    test_input := {
        "site_name": "Example Site",
        "site_url": "https://example.com",
        "repo_url": "https://github.com/example/repo",
        "edit_uri": "edit/main/docs"
    }
    allow := mkdocs_config_policy.allow with input as test_input
    allow == true
    violations := mkdocs_config_policy.violations with input as test_input
    count(violations) == 0
}

test_deny_missing_site_name if {
    test_input := {
        "site_url": "https://example.com",
        "repo_url": "https://github.com/example/repo",
        "edit_uri": "edit/main/docs"
    }

    violations := mkdocs_config_policy.violations with input as test_input
    "The site_name is missing or is empty within the mkdocs.yml file. Example: site_name: 'Chaos Engineering'." in violations
}

test_deny_empty_site_name if {
    test_input := {
        "site_name": "",
        "site_url": "https://example.com",
        "repo_url": "https://github.com/example/repo",
        "edit_uri": "edit/main/docs"
    }
    violations := mkdocs_config_policy.violations with input as test_input
    "The site_name is missing or is empty within the mkdocs.yml file. Example: site_name: 'Chaos Engineering'." in violations
}

test_deny_missing_site_url if {
    test_input := {
        "site_name": "Example Site",
        "repo_url": "https://github.com/example/repo",
        "edit_uri": "edit/main/docs"
    }
    violations := mkdocs_config_policy.violations with input as test_input
    "The site_url is missing or is empty within the mkdocs.yml file. Example: site_url: 'https://chaos-engineering.liatr.io/'." in violations
}

test_deny_empty_site_url if {
    test_input := {
        "site_name": "Example Site",
        "site_url": "",
        "repo_url": "https://github.com/example/repo",
        "edit_uri": "edit/main/docs"
    }
    violations := mkdocs_config_policy.violations with input as test_input
    "The site_url is missing or is empty within the mkdocs.yml file. Example: site_url: 'https://chaos-engineering.liatr.io/'." in violations
}

test_deny_missing_repo_url if {
    test_input := {
        "site_name": "Example Site",
        "site_url": "https://example.com",
        "edit_uri": "edit/main/docs"
    }
    violations := mkdocs_config_policy.violations with input as test_input
    "The repo_url is missing or is empty within the mkdocs.yml file. Example: repo_url: 'https://github.com/liatrio/chaos-engineering'." in violations
}

test_deny_empty_repo_url if {
    test_input := {
        "site_name": "Example Site",
        "site_url": "https://example.com",
        "repo_url": "",
        "edit_uri": "edit/main/docs"
    }
    violations := mkdocs_config_policy.violations with input as test_input
    "The repo_url is missing or is empty within the mkdocs.yml file. Example: repo_url: 'https://github.com/liatrio/chaos-engineering'." in violations
}

test_deny_missing_edit_uri if {
    test_input := {
        "site_name": "Example Site",
        "site_url": "https://example.com",
        "repo_url": "https://github.com/example/repo"
    }
    violations := mkdocs_config_policy.violations with input as test_input
    "The edit_uri is missing or is empty within the mkdocs.yml file. Example: edit_uri: 'edit/main/docs'." in violations
}

test_deny_empty_edit_uri if {
    test_input := {
        "site_name": "Example Site",
        "site_url": "https://example.com",
        "repo_url": "https://github.com/example/repo",
        "edit_uri": ""
    }
    violations := mkdocs_config_policy.violations with input as test_input
    "The edit_uri is missing or is empty within the mkdocs.yml file. Example: edit_uri: 'edit/main/docs'." in violations
}
