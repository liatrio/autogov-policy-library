package mkdocs.mkdocs_config_policy_test

import rego.v1

import data.mkdocs.mkdocs_config_policy

test_allow_no_violations if {
    test_input := {
        "site_name": "Example Site",
        "site_url": "https://example.com",
        "repo_url": "https://github.com/example/repo",
        "edit_uri": "https://github.com/example/repo/edit/main/docs"
    }
    allow := mkdocs_config_policy.allow with test_input as input
    allow == true
}

test_deny_missing_site_name if {
    test_input := {
        "site_url": "https://example.com",
        "repo_url": "https://github.com/example/repo",
        "edit_uri": "https://github.com/example/repo/edit/main/docs"
    }
    allow := mkdocs_config_policy.allow with test_input as input
    allow == false
    violations := mkdocs_config_policy.violations with test_input as input
    violations == ["site_name is missing"]
}

test_deny_missing_site_url if {
    test_input := {
        "site_name": "Example Site",
        "repo_url": "https://github.com/example/repo",
        "edit_uri": "https://github.com/example/repo/edit/main/docs"
    }
    allow := mkdocs_config_policy.allow with test_input as input
    allow == false
    violations := mkdocs_config_policy.violations with test_input as input
    violations == ["site_url is missing"]
}

test_deny_missing_repo_url if {
    test_input := {
        "site_name": "Example Site",
        "site_url": "https://example.com",
        "edit_uri": "https://github.com/example/repo/edit/main/docs"
    }
    allow := mkdocs_config_policy.allow with input as input
    allow == false
    violations := mkdocs_config_policy.violations with test_input as input
    violations == ["repo_url is missing"]
}

test_deny_missing_edit_uri if {
    test_input := {
        "site_name": "Example Site",
        "site_url": "https://example.com",
        "repo_url": "https://github.com/example/repo"
    }
    allow := mkdocs_config_policy.allow with test_input as input
    allow == false
    violations := mkdocs_config_policy.violations with test_input as input
    violations == ["edit_uri is missing"]
}
