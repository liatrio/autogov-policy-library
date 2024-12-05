package mkdocs.mkdocs_config_policy_test

import rego.v1

import data.mkdocs.mkdocs_config_policy

test_allow_no_violations if {
    test_input := {
        "site_name": "Example Site",
        "site_url": "https://example.com",
        "repo_url": "https://github.com/example/repo",
        "edit_uri": "edit/main/docs"
    }
    allow := mkdocs_config_policy.allow with input as test_input
    allow == true
}

test_deny_missing_site_name if {
    test_input := {
        "site_url": "https://example.com",
        "repo_url": "https://github.com/example/repo",
        "edit_uri": "edit/main/docs"
    }
    allow := mkdocs_config_policy.allow with input as test_input
    allow == false
    violations := mkdocs_config_policy.violations with input as test_input
    ["The site_name is missing or is empty within the mkdocs.yml file. Example: site_name: 'Chaos Engineering'."] in violations
}

test_deny_empty_site_name if {
    test_input := {
        "site_name": "",
        "site_url": "https://example.com",
        "repo_url": "https://github.com/example/repo",
        "edit_uri": "edit/main/docs"
    }
    allow := mkdocs_config_policy.allow with input as test_input
    allow == false
    violations := mkdocs_config_policy.violations with input as test_input
    ["The site_name is missing or is empty within the mkdocs.yml file. Example: site_name: 'Chaos Engineering'."] in violations
}

test_deny_missing_site_url if {
    test_input := {
        "site_name": "Example Site",
        "repo_url": "https://github.com/example/repo",
        "edit_uri": "edit/main/docs"
    }
    allow := mkdocs_config_policy.allow with input as test_input
    allow == false
    violations := mkdocs_config_policy.violations with input as test_input
    ["The site_url is missing or is empty within the mkdocs.yml file. Example: site_url: 'https://chaos-engineering.liatr.io/'."] in violations
}

test_deny_empty_site_url if {
    test_input := {
        "site_name": "Example Site",
        "site_url": "",
        "repo_url": "https://github.com/example/repo",
        "edit_uri": "edit/main/docs"
    }
    allow := mkdocs_config_policy.allow with input as test_input
    allow == false
    violations := mkdocs_config_policy.violations with input as test_input
    ["The site_url is missing or is empty within the mkdocs.yml file. Example: site_url: 'https://chaos-engineering.liatr.io/'."] in violations
}

test_deny_missing_repo_url if {
    test_input := {
        "site_name": "Example Site",
        "site_url": "https://example.com",
        "edit_uri": "edit/main/docs"
    }
    allow := mkdocs_config_policy.allow with input as test_input
    allow == false
    violations := mkdocs_config_policy.violations with input as test_input
    ["The repo_url is missing or is empty within the mkdocs.yml file. Example: repo_url: 'https://github.com/liatrio/chaos-engineering'."] in violations
}

test_deny_empty_repo_url if {
    test_input := {
        "site_name": "Example Site",
        "site_url": "https://example.com",
        "repo_url": "",
        "edit_uri": "edit/main/docs"
    }
    allow := mkdocs_config_policy.allow with input as test_input
    allow == false
    violations := mkdocs_config_policy.violations with input as test_input
    ["The repo_url is missing or is empty within the mkdocs.yml file. Example: repo_url: 'https://github.com/liatrio/chaos-engineering'."] in violations
}

test_deny_missing_edit_uri if {
    test_input := {
        "site_name": "Example Site",
        "site_url": "https://example.com",
        "repo_url": "https://github.com/example/repo"
    }
    allow := mkdocs_config_policy.allow with input as test_input
    allow == false
    violations := mkdocs_config_policy.violations with input as test_input
    ["The edit_uri is missing or is empty within the mkdocs.yml file. Example: edit_uri: 'edit/main/docs'."] in violations
}

test_deny_empty_edit_uri if {
    test_input := {
        "site_name": "Example Site",
        "site_url": "https://example.com",
        "repo_url": "https://github.com/example/repo",
        "edit_uri": ""
    }
    allow := mkdocs_config_policy.allow with input as test_input
    allow == false
    violations := mkdocs_config_policy.violations with input as test_input
    ["The edit_uri is missing or is empty within the mkdocs.yml file. Example: edit_uri: 'edit/main/docs'."] in violations
}
