package shared.access

import rego.v1

# Approved GitHub repository owner IDs. Defaults to the liatrio org so the
# canonical library keeps rejecting non-liatrio owners out of the box. A
# consumer can override the set (e.g. for their own org) by supplying their own
# approved_owner_ids rule, which takes precedence over this default.
# [liatrio]
default approved_owner_ids := {"5726618"}

# Approved GitHub repository IDs (consumer-supplied). Defaults to empty so the
# repository-id allowlist stays inert unless a consumer overrides it via
# data.shared.access.approved_repo_ids.
default approved_repo_ids := set()
