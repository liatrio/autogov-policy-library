package shared.access

import rego.v1

# [liatrio]
approved_owner_ids := {"5726618"}

# Approved GitHub repository IDs (consumer-supplied). Defaults to empty so the
# repository-id allowlist stays inert unless a consumer overrides it via
# data.shared.access.approved_repo_ids.
default approved_repo_ids := set()
