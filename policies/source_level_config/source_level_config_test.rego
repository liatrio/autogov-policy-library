package source_level_config_test

import data.source_level_config
import rego.v1

# the SHIPPED default require_min_source_posture must be false so the gate is
# fully inert day-one and no current consumer breaks. This test locks the inert
# default so an accidental flip to true (which would start enforcing the posture
# for every consumer that does not override it) fails the suite.
test_shipped_default_is_inert if {
	source_level_config.require_min_source_posture == false
}

# require_continuity ships true (the verifier requires recorded continuity for L3).
test_shipped_default_require_continuity_is_true if {
	source_level_config.require_continuity == true
}

# require_signed_commits ships false (the verifier does not require signed commits
# for L3 — it is annotation-only).
test_shipped_default_require_signed_commits_is_false if {
	source_level_config.require_signed_commits == false
}

# the narrow-bypass allowlist ships empty (only "no bypass actors" is narrow).
test_shipped_default_allowed_bypass_actors_is_empty if {
	count(source_level_config.allowed_bypass_actors) == 0
}

# a valid override still resolves (the default-assertion above does not pin the
# value when an operator explicitly configures it).
test_override_resolves if {
	cfg := {"require_min_source_posture": true}

	# regal ignore:unresolved-reference
	v := source_level_config.require_min_source_posture with data.source_level_thresholds as cfg
	v == true
}

# a valid allowlist override resolves to a set.
test_allowed_bypass_actors_override_resolves if {
	cfg := {"allowed_bypass_actors": ["RepositoryRole:5", "Team:42"]}

	# regal ignore:unresolved-reference
	s := source_level_config.allowed_bypass_actors with data.source_level_thresholds as cfg
	s == {"RepositoryRole:5", "Team:42"}
}

# a non-object override is a config error.
test_non_object_config_error if {
	# regal ignore:unresolved-reference
	errs := source_level_config.config_errors with data.source_level_thresholds as "nope"
	"source_level_thresholds must be an object" in errs
}

# a wrong-typed boolean flag is a config error.
test_bool_flag_typo_config_error if {
	# regal ignore:unresolved-reference
	errs := source_level_config.config_errors with data.source_level_thresholds as {"require_min_source_posture": "true"}
	"require_min_source_posture must be a boolean" in errs
}

# a non-string-array allowlist is a config error.
test_array_typo_config_error if {
	# regal ignore:unresolved-reference
	errs := source_level_config.config_errors with data.source_level_thresholds as {"allowed_bypass_actors": [5]}
	"allowed_bypass_actors must be an array of strings" in errs
}

# an unknown/misspelled key is a config error (fail closed).
test_unknown_key_config_error if {
	# regal ignore:unresolved-reference
	errs := source_level_config.config_errors with data.source_level_thresholds as {"require_min_souce_posture": true}
	"unknown config key: require_min_souce_posture" in errs
}
