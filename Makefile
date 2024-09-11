eval-good:
	@echo "Starting opa eval against real data..."
	@docker compose up \
		eval-good;
	@echo "Finished opa eval against real data"
	@echo ""
eval-bad: ## run opa eval against fake data
	@echo "Starting opa eval against fake data..."
	@docker compose up \
		eval-bad;
	@echo "Finished opa against fake data"
	@echo ""

.PHONY: all fmt lint check test

all: fmt lint check test ## run all validation checks

help: ## help for this Makefile
	@awk \
		'BEGIN {FS = ":.*##"; printf "\nUsage: make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' \
		$(MAKEFILE_LIST)

fmt: ## opa fmt command - corrects non-compliant files
	@echo "Starting opa fmt..."
	@docker compose up \
		fmt;
	@echo "Finished opa fmt"
	@echo ""

lint: ## regal lint command
	@echo "Starting regal lint..."
	@docker compose up \
		lint;
	@echo "Finished regal lint"
	@echo ""

check: ## opa check command
	@echo "Starting opa check..."
	@docker compose up \
		check;
	@echo "Finished opa check"
	@echo ""

test: ## run opa unit tests
	@echo "Starting opa test..."
	@docker compose up \
		test;
	@echo "Finished opa test"
	@echo ""