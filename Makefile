
all: ## does nothing yet (reserved)
	@ echo "There is no default target"

.PHONY: clean
clean: ## clean out generated files
	rm t/.last_run

.PHONY: test
test: ## run all tests (with current env)
	prove -r

.PHONY: test_all
test_all: ## test all YAML files
	env TEST_CHANGED_ONLY=0 prove -r

.PHONY: test_new
test_new: ## only test the new YAML files
	env TEST_CHANGED_ONLY=1 prove -r

######################################################################
# https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help ## Show all the Makefile targets with descriptions
help: ## show a list of targets
	@grep -E '^[a-zA-Z][/a-zA-Z0-9_.-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
