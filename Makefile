GENERATED=t/.last_run perl-cve-atom.xml generated_reports
CVE_FEED_FILE=perl-cve-atom.xml

all: ## does nothing yet (reserved)
	@ echo "There is no default target"

invert: ## turn the external_reports into CPANSA-style reports
	perl util/invert-third-party.pl

.PHONY: clean
clean: ## clean out generated files
	rm -rf $(GENERATED)

.PHONY: feed
feed: $(CVE_FEED_FILE)

$(CVE_FEED_FILE):
	perl util/make_feed > $@

.PHONY: test
test: ## run all tests (with current env)
	prove -r t

.PHONY: test_all
test_all: ## test all YAML files
	env TEST_CHANGED_ONLY=0 prove -r t

.PHONY: test_new
test_new: ## only test the new YAML files
	env TEST_CHANGED_ONLY=1 prove -r t

######################################################################
# https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help ## Show all the Makefile targets with descriptions
help: ## show a list of targets
	@grep -E '^[a-zA-Z][/a-zA-Z0-9_.-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
