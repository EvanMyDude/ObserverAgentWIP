PYTHON ?= python3
HOUR ?= 6
MINUTE ?= 0

.DEFAULT_GOAL := help
.PHONY: help test lint run run-rules report list doctor install uninstall

help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

test: ## Run the test suite
	$(PYTHON) -m unittest discover -s tests

lint: ## Byte-compile the package and tests with the target Python
	$(PYTHON) -m compileall -q observer tests

run: ## Ingest, detect, judge, and write today's report
	$(PYTHON) -m observer run

run-rules: ## Same as run, without the LLM judge
	$(PYTHON) -m observer run --no-llm

report: ## Print the latest report
	$(PYTHON) -m observer report

list: ## List open recommendations
	$(PYTHON) -m observer list

doctor: ## Check transcripts, hooks, schedule, and the claude CLI
	$(PYTHON) -m observer doctor

install: ## Install the hooks (backs up ~/.claude/settings.json) and the daily launchd job
	$(PYTHON) -m observer install-hooks --yes
	$(PYTHON) -m observer install-schedule --hour $(HOUR) --minute $(MINUTE) --load

uninstall: ## Remove the hooks and the launchd job; keeps ~/.observer
	$(PYTHON) -m observer uninstall-hooks --yes
	$(PYTHON) -m observer uninstall-schedule
