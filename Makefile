
.PHONY: help
help: ## show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: test
test: ## run unittests
	@python3 -m unittest discover

.PHONY: lint
lint: ## run flake8 linter
	@flake8

.PHONY: all
all: lint test
