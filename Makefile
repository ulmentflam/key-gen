.PHONY: setup test build lint format format.dry check clean help tidy docs

default: help

#❓ help: @ Displays all commands and tooling
help:
	@grep -E '[a-zA-Z\.\-]+:.*?@ .*$$' $(MAKEFILE_LIST)| tr -d '#'  | awk 'BEGIN {FS = ":.*?@ "}; {printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}'


#🧹 tidy: @ Tidies up the go mod
tidy:
	@go mod tidy


#🧹 clean: @ Cleans up the project
clean: tidy
	@go clean --testcache


#🔍 check: @ Runs all code verifications
check: lint test


#🔍 format.dry: @ Dry runs the code formatter
format.dry:
	@gofmt -s -d .

#🔍 format: @ Formats the code
format:
	@gofmt -s -w .

#🔍 lint: @ Strictly runs a code linter and formatter
lint: format
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@golangci-lint run

#📦 setup: @ Installs and compiles dependencies
setup: SHELL:=/bin/bash
setup: clean
	@go install golang.org/x/tools/cmd/goimports@latest
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go get .

#🧪 test: @ Runs all test suites
test: SHELL:=/bin/bash
test:
	@go test -v ./...

#📦 build: @ Builds the key-gen binary
build:
	@go build -o key-gen cmd/key-gen/main.go


