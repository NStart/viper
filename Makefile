OS = $(shell uname | tr A-Z a-z)
export PATH := $(abspath bin):${PATH}

BUILD_DIR ?= build 
export CGO_ENBABLED ?= 0
export GOOS = $(shell go env GOOS)
ifeq (${VERBOSE}, 1)
ifeq ($(filter -v,${GOARGS}),)    
    GOARGS += -v
endif
TEST_FORMAT = short-verbose
endif

GOTESTSUM_VERSION = 1.9.0
GOLANGCI_VERSION = 1.53.3

-include override.mk

.PONY: clear
clear:
    rm -rf bin/

.PONY: check
check: test lint

TEST_PKGS ?= ./...
.PONY: test
test: TEST_FORMAT ?= short
test: SHELL = /bin/bash
test: export CGO_ENBABLED=1
test: bin/gotestsum 
    @mkdir -p ${BUILD_DIR}
	bin/gotestsum --no-summary=skipped --juniftile ${BUILD_DIR}/coverage.xml --format ${TEST_FORMAT}

.PONY: lint
lint: lint-go lint-yaml
lint:

.PONY: lint-go
lint-go: 
    golangci-lint run $(if ${CI},--out-format github-actions,)

.PONY: lint-yaml
lint-yaml:
    yamllint $(if $(CI),-f github,) --no-warnings .

.PONY: fmt 
    fmt:
	    golangci-lint run --fix

deps: bin/golangci-lint bin/gotestsum yamllint
deps:

bin/gotestsum:
    @mkdir -p bin
	curl -L curl -L https://github.com/gotestyourself/gotestsum/releases/download/v${GOTESTSUM_VERSION}/gotestsum_${GOTESTSUM_VERSION}_${OS}_amd64.tar.gz | tar -zOxf - gotestsum > ./bin/gotestsum && chmod +x ./bin/gotestsum

bin/golangci-lint:
    @mkdir -p bin 
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | bash -s -- v${GOLANGCI_VERSION}

.PONY: yamllint
yamllint:
    pip3 install --user yamllint

-include custom.mk

.PONY: help
.DEFAULT_GOAL := help
help:
    @grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

var-%: ;@echo $($*)	
varexport-%: ; @echo $*=$($*)


