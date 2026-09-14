PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
EXT_NAME=gatekeeper
EXT_CONFIG=${PROJ_DIR}extension_config.cmake
# DuckDB stamps the engine identity from `git describe` of the checkout it compiles. A shallow clone
# of the pinned submodule cannot describe itself and DuckDB then stamps a dummy v0.0.1 that no real
# engine will load, so supply the release pin for exactly that revision. Any other checkout, including
# a community rebuild for a newer engine, keeps its own Git metadata: a fixed default here would label
# every rebuild as the pinned release. Override explicitly with `make release OVERRIDE_GIT_DESCRIBE=...`.
ifeq ($(origin OVERRIDE_GIT_DESCRIBE),undefined)
GATEKEEPER_PINNED_REVISION := $(shell sed -n 's/.*GATEKEEPER_DUCKDB_REVISION "\([0-9a-f]*\)".*/\1/p' $(PROJ_DIR)versions.cmake)
GATEKEEPER_PINNED_VERSION := $(shell sed -n 's/.*GATEKEEPER_DUCKDB_VERSION "\([0-9.]*\)".*/\1/p' $(PROJ_DIR)versions.cmake)
GATEKEEPER_ENGINE_DIR := $(or $(subst ",,$(DUCKDB_SRCDIR)),$(PROJ_DIR)duckdb)
ifeq ($(shell git -C $(GATEKEEPER_ENGINE_DIR) rev-parse HEAD 2>/dev/null),$(GATEKEEPER_PINNED_REVISION))
OVERRIDE_GIT_DESCRIBE := v$(GATEKEEPER_PINNED_VERSION)
endif
endif
include extension-ci-tools/makefiles/duckdb_extension.Makefile
