PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
EXT_NAME=gatekeeper
EXT_CONFIG=${PROJ_DIR}extension_config.cmake
# Release build default for the pinned submodule. Shallow clones cannot `git describe` the engine,
# and DuckDB then stamps a dummy v0.0.1 that no real engine will load. Override for another
# checkout: `make release OVERRIDE_GIT_DESCRIBE=v1.5.6` or `OVERRIDE_GIT_DESCRIBE= make release`
# to use the checkout's own tags.
OVERRIDE_GIT_DESCRIBE ?= v1.5.5
include extension-ci-tools/makefiles/duckdb_extension.Makefile
