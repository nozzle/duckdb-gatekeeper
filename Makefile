PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
EXT_NAME=gatekeeper
EXT_CONFIG=${PROJ_DIR}extension_config.cmake
# DuckDB derives binary metadata from its build checkout unless the caller overrides it.
include extension-ci-tools/makefiles/duckdb_extension.Makefile
