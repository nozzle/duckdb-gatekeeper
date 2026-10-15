include(${CMAKE_CURRENT_LIST_DIR}/versions.cmake)
duckdb_extension_load(gatekeeper SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR} EXTENSION_VERSION ${GATEKEEPER_VERSION})
# DuckDB 2.0 links into its own targets (unittest, shell, the native probes' library) only the extensions a config
# names; 1.5 links every loaded extension and has no such function.
if(COMMAND duckdb_extension_statically_link)
  duckdb_extension_statically_link(gatekeeper)
endif()
