include(${CMAKE_CURRENT_LIST_DIR}/versions.cmake)
duckdb_extension_load(gatekeeper SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR} EXTENSION_VERSION ${GATEKEEPER_VERSION})
