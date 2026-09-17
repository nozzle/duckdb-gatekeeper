cmake_minimum_required(VERSION 3.15)
project(gatekeeper)
if(NOT DuckDB_SOURCE_DIR)
  message(FATAL_ERROR "Gatekeeper must be built as part of a DuckDB source build")
endif()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
file(GLOB_RECURSE INVENTORY_FILES CONFIGURE_DEPENDS inventories/*.json)
file(GLOB SERIALIZATION_FILES CONFIGURE_DEPENDS
     "${DuckDB_SOURCE_DIR}/src/include/duckdb/storage/serialization/*.json")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    scripts/generate.py scripts/inventory.py scripts/schema_check.py scripts/versions.py versions.cmake
    ${INVENTORY_FILES} ${SERIALIZATION_FILES})
# The engine identity DuckDB stamps into this artifact's footer; the extension re-checks it at load
# time because the footer check itself can be disabled (see LoadInternal).
if(NOT DUCKDB_VERSION)
  message(FATAL_ERROR "DuckDB did not export DUCKDB_VERSION for the Gatekeeper engine guard")
endif()
# Generated headers live in the build tree so parallel configurations never race on shared files.
set(GATEKEEPER_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
execute_process(COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate.py
                        --output "${GATEKEEPER_GENERATED_DIR}"
                        --duckdb-source "${DuckDB_SOURCE_DIR}"
                        --duckdb-version "${DUCKDB_VERSION}"
                        --duckdb-source-id "${GIT_COMMIT_HASH}"
                RESULT_VARIABLE GENERATE_RESULT)
if(NOT GENERATE_RESULT EQUAL 0)
  message(FATAL_ERROR "Gatekeeper inventory generation failed")
endif()
include_directories(src/include ${GATEKEEPER_GENERATED_DIR}
                    "${DuckDB_SOURCE_DIR}/extension/json/include"
                    "${DuckDB_SOURCE_DIR}/third_party/yyjson/include")
set(EXTENSION_SOURCES src/gatekeeper_extension.cpp src/authorization.cpp src/check.cpp src/enforcement.cpp
    src/options.cpp src/pragma_guard.cpp src/validator.cpp "${DuckDB_SOURCE_DIR}/extension/json/json_serializer.cpp")
build_static_extension(gatekeeper ${EXTENSION_SOURCES})
build_loadable_extension(gatekeeper "" ${EXTENSION_SOURCES})
target_link_libraries(gatekeeper_extension duckdb_yyjson)
target_link_libraries(gatekeeper_loadable_extension duckdb_yyjson)
# vptr checks are disabled in every sanitizer configuration: the instrumented extension shares
# RTTI with an uninstrumented DuckDB/Python runtime, which UBSan reports as false positives.
option(GATEKEEPER_FUZZ "Build SQL/typed-option libFuzzer target (Clang required)" OFF)
if(GATEKEEPER_FUZZ)
  add_executable(gatekeeper_sql_fuzz test/fuzz/sql_options_fuzz.cpp)
  target_compile_definitions(gatekeeper_sql_fuzz PRIVATE GATEKEEPER_FUZZ)
  target_compile_definitions(gatekeeper_extension PRIVATE GATEKEEPER_FUZZ)
  target_compile_options(gatekeeper_sql_fuzz PRIVATE -fsanitize=fuzzer,address,undefined -fno-sanitize=vptr)
  target_link_options(gatekeeper_sql_fuzz PRIVATE -fsanitize=fuzzer,address,undefined -fno-sanitize=vptr)
  target_link_libraries(gatekeeper_sql_fuzz duckdb)
  foreach(TARGET gatekeeper_extension gatekeeper_loadable_extension)
    target_compile_options(${TARGET} PRIVATE -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize=vptr)
  endforeach()
endif()
option(GATEKEEPER_SANITIZE "Instrument Gatekeeper with address/undefined behavior sanitizers" OFF)
if(GATEKEEPER_SANITIZE)
  foreach(TARGET gatekeeper_extension gatekeeper_loadable_extension)
    target_compile_options(${TARGET} PRIVATE -fsanitize=address,undefined -fno-sanitize=vptr -fno-omit-frame-pointer)
    target_link_options(${TARGET} PRIVATE -fsanitize=address,undefined -fno-sanitize=vptr)
  endforeach()
endif()
install(TARGETS gatekeeper_extension EXPORT "${DUCKDB_EXPORT_SET}"
        LIBRARY DESTINATION "${INSTALL_LIB_DIR}" ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
