cmake_minimum_required(VERSION 3.15)
project(gatekeeper)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
file(GLOB_RECURSE INVENTORY_FILES CONFIGURE_DEPENDS inventories/*.json)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    scripts/generate.py scripts/inventory.py ${INVENTORY_FILES})
execute_process(COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate.py
                RESULT_VARIABLE GENERATE_RESULT)
if(NOT GENERATE_RESULT EQUAL 0)
  message(FATAL_ERROR "Gatekeeper inventory generation failed")
endif()
include_directories(src/include ${CMAKE_CURRENT_SOURCE_DIR}/generated
                    ${CMAKE_CURRENT_SOURCE_DIR}/duckdb/extension/json/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/duckdb/third_party/yyjson/include)
set(EXTENSION_SOURCES src/gatekeeper_extension.cpp src/validator.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/duckdb/extension/json/json_serializer.cpp)
build_static_extension(gatekeeper ${EXTENSION_SOURCES})
build_loadable_extension(gatekeeper "" ${EXTENSION_SOURCES})
target_link_libraries(gatekeeper_extension duckdb_yyjson)
target_link_libraries(gatekeeper_loadable_extension duckdb_yyjson)
option(GATEKEEPER_SANITIZE "Instrument Gatekeeper with address/undefined behavior sanitizers" OFF)
if(GATEKEEPER_SANITIZE)
  foreach(TARGET gatekeeper_extension gatekeeper_loadable_extension)
    target_compile_options(${TARGET} PRIVATE -fsanitize=address,undefined -fno-sanitize=vptr -fno-omit-frame-pointer)
    target_link_options(${TARGET} PRIVATE -fsanitize=address,undefined -fno-sanitize=vptr)
  endforeach()
endif()
install(TARGETS gatekeeper_extension EXPORT "${DUCKDB_EXPORT_SET}"
        LIBRARY DESTINATION "${INSTALL_LIB_DIR}" ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
