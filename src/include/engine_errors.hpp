#pragma once
#include "duckdb/common/exception.hpp"

namespace gatekeeper {
// These exceptions must reach DuckDB's cancellation/database invalidation handling.
inline bool PropagateEngineError(duckdb::ExceptionType type) {
	return type == duckdb::ExceptionType::INTERRUPT || type == duckdb::ExceptionType::INTERNAL ||
	       type == duckdb::ExceptionType::FATAL || type == duckdb::ExceptionType::OUT_OF_MEMORY;
}

inline const char *EngineErrorCode(bool binding) { return binding ? "binding" : "invalid_input"; }
} // namespace gatekeeper
