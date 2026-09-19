#pragma once
#include "duckdb/common/exception.hpp"
#include "validator.hpp"

namespace gatekeeper {
// These exceptions must reach DuckDB's cancellation/database invalidation handling.
inline bool PropagateEngineError(duckdb::ExceptionType type) {
	return type == duckdb::ExceptionType::INTERRUPT || type == duckdb::ExceptionType::INTERNAL ||
	       type == duckdb::ExceptionType::FATAL || type == duckdb::ExceptionType::OUT_OF_MEMORY;
}

// An engine error is 'binding' once the text was admitted and 'invalid_input' before.
inline const char *EngineErrorCode(bool binding) { return binding ? codes::BINDING : codes::INVALID_INPUT; }
} // namespace gatekeeper
