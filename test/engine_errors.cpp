#include "engine_errors.hpp"
#include <cassert>
#include <string>

int main() {
	using duckdb::ExceptionType;
	for (auto type :
	     {ExceptionType::INTERRUPT, ExceptionType::INTERNAL, ExceptionType::FATAL, ExceptionType::OUT_OF_MEMORY})
		assert(gatekeeper::PropagateEngineError(type));
	for (auto type : {ExceptionType::SERIALIZATION, ExceptionType::INVALID_INPUT, ExceptionType::BINDER,
	                  ExceptionType::PERMISSION, ExceptionType::PARSER})
		assert(!gatekeeper::PropagateEngineError(type));
	assert(std::string(gatekeeper::EngineErrorCode(false)) == "invalid_input");
	assert(std::string(gatekeeper::EngineErrorCode(true)) == "binding");
}
