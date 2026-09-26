#include "result_value.hpp"
#include "options.hpp"

namespace duckdb {

static LogicalType ViolationType() {
	return LogicalType::STRUCT({{"rule", LogicalType::VARCHAR},
	                            {"message", LogicalType::VARCHAR},
	                            {"catalog", LogicalType::VARCHAR},
	                            {"schema_path", LogicalType::LIST(LogicalType::VARCHAR)},
	                            {"table", LogicalType::VARCHAR},
	                            {"function_name", LogicalType::VARCHAR},
	                            {"position", LogicalType::BIGINT},
	                            {"function_type", LogicalType::VARCHAR}});
}

static LogicalType IdentityType(bool object) {
	return LogicalType::STRUCT({{"catalog", LogicalType::VARCHAR},
	                            {"schema_path", LogicalType::LIST(LogicalType::VARCHAR)},
	                            {object ? "table" : "name", LogicalType::VARCHAR},
	                            {"type", LogicalType::VARCHAR}});
}

LogicalType ResultType() {
	return LogicalType::STRUCT({{"allowed", LogicalType::BOOLEAN},
	                            {"code", LogicalType::VARCHAR},
	                            {"violations", LogicalType::LIST(ViolationType())},
	                            {"error_type", LogicalType::VARCHAR},
	                            {"error_message", LogicalType::VARCHAR},
	                            {"position", LogicalType::BIGINT},
	                            {"objects", LogicalType::LIST(IdentityType(true))},
	                            {"functions", LogicalType::LIST(IdentityType(false))},
	                            {"caller_objects", LogicalType::LIST(IdentityType(true))}});
}

static Value Position(int64_t position) { return position < 0 ? Value(LogicalType::BIGINT) : Value::BIGINT(position); }

Value ResultValue(const gatekeeper::Result &result) {
	vector<Value> violations;
	for (auto &v : result.violations) {
		violations.push_back(Value::STRUCT(
		    ViolationType(), {Value(v.rule), Value(v.message), Value(v.catalog), gatekeeper::PathValue(v.schema_path),
			                  Value(v.table), Value(v.function_name), Position(v.position), Value(v.function_type)}));
	}
	auto identities = [&](const std::set<gatekeeper::Identity> &entries, bool object) {
		vector<Value> values;
		if (result.allowed) {
			for (const auto &entry : entries)
				values.push_back(
				    Value::STRUCT(IdentityType(object), {Value(entry.catalog), gatekeeper::PathValue(entry.schema_path),
					                                     Value(entry.name), Value(entry.type)}));
		}
		return Value::LIST(IdentityType(object), values);
	};
	return Value::STRUCT(ResultType(),
	                     {Value::BOOLEAN(result.allowed), Value(result.code), Value::LIST(ViolationType(), violations),
	                      Value(result.error_type), Value(result.error_message), Position(result.position),
	                      identities(result.objects, true), identities(result.functions, false),
	                      identities(result.caller_objects, true)});
}
} // namespace duckdb
