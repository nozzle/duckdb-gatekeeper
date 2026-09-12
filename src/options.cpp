#include "options.hpp"
#include "duckdb/common/types/value.hpp"
#include <stdexcept>

namespace gatekeeper {
using duckdb::LogicalType;
using duckdb::LogicalTypeId;
using duckdb::Value;

LogicalType OptionType(const std::string &name) {
	if (name == "check_functions" || name == "use_default_functions" || name == "allow_recursive_ctes" ||
	    name == "allow_table_functions" || name == "allow_dynamic_sql" || name == "allow_file_table_references")
		return LogicalType::BOOLEAN;
	if (name == "allowed_functions" || name == "blocked_functions" || name == "allowed_catalogs" ||
	    name == "allowed_schemas")
		return LogicalType::LIST(LogicalType::VARCHAR);
	if (name == "allowed_tables")
		return LogicalType::ANY;
	if (name == "max_statements" || name == "max_ast_bytes" || name == "max_ast_nodes" || name == "max_ast_depth")
		return LogicalType::BIGINT;
	throw std::invalid_argument("unknown option: " + name);
}

static Names Strings(const Value &value, bool lower) {
	if (value.type().id() != LogicalTypeId::LIST)
		throw std::invalid_argument("expected VARCHAR[]");
	Names result;
	for (const auto &item : duckdb::ListValue::GetChildren(value)) {
		if (item.IsNull() || item.type().id() != LogicalTypeId::VARCHAR)
			throw std::invalid_argument("expected non-NULL string");
		auto text = item.GetValue<std::string>();
		if (text.empty() || text.find('\0') != std::string::npos)
			throw std::invalid_argument("names must be nonempty and NUL-free");
		result.insert(lower ? Lower(text) : text);
	}
	return result;
}

void ApplyOptions(Policy &policy, const std::vector<std::pair<std::string, Value>> &options) {
	Names seen;
	for (const auto &option : options) {
		auto &name = option.first;
		auto &value = option.second;
		if (!seen.insert(name).second)
			throw std::invalid_argument("duplicate option: " + name);
		auto type = OptionType(name);
		if (value.IsNull())
			throw std::invalid_argument("NULL option: " + name);
		if (type == LogicalType::BOOLEAN) {
			if (value.type() != type)
				throw std::invalid_argument("expected BOOLEAN: " + name);
			auto flag = value.GetValue<bool>();
			if (name == "check_functions")
				policy.functions = flag;
			if (name == "use_default_functions")
				policy.defaults = flag;
			if (name == "allow_recursive_ctes")
				policy.recursive = flag;
			if (name == "allow_table_functions")
				policy.table_functions = flag;
			if (name == "allow_dynamic_sql")
				policy.dynamic_sql = flag;
			if (name == "allow_file_table_references")
				policy.file_tables = flag;
		} else if (name == "allowed_functions")
			policy.allowed_functions = Strings(value, true);
		else if (name == "blocked_functions")
			policy.blocked_functions = Strings(value, true);
		else if (name == "allowed_catalogs") {
			policy.catalogs = true;
			policy.allowed_catalogs = Strings(value, true);
		} else if (name == "allowed_schemas") {
			policy.schemas = true;
			policy.allowed_schemas = Strings(value, true);
		} else if (name == "allowed_tables") {
			if (value.type().id() != LogicalTypeId::LIST)
				throw std::invalid_argument("allowed_tables requires a list of structs");
			policy.tables = true;
			policy.allowed_tables.clear();
			for (const auto &entry : duckdb::ListValue::GetChildren(value)) {
				if (entry.IsNull() || entry.type().id() != LogicalTypeId::STRUCT)
					throw std::invalid_argument("expected table struct");
				auto &types = duckdb::StructType::GetChildTypes(entry.type());
				auto &values = duckdb::StructValue::GetChildren(entry);
				Names fields;
				Table table;
				for (size_t i = 0; i < types.size(); i++) {
					auto key = types[i].first;
					if (!fields.insert(key).second || (key != "catalog" && key != "schema" && key != "table"))
						throw std::invalid_argument("unknown table field: " + key);
					if (values[i].IsNull() && key == "catalog")
						continue;
					if (values[i].IsNull() || values[i].type().id() != LogicalTypeId::VARCHAR)
						throw std::invalid_argument("expected table identifier string");
					auto text = values[i].GetValue<std::string>();
					if (text.empty() || text.find('\0') != std::string::npos)
						throw std::invalid_argument("table identifiers must be nonempty and NUL-free");
					text = Lower(text);
					if (key == "catalog")
						table.catalog = text;
					if (key == "schema")
						table.schema = text;
					if (key == "table")
						table.table = text;
				}
				if (!fields.count("schema") || !fields.count("table"))
					throw std::invalid_argument("table entries require schema and table");
				policy.allowed_tables.insert(table);
			}
		} else {
			if (value.type() != LogicalType::BIGINT)
				throw std::invalid_argument("expected integer limit");
			auto limit = value.GetValue<int64_t>();
			uint64_t ceiling = name == "max_statements"  ? 1000
			                   : name == "max_ast_bytes" ? 8388608
			                   : name == "max_ast_nodes" ? 100000
			                                             : 512;
			if (limit <= 0 || uint64_t(limit) > ceiling)
				throw std::invalid_argument("invalid limit: " + name);
			if (name == "max_statements")
				policy.statements = limit;
			if (name == "max_ast_bytes")
				policy.bytes = limit;
			if (name == "max_ast_nodes")
				policy.nodes = limit;
			if (name == "max_ast_depth")
				policy.depth = limit;
		}
	}
	if (seen.count("check_functions") && !seen.count("use_default_functions"))
		policy.defaults = policy.functions;
	if (!policy.functions && !seen.count("allowed_functions"))
		policy.allowed_functions.clear();
	if (!policy.functions && !seen.count("use_default_functions"))
		policy.defaults = false;
	if (!policy.functions && (policy.defaults || !policy.allowed_functions.empty()))
		throw std::invalid_argument("allowlist options require check_functions");
}
} // namespace gatekeeper
