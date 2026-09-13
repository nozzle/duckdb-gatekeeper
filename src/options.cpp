#include "options.hpp"
#include "duckdb/common/types/value.hpp"
#include <stdexcept>

namespace gatekeeper {
using duckdb::LogicalType;
using duckdb::LogicalTypeId;
using duckdb::Value;

const std::vector<std::string> &OptionNames() {
	static const std::vector<std::string> names = {
	    "check_functions",       "use_default_functions", "allow_recursive_ctes",
	    "allow_table_functions", "allow_dynamic_sql",     "allow_file_table_references",
	    "allowed_functions",     "blocked_functions",     "allowed_catalogs",
	    "allowed_schemas",       "allowed_tables",        "allowed_types",
	    "max_statements",        "max_ast_bytes",         "max_ast_nodes",
	    "max_ast_depth"};
	return names;
}

LogicalType OptionType(const std::string &name) {
	if (name == "check_functions" || name == "use_default_functions" || name == "allow_recursive_ctes" ||
	    name == "allow_table_functions" || name == "allow_dynamic_sql" || name == "allow_file_table_references")
		return LogicalType::BOOLEAN;
	if (name == "allowed_functions" || name == "blocked_functions" || name == "allowed_catalogs" ||
	    name == "allowed_schemas")
		return LogicalType::LIST(LogicalType::VARCHAR);
	if (name == "allowed_tables" || name == "allowed_types")
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
		} else if (name == "allowed_tables" || name == "allowed_types") {
			bool is_type = name == "allowed_types";
			std::string leaf = is_type ? "type" : "table";
			if (value.type().id() != LogicalTypeId::LIST)
				throw std::invalid_argument(name + " requires a list of structs");
			const auto &entry_type = duckdb::ListType::GetChildType(value.type());
			if (entry_type.id() == LogicalTypeId::STRUCT) {
				Names fields;
				for (const auto &field : duckdb::StructType::GetChildTypes(entry_type)) {
					if (!fields.insert(field.first).second ||
					    (field.first != "catalog" && field.first != "schema" && field.first != leaf))
						throw std::invalid_argument("unknown " + leaf + " field: " + field.first);
				}
				if (!fields.count("schema") || !fields.count(leaf))
					throw std::invalid_argument(leaf + " entries require schema and " + leaf);
			}
			if (!is_type)
				policy.tables = true;
			auto &identities = is_type ? policy.allowed_types : policy.allowed_tables;
			identities.clear();
			for (const auto &entry : duckdb::ListValue::GetChildren(value)) {
				if (entry.IsNull() || entry.type().id() != LogicalTypeId::STRUCT)
					throw std::invalid_argument("expected " + leaf + " struct");
				auto &types = duckdb::StructType::GetChildTypes(entry.type());
				auto &values = duckdb::StructValue::GetChildren(entry);
				Names fields;
				Table table;
				for (size_t i = 0; i < types.size(); i++) {
					auto key = types[i].first;
					if (!fields.insert(key).second || (key != "catalog" && key != "schema" && key != leaf))
						throw std::invalid_argument("unknown " + leaf + " field: " + key);
					if (values[i].IsNull() && key == "catalog")
						continue;
					if (values[i].IsNull() || values[i].type().id() != LogicalTypeId::VARCHAR)
						throw std::invalid_argument("expected " + leaf + " identifier string");
					auto text = values[i].GetValue<std::string>();
					if (text.empty() || text.find('\0') != std::string::npos)
						throw std::invalid_argument(leaf + " identifiers must be nonempty and NUL-free");
					text = Lower(text);
					if (key == "catalog")
						table.catalog = text;
					if (key == "schema")
						table.schema = text;
					if (key == leaf)
						table.table = text;
				}
				if (!fields.count("schema") || !fields.count(leaf))
					throw std::invalid_argument(leaf + " entries require schema and " + leaf);
				identities.insert(table);
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

Value PolicyValue(const Policy &policy) {
	auto strings = [](const Names &names) {
		duckdb::vector<Value> values;
		for (const auto &name : names)
			values.emplace_back(name);
		return Value::LIST(LogicalType::VARCHAR, values);
	};
	auto identities = [](const std::set<Table> &entries, const std::string &leaf) {
		auto type = LogicalType::STRUCT(
		    {{"catalog", LogicalType::VARCHAR}, {"schema", LogicalType::VARCHAR}, {leaf, LogicalType::VARCHAR}});
		duckdb::vector<Value> values;
		for (const auto &entry : entries)
			values.push_back(
			    Value::STRUCT(type, {entry.catalog.empty() ? Value(LogicalType::VARCHAR) : Value(entry.catalog),
				                     Value(entry.schema), Value(entry.table)}));
		return Value::LIST(type, values);
	};
	return Value::STRUCT({{"check_functions", Value::BOOLEAN(policy.functions)},
	                      {"use_default_functions", Value::BOOLEAN(policy.defaults)},
	                      {"allow_recursive_ctes", Value::BOOLEAN(policy.recursive)},
	                      {"allow_table_functions", Value::BOOLEAN(policy.table_functions)},
	                      {"allow_dynamic_sql", Value::BOOLEAN(policy.dynamic_sql)},
	                      {"allow_file_table_references", Value::BOOLEAN(policy.file_tables)},
	                      {"allowed_functions", strings(policy.allowed_functions)},
	                      {"blocked_functions", strings(policy.blocked_functions)},
	                      {"allowed_catalogs", strings(policy.allowed_catalogs)},
	                      {"allowed_schemas", strings(policy.allowed_schemas)},
	                      {"allowed_tables", identities(policy.allowed_tables, "table")},
	                      {"allowed_types", identities(policy.allowed_types, "type")},
	                      {"max_statements", Value::BIGINT(policy.statements)},
	                      {"max_ast_bytes", Value::BIGINT(policy.bytes)},
	                      {"max_ast_nodes", Value::BIGINT(policy.nodes)},
	                      {"max_ast_depth", Value::BIGINT(policy.depth)},
	                      {"restrict_catalogs", Value::BOOLEAN(policy.catalogs)},
	                      {"restrict_schemas", Value::BOOLEAN(policy.schemas)},
	                      {"restrict_tables", Value::BOOLEAN(policy.tables)}});
}

Policy ReadPolicy(const Value &value) {
	// Recheck at use time: host configuration APIs can bypass extension SET callbacks.
	static const auto type = PolicyValue(Policy()).type();
	if (value.IsNull() || value.type() != type)
		throw std::invalid_argument("gatekeeper_policy requires the complete canonical policy STRUCT");
	auto &fields = duckdb::StructType::GetChildTypes(value.type());
	auto &values = duckdb::StructValue::GetChildren(value);
	std::vector<std::pair<std::string, Value>> options;
	bool catalogs = false, schemas = false, tables = false;
	for (size_t i = 0; i < fields.size(); i++) {
		auto &name = fields[i].first;
		if (values[i].IsNull())
			throw std::invalid_argument("NULL policy field: " + name);
		if (name == "restrict_catalogs")
			catalogs = values[i].GetValue<bool>();
		else if (name == "restrict_schemas")
			schemas = values[i].GetValue<bool>();
		else if (name == "restrict_tables")
			tables = values[i].GetValue<bool>();
		else
			options.emplace_back(name, values[i]);
	}
	Policy policy;
	ApplyOptions(policy, options);
	policy.catalogs = catalogs;
	policy.schemas = schemas;
	policy.tables = tables;
	return policy;
}
} // namespace gatekeeper
