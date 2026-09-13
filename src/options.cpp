#include "options.hpp"
#include "duckdb/common/types/value.hpp"
#include <stdexcept>

namespace gatekeeper {
using duckdb::LogicalType;
using duckdb::LogicalTypeId;
using duckdb::Value;

const std::vector<std::string> &OptionNames() {
	static const std::vector<std::string> names = {
	    "check_functions",         "use_default_functions", "allow_recursive_ctes", "allow_table_functions",
	    "allow_replacement_scans", "allowed_functions",     "blocked_functions",    "allowed_tables",
	    "max_statements",          "max_ast_bytes",         "max_ast_nodes",        "max_ast_depth"};
	return names;
}

LogicalType OptionType(const std::string &name) {
	if (name == "check_functions" || name == "use_default_functions" || name == "allow_recursive_ctes" ||
	    name == "allow_table_functions" || name == "allow_replacement_scans")
		return LogicalType::BOOLEAN;
	if (name == "allowed_functions" || name == "blocked_functions")
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
			if (name == "allow_replacement_scans")
				policy.replacement_scans = flag;
		} else if (name == "allowed_functions")
			policy.allowed_functions = Strings(value, true);
		else if (name == "blocked_functions")
			policy.blocked_functions = Strings(value, true);
		else if (name == "allowed_tables") {
			std::string leaf = "table";
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
			policy.tables = true;
			auto &identities = policy.allowed_tables;
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
		// The canonical setting is NULL-free at every depth: an empty catalog means any catalog. A NULL
		// produced by DuckDB's lossy STRUCT cast (for example a misspelled catalog key on direct SET) is
		// therefore always distinguishable from an intentional any-catalog entry and is rejected on read.
		for (const auto &entry : entries)
			values.push_back(Value::STRUCT(type, {Value(entry.catalog), Value(entry.schema), Value(entry.table)}));
		return Value::LIST(type, values);
	};
	return Value::STRUCT({{"check_functions", Value::BOOLEAN(policy.functions)},
	                      {"use_default_functions", Value::BOOLEAN(policy.defaults)},
	                      {"allow_recursive_ctes", Value::BOOLEAN(policy.recursive)},
	                      {"allow_table_functions", Value::BOOLEAN(policy.table_functions)},
	                      {"allow_replacement_scans", Value::BOOLEAN(policy.replacement_scans)},
	                      {"allowed_functions", strings(policy.allowed_functions)},
	                      {"blocked_functions", strings(policy.blocked_functions)},
	                      {"allowed_tables", identities(policy.allowed_tables, "table")},
	                      {"max_statements", Value::BIGINT(policy.statements)},
	                      {"max_ast_bytes", Value::BIGINT(policy.bytes)},
	                      {"max_ast_nodes", Value::BIGINT(policy.nodes)},
	                      {"max_ast_depth", Value::BIGINT(policy.depth)},
	                      {"restrict_tables", Value::BOOLEAN(policy.tables)}});
}

// Decode one canonical identity list. Unlike request options, the canonical form never contains NULL: a
// NULL here means DuckDB's STRUCT cast dropped or NULL-filled a field, so fail instead of widening.
static Value CanonicalIdentities(const std::string &name, const Value &value) {
	auto &entry_type = duckdb::ListType::GetChildType(value.type());
	duckdb::vector<Value> entries;
	for (const auto &entry : duckdb::ListValue::GetChildren(value)) {
		if (entry.IsNull())
			throw std::invalid_argument("NULL policy field: " + name + " entry");
		auto &fields = duckdb::StructType::GetChildTypes(entry.type());
		auto values = duckdb::StructValue::GetChildren(entry);
		for (size_t i = 0; i < fields.size(); i++) {
			if (values[i].IsNull())
				throw std::invalid_argument("NULL policy field: " + name + "." + fields[i].first);
			// The canonical any-catalog spelling is '', which request decoding expresses as NULL.
			if (fields[i].first == "catalog" && values[i].GetValue<std::string>().empty())
				values[i] = Value(LogicalType::VARCHAR);
		}
		entries.push_back(Value::STRUCT(entry_type, values));
	}
	return Value::LIST(entry_type, entries);
}

Policy ReadPolicy(const Value &value) {
	// Recheck at use time: host configuration APIs can bypass extension SET callbacks.
	static const auto type = PolicyValue(Policy()).type();
	if (value.IsNull() || value.type() != type)
		throw std::invalid_argument("gatekeeper_policy requires the complete canonical policy STRUCT");
	auto &fields = duckdb::StructType::GetChildTypes(value.type());
	auto &values = duckdb::StructValue::GetChildren(value);
	std::vector<std::pair<std::string, Value>> options;
	bool tables = false;
	for (size_t i = 0; i < fields.size(); i++) {
		auto &name = fields[i].first;
		if (values[i].IsNull())
			throw std::invalid_argument("NULL policy field: " + name);
		if (name == "restrict_tables")
			tables = values[i].GetValue<bool>();
		else if (name == "allowed_tables")
			options.emplace_back(name, CanonicalIdentities(name, values[i]));
		else
			options.emplace_back(name, values[i]);
	}
	Policy policy;
	ApplyOptions(policy, options);
	if (!tables && !policy.allowed_tables.empty())
		throw std::invalid_argument("nonempty allowed_tables requires restrict_tables = true");
	policy.tables = tables;
	return policy;
}
} // namespace gatekeeper
