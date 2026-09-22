#include "options.hpp"
#include "duckdb/common/types/value.hpp"
#include <memory>
#include <stdexcept>

namespace gatekeeper {
using duckdb::LogicalType;
using duckdb::LogicalTypeId;
using duckdb::Value;

enum class OptionKind { DEFAULTS, ALLOWED_FUNCTIONS, BLOCKED_FUNCTIONS, ALLOWED_TABLES, BLOCKED_TABLES };
struct OptionSpec {
	std::string name;
	OptionKind kind;
	LogicalTypeId element;
};
static const std::vector<OptionSpec> &Options() {
	static const std::vector<OptionSpec> options = {
	    {"use_default_functions", OptionKind::DEFAULTS, LogicalTypeId::BOOLEAN},
	    {"allowed_functions", OptionKind::ALLOWED_FUNCTIONS, LogicalTypeId::VARCHAR},
	    {"blocked_functions", OptionKind::BLOCKED_FUNCTIONS, LogicalTypeId::VARCHAR},
	    {"allowed_tables", OptionKind::ALLOWED_TABLES, LogicalTypeId::STRUCT},
	    {"blocked_tables", OptionKind::BLOCKED_TABLES, LogicalTypeId::STRUCT}};
	return options;
}
static const OptionSpec &FindOption(const std::string &name) {
	for (const auto &option : Options())
		if (option.name == name)
			return option;
	throw std::invalid_argument("unknown option: " + name);
}

const std::vector<std::string> &OptionNames() {
	static const auto names = [] {
		std::vector<std::string> result;
		for (const auto &option : Options())
			result.push_back(option.name);
		return result;
	}();
	return names;
}

void CheckOptionShape(const std::string &name, const Value &value) {
	auto element = FindOption(name).element;
	if (value.IsNull())
		return; // NULL values are reported at execution by validation.
	if (element == LogicalTypeId::BOOLEAN) {
		if (value.type() != LogicalType::BOOLEAN)
			throw std::invalid_argument(name + " requires BOOLEAN");
		return;
	}
	auto message = name + (element == LogicalTypeId::VARCHAR ? " requires VARCHAR[]" : " requires STRUCT[]");
	if (value.type().id() != LogicalTypeId::LIST)
		throw std::invalid_argument(message);
	// Empty and all-NULL lists have no value that can violate the element shape. DuckDB
	// gives untyped [] and [NULL] INTEGER[]; semantic decoding still rejects NULL members.
	if (duckdb::ListType::GetChildType(value.type()).id() != element)
		for (const auto &entry : duckdb::ListValue::GetChildren(value))
			if (!entry.IsNull())
				throw std::invalid_argument(message);
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

void CheckArguments(const std::vector<std::pair<std::string, Value>> &arguments) {
	for (const auto &argument : arguments) {
		if (argument.first == "json") {
			if (arguments.size() != 1)
				throw std::invalid_argument("json and typed Gatekeeper options are mutually exclusive");
			if (!argument.second.IsNull() && argument.second.type().id() != LogicalTypeId::VARCHAR)
				throw std::invalid_argument("json requires VARCHAR");
		} else
			CheckOptionShape(argument.first, argument.second);
	}
}

using namespace duckdb_yyjson;

static std::string JsonString(Json *value) {
	if (!yyjson_is_str(value))
		throw std::invalid_argument("expected JSON string");
	return std::string(yyjson_get_str(value), yyjson_get_len(value));
}

static std::vector<std::pair<std::string, Json *>> JsonObject(Json *object) {
	if (!yyjson_is_obj(object))
		throw std::invalid_argument("expected JSON object");
	std::vector<std::pair<std::string, Json *>> fields;
	Names seen;
	size_t i, count;
	Json *key, *value;
	yyjson_obj_foreach(object, i, count, key, value) {
		auto name = JsonString(key);
		if (!seen.insert(name).second)
			throw std::invalid_argument("duplicate JSON field: " + name);
		fields.emplace_back(std::move(name), value);
	}
	return fields;
}

static Value JsonOption(const std::string &name, Json *value) {
	auto element = FindOption(name).element;
	if (yyjson_is_null(value))
		return Value(); // Let the shared decoder report NULL options.
	if (element == LogicalTypeId::BOOLEAN) {
		if (!yyjson_is_bool(value))
			throw std::invalid_argument(name + " requires JSON boolean");
		return Value::BOOLEAN(yyjson_get_bool(value));
	}
	if (!yyjson_is_arr(value))
		throw std::invalid_argument(name + " requires JSON array");
	auto type = element == LogicalTypeId::VARCHAR ? LogicalType::VARCHAR
	                                              : LogicalType::STRUCT({{"catalog", LogicalType::VARCHAR},
	                                                                     {"schema", LogicalType::VARCHAR},
	                                                                     {"table", LogicalType::VARCHAR}});
	duckdb::vector<Value> entries;
	size_t i, count;
	Json *entry;
	yyjson_arr_foreach(value, i, count, entry) {
		if (yyjson_is_null(entry))
			entries.emplace_back(type);
		else if (element == LogicalTypeId::VARCHAR)
			entries.emplace_back(JsonString(entry));
		else {
			duckdb::vector<Value> fields(3, Value(LogicalType::VARCHAR));
			bool schema = false, table = false;
			for (const auto &field : JsonObject(entry)) {
				size_t index;
				if (field.first == "catalog")
					index = 0;
				else if (field.first == "schema") {
					index = 1;
					schema = true;
				} else if (field.first == "table") {
					index = 2;
					table = true;
				} else
					throw std::invalid_argument("unknown table field: " + field.first);
				if (!yyjson_is_null(field.second))
					fields[index] = Value(JsonString(field.second));
			}
			if (!schema || !table)
				throw std::invalid_argument("table entries require schema and table");
			entries.push_back(Value::STRUCT(type, fields));
		}
	}
	return Value::LIST(type, entries);
}

static std::vector<std::pair<std::string, Value>> JsonOptions(const Value &input) {
	if (input.IsNull())
		throw std::invalid_argument("NULL json argument");
	auto text = input.GetValue<std::string>();
	yyjson_read_err error;
	std::unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)> doc(
	    yyjson_read_opts(text.data(), text.size(), 0, nullptr, &error), yyjson_doc_free);
	if (!doc)
		throw std::invalid_argument("invalid policy JSON at byte " + std::to_string(error.pos) + ": " + error.msg);
	Json *options = nullptr;
	bool version = false;
	for (const auto &field : JsonObject(yyjson_doc_get_root(doc.get()))) {
		if (field.first == "version") {
			if (!yyjson_is_num(field.second) || yyjson_get_num(field.second) != 1)
				throw std::invalid_argument("policy JSON version must be 1");
			version = true;
		} else if (field.first == "options")
			options = field.second;
		else if (field.first == "$schema") {
			if (JsonString(field.second) !=
			    "https://raw.githubusercontent.com/nozzle/duckdb-gatekeeper/main/docs/policy-v1.schema.json")
				throw std::invalid_argument("unknown policy JSON $schema");
		} else
			throw std::invalid_argument("unknown policy JSON field: " + field.first);
	}
	if (!version || !options)
		throw std::invalid_argument("policy JSON requires version and options");
	std::vector<std::pair<std::string, Value>> result;
	for (const auto &option : JsonObject(options))
		result.emplace_back(option.first, JsonOption(option.first, option.second));
	return result;
}

void ApplyArguments(Policy &policy, const std::vector<std::pair<std::string, Value>> &arguments) {
	CheckArguments(arguments);
	if (arguments.size() == 1 && arguments[0].first == "json")
		ApplyOptions(policy, JsonOptions(arguments[0].second));
	else
		ApplyOptions(policy, arguments);
}

void ApplyOptions(Policy &policy, const std::vector<std::pair<std::string, Value>> &options) {
	Names seen;
	for (const auto &option : options) {
		auto &name = option.first;
		auto &value = option.second;
		if (!seen.insert(name).second)
			throw std::invalid_argument("duplicate option: " + name);
		auto kind = FindOption(name).kind;
		CheckOptionShape(name, value);
		if (value.IsNull())
			throw std::invalid_argument("NULL option: " + name);
		if (kind == OptionKind::DEFAULTS) {
			policy.defaults = value.GetValue<bool>();
		} else if (kind == OptionKind::ALLOWED_FUNCTIONS)
			policy.allowed_functions = Strings(value, true);
		else if (kind == OptionKind::BLOCKED_FUNCTIONS)
			policy.blocked_functions = Strings(value, true);
		else {
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
			if (kind == OptionKind::ALLOWED_TABLES)
				policy.tables = true;
			auto &identities = kind == OptionKind::ALLOWED_TABLES ? policy.allowed_tables : policy.blocked_tables;
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
		}
	}
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
	return Value::STRUCT({{"use_default_functions", Value::BOOLEAN(policy.defaults)},
	                      {"allowed_functions", strings(policy.allowed_functions)},
	                      {"blocked_functions", strings(policy.blocked_functions)},
	                      {"allowed_tables", identities(policy.allowed_tables, "table")},
	                      {"blocked_tables", identities(policy.blocked_tables, "table")},
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
		else if (name == "allowed_tables" || name == "blocked_tables")
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
