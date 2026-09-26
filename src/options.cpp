#include "options.hpp"
#include "duckdb/common/types/value.hpp"
#include "engine_api.hpp"
#include "function_policy.hpp"
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
	    {"allowed_functions", OptionKind::ALLOWED_FUNCTIONS, LogicalTypeId::STRUCT},
	    {"blocked_functions", OptionKind::BLOCKED_FUNCTIONS, LogicalTypeId::STRUCT},
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
	if (name == "allowed_functions" || name == "blocked_functions")
		message += "; migrate to policy v2 {catalog?, schema_path, name, type?} rules";
	if (value.type().id() != LogicalTypeId::LIST)
		throw std::invalid_argument(message);
	// Empty and all-NULL lists have no value that can violate the element shape. DuckDB
	// gives untyped [] and [NULL] INTEGER[]; semantic decoding still rejects NULL members.
	if (duckdb::ListType::GetChildType(value.type()).id() != element)
		for (const auto &entry : duckdb::ListValue::GetChildren(value))
			if (!entry.IsNull())
				throw std::invalid_argument(message);
}

static NamePath SchemaPath(const Value &value) {
	if (value.IsNull() || value.type().id() != LogicalTypeId::LIST)
		throw std::invalid_argument("schema_path requires a nonempty VARCHAR[]");
	NamePath path;
	for (const auto &part : duckdb::ListValue::GetChildren(value)) {
		if (part.IsNull() || part.type().id() != LogicalTypeId::VARCHAR)
			throw std::invalid_argument("schema_path requires non-NULL string components");
		auto text = part.GetValue<std::string>();
		if (text.empty() || text.find('\0') != std::string::npos)
			throw std::invalid_argument("schema_path components must be nonempty and NUL-free");
		path.push_back(Lower(text));
	}
	if (path.empty())
		throw std::invalid_argument("schema_path must be nonempty");
	return path;
}

Value PathValue(const NamePath &path) {
	duckdb::vector<Value> values;
	for (const auto &part : path)
		values.emplace_back(part);
	return Value::LIST(LogicalType::VARCHAR, values);
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

static std::string JsonString(Json *value, const std::string &path) {
	if (!yyjson_is_str(value))
		throw std::invalid_argument(path + ": expected JSON string");
	return std::string(yyjson_get_str(value), yyjson_get_len(value));
}

static std::vector<std::pair<std::string, Json *>> JsonObject(Json *object, const std::string &path) {
	if (!yyjson_is_obj(object))
		throw std::invalid_argument(path + ": expected JSON object");
	std::vector<std::pair<std::string, Json *>> fields;
	Names seen;
	size_t i, count;
	Json *key, *value;
	yyjson_obj_foreach(object, i, count, key, value) {
		auto name = JsonString(key, path);
		if (!seen.insert(name).second)
			throw std::invalid_argument(path + ": duplicate JSON field: " + name);
		fields.emplace_back(std::move(name), value);
	}
	return fields;
}

static Value JsonOption(const std::string &name, Json *value) {
	auto element = FindOption(name).element;
	const bool functions = name == "allowed_functions" || name == "blocked_functions";
	const std::string leaf = functions ? "name" : "table";
	if (yyjson_is_null(value))
		return Value(); // Let the shared decoder report NULL options.
	if (element == LogicalTypeId::BOOLEAN) {
		if (!yyjson_is_bool(value))
			throw std::invalid_argument(name + " requires JSON boolean");
		return Value::BOOLEAN(yyjson_get_bool(value));
	}
	if (!yyjson_is_arr(value))
		throw std::invalid_argument(name + " requires JSON array");
	auto type = element == LogicalTypeId::VARCHAR
	                ? LogicalType::VARCHAR
	                : LogicalType::STRUCT({{"catalog", LogicalType::VARCHAR},
	                                       {"schema_path", LogicalType::LIST(LogicalType::VARCHAR)},
	                                       {duckdb::engine::ToName(leaf), LogicalType::VARCHAR}});
	if (functions)
		type = LogicalType::STRUCT({{"catalog", LogicalType::VARCHAR},
		                            {"schema_path", LogicalType::LIST(LogicalType::VARCHAR)},
		                            {"name", LogicalType::VARCHAR},
		                            {"type", LogicalType::VARCHAR}});
	duckdb::vector<Value> entries;
	size_t i, count;
	Json *entry;
	yyjson_arr_foreach(value, i, count, entry) {
		auto path = "options." + name + "[" + std::to_string(i) + "]";
		if (yyjson_is_null(entry))
			entries.emplace_back(type);
		else if (element == LogicalTypeId::VARCHAR)
			entries.emplace_back(JsonString(entry, path));
		else {
			if (functions && yyjson_is_str(entry))
				throw std::invalid_argument(path + ": migrate " + name + " to policy v2 qualified objects");
			duckdb::vector<Value> fields(functions ? 4 : 3, Value(LogicalType::VARCHAR));
			fields[1] = Value(LogicalType::LIST(LogicalType::VARCHAR));
			bool schema = false, table = false;
			for (const auto &field : JsonObject(entry, path)) {
				size_t index;
				if (field.first == "catalog")
					index = 0;
				else if (field.first == "schema_path") {
					index = 1;
					schema = true;
					if (!yyjson_is_arr(field.second))
						throw std::invalid_argument("schema_path requires JSON array");
					NamePath parts;
					size_t j, n;
					Json *part;
					yyjson_arr_foreach(field.second, j, n, part)
					    parts.push_back(JsonString(part, path + ".schema_path"));
					fields[index] = PathValue(parts);
					continue;
				} else if (field.first == leaf) {
					index = 2;
					table = true;
				} else if (functions && field.first == "type") {
					index = 3;
				} else
					throw std::invalid_argument(std::string("unknown ") + (functions ? "function" : "table") +
					                            " field: " + field.first);
				if (!yyjson_is_null(field.second))
					fields[index] = Value(JsonString(field.second, path + "." + field.first));
			}
			if (!schema || !table)
				throw std::invalid_argument("identity entries require schema_path and " + leaf);
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
	for (const auto &field : JsonObject(yyjson_doc_get_root(doc.get()), "policy")) {
		if (field.first == "version") {
			if (!yyjson_is_num(field.second) || yyjson_get_num(field.second) != 2)
				throw std::invalid_argument("policy JSON version must be 2");
			version = true;
		} else if (field.first == "options")
			options = field.second;
		else if (field.first == "$schema") {
			if (JsonString(field.second, "$schema") !=
			    "https://raw.githubusercontent.com/nozzle/duckdb-gatekeeper/main/docs/policy-v2.schema.json")
				throw std::invalid_argument("unknown policy JSON $schema");
		} else
			throw std::invalid_argument("unknown policy JSON field: " + field.first);
	}
	if (!version || !options)
		throw std::invalid_argument("policy JSON requires version and options");
	std::vector<std::pair<std::string, Value>> result;
	for (const auto &option : JsonObject(options, "options"))
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
		} else {
			const bool functions = kind == OptionKind::ALLOWED_FUNCTIONS || kind == OptionKind::BLOCKED_FUNCTIONS;
			auto &function_rules =
			    kind == OptionKind::ALLOWED_FUNCTIONS ? policy.allowed_functions : policy.blocked_functions;
			std::string leaf = functions ? "name" : "table";
			if (value.type().id() != LogicalTypeId::LIST)
				throw std::invalid_argument(name + " requires a list of structs");
			const auto &entry_type = duckdb::ListType::GetChildType(value.type());
			if (entry_type.id() == LogicalTypeId::STRUCT) {
				Names fields;
				for (const auto &field : duckdb::StructType::GetChildTypes(entry_type)) {
					auto &key = duckdb::engine::Str(field.first);
					if (!fields.insert(key).second ||
					    (key != "catalog" && key != "schema_path" && key != leaf && !(functions && key == "type")))
						throw std::invalid_argument("unknown " + leaf + " field: " + key);
				}
				if (!fields.count("schema_path") || !fields.count(leaf))
					throw std::invalid_argument(leaf + " entries require schema_path and " + leaf);
			}
			if (kind == OptionKind::ALLOWED_TABLES)
				policy.tables = true;
			auto &identities = kind == OptionKind::ALLOWED_TABLES ? policy.allowed_tables : policy.blocked_tables;
			if (functions)
				function_rules.clear();
			else
				identities.clear();
			for (const auto &entry : duckdb::ListValue::GetChildren(value)) {
				if (entry.IsNull() || entry.type().id() != LogicalTypeId::STRUCT)
					throw std::invalid_argument("expected " + leaf + " struct");
				auto &types = duckdb::StructType::GetChildTypes(entry.type());
				auto &values = duckdb::StructValue::GetChildren(entry);
				Names fields;
				Table table;
				std::string function_type;
				for (size_t i = 0; i < types.size(); i++) {
					auto &key = duckdb::engine::Str(types[i].first);
					if (!fields.insert(key).second ||
					    (key != "catalog" && key != "schema_path" && key != leaf && !(functions && key == "type")))
						throw std::invalid_argument("unknown " + leaf + " field: " + key);
					if (key == "schema_path") {
						table.schema_path = SchemaPath(values[i]);
						continue;
					}
					if (values[i].IsNull() && (key == "catalog" || (functions && key == "type")))
						continue;
					if (values[i].IsNull() || values[i].type().id() != LogicalTypeId::VARCHAR)
						throw std::invalid_argument("expected " + leaf + " identifier string");
					auto text = values[i].GetValue<std::string>();
					if (text.empty() || text.find('\0') != std::string::npos)
						throw std::invalid_argument(leaf + " identifiers must be nonempty and NUL-free");
					text = Lower(text);
					if (key == "catalog")
						table.catalog = text;
					if (key == leaf)
						table.table = text;
					if (functions && key == "type") {
						if (!SupportedFunctionKind(text))
							throw std::invalid_argument("unsupported function type: " + text);
						function_type = text;
					}
				}
				if (!fields.count("schema_path") || !fields.count(leaf))
					throw std::invalid_argument(leaf + " entries require schema_path and " + leaf);
				if (functions)
					function_rules.insert({table.catalog, table.schema_path, table.table, function_type});
				else
					identities.insert(table);
			}
		}
	}
}

Value PolicyValue(const Policy &policy) {
	auto function_type = LogicalType::STRUCT({{"catalog", LogicalType::VARCHAR},
	                                          {"schema_path", LogicalType::LIST(LogicalType::VARCHAR)},
	                                          {"name", LogicalType::VARCHAR},
	                                          {"type", LogicalType::VARCHAR}});
	auto functions = [&](const std::set<FunctionGrant> &rules) {
		duckdb::vector<Value> values;
		for (const auto &entry : rules)
			values.push_back(Value::STRUCT(function_type, {Value(entry.catalog), PathValue(entry.schema_path),
			                                               Value(entry.name), Value(entry.type)}));
		return Value::LIST(function_type, values);
	};
	auto identities = [](const std::set<Table> &entries, const std::string &leaf) {
		auto type = LogicalType::STRUCT({{"catalog", LogicalType::VARCHAR},
		                                 {"schema_path", LogicalType::LIST(LogicalType::VARCHAR)},
		                                 {duckdb::engine::ToName(leaf), LogicalType::VARCHAR}});
		duckdb::vector<Value> values;
		// The canonical setting is NULL-free at every depth: an empty catalog means any catalog. A NULL
		// produced by DuckDB's lossy STRUCT cast (for example a misspelled catalog key on direct SET) is
		// therefore always distinguishable from an intentional any-catalog entry and is rejected on read.
		for (const auto &entry : entries)
			values.push_back(
			    Value::STRUCT(type, {Value(entry.catalog), PathValue(entry.schema_path), Value(entry.table)}));
		return Value::LIST(type, values);
	};
	return Value::STRUCT({{"use_default_functions", Value::BOOLEAN(policy.defaults)},
	                      {"allowed_functions", functions(policy.allowed_functions)},
	                      {"blocked_functions", functions(policy.blocked_functions)},
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
			auto &field = duckdb::engine::Str(fields[i].first);
			if (values[i].IsNull())
				throw std::invalid_argument("NULL policy field: " + name + "." + field);
			// The canonical any-catalog spelling is '', which request decoding expresses as NULL.
			if ((field == "catalog" ||
			     ((name == "allowed_functions" || name == "blocked_functions") && field == "type")) &&
			    values[i].GetValue<std::string>().empty())
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
		auto &name = duckdb::engine::Str(fields[i].first);
		if (values[i].IsNull())
			throw std::invalid_argument("NULL policy field: " + name);
		if (name == "restrict_tables")
			tables = values[i].GetValue<bool>();
		else if (name == "allowed_tables" || name == "blocked_tables" || name == "allowed_functions" ||
		         name == "blocked_functions")
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
