#include "audit.hpp"
#include "check.hpp"
#include "duckdb/common/types/hash.hpp"
#include "duckdb/logging/log_manager.hpp"
#include "duckdb/logging/log_type.hpp"
#include "duckdb/logging/logger.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/transaction/meta_transaction.hpp"
#include "options.hpp"
#include "result_value.hpp"

namespace duckdb {

// Longest statement text a record carries. Denied text is where junk payloads arrive, in-memory log storage is
// unbounded, and MAX_AST_BYTES admits 8 MiB; statement_length always reports the full size.
static constexpr idx_t MAX_LOGGED_STATEMENT = 65536;

// One record per decision or setting change. The decision columns are exactly gatekeeper_validate's, so the
// log and the function describe a statement the same way; the rest says how and where it was made. Which
// connection, transaction, and query it belongs to are DuckDB's own log-context columns, filled in per record
// (see Write). Messages are serialized as the struct's text form, which duckdb_logs_parsed('Gatekeeper')
// casts back.
class GatekeeperLogType : public LogType {
  public:
	static constexpr const char *NAME = "Gatekeeper";
	static constexpr LogLevel LEVEL = LogLevel::LOG_INFO;
	GatekeeperLogType() : LogType(NAME, LEVEL, GetLogType()) {}
	static LogicalType GetLogType() {
		child_list_t<LogicalType> fields = {
		    {"event", LogicalType::VARCHAR}, {"mode", LogicalType::VARCHAR}, {"boundary", LogicalType::VARCHAR}};
		auto result_type = ResultType(); // keep the type alive while its child list is read
		for (const auto &field : StructType::GetChildTypes(result_type))
			fields.push_back(field);
		fields.emplace_back("statement", LogicalType::VARCHAR);
		fields.emplace_back("statement_length", LogicalType::BIGINT);
		fields.emplace_back("policy_hash", LogicalType::VARCHAR);
		fields.emplace_back("new_value", LogicalType::VARCHAR);
		return LogicalType::STRUCT(std::move(fields));
	}
};

static const char *ModeName(DecisionMode mode) {
	switch (mode) {
	case DecisionMode::ENFORCE:
		return "enforce";
	case DecisionMode::VALIDATE:
		return "validate";
	}
	return "unknown";
}

static Value BoundaryName(Boundary boundary) {
	switch (boundary) {
	case Boundary::BINDING:
		return Value("binding");
	case Boundary::AUTHORIZE:
		return Value("authorize");
	case Boundary::EXECUTION:
		return Value("execution");
	case Boundary::PREPARE:
		return Value("prepare");
	case Boundary::REPLACEMENT_SCAN:
		return Value("replacement_scan");
	case Boundary::NONE:
		break;
	}
	return Value(LogicalType::VARCHAR);
}

// Sixteen lowercase hex digits of DuckDB's string hash, stable across processes and platforms.
static string HashText(const string &text) {
	static const char digits[] = "0123456789abcdef";
	auto hash = Hash(text.c_str(), text.size());
	string hex(16, '0');
	for (int i = 15; i >= 0; i--, hash >>= 4)
		hex[static_cast<size_t>(i)] = digits[hash & 0xf];
	return hex;
}

// The canonical text of a policy is its setting value; the same string hashes here and in policy_changed.
static Value PolicyHash(optional_ptr<const gatekeeper::Policy> policy) {
	if (!policy)
		return Value(LogicalType::VARCHAR);
	return Value(HashText(gatekeeper::PolicyValue(*policy).ToString()));
}

// Statement text as the record stores it: cut at the cap on a UTF-8 boundary, with NUL bytes (which would
// truncate the message on the way into storage) replaced so every record stays parseable.
static Value StatementText(const string &statement) {
	auto length = MinValue<idx_t>(statement.size(), MAX_LOGGED_STATEMENT);
	while (length > 0 && length < statement.size() && (static_cast<uint8_t>(statement[length]) & 0xC0) == 0x80)
		length--;
	string text = statement.substr(0, length);
	for (size_t at = text.find('\0'); at != string::npos; at = text.find('\0', at + 3))
		text.replace(at, 1, "\xEF\xBF\xBD");
	return Value(std::move(text));
}

// Everything a record needs, held by reference: nothing is serialized or hashed until Write has decided the
// record will be kept, so a disabled log costs one atomic check per decision.
struct Record {
	const char *event;
	Value mode, boundary;
	optional_ptr<const gatekeeper::Result> result;
	optional_ptr<const string> statement;
	optional_ptr<const gatekeeper::Policy> policy;
	optional_ptr<const Value> new_value;
};

static string Serialize(const Record &record) {
	vector<Value> fields = {Value(record.event), record.mode, record.boundary};
	if (record.result) {
		auto value = ResultValue(*record.result); // keep the value alive while its children are read
		for (const auto &field : StructValue::GetChildren(value))
			fields.push_back(field);
	} else {
		auto result_type = ResultType();
		for (const auto &field : StructType::GetChildTypes(result_type))
			fields.emplace_back(field.second);
	}
	if (record.statement) {
		fields.push_back(StatementText(*record.statement));
		fields.push_back(Value::BIGINT(NumericCast<int64_t>(record.statement->size())));
	} else {
		fields.emplace_back(LogicalType::VARCHAR);
		fields.emplace_back(LogicalType::BIGINT);
	}
	fields.push_back(PolicyHash(record.policy));
	fields.push_back(record.new_value && !record.new_value->IsNull() ? Value(record.new_value->ToString())
	                                                                 : Value(LogicalType::VARCHAR));
	return Value::STRUCT(GatekeeperLogType::GetLogType(), std::move(fields)).ToString();
}

// Whether to write is decided on the database logger, never the connection's. A connection's logger is a
// snapshot of the log configuration taken when it was created and refreshed only after QueryBegin hooks have
// run and at query end, so on a connection that predates enable_logging it is a NopLogger for exactly the
// first statement whose denial should be recorded. The database logger tracks the configuration live.
static Logger &AuditLogger(ClientContext &context) { return Logger::Get(DatabaseInstance::GetDatabase(context)); }

static void Write(ClientContext &context, LogLevel level, const Record &record) {
	if (!AuditLogger(context).ShouldLog(GatekeeperLogType::NAME, level))
		return;
	// The record is written through a logger carrying this connection's identity, so DuckDB's own context
	// columns (connection_id, transaction_id, query_id) describe it. The connection's logger cannot be used:
	// QueryBegin runs before the engine refreshes it for the new query, so its context is the previous query's.
	// The engine resets the query number at query end; outside a query (a Prepare() pre-screen) it is the
	// sentinel and stays unset.
	LoggingContext logging_context(LogContextScope::CONNECTION);
	logging_context.connection_id = context.GetConnectionId();
	if (context.transaction.HasActiveTransaction()) {
		logging_context.transaction_id = context.transaction.ActiveTransaction().global_transaction_id;
		auto query = context.transaction.GetActiveQuery();
		if (query != MAXIMUM_QUERY_ID)
			logging_context.query_id = query;
	}
	auto logger = DatabaseInstance::GetDatabase(context).GetLogManager().CreateLogger(logging_context, true);
	logger->WriteLog(GatekeeperLogType::NAME, level, Serialize(record));
}

void Decide(ClientContext &context, const DecisionSite &site, const gatekeeper::Result &result) {
	auto level = result.allowed ? LogLevel::LOG_DEBUG : LogLevel::LOG_INFO;
	Write(context, level,
	      {"decision", Value(ModeName(site.mode)), BoundaryName(site.boundary), &result, site.statement, site.policy,
	       nullptr});
	if (!result.allowed && site.mode == DecisionMode::ENFORCE)
		throw PermissionException(DenialMessage(result));
}

void LogSettingChange(ClientContext &context, const string &event, const Value &value,
                      optional_ptr<const gatekeeper::Policy> policy) {
	Write(context, LogLevel::LOG_INFO,
	      {event.c_str(), Value(LogicalType::VARCHAR), Value(LogicalType::VARCHAR), nullptr, nullptr, policy, &value});
}

bool DenialsRecorded(ClientContext &context) {
	return AuditLogger(context).ShouldLog(GatekeeperLogType::NAME, LogLevel::LOG_INFO);
}

void RegisterAudit(ExtensionLoader &loader) {
	auto &manager = loader.GetDatabaseInstance().GetLogManager();
	if (!manager.LookupLogType(GatekeeperLogType::NAME))
		manager.RegisterLogType(make_uniq<GatekeeperLogType>());
}
} // namespace duckdb
