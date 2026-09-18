#pragma once
#include "duckdb/common/optional_ptr.hpp"
#include "duckdb/common/string.hpp"
#include "validator.hpp"

namespace duckdb {
class ClientContext;
class ExtensionLoader;
class Value;

// How a decision applies to the statement it describes. An enforced statement is refused when denied; a
// validated statement is reported to the caller of gatekeeper_validate, never refused here.
enum class DecisionMode : uint8_t { ENFORCE, VALIDATE };

// Where in the statement's lifecycle the decision was made.
enum class Boundary : uint8_t {
	BINDING,          // text check before the engine binds
	AUTHORIZE,        // private bind with catalog authorization
	EXECUTION,        // the plan the engine is about to execute
	PREPARE,          // pre-screen of a plan bound by Prepare(), outside any query
	REPLACEMENT_SCAN, // a reader resolved for a name the catalog did not have, outside the private bind
	NONE,             // the whole composition at once, as gatekeeper_validate runs it; recorded as NULL
};

struct DecisionSite {
	DecisionMode mode;
	Boundary boundary;
	optional_ptr<const gatekeeper::Policy> policy; // the global ceiling in force, for policy_hash
	optional_ptr<const string> statement;          // caller-written text, when a query is active
};

// The one place a decision becomes observable. Writes a record of log type "Gatekeeper" when logging admits
// it (INFO for a denial, DEBUG for an allow), then refuses a denied statement in ENFORCE mode by throwing
// PermissionException with the denial message. Allowed decisions and VALIDATE mode return.
void Decide(ClientContext &context, const DecisionSite &site, const gatekeeper::Result &result);

// Records a host change to one of Gatekeeper's global settings (event names end in _changed).
void LogSettingChange(ClientContext &context, const string &event, const Value &value,
                      optional_ptr<const gatekeeper::Policy> policy = nullptr);

// Whether a denial recorded now would reach the log: logging is enabled at INFO or below and the Gatekeeper
// type is not filtered out.
bool DenialsRecorded(ClientContext &context);

// Registers the Gatekeeper log type so duckdb_logs_parsed('Gatekeeper') and enable_logging('Gatekeeper') work.
void RegisterAudit(ExtensionLoader &loader);
} // namespace duckdb
