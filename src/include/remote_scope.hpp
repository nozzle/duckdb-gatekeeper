#pragma once
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"
#include "validator.hpp"
#if GATEKEEPER_DUCKDB_MAJOR >= 2
#include "duckdb/common/enums/optimizer_type.hpp"
#include "duckdb/main/database_manager.hpp"
#include "duckdb/main/settings.hpp"
#endif

namespace duckdb {
// Remote SQL rewrites bind a delegating table function before PostBind. Refuse that configuration
// before the engine plans, including when parameters defer the private authorization bind.
inline bool CheckRemoteScope(ClientContext &context, gatekeeper::Result &result) {
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	auto &config = DBConfig::GetConfig(context);
	if (DatabaseManager::Get(context).GetRemoteCatalogCount() > 0 && Settings::Get<EnableOptimizerSetting>(context) &&
	    !config.options.disabled_optimizers.count(OptimizerType::REMOTE_PUSHDOWN)) {
		result.violations.emplace(gatekeeper::rules::STATEMENT,
		                          "remote SQL pushdown is unsupported: disable remote_pushdown before authorization");
		return false;
	}
#endif
	return true;
}

// These functions execute opaque SQL during binding. A trusted view does not supply the missing
// remote dependency evidence. Attached base-table GetScanFunction does not look up these entries.
inline bool OpaqueQuackFunction(const string &name) {
	auto lower = gatekeeper::Lower(name);
	return lower == "quack_query" || lower == "quack_query_by_name";
}
} // namespace duckdb
