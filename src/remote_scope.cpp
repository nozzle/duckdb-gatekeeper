#include "remote_scope.hpp"
#include "audit.hpp"
#include "check.hpp"
#include "duckdb/catalog/catalog_entry/table_function_catalog_entry.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/planner/extension_callback.hpp"
#include "enforcement.hpp"
#include "engine_api.hpp"
#include "policy_setting.hpp"

namespace duckdb {
// Prepare() and parameterized execution can bind before the private authorization pass. Guard the
// actual opaque bind callback as well as the private catalog lookup; PostBind is too late here.
struct QuackBindGuard : TableFunctionInfo {
	table_function_bind_t original;
	shared_ptr<TableFunctionInfo> original_info;
};

static unique_ptr<FunctionData> GuardQuackBind(ClientContext &context, TableFunctionBindInput &input,
                                               vector<LogicalType> &types, engine::NameList &names) {
	auto &guard = input.info->Cast<QuackBindGuard>();
	auto mode = ReplacementGate(context);
	if (mode != GateMode::OPEN) {
		gatekeeper::Result result;
		gatekeeper::Policy policy;
		auto snapshot = AdmittedPolicy(context);
		if (!snapshot && TryGlobalPolicy(context, policy, result))
			snapshot = &policy;
		result.violations.emplace(gatekeeper::rules::STATEMENT, "opaque Quack SQL delegation is unsupported", "",
		                          gatekeeper::NamePath{}, "", engine::FunctionName(input.table_function));
		MarkDenied(result);
		MarkGateDecided(context);
		Decide(context,
		       {mode == GateMode::LOG_ONLY ? DecisionMode::LOG_ONLY : DecisionMode::ENFORCE, Boundary::AUTHORIZE,
		        snapshot, AdmittedQuery(context)},
		       result);
	}
	// Preserve the extension's original bind input, including its own function info.
	auto old_info = input.info;
	input.info = guard.original_info.get();
	try {
		auto result = guard.original(context, input, types, names);
		input.info = old_info;
		return result;
	} catch (...) {
		input.info = old_info;
		throw;
	}
}

static void InstallQuackGuards(ExtensionLoader &loader) {
	for (const auto *name : {"quack_query", "quack_query_by_name"}) {
		auto entry = loader.TryGetTableFunction(name);
		if (!entry)
			continue;
		auto &functions = entry->Cast<TableFunctionCatalogEntry>().functions;
		auto wrap = [](TableFunction &function) {
			if (!function.bind || function.bind == GuardQuackBind)
				return;
			auto guard = make_shared_ptr<QuackBindGuard>();
			guard->original = function.bind;
			guard->original_info = function.function_info;
			function.function_info = std::move(guard);
			function.bind = GuardQuackBind;
		};
#if GATEKEEPER_DUCKDB_MAJOR >= 2
		functions.ApplyToFunctions(wrap);
#else
		for (idx_t i = 0; i < functions.Size(); i++)
			wrap(functions.GetFunctionReferenceByOffset(i));
#endif
	}
}

struct QuackLoadCallback : ExtensionCallback {
	void OnExtensionLoaded(DatabaseInstance &db, const string &name) override {
		if (name != "quack")
			return;
		ExtensionLoader loader(db, "gatekeeper");
		InstallQuackGuards(loader);
	}
};

void RegisterRemoteScope(ExtensionLoader &loader) {
	InstallQuackGuards(loader);
	ExtensionCallback::Register(DBConfig::GetConfig(loader.GetDatabaseInstance()),
	                            make_shared_ptr<QuackLoadCallback>());
}
} // namespace duckdb
