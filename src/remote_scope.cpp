#include "remote_scope.hpp"
#include "audit.hpp"
#include "check.hpp"
#include "duckdb/catalog/catalog_entry/table_function_catalog_entry.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/extension_manager.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"
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
		// Copy the set and overloads. Never mutate a published entry or a shared function slot:
		// concurrent binders may still be using it. Catalog replacement publishes a new entry.
		auto functions = entry->Cast<TableFunctionCatalogEntry>().functions;
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
		CreateTableFunctionInfo replacement(std::move(functions));
		replacement.on_conflict = OnCreateConflict::REPLACE_ON_CONFLICT;
		loader.RegisterFunction(std::move(replacement));
	}
}

struct QuackLoadCallback : ExtensionCallback {
	mutex lock;
	bool sealed = false;

	static bool IsQuack(DatabaseInstance &db, const string &name) {
#if GATEKEEPER_DUCKDB_MAJOR >= 2
		auto info = ExtensionManager::Get(db).GetExtensionInfo(name);
		return info && info->orig_ext_name == "quack";
#else
		return name == "quack";
#endif
	}

	void OnBeginExtensionLoad(DatabaseInstance &db, const string &name) override {
		if (!IsQuack(db, name))
			return;
		lock_guard<mutex> guard(lock);
		if (sealed)
			throw PermissionException("Load Quack before activating Gatekeeper enforcement; remote setup is sealed");
	}

	void Seal(ClientContext &context) {
		lock_guard<mutex> guard(lock);
		if (sealed)
			return;
		auto &manager = ExtensionManager::Get(context);
		vector<unique_lock<mutex>> loads;
		// BeginLoad inserts ExtensionInfo before notifying callbacks. Holding this lock blocks new
		// Quack loads at OnBegin; try-locking existing entries catches loads that began before our
		// callback was registered as well. Never wait: a loader may itself be waiting for this lock.
		for (const auto &name : manager.GetExtensions()) {
			if (!IsQuack(*context.db, name))
				continue;
			auto info = manager.GetExtensionInfo(name);
			unique_lock<mutex> loading(info->lock, std::try_to_lock);
			if (!loading.owns_lock() || !info->is_loaded)
				throw PermissionException("Quack load is unfinished; complete extension setup before enforcement");
			loads.push_back(std::move(loading));
		}
		ExtensionLoader loader(*context.db, "gatekeeper");
		InstallQuackGuards(loader);
		sealed = true;
	}
};

void RegisterRemoteScope(ExtensionLoader &loader) {
	ExtensionCallback::Register(DBConfig::GetConfig(loader.GetDatabaseInstance()),
	                            make_shared_ptr<QuackLoadCallback>());
}

void SealRemoteScope(ClientContext &context) {
	for (auto &callback : ExtensionCallback::Iterate(context)) {
		auto state = dynamic_cast<QuackLoadCallback *>(callback.get());
		if (state) {
			state->Seal(context);
			return;
		}
	}
	throw InternalException("Gatekeeper remote setup state is missing");
}
} // namespace duckdb
