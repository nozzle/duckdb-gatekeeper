#include "remote_scope.hpp"
#include "audit.hpp"
#include "check.hpp"
#include "duckdb/catalog/catalog_entry/table_function_catalog_entry.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/extension_helper.hpp"
#include "duckdb/main/extension_manager.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"
#include "duckdb/planner/extension_callback.hpp"
#include "enforcement.hpp"
#include "engine_api.hpp"
#include "policy_setting.hpp"
#if GATEKEEPER_DUCKDB_MAJOR >= 2
#include "duckdb/main/database.hpp"
#include "duckdb/storage/object_cache.hpp"
#endif

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
	bool failed = false;
	set<string> pending, completed, startup;
	set<string> unobserved;

	void OnBeginExtensionLoad(DatabaseInstance &, const string &name) override {
		lock_guard<mutex> guard(lock);
		if (sealed)
			throw PermissionException(
			    "Load extensions before activating Gatekeeper enforcement; remote setup is sealed");
		pending.insert(name);
	}
	void OnExtensionLoaded(DatabaseInstance &, const string &name) override {
		lock_guard<mutex> guard(lock);
		// Even an observed finish cannot redeem a load whose start we missed: its earlier callbacks
		// were outside our setup protocol. The engine reports literal aliases here, without normalization.
		if (pending.erase(name) || name == "gatekeeper")
			completed.insert(name);
		else
			unobserved.insert(name);
	}
	void OnExtensionLoadFail(DatabaseInstance &, const string &, const ErrorData &) override {
		lock_guard<mutex> guard(lock);
		// Failure notifications may use the original name instead of the alias. Do not guess which
		// attempt ended; poison this setup. All state is ours, never borrowed from ExtensionManager.
		failed = true;
	}

	void Seal(ClientContext &context) {
		lock_guard<mutex> guard(lock);
		if (sealed)
			return;
		if (failed || !pending.empty() || !unobserved.empty())
			throw PermissionException(
			    "Extension setup is incomplete or failed; recreate the database with Gatekeeper loaded first");
		// GetExtensions returns owned strings under the registry mutex. Never dereference the
		// registry's removable ExtensionInfo entries. A load inserted after this snapshot still
		// must pass our begin callback, which takes this same lock and will see the seal.
		for (const auto &name : ExtensionManager::Get(context).GetExtensions())
			if (!completed.count(name) && !startup.count(name))
				throw PermissionException(
				    "Extension setup predates Gatekeeper (%s); recreate the database with Gatekeeper loaded first",
				    name);
		ExtensionLoader loader(*context.db, "gatekeeper");
		InstallQuackGuards(loader);
		sealed = true;
	}
};

void RegisterRemoteScope(ExtensionLoader &loader) {
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	auto state = make_shared_ptr<QuackLoadCallback>();
	// Core startup libraries cannot register Quack delegation. Exempt only these known engine
	// libraries, never arbitrary linked extensions (a custom binary may itself link Quack).
	const set<string> core = {"core_functions", "icu", "json", "parquet"};
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	for (const auto &extension : config.linked_extensions)
		if (core.count(extension.name))
			state->startup.insert(extension.name);
	// The upstream SQL runner installs its fixed debug filesystem before any test LOAD. Its
	// owned cache marker distinguishes that implementation from an arbitrary LOAD AS debug_fs.
	auto debug_fs = loader.GetDatabaseInstance().GetObjectCache().GetObject("debug_fs_instance-instance");
	if (debug_fs && debug_fs->GetObjectType() == "debug_fs_instance")
		state->startup.insert("debug_fs");
#else
	// 1.5 has no aliases or registry removal: its entries live for the database lifetime.
	// Inspect only this release's stable entries, under their load lock, to identify completed
	// statically linked startup loads. The loadable's compile-time linked list is not the host's.
	auto &manager = ExtensionManager::Get(loader.GetDatabaseInstance());
	for (const auto &name : manager.GetExtensions()) {
		auto info = manager.GetExtensionInfo(name);
		unique_lock<mutex> loading(info->lock, std::try_to_lock);
		if (core.count(name) && loading.owns_lock() && info->is_loaded && info->install_info &&
		    info->install_info->mode == ExtensionInstallMode::STATICALLY_LINKED)
			state->startup.insert(name);
	}
#endif
	ExtensionCallback::Register(config, state);
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
