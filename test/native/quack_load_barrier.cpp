// Test-only extension: park a Quack loader after BeginLoad acquired its per-extension lock.
// The fixture can then prove enforcement refuses an unfinished load, without timing sleeps.
#include "duckdb.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/planner/extension_callback.hpp"
#include <chrono>
#include <condition_variable>

namespace duckdb {
struct LoadBarrier : ExtensionCallback {
	std::mutex mutex;
	std::condition_variable changed;
	bool entered = false;
	bool released = false;
	void OnBeginExtensionLoad(DatabaseInstance &, const string &name) override {
		if (name != "quack" && name != "q" && name != "http")
			return;
		std::unique_lock<std::mutex> guard(mutex);
		entered = true;
		changed.notify_all();
		if (!changed.wait_for(guard, std::chrono::seconds(30), [&] { return released; }))
			throw InvalidInputException("Quack load barrier timed out");
	}
};

static void Barrier(const DataChunk &input, ExpressionState &state, Vector &result) {
	for (auto &callback : ExtensionCallback::Iterate(state.GetContext())) {
		auto barrier = dynamic_cast<LoadBarrier *>(callback.get());
		if (!barrier)
			continue;
		std::unique_lock<std::mutex> guard(barrier->mutex);
		if (input.GetValue(0, 0).GetValue<bool>()) {
			barrier->released = true;
			barrier->changed.notify_all();
		} else if (!barrier->changed.wait_for(guard, std::chrono::seconds(30), [&] { return barrier->entered; })) {
			throw InvalidInputException("Quack load did not enter barrier");
		}
		result.SetValue(0, Value::BOOLEAN(true));
		return;
	}
	throw InternalException("Missing Quack load barrier");
}
} // namespace duckdb

extern "C" {
DUCKDB_CPP_EXTENSION_ENTRY(quack_load_barrier, loader) {
	using namespace duckdb;
	ExtensionCallback::Register(DBConfig::GetConfig(loader.GetDatabaseInstance()), make_shared_ptr<LoadBarrier>());
	ScalarFunction function("quack_load_barrier", {LogicalType::BOOLEAN}, LogicalType::BOOLEAN, Barrier);
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	function.SetVolatile();
#else
	function.stability = FunctionStability::VOLATILE;
#endif
	loader.RegisterFunction(function);
}
}
