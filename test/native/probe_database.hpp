#pragma once

#include "duckdb.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension_helper.hpp"

#include <cstdlib>
#include <stdexcept>

// An explicit artifact lets a probe use a shared engine library without accidentally testing the older
// Gatekeeper linked into that library. Ordinary CI builds still exercise their statically linked extension.
inline void ConfigureProbeArtifact(duckdb::DBConfig &config) {
	if (!std::getenv("GATEKEEPER_EXTENSION"))
		return;
	config.options.load_extensions = false;
	config.SetOptionByName("allow_unsigned_extensions", duckdb::Value::BOOLEAN(true));
}

inline void LoadProbeArtifact(duckdb::DuckDB &db) {
	auto artifact = std::getenv("GATEKEEPER_EXTENSION");
	if (!artifact)
		return;
	if (db.ExtensionIsLoaded("gatekeeper"))
		throw std::runtime_error("probe must not use a previously linked Gatekeeper");
	duckdb::ExtensionHelper::LoadExtension(db, "core_functions");
	duckdb::Connection connection(db);
	std::string escaped;
	for (char c : std::string(artifact)) {
		escaped += c;
		if (c == '\'')
			escaped += c;
	}
	auto result = connection.Query("LOAD '" + escaped + "'");
	if (result->HasError())
		throw std::runtime_error(result->GetError());
}
