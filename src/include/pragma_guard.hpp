#pragma once

namespace duckdb {
class DBConfig;
class ExtensionLoader;
// Registers the parser override that rewrites every PRAGMA whose arguments are not constants into
// PRAGMA gatekeeper_rejected_pragma('<name>'), and that pragma, which refuses to run. The engine only
// consults parser overrides while the host sets allow_parser_override_extension to fallback or strict.
void RegisterPragmaGuard(ExtensionLoader &loader);
// Whether another parser override is registered ahead of Gatekeeper's. The engine takes the first
// override that answers, so statements it produces never pass through the guard.
bool PragmaGuardShadowed(DBConfig &config);
} // namespace duckdb
