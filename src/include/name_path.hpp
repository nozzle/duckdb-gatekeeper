#pragma once
#include <string>
#include <vector>

namespace gatekeeper {
using NamePath = std::vector<std::string>;
NamePath FoldPath(NamePath path);
} // namespace gatekeeper
