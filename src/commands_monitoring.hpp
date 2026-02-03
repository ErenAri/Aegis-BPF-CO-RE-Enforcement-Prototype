// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

namespace aegis {

// Stats and monitoring commands
int cmd_stats();
int cmd_metrics(const std::string& out_path);
int cmd_health(bool json_output = false);

}  // namespace aegis
