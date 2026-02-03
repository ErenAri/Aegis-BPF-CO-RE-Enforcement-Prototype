// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>
#include <cstdint>

namespace aegis {

// Block commands
int cmd_block_add(const std::string& path);
int cmd_block_del(const std::string& path);
int cmd_block_list();
int cmd_block_clear();

// Allow commands
int cmd_allow_add(const std::string& path);
int cmd_allow_del(const std::string& path);
int cmd_allow_list();

// Network commands
int cmd_network_deny_add_ip(const std::string& ip);
int cmd_network_deny_add_cidr(const std::string& cidr);
int cmd_network_deny_add_port(uint16_t port, const std::string& protocol_str, const std::string& direction_str);
int cmd_network_deny_del_ip(const std::string& ip);
int cmd_network_deny_del_cidr(const std::string& cidr);
int cmd_network_deny_del_port(uint16_t port, const std::string& protocol_str, const std::string& direction_str);
int cmd_network_deny_list();
int cmd_network_deny_clear();
int cmd_network_stats();

// Policy commands
int cmd_policy_lint(const std::string& path);
int cmd_policy_validate(const std::string& path, bool verbose);
int cmd_policy_apply(const std::string& path, bool reset, const std::string& sha256,
                     const std::string& sha256_file, bool rollback_on_failure);
int cmd_policy_apply_signed(const std::string& bundle_path, bool require_signature);
int cmd_policy_sign(const std::string& policy_path, const std::string& key_path, const std::string& output_path);
int cmd_policy_export(const std::string& path);
int cmd_policy_show();
int cmd_policy_rollback();

// Key management commands
int cmd_keys_list();
int cmd_keys_add(const std::string& key_file);

// Survival commands
int cmd_survival_list();
int cmd_survival_verify();

// Stats and monitoring commands
int cmd_stats();
int cmd_metrics(const std::string& out_path);
int cmd_health();

}  // namespace aegis
