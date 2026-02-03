// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - eBPF-based runtime security agent
 *
 * Main entry point for CLI command parsing and dispatch.
 */

#include "commands.hpp"
#include "daemon.hpp"
#include "events.hpp"
#include "logging.hpp"
#include "policy.hpp"
#include "utils.hpp"

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>

namespace aegis {

static int usage(const char* prog)
{
    std::cerr << "Usage: " << prog
              << " run [--audit|--enforce] [--seccomp] [--deadman-ttl=<seconds>] [--lsm-hook=file|inode|both] [--ringbuf-bytes=<bytes>] [--event-sample-rate=<n>] [--log=stdout|journald|both] [--log-level=debug|info|warn|error] [--log-format=text|json]"
              << " | block {add|del|list|clear} [path]"
              << " | allow {add|del} <cgroup_path> | allow list"
              << " | network deny {add|del} --ip <addr> | --cidr <cidr> | --port <port> [--protocol tcp|udp|any] [--direction egress|bind|both]"
              << " | network deny {list|clear}"
              << " | network stats"
              << " | survival {list|verify}"
              << " | policy {lint|validate|apply|export} <file> [--reset] [--sha256 <hex>|--sha256-file <path>] [--no-rollback] [--require-signature] [--verbose]"
              << " | policy sign <policy.conf> --key <private.key> --output <policy.signed>"
              << " | policy {show|rollback}"
              << " | keys {list|add <pubkey.pub>}"
              << " | stats"
              << " | metrics [--out <path>]"
              << " | health" << std::endl;
    return 1;
}

static LogLevel parse_log_level(const std::string& value)
{
    if (value == "debug") return LogLevel::Debug;
    if (value == "info") return LogLevel::Info;
    if (value == "warn" || value == "warning") return LogLevel::Warning;
    if (value == "error") return LogLevel::Error;
    return LogLevel::Info;
}

}  // namespace aegis

int main(int argc, char** argv)
{
    using namespace aegis;

    // Parse global logging options first
    LogLevel log_level = LogLevel::Info;
    bool json_format = false;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.rfind("--log-level=", 0) == 0) {
            log_level = parse_log_level(arg.substr(12));
        }
        else if (arg.rfind("--log-format=", 0) == 0) {
            json_format = (arg.substr(13) == "json");
        }
    }

    logger().set_level(log_level);
    logger().set_json_format(json_format);

    if (argc == 1) {
        return daemon_run(false, false, 0, LsmHookMode::FileOpen, 0, 1);
    }

    std::string cmd = argv[1];

    // ========================================================================
    // Run command (daemon mode)
    // ========================================================================
    if (cmd == "run") {
        bool audit_only = false;
        bool enable_seccomp = false;
        uint32_t deadman_ttl = 0;
        uint32_t ringbuf_bytes = 0;
        uint32_t event_sample_rate = 1;
        LsmHookMode lsm_hook = LsmHookMode::FileOpen;

        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--audit" || arg == "--mode=audit") {
                audit_only = true;
            }
            else if (arg == "--enforce" || arg == "--mode=enforce") {
                audit_only = false;
            }
            else if (arg == "--seccomp") {
                enable_seccomp = true;
            }
            else if (arg.rfind("--deadman-ttl=", 0) == 0) {
                std::string value = arg.substr(std::strlen("--deadman-ttl="));
                uint64_t ttl = 0;
                if (!parse_uint64(value, ttl) || ttl > UINT32_MAX) {
                    logger().log(SLOG_ERROR("Invalid deadman TTL value").field("value", value));
                    return 1;
                }
                deadman_ttl = static_cast<uint32_t>(ttl);
            }
            else if (arg == "--deadman-ttl") {
                if (i + 1 >= argc) return usage(argv[0]);
                std::string value = argv[++i];
                uint64_t ttl = 0;
                if (!parse_uint64(value, ttl) || ttl > UINT32_MAX) {
                    logger().log(SLOG_ERROR("Invalid deadman TTL value").field("value", value));
                    return 1;
                }
                deadman_ttl = static_cast<uint32_t>(ttl);
            }
            else if (arg.rfind("--log=", 0) == 0) {
                std::string value = arg.substr(std::strlen("--log="));
                if (!set_event_log_sink(value)) return usage(argv[0]);
            }
            else if (arg == "--log") {
                if (i + 1 >= argc) return usage(argv[0]);
                std::string value = argv[++i];
                if (!set_event_log_sink(value)) return usage(argv[0]);
            }
            else if (arg.rfind("--log-level=", 0) == 0 || arg.rfind("--log-format=", 0) == 0) {
                // Already processed
            }
            else if (arg.rfind("--ringbuf-bytes=", 0) == 0) {
                std::string value = arg.substr(std::strlen("--ringbuf-bytes="));
                uint64_t bytes = 0;
                if (!parse_uint64(value, bytes) || bytes > UINT32_MAX) {
                    logger().log(SLOG_ERROR("Invalid ringbuf size").field("value", value));
                    return 1;
                }
                ringbuf_bytes = static_cast<uint32_t>(bytes);
            }
            else if (arg.rfind("--event-sample-rate=", 0) == 0) {
                std::string value = arg.substr(std::strlen("--event-sample-rate="));
                uint64_t rate = 0;
                if (!parse_uint64(value, rate) || rate == 0 || rate > UINT32_MAX) {
                    logger().log(SLOG_ERROR("Invalid event sample rate").field("value", value));
                    return 1;
                }
                event_sample_rate = static_cast<uint32_t>(rate);
            }
            else if (arg.rfind("--lsm-hook=", 0) == 0) {
                std::string value = arg.substr(std::strlen("--lsm-hook="));
                if (!parse_lsm_hook(value, lsm_hook)) {
                    logger().log(SLOG_ERROR("Invalid lsm hook value").field("value", value));
                    return 1;
                }
            }
            else if (arg == "--ringbuf-bytes") {
                if (i + 1 >= argc) return usage(argv[0]);
                std::string value = argv[++i];
                uint64_t bytes = 0;
                if (!parse_uint64(value, bytes) || bytes > UINT32_MAX) {
                    logger().log(SLOG_ERROR("Invalid ringbuf size").field("value", value));
                    return 1;
                }
                ringbuf_bytes = static_cast<uint32_t>(bytes);
            }
            else if (arg == "--event-sample-rate") {
                if (i + 1 >= argc) return usage(argv[0]);
                std::string value = argv[++i];
                uint64_t rate = 0;
                if (!parse_uint64(value, rate) || rate == 0 || rate > UINT32_MAX) {
                    logger().log(SLOG_ERROR("Invalid event sample rate").field("value", value));
                    return 1;
                }
                event_sample_rate = static_cast<uint32_t>(rate);
            }
            else if (arg == "--lsm-hook") {
                if (i + 1 >= argc) return usage(argv[0]);
                std::string value = argv[++i];
                if (!parse_lsm_hook(value, lsm_hook)) {
                    logger().log(SLOG_ERROR("Invalid lsm hook value").field("value", value));
                    return 1;
                }
            }
            else {
                return usage(argv[0]);
            }
        }
        return daemon_run(audit_only, enable_seccomp, deadman_ttl, lsm_hook, ringbuf_bytes, event_sample_rate);
    }

    // ========================================================================
    // Block commands
    // ========================================================================
    if (cmd == "block") {
        if (argc < 3) return usage(argv[0]);
        std::string sub = argv[2];
        if (sub == "add") {
            if (argc != 4) return usage(argv[0]);
            return cmd_block_add(argv[3]);
        }
        if (sub == "del") {
            if (argc != 4) return usage(argv[0]);
            return cmd_block_del(argv[3]);
        }
        if (sub == "list") {
            return cmd_block_list();
        }
        if (sub == "clear") {
            return cmd_block_clear();
        }
        return usage(argv[0]);
    }

    // ========================================================================
    // Allow commands
    // ========================================================================
    if (cmd == "allow") {
        if (argc < 3) return usage(argv[0]);
        std::string sub = argv[2];
        if (sub == "add") {
            if (argc != 4) return usage(argv[0]);
            return cmd_allow_add(argv[3]);
        }
        if (sub == "del") {
            if (argc != 4) return usage(argv[0]);
            return cmd_allow_del(argv[3]);
        }
        if (sub == "list") {
            if (argc > 3) return usage(argv[0]);
            return cmd_allow_list();
        }
        return usage(argv[0]);
    }

    // ========================================================================
    // Network commands
    // ========================================================================
    if (cmd == "network") {
        if (argc < 3) return usage(argv[0]);
        std::string sub = argv[2];

        if (sub == "stats") {
            return cmd_network_stats();
        }

        if (sub == "deny") {
            if (argc < 4) return usage(argv[0]);
            std::string action = argv[3];

            if (action == "list") {
                return cmd_network_deny_list();
            }
            if (action == "clear") {
                return cmd_network_deny_clear();
            }

            // Parse add/del options
            std::string ip, cidr, protocol = "any", direction = "both";
            uint16_t port = 0;
            bool has_ip = false, has_cidr = false, has_port = false;

            for (int i = 4; i < argc; ++i) {
                std::string arg = argv[i];
                if (arg == "--ip") {
                    if (i + 1 >= argc) return usage(argv[0]);
                    ip = argv[++i];
                    has_ip = true;
                }
                else if (arg == "--cidr") {
                    if (i + 1 >= argc) return usage(argv[0]);
                    cidr = argv[++i];
                    has_cidr = true;
                }
                else if (arg == "--port") {
                    if (i + 1 >= argc) return usage(argv[0]);
                    uint64_t p = 0;
                    if (!parse_uint64(argv[++i], p) || p > 65535) {
                        logger().log(SLOG_ERROR("Invalid port").field("value", argv[i]));
                        return 1;
                    }
                    port = static_cast<uint16_t>(p);
                    has_port = true;
                }
                else if (arg == "--protocol") {
                    if (i + 1 >= argc) return usage(argv[0]);
                    protocol = argv[++i];
                }
                else if (arg == "--direction") {
                    if (i + 1 >= argc) return usage(argv[0]);
                    direction = argv[++i];
                }
                else {
                    return usage(argv[0]);
                }
            }

            if (action == "add") {
                if (has_ip) return cmd_network_deny_add_ip(ip);
                if (has_cidr) return cmd_network_deny_add_cidr(cidr);
                if (has_port) return cmd_network_deny_add_port(port, protocol, direction);
                return usage(argv[0]);
            }
            if (action == "del") {
                if (has_ip) return cmd_network_deny_del_ip(ip);
                if (has_cidr) return cmd_network_deny_del_cidr(cidr);
                if (has_port) return cmd_network_deny_del_port(port, protocol, direction);
                return usage(argv[0]);
            }
        }
        return usage(argv[0]);
    }

    // ========================================================================
    // Policy commands
    // ========================================================================
    if (cmd == "policy") {
        if (argc < 3) return usage(argv[0]);
        std::string sub = argv[2];

        if (sub == "lint") {
            if (argc != 4) return usage(argv[0]);
            return cmd_policy_lint(argv[3]);
        }
        if (sub == "validate") {
            if (argc < 4) return usage(argv[0]);
            bool verbose = false;
            for (int i = 4; i < argc; ++i) {
                std::string arg = argv[i];
                if (arg == "--verbose" || arg == "-v") {
                    verbose = true;
                }
                else {
                    return usage(argv[0]);
                }
            }
            return cmd_policy_validate(argv[3], verbose);
        }
        if (sub == "apply") {
            if (argc < 4) return usage(argv[0]);
            bool reset = false;
            bool rollback_on_failure = true;
            bool require_signature = false;
            std::string sha256, sha256_file;

            for (int i = 4; i < argc; ++i) {
                std::string arg = argv[i];
                if (arg == "--reset") {
                    reset = true;
                }
                else if (arg == "--no-rollback") {
                    rollback_on_failure = false;
                }
                else if (arg == "--require-signature") {
                    require_signature = true;
                }
                else if (arg == "--sha256") {
                    if (i + 1 >= argc) return usage(argv[0]);
                    sha256 = argv[++i];
                }
                else if (arg == "--sha256-file") {
                    if (i + 1 >= argc) return usage(argv[0]);
                    sha256_file = argv[++i];
                }
                else {
                    return usage(argv[0]);
                }
            }

            // Check if file looks like a signed bundle
            std::ifstream check_file(argv[3]);
            std::string first_line;
            std::getline(check_file, first_line);
            check_file.close();
            if (first_line.starts_with("AEGIS-POLICY-BUNDLE") || require_signature) {
                return cmd_policy_apply_signed(argv[3], require_signature);
            }
            return cmd_policy_apply(argv[3], reset, sha256, sha256_file, rollback_on_failure);
        }
        if (sub == "sign") {
            if (argc < 4) return usage(argv[0]);
            std::string key_path, output_path;
            for (int i = 4; i < argc; ++i) {
                std::string arg = argv[i];
                if (arg == "--key") {
                    if (i + 1 >= argc) return usage(argv[0]);
                    key_path = argv[++i];
                }
                else if (arg == "--output") {
                    if (i + 1 >= argc) return usage(argv[0]);
                    output_path = argv[++i];
                }
                else {
                    return usage(argv[0]);
                }
            }
            if (key_path.empty() || output_path.empty()) return usage(argv[0]);
            return cmd_policy_sign(argv[3], key_path, output_path);
        }
        if (sub == "export") {
            if (argc != 4) return usage(argv[0]);
            return cmd_policy_export(argv[3]);
        }
        if (sub == "show") {
            if (argc != 3) return usage(argv[0]);
            return cmd_policy_show();
        }
        if (sub == "rollback") {
            if (argc != 3) return usage(argv[0]);
            return cmd_policy_rollback();
        }
        return usage(argv[0]);
    }

    // ========================================================================
    // Key management commands
    // ========================================================================
    if (cmd == "keys") {
        if (argc < 3) return usage(argv[0]);
        std::string sub = argv[2];
        if (sub == "list") {
            return cmd_keys_list();
        }
        if (sub == "add") {
            if (argc != 4) return usage(argv[0]);
            return cmd_keys_add(argv[3]);
        }
        return usage(argv[0]);
    }

    // ========================================================================
    // Survival commands
    // ========================================================================
    if (cmd == "survival") {
        if (argc < 3) return usage(argv[0]);
        std::string sub = argv[2];
        if (sub == "list") {
            return cmd_survival_list();
        }
        if (sub == "verify") {
            return cmd_survival_verify();
        }
        return usage(argv[0]);
    }

    // ========================================================================
    // Stats and monitoring commands
    // ========================================================================
    if (cmd == "health") {
        if (argc > 2) return usage(argv[0]);
        return cmd_health();
    }

    if (cmd == "metrics") {
        std::string out_path;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--out") {
                if (i + 1 >= argc) return usage(argv[0]);
                out_path = argv[++i];
            }
            else {
                return usage(argv[0]);
            }
        }
        return cmd_metrics(out_path);
    }

    if (cmd == "stats") {
        if (argc > 2) return usage(argv[0]);
        return cmd_stats();
    }

    return usage(argv[0]);
}
