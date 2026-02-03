// cppcheck-suppress-file missingIncludeSystem
#include "cli_run.hpp"

#include "cli_common.hpp"
#include "daemon.hpp"
#include "events.hpp"
#include "logging.hpp"
#include "utils.hpp"

#include <cstdint>
#include <cstring>
#include <string>

namespace aegis {

namespace {

bool parse_u32_option(const std::string& value, uint32_t& out, const char* error_message, bool require_nonzero)
{
    uint64_t parsed = 0;
    if (!parse_uint64(value, parsed) || parsed > UINT32_MAX || (require_nonzero && parsed == 0)) {
        logger().log(SLOG_ERROR(error_message).field("value", value));
        return false;
    }
    out = static_cast<uint32_t>(parsed);
    return true;
}

}  // namespace

int dispatch_run_command(int argc, char** argv, const char* prog)
{
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
            if (!parse_u32_option(value, deadman_ttl, "Invalid deadman TTL value", false)) return 1;
        }
        else if (arg == "--deadman-ttl") {
            if (i + 1 >= argc) return usage(prog);
            if (!parse_u32_option(argv[++i], deadman_ttl, "Invalid deadman TTL value", false)) return 1;
        }
        else if (arg.rfind("--log=", 0) == 0) {
            std::string value = arg.substr(std::strlen("--log="));
            if (!set_event_log_sink(value)) return usage(prog);
        }
        else if (arg == "--log") {
            if (i + 1 >= argc) return usage(prog);
            if (!set_event_log_sink(argv[++i])) return usage(prog);
        }
        else if (arg.rfind("--log-level=", 0) == 0 || arg.rfind("--log-format=", 0) == 0) {
            // Already processed globally.
        }
        else if (arg.rfind("--ringbuf-bytes=", 0) == 0) {
            std::string value = arg.substr(std::strlen("--ringbuf-bytes="));
            if (!parse_u32_option(value, ringbuf_bytes, "Invalid ringbuf size", false)) return 1;
        }
        else if (arg == "--ringbuf-bytes") {
            if (i + 1 >= argc) return usage(prog);
            if (!parse_u32_option(argv[++i], ringbuf_bytes, "Invalid ringbuf size", false)) return 1;
        }
        else if (arg.rfind("--event-sample-rate=", 0) == 0) {
            std::string value = arg.substr(std::strlen("--event-sample-rate="));
            if (!parse_u32_option(value, event_sample_rate, "Invalid event sample rate", true)) return 1;
        }
        else if (arg == "--event-sample-rate") {
            if (i + 1 >= argc) return usage(prog);
            if (!parse_u32_option(argv[++i], event_sample_rate, "Invalid event sample rate", true)) return 1;
        }
        else if (arg.rfind("--lsm-hook=", 0) == 0) {
            std::string value = arg.substr(std::strlen("--lsm-hook="));
            if (!parse_lsm_hook(value, lsm_hook)) {
                logger().log(SLOG_ERROR("Invalid lsm hook value").field("value", value));
                return 1;
            }
        }
        else if (arg == "--lsm-hook") {
            if (i + 1 >= argc) return usage(prog);
            std::string value = argv[++i];
            if (!parse_lsm_hook(value, lsm_hook)) {
                logger().log(SLOG_ERROR("Invalid lsm hook value").field("value", value));
                return 1;
            }
        }
        else {
            return usage(prog);
        }
    }

    return daemon_run(audit_only, enable_seccomp, deadman_ttl, lsm_hook, ringbuf_bytes, event_sample_rate);
}

}  // namespace aegis
