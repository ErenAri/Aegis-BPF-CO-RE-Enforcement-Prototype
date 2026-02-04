// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Daemon implementation
 *
 * Main daemon run loop and related functionality.
 */

#include "daemon.hpp"
#include "bpf_ops.hpp"
#include "events.hpp"
#include "kernel_features.hpp"
#include "logging.hpp"
#include "seccomp.hpp"
#include "types.hpp"
#include "utils.hpp"

#include <bpf/libbpf.h>
#include <atomic>
#include <csignal>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

namespace aegis {

namespace {
volatile sig_atomic_t g_exiting = 0;
std::atomic<bool> g_heartbeat_running{false};

void handle_signal(int)
{
    g_exiting = 1;
}

void heartbeat_thread(BpfState* state, uint32_t ttl_seconds)
{
    uint32_t sleep_interval = ttl_seconds / 2;
    if (sleep_interval < 1) {
        sleep_interval = 1;
    }

    while (g_heartbeat_running.load() && !g_exiting) {
        // Update deadman deadline
        struct timespec ts {};
        clock_gettime(CLOCK_BOOTTIME, &ts);
        uint64_t now_ns = static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL +
                          static_cast<uint64_t>(ts.tv_nsec);
        uint64_t new_deadline = now_ns + (static_cast<uint64_t>(ttl_seconds) * 1000000000ULL);

        auto result = update_deadman_deadline(*state, new_deadline);
        if (!result) {
            logger().log(SLOG_WARN("Failed to update deadman deadline")
                             .field("error", result.error().to_string()));
        }

        // Sleep for TTL/2, but check exit flags more frequently.
        for (uint32_t i = 0; i < sleep_interval && g_heartbeat_running.load() && !g_exiting; ++i) {
            sleep(1);
        }
    }
}

Result<void> setup_agent_cgroup(BpfState& state)
{
    static constexpr const char* kAgentCgroup = "/sys/fs/cgroup/aegis_agent";

    std::error_code ec;
    std::filesystem::create_directories(kAgentCgroup, ec);
    if (ec) {
        return Error(ErrorCode::IoError, "Failed to create cgroup", ec.message());
    }

    std::ofstream procs(std::string(kAgentCgroup) + "/cgroup.procs", std::ios::out | std::ios::trunc);
    if (!procs.is_open()) {
        return Error(ErrorCode::IoError, "Failed to open cgroup.procs", kAgentCgroup);
    }
    procs << getpid();
    procs.close();

    struct stat st {};
    if (stat(kAgentCgroup, &st) != 0) {
        return Error::system(errno, "stat failed for " + std::string(kAgentCgroup));
    }

    uint64_t cgid = static_cast<uint64_t>(st.st_ino);

    TRY(bump_memlock_rlimit());

    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.allow_cgroup), &cgid, &one, BPF_ANY)) {
        return Error::system(errno, "Failed to update allow_cgroup_map");
    }

    return {};
}

const char* enforce_signal_name(uint8_t signal)
{
    switch (signal) {
    case kEnforceSignalNone:
        return "none";
    case kEnforceSignalInt:
        return "sigint";
    case kEnforceSignalKill:
        return "sigkill";
    case kEnforceSignalTerm:
        return "sigterm";
    default:
        return "sigterm";
    }
}

}  // namespace

const char* lsm_hook_name(LsmHookMode mode)
{
    switch (mode) {
    case LsmHookMode::FileOpen:
        return "file_open";
    case LsmHookMode::InodePermission:
        return "inode_permission";
    case LsmHookMode::Both:
        return "both";
    default:
        return "unknown";
    }
}

bool parse_lsm_hook(const std::string& value, LsmHookMode& out)
{
    if (value == "file" || value == "file_open") {
        out = LsmHookMode::FileOpen;
        return true;
    }
    if (value == "inode" || value == "inode_permission") {
        out = LsmHookMode::InodePermission;
        return true;
    }
    if (value == "both") {
        out = LsmHookMode::Both;
        return true;
    }
    return false;
}

int daemon_run(bool audit_only,
               bool enable_seccomp,
               uint32_t deadman_ttl,
               uint8_t enforce_signal,
               LsmHookMode lsm_hook,
               uint32_t ringbuf_bytes,
               uint32_t event_sample_rate)
{
    // Check for break-glass mode FIRST
    bool break_glass_active = detect_break_glass();
    if (break_glass_active) {
        logger().log(SLOG_WARN("Break-glass mode detected - forcing audit-only mode"));
        audit_only = true;
    }

    if (enforce_signal != kEnforceSignalNone &&
        enforce_signal != kEnforceSignalInt &&
        enforce_signal != kEnforceSignalKill &&
        enforce_signal != kEnforceSignalTerm) {
        logger().log(SLOG_WARN("Invalid enforce signal configured; using SIGTERM")
                         .field("signal", static_cast<int64_t>(enforce_signal)));
        enforce_signal = kEnforceSignalTerm;
    }

    // Validate config directory permissions (security check)
    auto config_perm_result = validate_config_directory_permissions("/etc/aegisbpf");
    if (!config_perm_result) {
        logger().log(SLOG_ERROR("Config directory permission check failed")
                         .field("error", config_perm_result.error().to_string()));
        return 1;
    }

    // Detect kernel features for graceful degradation
    auto features_result = detect_kernel_features();
    if (!features_result) {
        logger().log(SLOG_ERROR("Failed to detect kernel features")
                         .field("error", features_result.error().to_string()));
        return 1;
    }
    KernelFeatures features = *features_result;

    // Determine enforcement capability
    EnforcementCapability cap = determine_capability(features);
    logger().log(SLOG_INFO("Kernel feature detection complete")
                     .field("kernel_version", features.kernel_version)
                     .field("capability", capability_name(cap))
                     .field("bpf_lsm", features.bpf_lsm)
                     .field("cgroup_v2", features.cgroup_v2)
                     .field("btf", features.btf)
                     .field("ringbuf", features.ringbuf));

    // Handle capability-based decisions
    if (cap == EnforcementCapability::Disabled) {
        logger().log(SLOG_ERROR("Cannot run AegisBPF on this system")
                         .field("explanation", capability_explanation(features, cap)));
        return 1;
    }

    bool lsm_enabled = features.bpf_lsm;

    if (cap == EnforcementCapability::AuditOnly) {
        if (!audit_only) {
            logger().log(SLOG_WARN("Full enforcement not available; falling back to audit-only mode")
                             .field("explanation", capability_explanation(features, cap)));
            audit_only = true;
        }
        else {
            logger().log(SLOG_INFO("Running in audit-only mode")
                             .field("explanation", capability_explanation(features, cap)));
        }
    }

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit")
                         .field("error", rlimit_result.error().to_string()));
        return 1;
    }

    if (ringbuf_bytes > 0) {
        set_ringbuf_bytes(ringbuf_bytes);
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    auto version_result = ensure_layout_version(state);
    if (!version_result) {
        logger().log(SLOG_ERROR("Layout version check failed")
                         .field("error", version_result.error().to_string()));
        return 1;
    }

    // Set up full agent config with deadman switch and break-glass
    AgentConfig config{};
    config.audit_only = audit_only ? 1 : 0;
    config.break_glass_active = break_glass_active ? 1 : 0;
    config.deadman_enabled = (deadman_ttl > 0) ? 1 : 0;
    config.enforce_signal = enforce_signal;
    config.deadman_ttl_seconds = deadman_ttl;
    config.event_sample_rate = event_sample_rate ? event_sample_rate : 1;
    if (config.deadman_enabled) {
        struct timespec ts {};
        clock_gettime(CLOCK_BOOTTIME, &ts);
        uint64_t now_ns = static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL +
                          static_cast<uint64_t>(ts.tv_nsec);
        config.deadman_deadline_ns = now_ns + (static_cast<uint64_t>(deadman_ttl) * 1000000000ULL);
    }

    auto config_result = set_agent_config_full(state, config);
    if (!config_result) {
        logger().log(SLOG_ERROR("Failed to set agent config")
                         .field("error", config_result.error().to_string()));
        return 1;
    }

    // Populate survival allowlist with critical binaries
    auto survival_result = populate_survival_allowlist(state);
    if (!survival_result) {
        logger().log(SLOG_WARN("Failed to populate survival allowlist")
                         .field("error", survival_result.error().to_string()));
    }

    auto cgroup_result = setup_agent_cgroup(state);
    if (!cgroup_result) {
        logger().log(SLOG_ERROR("Failed to setup agent cgroup")
                         .field("error", cgroup_result.error().to_string()));
        return 1;
    }

    bool use_inode_permission = (lsm_hook == LsmHookMode::Both || lsm_hook == LsmHookMode::InodePermission);
    bool use_file_open = (lsm_hook == LsmHookMode::Both || lsm_hook == LsmHookMode::FileOpen);
    auto attach_result = attach_all(state, lsm_enabled, use_inode_permission, use_file_open);
    if (!attach_result) {
        logger().log(SLOG_ERROR("Failed to attach programs")
                         .field("error", attach_result.error().to_string()));
        return 1;
    }

    RingBufferGuard rb(ring_buffer__new(bpf_map__fd(state.events), handle_event, nullptr, nullptr));
    if (!rb) {
        logger().log(SLOG_ERROR("Failed to create ring buffer"));
        return 1;
    }

    // Apply seccomp filter after all initialization is complete
    if (enable_seccomp) {
        auto seccomp_result = apply_seccomp_filter();
        if (!seccomp_result) {
            logger().log(SLOG_ERROR("Failed to apply seccomp filter")
                             .field("error", seccomp_result.error().to_string()));
            return 1;
        }
    }

    bool network_enabled = lsm_enabled && (state.deny_ipv4 != nullptr || state.deny_ipv6 != nullptr);
    logger().log(SLOG_INFO("Agent started")
                     .field("audit_only", audit_only)
                     .field("enforce_signal", enforce_signal_name(config.enforce_signal))
                     .field("lsm_enabled", lsm_enabled)
                     .field("lsm_hook", lsm_hook_name(lsm_hook))
                     .field("network_enabled", network_enabled)
                     .field("event_sample_rate", static_cast<int64_t>(config.event_sample_rate))
                     .field("ringbuf_bytes", static_cast<int64_t>(ringbuf_bytes))
                     .field("seccomp", enable_seccomp)
                     .field("break_glass", break_glass_active)
                     .field("deadman_ttl", static_cast<int64_t>(deadman_ttl)));

    // Start heartbeat thread if deadman switch is enabled
    std::thread heartbeat;
    if (deadman_ttl > 0) {
        g_heartbeat_running.store(true);
        heartbeat = std::thread(heartbeat_thread, &state, deadman_ttl);
        logger().log(SLOG_INFO("Deadman switch heartbeat started")
                         .field("ttl_seconds", static_cast<int64_t>(deadman_ttl)));
    }

    int err = 0;
    while (!g_exiting) {
        err = ring_buffer__poll(rb.get(), 250);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            logger().log(SLOG_ERROR("Ring buffer poll failed").error_code(-err));
            break;
        }
    }

    // Stop heartbeat thread
    if (deadman_ttl > 0 && heartbeat.joinable()) {
        g_heartbeat_running.store(false);
        heartbeat.join();
    }

    logger().log(SLOG_INFO("Agent stopped"));
    return err < 0 ? 1 : 0;
}

}  // namespace aegis
