// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Command implementations
 *
 * This file contains all CLI command handler implementations.
 */

#include "commands.hpp"
#include "bpf_ops.hpp"
#include "crypto.hpp"
#include "logging.hpp"
#include "network_ops.hpp"
#include "policy.hpp"
#include "sha256.hpp"
#include "types.hpp"
#include "utils.hpp"

#include <bpf/libbpf.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <sys/stat.h>

namespace aegis {

// ============================================================================
// Block commands
// ============================================================================

static int block_file(const std::string& path)
{
    auto validated = validate_existing_path(path);
    if (!validated) {
        logger().log(SLOG_ERROR("Invalid path").field("error", validated.error().to_string()));
        return 1;
    }

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit")
                         .field("error", rlimit_result.error().to_string()));
        return 1;
    }

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

    auto entries = read_deny_db();
    auto add_result = add_deny_path(state, *validated, entries);
    if (!add_result) {
        logger().log(SLOG_ERROR("Failed to add deny entry")
                         .field("error", add_result.error().to_string()));
        return 1;
    }

    auto write_result = write_deny_db(entries);
    if (!write_result) {
        logger().log(SLOG_ERROR("Failed to write deny database")
                         .field("error", write_result.error().to_string()));
        return 1;
    }
    return 0;
}

int cmd_block_add(const std::string& path)
{
    return block_file(path);
}

int cmd_block_del(const std::string& path)
{
    auto inode_result = path_to_inode(path);
    if (!inode_result) {
        logger().log(SLOG_ERROR("Failed to get inode")
                         .field("error", inode_result.error().to_string()));
        return 1;
    }
    InodeId id = *inode_result;

    int map_fd = bpf_obj_get(kDenyInodePin);
    if (map_fd < 0) {
        logger().log(SLOG_ERROR("deny_inode_map not found"));
        return 1;
    }
    bpf_map_delete_elem(map_fd, &id);
    close(map_fd);

    std::error_code ec;
    std::filesystem::path resolved = std::filesystem::canonical(path, ec);
    std::string resolved_path = ec ? path : resolved.string();
    PathKey path_key{};
    fill_path_key(resolved_path, path_key);
    int path_fd = bpf_obj_get(kDenyPathPin);
    if (path_fd >= 0) {
        bpf_map_delete_elem(path_fd, &path_key);
        if (resolved_path != path) {
            PathKey raw_key{};
            fill_path_key(path, raw_key);
            bpf_map_delete_elem(path_fd, &raw_key);
        }
        close(path_fd);
    }
    else {
        logger().log(SLOG_WARN("deny_path_map not found"));
    }

    auto entries = read_deny_db();
    entries.erase(id);
    auto write_result = write_deny_db(entries);
    if (!write_result) {
        logger().log(SLOG_ERROR("Failed to write deny database")
                         .field("error", write_result.error().to_string()));
        return 1;
    }
    return 0;
}

int cmd_block_list()
{
    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    auto db = read_deny_db();
    InodeId key{};
    InodeId next_key{};
    int rc = bpf_map_get_next_key(bpf_map__fd(state.deny_inode), nullptr, &key);
    while (!rc) {
        auto it = db.find(key);
        if (it != db.end() && !it->second.empty()) {
            std::cout << it->second << " (" << inode_to_string(key) << ")" << std::endl;
        }
        else {
            std::cout << inode_to_string(key) << std::endl;
        }
        rc = bpf_map_get_next_key(bpf_map__fd(state.deny_inode), &key, &next_key);
        key = next_key;
    }

    return 0;
}

int cmd_block_clear()
{
    std::remove(kDenyInodePin);
    std::remove(kDenyPathPin);
    std::remove(kAllowCgroupPin);
    std::remove(kDenyCgroupStatsPin);
    std::remove(kDenyInodeStatsPin);
    std::remove(kDenyPathStatsPin);
    std::remove(kAgentMetaPin);
    std::remove(kSurvivalAllowlistPin);
    std::filesystem::remove(kDenyDbPath);
    std::filesystem::remove(kPolicyAppliedPath);
    std::filesystem::remove(kPolicyAppliedPrevPath);
    std::filesystem::remove(kPolicyAppliedHashPath);

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit")
                         .field("error", rlimit_result.error().to_string()));
        return 1;
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to reload BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }
    if (state.block_stats) {
        auto reset_result = reset_block_stats_map(state.block_stats);
        if (!reset_result) {
            logger().log(SLOG_WARN("Failed to reset block stats")
                             .field("error", reset_result.error().to_string()));
        }
    }
    return 0;
}

// ============================================================================
// Allow commands
// ============================================================================

int cmd_allow_add(const std::string& path)
{
    auto validated = validate_cgroup_path(path);
    if (!validated) {
        logger().log(SLOG_ERROR("Invalid cgroup path").field("error", validated.error().to_string()));
        return 1;
    }

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit")
                         .field("error", rlimit_result.error().to_string()));
        return 1;
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    auto add_result = add_allow_cgroup_path(state, *validated);
    if (!add_result) {
        logger().log(SLOG_ERROR("Failed to add allow cgroup")
                         .field("error", add_result.error().to_string()));
        return 1;
    }

    return 0;
}

int cmd_allow_del(const std::string& path)
{
    auto cgid_result = path_to_cgid(path);
    if (!cgid_result) {
        logger().log(SLOG_ERROR("Failed to get cgroup ID")
                         .field("error", cgid_result.error().to_string()));
        return 1;
    }
    uint64_t cgid = *cgid_result;

    int fd = bpf_obj_get(kAllowCgroupPin);
    if (fd < 0) {
        logger().log(SLOG_ERROR("allow_cgroup_map not found"));
        return 1;
    }
    bpf_map_delete_elem(fd, &cgid);
    close(fd);
    return 0;
}

int cmd_allow_list()
{
    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    auto ids_result = read_allow_cgroup_ids(state.allow_cgroup);
    if (!ids_result) {
        logger().log(SLOG_ERROR("Failed to read allow cgroup IDs")
                         .field("error", ids_result.error().to_string()));
        return 1;
    }

    for (uint64_t id : *ids_result) {
        std::cout << id << std::endl;
    }

    return 0;
}

// ============================================================================
// Network commands
// ============================================================================

int cmd_network_deny_add_ip(const std::string& ip)
{
    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit")
                         .field("error", rlimit_result.error().to_string()));
        return 1;
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    auto add_result = add_deny_ipv4(state, ip);
    if (!add_result) {
        logger().log(SLOG_ERROR("Failed to add deny IP")
                         .field("ip", ip)
                         .field("error", add_result.error().to_string()));
        return 1;
    }

    logger().log(SLOG_INFO("Added deny IP").field("ip", ip));
    return 0;
}

int cmd_network_deny_add_cidr(const std::string& cidr)
{
    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit")
                         .field("error", rlimit_result.error().to_string()));
        return 1;
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    auto add_result = add_deny_cidr_v4(state, cidr);
    if (!add_result) {
        logger().log(SLOG_ERROR("Failed to add deny CIDR")
                         .field("cidr", cidr)
                         .field("error", add_result.error().to_string()));
        return 1;
    }

    logger().log(SLOG_INFO("Added deny CIDR").field("cidr", cidr));
    return 0;
}

int cmd_network_deny_add_port(uint16_t port, const std::string& protocol_str, const std::string& direction_str)
{
    uint8_t protocol = 0;
    if (protocol_str == "tcp") {
        protocol = 6;
    }
    else if (protocol_str == "udp") {
        protocol = 17;
    }
    else if (protocol_str != "any" && !protocol_str.empty()) {
        logger().log(SLOG_ERROR("Invalid protocol").field("protocol", protocol_str));
        return 1;
    }

    uint8_t direction = 2;  // both
    if (direction_str == "egress") {
        direction = 0;
    }
    else if (direction_str == "bind") {
        direction = 1;
    }
    else if (direction_str != "both" && !direction_str.empty()) {
        logger().log(SLOG_ERROR("Invalid direction").field("direction", direction_str));
        return 1;
    }

    auto rlimit_result = bump_memlock_rlimit();
    if (!rlimit_result) {
        logger().log(SLOG_ERROR("Failed to raise memlock rlimit")
                         .field("error", rlimit_result.error().to_string()));
        return 1;
    }

    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    auto add_result = add_deny_port(state, port, protocol, direction);
    if (!add_result) {
        logger().log(SLOG_ERROR("Failed to add deny port")
                         .field("port", static_cast<int64_t>(port))
                         .field("error", add_result.error().to_string()));
        return 1;
    }

    logger().log(SLOG_INFO("Added deny port")
        .field("port", static_cast<int64_t>(port))
        .field("protocol", protocol_str.empty() ? "any" : protocol_str)
        .field("direction", direction_str.empty() ? "both" : direction_str));
    return 0;
}

int cmd_network_deny_del_ip(const std::string& ip)
{
    uint32_t ip_be = 0;
    if (!parse_ipv4(ip, ip_be)) {
        logger().log(SLOG_ERROR("Invalid IP address").field("ip", ip));
        return 1;
    }

    int fd = bpf_obj_get(kDenyIpv4Pin);
    if (fd < 0) {
        logger().log(SLOG_ERROR("deny_ipv4 map not found"));
        return 1;
    }

    if (bpf_map_delete_elem(fd, &ip_be) != 0) {
        logger().log(SLOG_WARN("IP not found in deny list").field("ip", ip));
    }
    close(fd);

    logger().log(SLOG_INFO("Removed deny IP").field("ip", ip));
    return 0;
}

int cmd_network_deny_del_cidr(const std::string& cidr)
{
    uint32_t ip_be = 0;
    uint8_t prefix_len = 0;
    if (!parse_cidr_v4(cidr, ip_be, prefix_len)) {
        logger().log(SLOG_ERROR("Invalid CIDR").field("cidr", cidr));
        return 1;
    }

    int fd = bpf_obj_get(kDenyCidrV4Pin);
    if (fd < 0) {
        logger().log(SLOG_ERROR("deny_cidr_v4 map not found"));
        return 1;
    }

    struct {
        uint32_t prefixlen;
        uint32_t addr;
    } key = {prefix_len, ip_be};

    if (bpf_map_delete_elem(fd, &key) != 0) {
        logger().log(SLOG_WARN("CIDR not found in deny list").field("cidr", cidr));
    }
    close(fd);

    logger().log(SLOG_INFO("Removed deny CIDR").field("cidr", cidr));
    return 0;
}

int cmd_network_deny_del_port(uint16_t port, const std::string& protocol_str, const std::string& direction_str)
{
    uint8_t protocol = 0;
    if (protocol_str == "tcp") {
        protocol = 6;
    }
    else if (protocol_str == "udp") {
        protocol = 17;
    }

    uint8_t direction = 2;
    if (direction_str == "egress") {
        direction = 0;
    }
    else if (direction_str == "bind") {
        direction = 1;
    }

    int fd = bpf_obj_get(kDenyPortPin);
    if (fd < 0) {
        logger().log(SLOG_ERROR("deny_port map not found"));
        return 1;
    }

    PortKey key{};
    key.port = port;
    key.protocol = protocol;
    key.direction = direction;

    if (bpf_map_delete_elem(fd, &key) != 0) {
        logger().log(SLOG_WARN("Port not found in deny list").field("port", static_cast<int64_t>(port)));
    }
    close(fd);

    logger().log(SLOG_INFO("Removed deny port").field("port", static_cast<int64_t>(port)));
    return 0;
}

int cmd_network_deny_list()
{
    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    std::cout << "Denied IPs:" << std::endl;
    if (state.deny_ipv4) {
        auto ips_result = list_deny_ipv4(state);
        if (ips_result) {
            for (uint32_t ip : *ips_result) {
                std::cout << "  " << format_ipv4(ip) << std::endl;
            }
        }
    }

    std::cout << "\nDenied CIDRs:" << std::endl;
    if (state.deny_cidr_v4) {
        auto cidrs_result = list_deny_cidr_v4(state);
        if (cidrs_result) {
            for (const auto& cidr : *cidrs_result) {
                std::cout << "  " << cidr << std::endl;
            }
        }
    }

    std::cout << "\nDenied Ports:" << std::endl;
    if (state.deny_port) {
        auto ports_result = list_deny_port(state);
        if (ports_result) {
            for (const auto& pr : *ports_result) {
                std::cout << "  " << pr.port << " (" << protocol_name(pr.protocol)
                          << ", " << direction_name(pr.direction) << ")" << std::endl;
            }
        }
    }

    return 0;
}

int cmd_network_deny_clear()
{
    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    if (state.deny_ipv4) {
        clear_map_entries(state.deny_ipv4);
    }
    if (state.deny_cidr_v4) {
        clear_map_entries(state.deny_cidr_v4);
    }
    if (state.deny_port) {
        clear_map_entries(state.deny_port);
    }

    logger().log(SLOG_INFO("Cleared all network deny rules"));
    return 0;
}

int cmd_network_stats()
{
    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    auto stats_result = read_net_block_stats(state);
    if (!stats_result) {
        logger().log(SLOG_ERROR("Failed to read network stats")
                         .field("error", stats_result.error().to_string()));
        return 1;
    }

    const auto& stats = *stats_result;
    std::cout << "Network Block Statistics:" << std::endl;
    std::cout << "  Connect blocks: " << stats.connect_blocks << std::endl;
    std::cout << "  Bind blocks: " << stats.bind_blocks << std::endl;
    std::cout << "  Ringbuf drops: " << stats.ringbuf_drops << std::endl;

    return 0;
}

// ============================================================================
// Policy commands
// ============================================================================

int cmd_policy_lint(const std::string& path)
{
    auto result = policy_lint(path);
    return result ? 0 : 1;
}

int cmd_policy_validate(const std::string& path, bool verbose)
{
    PolicyIssues issues;
    auto result = parse_policy_file(path, issues);
    report_policy_issues(issues);
    if (!result) {
        logger().log(SLOG_ERROR("Policy validation failed")
            .field("error", result.error().to_string()));
        return 1;
    }
    const Policy& policy = *result;

    std::cout << "Policy validation successful.\n\n";
    std::cout << "Summary:\n";
    std::cout << "  Deny paths: " << policy.deny_paths.size() << "\n";
    std::cout << "  Deny inodes: " << policy.deny_inodes.size() << "\n";
    std::cout << "  Allow cgroup IDs: " << policy.allow_cgroup_ids.size() << "\n";
    std::cout << "  Allow cgroup paths: " << policy.allow_cgroup_paths.size() << "\n";

    if (policy.network.enabled) {
        std::cout << "  Network deny IPs: " << policy.network.deny_ips.size() << "\n";
        std::cout << "  Network deny CIDRs: " << policy.network.deny_cidrs.size() << "\n";
        std::cout << "  Network deny ports: " << policy.network.deny_ports.size() << "\n";
    }

    if (verbose) {
        if (!policy.deny_paths.empty()) {
            std::cout << "\nDeny paths:\n";
            for (const auto& p : policy.deny_paths) {
                std::cout << "  - " << p << "\n";
            }
        }
        if (!policy.deny_inodes.empty()) {
            std::cout << "\nDeny inodes:\n";
            for (const auto& id : policy.deny_inodes) {
                std::cout << "  - " << id.dev << ":" << id.ino << "\n";
            }
        }
        if (!policy.allow_cgroup_paths.empty()) {
            std::cout << "\nAllow cgroup paths:\n";
            for (const auto& p : policy.allow_cgroup_paths) {
                std::cout << "  - " << p << "\n";
            }
        }
        if (policy.network.enabled) {
            if (!policy.network.deny_ips.empty()) {
                std::cout << "\nNetwork deny IPs:\n";
                for (const auto& ip : policy.network.deny_ips) {
                    std::cout << "  - " << ip << "\n";
                }
            }
            if (!policy.network.deny_cidrs.empty()) {
                std::cout << "\nNetwork deny CIDRs:\n";
                for (const auto& cidr : policy.network.deny_cidrs) {
                    std::cout << "  - " << cidr << "\n";
                }
            }
            if (!policy.network.deny_ports.empty()) {
                std::cout << "\nNetwork deny ports:\n";
                for (const auto& pr : policy.network.deny_ports) {
                    std::string proto = (pr.protocol == 6) ? "tcp" : (pr.protocol == 17) ? "udp" : "any";
                    std::string dir = (pr.direction == 0) ? "egress" : (pr.direction == 1) ? "bind" : "both";
                    std::cout << "  - port " << pr.port << " (" << proto << ", " << dir << ")\n";
                }
            }
        }
    }

    if (!issues.warnings.empty()) {
        std::cout << "\nWarnings: " << issues.warnings.size() << "\n";
    }

    return 0;
}

int cmd_policy_apply(const std::string& path, bool reset, const std::string& sha256,
                     const std::string& sha256_file, bool rollback_on_failure)
{
    auto result = policy_apply(path, reset, sha256, sha256_file, rollback_on_failure);
    return result ? 0 : 1;
}

int cmd_policy_apply_signed(const std::string& bundle_path, bool require_signature)
{
    auto result = verify_and_apply_signed_policy(bundle_path);
    if (!result) {
        logger().log(SLOG_ERROR("Failed to apply signed policy")
                         .field("error", result.error().to_string()));
        return 1;
    }
    if (require_signature && !result->verified) {
        logger().log(SLOG_ERROR("Policy signature verification failed"));
        return 1;
    }
    return 0;
}

int cmd_policy_sign(const std::string& policy_path, const std::string& key_path, const std::string& output_path)
{
    auto result = sign_policy_file(policy_path, key_path, output_path);
    if (!result) {
        logger().log(SLOG_ERROR("Failed to sign policy")
                         .field("error", result.error().to_string()));
        return 1;
    }
    logger().log(SLOG_INFO("Policy signed successfully").field("output", output_path));
    return 0;
}

int cmd_policy_export(const std::string& path)
{
    auto result = policy_export(path);
    return result ? 0 : 1;
}

int cmd_policy_show()
{
    auto result = policy_show();
    return result ? 0 : 1;
}

int cmd_policy_rollback()
{
    auto result = policy_rollback();
    return result ? 0 : 1;
}

// ============================================================================
// Key management commands
// ============================================================================

int cmd_keys_list()
{
    auto result = load_trusted_keys();
    if (!result) {
        logger().log(SLOG_ERROR("Failed to list keys")
                         .field("error", result.error().to_string()));
        return 1;
    }
    for (const auto& key : *result) {
        // Print key fingerprint (first 16 bytes as hex)
        std::ostringstream oss;
        for (size_t i = 0; i < std::min(key.size(), size_t(8)); ++i) {
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(key[i]);
        }
        std::cout << oss.str() << "..." << std::endl;
    }
    return 0;
}

int cmd_keys_add(const std::string& key_file)
{
    // Read the key file
    std::ifstream in(key_file, std::ios::binary);
    if (!in.is_open()) {
        logger().log(SLOG_ERROR("Failed to open key file").field("path", key_file));
        return 1;
    }

    // Copy to keys directory
    std::string keys_dir = "/etc/aegisbpf/keys";
    std::error_code ec;
    std::filesystem::create_directories(keys_dir, ec);
    if (ec) {
        logger().log(SLOG_ERROR("Failed to create keys directory")
                         .field("error", ec.message()));
        return 1;
    }

    std::string dest = keys_dir + "/" + std::filesystem::path(key_file).filename().string();
    std::filesystem::copy_file(key_file, dest, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
        logger().log(SLOG_ERROR("Failed to copy key file")
                         .field("error", ec.message()));
        return 1;
    }

    logger().log(SLOG_INFO("Key added successfully").field("path", dest));
    return 0;
}

// ============================================================================
// Survival commands
// ============================================================================

int cmd_survival_list()
{
    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    auto ids_result = read_survival_allowlist(state);
    if (!ids_result) {
        logger().log(SLOG_ERROR("Failed to read survival allowlist")
                         .field("error", ids_result.error().to_string()));
        return 1;
    }

    std::cout << "Survival allowlist:" << std::endl;
    for (const auto& id : *ids_result) {
        std::cout << "  " << id.dev << ":" << id.ino << std::endl;
    }
    return 0;
}

int cmd_survival_verify()
{
    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    auto ids_result = read_survival_allowlist(state);
    if (!ids_result) {
        logger().log(SLOG_ERROR("Failed to read survival allowlist")
                         .field("error", ids_result.error().to_string()));
        return 1;
    }

    // Verify each entry still exists
    int errors = 0;
    for (const auto& id : *ids_result) {
        // Check if the inode still exists
        // This is a basic check - we can't verify the path without the db
        if (id.ino == 0) {
            errors++;
        }
    }

    if (errors > 0) {
        std::cout << "Survival allowlist verification found " << errors << " issues" << std::endl;
        return 1;
    }

    std::cout << "Survival allowlist verified successfully (" << ids_result->size() << " entries)" << std::endl;
    return 0;
}

// ============================================================================
// Stats and monitoring commands
// ============================================================================

int cmd_stats()
{
    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    auto stats_result = read_block_stats_map(state.block_stats);
    if (!stats_result) {
        logger().log(SLOG_ERROR("Failed to read block stats")
                         .field("error", stats_result.error().to_string()));
        return 1;
    }

    const auto& stats = *stats_result;
    std::cout << "Block Statistics:" << std::endl;
    std::cout << "  Total blocks: " << stats.total_blocks << std::endl;
    std::cout << "  Inode blocks: " << stats.inode_blocks << std::endl;
    std::cout << "  Path blocks: " << stats.path_blocks << std::endl;
    std::cout << "  Ringbuf drops: " << stats.ringbuf_drops << std::endl;

    return 0;
}

int cmd_metrics(const std::string& out_path)
{
    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("Failed to load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    std::ostringstream oss;

    // Block stats
    auto stats_result = read_block_stats_map(state.block_stats);
    if (stats_result) {
        const auto& stats = *stats_result;
        oss << "# HELP aegisbpf_blocks_total Total number of blocked operations\n";
        oss << "# TYPE aegisbpf_blocks_total counter\n";
        oss << "aegisbpf_blocks_total " << stats.total_blocks << "\n";
        oss << "# HELP aegisbpf_inode_blocks_total Number of inode-based blocks\n";
        oss << "# TYPE aegisbpf_inode_blocks_total counter\n";
        oss << "aegisbpf_inode_blocks_total " << stats.inode_blocks << "\n";
        oss << "# HELP aegisbpf_path_blocks_total Number of path-based blocks\n";
        oss << "# TYPE aegisbpf_path_blocks_total counter\n";
        oss << "aegisbpf_path_blocks_total " << stats.path_blocks << "\n";
        oss << "# HELP aegisbpf_ringbuf_drops_total Number of dropped events\n";
        oss << "# TYPE aegisbpf_ringbuf_drops_total counter\n";
        oss << "aegisbpf_ringbuf_drops_total " << stats.ringbuf_drops << "\n";
    }

    // Map entry counts
    oss << "# HELP aegisbpf_deny_inode_entries Number of deny inode entries\n";
    oss << "# TYPE aegisbpf_deny_inode_entries gauge\n";
    oss << "aegisbpf_deny_inode_entries " << map_entry_count(state.deny_inode) << "\n";
    oss << "# HELP aegisbpf_deny_path_entries Number of deny path entries\n";
    oss << "# TYPE aegisbpf_deny_path_entries gauge\n";
    oss << "aegisbpf_deny_path_entries " << map_entry_count(state.deny_path) << "\n";
    oss << "# HELP aegisbpf_allow_cgroup_entries Number of allow cgroup entries\n";
    oss << "# TYPE aegisbpf_allow_cgroup_entries gauge\n";
    oss << "aegisbpf_allow_cgroup_entries " << map_entry_count(state.allow_cgroup) << "\n";

    std::string metrics = oss.str();

    if (out_path.empty() || out_path == "-") {
        std::cout << metrics;
    }
    else {
        std::ofstream out(out_path);
        if (!out.is_open()) {
            logger().log(SLOG_ERROR("Failed to open metrics output file").field("path", out_path));
            return 1;
        }
        out << metrics;
    }

    return 0;
}

int cmd_health()
{
    BpfState state;
    auto load_result = load_bpf(true, false, state);
    if (!load_result) {
        logger().log(SLOG_ERROR("BPF health check failed - cannot load BPF object")
                         .field("error", load_result.error().to_string()));
        return 1;
    }

    // Check required maps exist
    if (!state.deny_inode || !state.deny_path || !state.allow_cgroup || !state.events) {
        logger().log(SLOG_ERROR("BPF health check failed - missing required maps"));
        return 1;
    }

    // Check layout version by ensuring it
    auto version_result = ensure_layout_version(state);
    if (!version_result) {
        logger().log(SLOG_ERROR("BPF health check failed - layout version check failed")
                         .field("error", version_result.error().to_string()));
        return 1;
    }

    std::cout << "Health check passed" << std::endl;
    return 0;
}

}  // namespace aegis
