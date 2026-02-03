// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - Network command implementations
 */

#include "commands_network.hpp"

#include "bpf_ops.hpp"
#include "logging.hpp"
#include "network_ops.hpp"
#include "types.hpp"
#include "utils.hpp"

#include <cstdint>
#include <iostream>
#include <unistd.h>

namespace aegis {

namespace {

bool parse_protocol(const std::string& protocol_str, uint8_t& protocol)
{
    protocol = 0;
    if (protocol_str == "tcp") {
        protocol = 6;
    }
    else if (protocol_str == "udp") {
        protocol = 17;
    }
    else if (protocol_str != "any" && !protocol_str.empty()) {
        logger().log(SLOG_ERROR("Invalid protocol").field("protocol", protocol_str));
        return false;
    }
    return true;
}

bool parse_direction(const std::string& direction_str, uint8_t& direction)
{
    direction = 2;
    if (direction_str == "egress") {
        direction = 0;
    }
    else if (direction_str == "bind") {
        direction = 1;
    }
    else if (direction_str != "both" && !direction_str.empty()) {
        logger().log(SLOG_ERROR("Invalid direction").field("direction", direction_str));
        return false;
    }
    return true;
}

}  // namespace

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
    if (!parse_protocol(protocol_str, protocol)) return 1;

    uint8_t direction = 2;
    if (!parse_direction(direction_str, direction)) return 1;

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
    if (!parse_protocol(protocol_str, protocol)) return 1;

    uint8_t direction = 2;
    if (!parse_direction(direction_str, direction)) return 1;

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
                std::cout << "  " << format_cidr_v4(cidr.first, cidr.second) << std::endl;
            }
        }
    }

    std::cout << "\nDenied Ports:" << std::endl;
    if (state.deny_port) {
        auto ports_result = list_deny_ports(state);
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

}  // namespace aegis
