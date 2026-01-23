#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <algorithm>
#include <cctype>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <limits.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef HAVE_SYSTEMD
#include <systemd/sd-journal.h>
#include <syslog.h>
#endif

static constexpr const char *kPinRoot = "/sys/fs/bpf/aegisbpf";
static constexpr const char *kDenyInodePin = "/sys/fs/bpf/aegisbpf/deny_inode";
static constexpr const char *kDenyPathPin = "/sys/fs/bpf/aegisbpf/deny_path";
static constexpr const char *kAllowCgroupPin = "/sys/fs/bpf/aegisbpf/allow_cgroup";
static constexpr const char *kBlockStatsPin = "/sys/fs/bpf/aegisbpf/block_stats";
static constexpr const char *kDenyCgroupStatsPin = "/sys/fs/bpf/aegisbpf/deny_cgroup_stats";
static constexpr const char *kDenyInodeStatsPin = "/sys/fs/bpf/aegisbpf/deny_inode_stats";
static constexpr const char *kDenyPathStatsPin = "/sys/fs/bpf/aegisbpf/deny_path_stats";
static constexpr const char *kAgentMetaPin = "/sys/fs/bpf/aegisbpf/agent_meta";
static constexpr const char *kBpfObjPath = AEGIS_BPF_OBJ_PATH;
static constexpr const char *kBpfObjInstallPath = "/usr/lib/aegisbpf/aegis.bpf.o";
static constexpr const char *kDenyDbDir = "/var/lib/aegisbpf";
static constexpr const char *kDenyDbPath = "/var/lib/aegisbpf/deny.db";
static constexpr const char *kPolicyAppliedPath = "/var/lib/aegisbpf/policy.applied";
static constexpr const char *kPolicyAppliedPrevPath = "/var/lib/aegisbpf/policy.applied.prev";
static constexpr const char *kPolicyAppliedHashPath = "/var/lib/aegisbpf/policy.applied.sha256";
static constexpr uint32_t kLayoutVersion = 1;
static constexpr size_t kDenyPathMax = 256;

enum EventType : uint32_t {
    EVENT_EXEC = 1,
    EVENT_BLOCK = 2
};

enum class EventLogSink {
    Stdout,
    Journald,
    StdoutAndJournald
};

static EventLogSink g_event_sink = EventLogSink::Stdout;

struct exec_event {
    uint32_t pid;
    uint32_t ppid;
    uint64_t start_time;
    uint64_t cgid;
    char comm[16];
};

struct block_event {
    uint32_t ppid;
    uint64_t start_time;
    uint64_t parent_start_time;
    uint32_t pid;
    uint64_t cgid;
    char comm[16];
    uint64_t ino;
    uint32_t dev;
    char path[kDenyPathMax];
    char action[8];
};

struct event {
    uint32_t type;
    union {
        exec_event exec;
        block_event block;
    };
};

struct BlockStats {
    uint64_t blocks;
    uint64_t ringbuf_drops;
};

struct InodeId {
    uint64_t ino;
    uint32_t dev;

    bool operator==(const InodeId &other) const noexcept
    {
        return ino == other.ino && dev == other.dev;
    }
};

struct InodeIdHash {
    std::size_t operator()(const InodeId &id) const noexcept
    {
        return std::hash<uint64_t>{}(id.ino) ^ (std::hash<uint32_t>{}(id.dev) << 1);
    }
};

struct PathKey {
    char path[kDenyPathMax];
};

using DenyEntries = std::unordered_map<InodeId, std::string, InodeIdHash>;

struct AgentConfig {
    uint8_t audit_only;
};

struct AgentMeta {
    uint32_t layout_version;
};

struct Policy {
    int version = 0;
    std::vector<std::string> deny_paths;
    std::vector<InodeId> deny_inodes;
    std::vector<std::string> allow_cgroup_paths;
    std::vector<uint64_t> allow_cgroup_ids;
};

struct PolicyIssues {
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
};

struct BpfState {
    bpf_object *obj = nullptr;
    bpf_map *events = nullptr;
    bpf_map *deny_inode = nullptr;
    bpf_map *deny_path = nullptr;
    bpf_map *allow_cgroup = nullptr;
    bpf_map *block_stats = nullptr;
    bpf_map *deny_cgroup_stats = nullptr;
    bpf_map *deny_inode_stats = nullptr;
    bpf_map *deny_path_stats = nullptr;
    bpf_map *agent_meta = nullptr;
    bpf_map *config_map = nullptr;
    std::vector<bpf_link *> links;
    bool inode_reused = false;
    bool deny_path_reused = false;
    bool cgroup_reused = false;
    bool block_stats_reused = false;
    bool deny_cgroup_stats_reused = false;
    bool deny_inode_stats_reused = false;
    bool deny_path_stats_reused = false;
    bool agent_meta_reused = false;
};

static int setup_agent_cgroup(BpfState &state);

static volatile sig_atomic_t exiting;

static void handle_signal(int)
{
    exiting = 1;
}

static bool kernel_bpf_lsm_enabled()
{
    std::ifstream lsm("/sys/kernel/security/lsm");
    std::string line;
    if (!lsm.is_open() || !std::getline(lsm, line))
        return false;
    return line.find("bpf") != std::string::npos;
}

static int bump_memlock_rlimit()
{
    rlimit rlim;
    std::memset(&rlim, 0, sizeof(rlim));
    rlim.rlim_cur = RLIM_INFINITY;
    rlim.rlim_max = RLIM_INFINITY;
    return setrlimit(RLIMIT_MEMLOCK, &rlim);
}

static int ensure_pin_dir()
{
    if (mkdir(kPinRoot, 0755) && errno != EEXIST)
        return -1;
    return 0;
}

static int ensure_db_dir()
{
    std::error_code ec;
    std::filesystem::create_directories(kDenyDbDir, ec);
    return ec ? -1 : 0;
}

static std::string resolve_bpf_obj_path()
{
    const char *env = std::getenv("AEGIS_BPF_OBJ");
    if (env && *env)
        return std::string(env);

    auto exe_in_system_prefix = []() -> bool {
        char buf[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (len <= 0)
            return false;
        buf[len] = '\0';
        std::string exe(buf);
        return exe.rfind("/usr/", 0) == 0 || exe.rfind("/usr/local/", 0) == 0;
    };

    std::error_code ec;
    if (exe_in_system_prefix()) {
        if (std::filesystem::exists(kBpfObjInstallPath, ec))
            return kBpfObjInstallPath;
        if (std::filesystem::exists(kBpfObjPath, ec))
            return kBpfObjPath;
    } else {
        if (std::filesystem::exists(kBpfObjPath, ec))
            return kBpfObjPath;
        if (std::filesystem::exists(kBpfObjInstallPath, ec))
            return kBpfObjInstallPath;
    }
    return kBpfObjPath;
}

static std::string inode_to_string(const InodeId &id)
{
    std::ostringstream oss;
    oss << id.dev << ":" << id.ino;
    return oss.str();
}

static bool path_to_inode(const std::string &path, InodeId &id)
{
    struct stat st {};
    if (stat(path.c_str(), &st) != 0) {
        std::cerr << "stat failed for " << path << ": " << std::strerror(errno) << std::endl;
        return false;
    }
    id.ino = st.st_ino;
    id.dev = static_cast<uint32_t>(st.st_dev);
    return true;
}

static bool path_to_cgid(const std::string &path, uint64_t &cgid)
{
    struct stat st {};
    if (stat(path.c_str(), &st) != 0) {
        std::cerr << "stat failed for " << path << ": " << std::strerror(errno) << std::endl;
        return false;
    }
    cgid = static_cast<uint64_t>(st.st_ino);
    return true;
}

static void fill_path_key(const std::string &path, PathKey &key)
{
    std::memset(&key, 0, sizeof(key));
    size_t len = path.size();
    if (len >= sizeof(key.path))
        len = sizeof(key.path) - 1;
    std::memcpy(key.path, path.data(), len);
}

static std::string resolve_cgroup_path(uint64_t cgid)
{
    static std::unordered_map<uint64_t, std::string> cache;
    auto it = cache.find(cgid);
    if (it != cache.end())
        return it->second;

    std::error_code ec;
    std::filesystem::recursive_directory_iterator dir("/sys/fs/cgroup",
                                                      std::filesystem::directory_options::skip_permission_denied, ec);
    std::string found;
    for (; dir != std::filesystem::recursive_directory_iterator(); ++dir) {
        if (!dir->is_directory())
            continue;
        struct stat st {};
        if (stat(dir->path().c_str(), &st) != 0)
            continue;
        if (static_cast<uint64_t>(st.st_ino) == cgid) {
            found = dir->path().string();
            break;
        }
    }
    cache[cgid] = found;
    return found;
}

struct CwdCacheEntry {
    uint64_t start_time;
    std::string cwd;
};

static std::string read_proc_cwd(uint32_t pid)
{
    std::string link = "/proc/" + std::to_string(pid) + "/cwd";
    char buf[PATH_MAX];
    ssize_t len = readlink(link.c_str(), buf, sizeof(buf) - 1);
    if (len < 0)
        return {};
    buf[len] = '\0';
    return std::string(buf);
}

static std::string resolve_relative_path(uint32_t pid, uint64_t start_time, const std::string &path)
{
    if (path.empty() || path.front() == '/')
        return path;

    static std::unordered_map<uint32_t, CwdCacheEntry> cache;
    auto it = cache.find(pid);
    if (it == cache.end() || (start_time && it->second.start_time != start_time)) {
        std::string cwd = read_proc_cwd(pid);
        if (cwd.empty())
            return path;
        cache[pid] = {start_time, cwd};
        it = cache.find(pid);
    }

    std::filesystem::path combined = std::filesystem::path(it->second.cwd) / path;
    return combined.lexically_normal().string();
}

static std::string trim(const std::string &s)
{
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start])))
        ++start;
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1])))
        --end;
    return s.substr(start, end - start);
}

static bool parse_key_value(const std::string &line, std::string &key, std::string &value)
{
    size_t pos = line.find('=');
    if (pos == std::string::npos)
        return false;
    key = trim(line.substr(0, pos));
    value = trim(line.substr(pos + 1));
    return !key.empty();
}

static bool parse_uint64(const std::string &text, uint64_t &out)
{
    if (text.empty())
        return false;
    char *end = nullptr;
    errno = 0;
    unsigned long long val = std::strtoull(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str() || *end != '\0')
        return false;
    out = static_cast<uint64_t>(val);
    return true;
}

static bool parse_inode_id(const std::string &text, InodeId &out)
{
    size_t pos = text.find(':');
    if (pos == std::string::npos)
        return false;
    std::string dev_str = trim(text.substr(0, pos));
    std::string ino_str = trim(text.substr(pos + 1));
    uint64_t dev = 0;
    uint64_t ino = 0;
    if (!parse_uint64(dev_str, dev) || !parse_uint64(ino_str, ino))
        return false;
    if (dev > UINT32_MAX)
        return false;
    out.dev = static_cast<uint32_t>(dev);
    out.ino = ino;
    return true;
}

static void report_policy_issues(const PolicyIssues &issues)
{
    for (const auto &err : issues.errors)
        std::cerr << "Policy error: " << err << std::endl;
    for (const auto &warn : issues.warnings)
        std::cerr << "Policy warning: " << warn << std::endl;
}

static bool parse_policy_file(const std::string &path, Policy &policy, PolicyIssues &issues)
{
    std::ifstream in(path);
    if (!in.is_open()) {
        issues.errors.push_back("Failed to open '" + path + "': " + std::strerror(errno));
        return false;
    }

    std::string section;
    std::unordered_set<std::string> deny_path_seen;
    std::unordered_set<std::string> deny_inode_seen;
    std::unordered_set<std::string> allow_path_seen;
    std::unordered_set<uint64_t> allow_id_seen;
    std::string line;
    size_t line_no = 0;
    while (std::getline(in, line)) {
        ++line_no;
        std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#')
            continue;
        if (trimmed.front() == '[' && trimmed.back() == ']') {
            section = trim(trimmed.substr(1, trimmed.size() - 2));
            if (section != "deny_path" && section != "deny_inode" && section != "allow_cgroup") {
                issues.errors.push_back("line " + std::to_string(line_no) + ": unknown section '" + section + "'");
                section.clear();
            }
            continue;
        }
        if (section.empty()) {
            std::string key;
            std::string value;
            if (!parse_key_value(trimmed, key, value)) {
                issues.errors.push_back("line " + std::to_string(line_no) + ": expected key=value in header");
                continue;
            }
            if (key == "version") {
                uint64_t version = 0;
                if (!parse_uint64(value, version) || version == 0 || version > INT_MAX) {
                    issues.errors.push_back("line " + std::to_string(line_no) + ": invalid version");
                    continue;
                }
                policy.version = static_cast<int>(version);
            } else {
                issues.errors.push_back("line " + std::to_string(line_no) + ": unknown header key '" + key + "'");
            }
            continue;
        }

        if (section == "deny_path") {
            if (trimmed.size() >= kDenyPathMax) {
                issues.errors.push_back("line " + std::to_string(line_no) + ": deny_path is too long");
                continue;
            }
            if (!trimmed.empty() && trimmed.front() != '/')
                issues.warnings.push_back("line " + std::to_string(line_no) + ": deny_path is relative");
            if (deny_path_seen.insert(trimmed).second)
                policy.deny_paths.push_back(trimmed);
            continue;
        }
        if (section == "deny_inode") {
            InodeId id {};
            if (!parse_inode_id(trimmed, id)) {
                issues.errors.push_back("line " + std::to_string(line_no) + ": invalid inode format (dev:ino)");
                continue;
            }
            std::string id_key = inode_to_string(id);
            if (deny_inode_seen.insert(id_key).second)
                policy.deny_inodes.push_back(id);
            continue;
        }
        if (section == "allow_cgroup") {
            if (trimmed.rfind("cgid:", 0) == 0) {
                std::string id_str = trim(trimmed.substr(5));
                uint64_t cgid = 0;
                if (!parse_uint64(id_str, cgid)) {
                    issues.errors.push_back("line " + std::to_string(line_no) + ": invalid cgid value");
                    continue;
                }
                if (allow_id_seen.insert(cgid).second)
                    policy.allow_cgroup_ids.push_back(cgid);
                continue;
            }
            if (!trimmed.empty() && trimmed.front() != '/')
                issues.warnings.push_back("line " + std::to_string(line_no) + ": allow_cgroup path is relative");
            if (allow_path_seen.insert(trimmed).second)
                policy.allow_cgroup_paths.push_back(trimmed);
            continue;
        }
    }

    if (policy.version == 0)
        issues.errors.push_back("missing header key: version");
    if (policy.version != 1)
        issues.errors.push_back("unsupported policy version: " + std::to_string(policy.version));
    return issues.errors.empty();
}

static std::string read_file_first_line(const std::string &path)
{
    std::ifstream in(path);
    std::string line;
    if (!in.is_open())
        return {};
    if (!std::getline(in, line))
        return {};
    return line;
}

static std::string find_kernel_config_value_in_file(const std::string &path, const std::string &key)
{
    std::ifstream in(path);
    if (!in.is_open())
        return {};
    std::string line;
    std::string prefix = key + "=";
    while (std::getline(in, line)) {
        if (line.rfind(prefix, 0) == 0)
            return line.substr(prefix.size());
    }
    return {};
}

static std::string find_kernel_config_value_in_proc(const std::string &key)
{
    if (!std::filesystem::exists("/proc/config.gz"))
        return {};
    FILE *fp = popen("zcat /proc/config.gz 2>/dev/null", "r");
    if (!fp)
        return {};
    std::string prefix = key + "=";
    char buf[4096];
    std::string value;
    while (fgets(buf, sizeof(buf), fp)) {
        std::string line(buf);
        if (line.rfind(prefix, 0) == 0) {
            value = line.substr(prefix.size());
            value = trim(value);
            break;
        }
    }
    pclose(fp);
    return value;
}

static std::string kernel_config_value(const std::string &key)
{
    struct utsname uts {};
    if (uname(&uts) == 0) {
        std::string path = std::string("/boot/config-") + uts.release;
        std::string value = find_kernel_config_value_in_file(path, key);
        if (!value.empty())
            return value;
    }
    return find_kernel_config_value_in_proc(key);
}

static std::string join_list(const std::vector<std::string> &items)
{
    std::ostringstream oss;
    for (size_t i = 0; i < items.size(); ++i) {
        if (i)
            oss << ", ";
        oss << items[i];
    }
    return oss.str();
}

struct Sha256State {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    size_t datalen;
};

static uint32_t sha256_rotr(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32 - n));
}

static uint32_t sha256_ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}

static uint32_t sha256_maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

static uint32_t sha256_ep0(uint32_t x)
{
    return sha256_rotr(x, 2) ^ sha256_rotr(x, 13) ^ sha256_rotr(x, 22);
}

static uint32_t sha256_ep1(uint32_t x)
{
    return sha256_rotr(x, 6) ^ sha256_rotr(x, 11) ^ sha256_rotr(x, 25);
}

static uint32_t sha256_sig0(uint32_t x)
{
    return sha256_rotr(x, 7) ^ sha256_rotr(x, 18) ^ (x >> 3);
}

static uint32_t sha256_sig1(uint32_t x)
{
    return sha256_rotr(x, 17) ^ sha256_rotr(x, 19) ^ (x >> 10);
}

static const uint32_t kSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_transform(Sha256State &ctx, const uint8_t data[64])
{
    uint32_t m[64];
    for (size_t i = 0; i < 16; ++i) {
        m[i] = (static_cast<uint32_t>(data[i * 4]) << 24) |
               (static_cast<uint32_t>(data[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(data[i * 4 + 2]) << 8) |
               (static_cast<uint32_t>(data[i * 4 + 3]));
    }
    for (size_t i = 16; i < 64; ++i)
        m[i] = sha256_sig1(m[i - 2]) + m[i - 7] + sha256_sig0(m[i - 15]) + m[i - 16];

    uint32_t a = ctx.state[0];
    uint32_t b = ctx.state[1];
    uint32_t c = ctx.state[2];
    uint32_t d = ctx.state[3];
    uint32_t e = ctx.state[4];
    uint32_t f = ctx.state[5];
    uint32_t g = ctx.state[6];
    uint32_t h = ctx.state[7];

    for (size_t i = 0; i < 64; ++i) {
        uint32_t t1 = h + sha256_ep1(e) + sha256_ch(e, f, g) + kSha256K[i] + m[i];
        uint32_t t2 = sha256_ep0(a) + sha256_maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx.state[0] += a;
    ctx.state[1] += b;
    ctx.state[2] += c;
    ctx.state[3] += d;
    ctx.state[4] += e;
    ctx.state[5] += f;
    ctx.state[6] += g;
    ctx.state[7] += h;
}

static void sha256_init(Sha256State &ctx)
{
    ctx.datalen = 0;
    ctx.bitlen = 0;
    ctx.state[0] = 0x6a09e667;
    ctx.state[1] = 0xbb67ae85;
    ctx.state[2] = 0x3c6ef372;
    ctx.state[3] = 0xa54ff53a;
    ctx.state[4] = 0x510e527f;
    ctx.state[5] = 0x9b05688c;
    ctx.state[6] = 0x1f83d9ab;
    ctx.state[7] = 0x5be0cd19;
}

static void sha256_update(Sha256State &ctx, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        ctx.data[ctx.datalen] = data[i];
        ctx.datalen++;
        if (ctx.datalen == 64) {
            sha256_transform(ctx, ctx.data);
            ctx.bitlen += 512;
            ctx.datalen = 0;
        }
    }
}

static void sha256_final(Sha256State &ctx, uint8_t hash[32])
{
    size_t i = ctx.datalen;
    if (ctx.datalen < 56) {
        ctx.data[i++] = 0x80;
        while (i < 56)
            ctx.data[i++] = 0x00;
    } else {
        ctx.data[i++] = 0x80;
        while (i < 64)
            ctx.data[i++] = 0x00;
        sha256_transform(ctx, ctx.data);
        std::memset(ctx.data, 0, 56);
    }

    ctx.bitlen += ctx.datalen * 8;
    ctx.data[63] = static_cast<uint8_t>(ctx.bitlen);
    ctx.data[62] = static_cast<uint8_t>(ctx.bitlen >> 8);
    ctx.data[61] = static_cast<uint8_t>(ctx.bitlen >> 16);
    ctx.data[60] = static_cast<uint8_t>(ctx.bitlen >> 24);
    ctx.data[59] = static_cast<uint8_t>(ctx.bitlen >> 32);
    ctx.data[58] = static_cast<uint8_t>(ctx.bitlen >> 40);
    ctx.data[57] = static_cast<uint8_t>(ctx.bitlen >> 48);
    ctx.data[56] = static_cast<uint8_t>(ctx.bitlen >> 56);
    sha256_transform(ctx, ctx.data);

    for (i = 0; i < 4; ++i) {
        hash[i] = (ctx.state[0] >> (24 - i * 8)) & 0xff;
        hash[i + 4] = (ctx.state[1] >> (24 - i * 8)) & 0xff;
        hash[i + 8] = (ctx.state[2] >> (24 - i * 8)) & 0xff;
        hash[i + 12] = (ctx.state[3] >> (24 - i * 8)) & 0xff;
        hash[i + 16] = (ctx.state[4] >> (24 - i * 8)) & 0xff;
        hash[i + 20] = (ctx.state[5] >> (24 - i * 8)) & 0xff;
        hash[i + 24] = (ctx.state[6] >> (24 - i * 8)) & 0xff;
        hash[i + 28] = (ctx.state[7] >> (24 - i * 8)) & 0xff;
    }
}

static bool sha256_file_hex(const std::string &path, std::string &out_hex)
{
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open())
        return false;
    Sha256State ctx {};
    sha256_init(ctx);
    char buf[4096];
    while (in.good()) {
        in.read(buf, sizeof(buf));
        std::streamsize got = in.gcount();
        if (got > 0)
            sha256_update(ctx, reinterpret_cast<const uint8_t *>(buf), static_cast<size_t>(got));
    }
    if (!in.eof() && in.fail())
        return false;
    uint8_t hash[32];
    sha256_final(ctx, hash);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : hash)
        oss << std::setw(2) << static_cast<int>(b);
    out_hex = oss.str();
    return true;
}

static bool parse_sha256_token(const std::string &text, std::string &hex)
{
    std::istringstream iss(text);
    std::string token;
    if (!(iss >> token))
        return false;
    if (token.size() != 64)
        return false;
    for (char c : token) {
        if (!std::isxdigit(static_cast<unsigned char>(c)))
            return false;
    }
    std::transform(token.begin(), token.end(), token.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    hex = token;
    return true;
}

static bool path_exists(const char *path, std::error_code &ec)
{
    ec.clear();
    return std::filesystem::exists(path, ec);
}

static size_t map_entry_count(bpf_map *map)
{
    if (!map)
        return 0;
    const size_t key_sz = bpf_map__key_size(map);
    std::vector<uint8_t> key(key_sz);
    std::vector<uint8_t> next_key(key_sz);
    size_t count = 0;
    int fd = bpf_map__fd(map);
    int rc = bpf_map_get_next_key(fd, nullptr, key.data());
    while (!rc) {
        ++count;
        rc = bpf_map_get_next_key(fd, key.data(), next_key.data());
        key.swap(next_key);
    }
    return count;
}

static int clear_map_entries(bpf_map *map)
{
    if (!map)
        return -ENOENT;
    int fd = bpf_map__fd(map);
    const size_t key_sz = bpf_map__key_size(map);
    std::vector<uint8_t> key(key_sz);
    std::vector<uint8_t> next_key(key_sz);
    int rc = bpf_map_get_next_key(fd, nullptr, key.data());
    while (!rc) {
        rc = bpf_map_get_next_key(fd, key.data(), next_key.data());
        bpf_map_delete_elem(fd, key.data());
        if (!rc)
            key.swap(next_key);
    }
    return 0;
}

static DenyEntries read_deny_db()
{
    DenyEntries entries;
    std::ifstream in(kDenyDbPath);
    if (!in.is_open())
        return entries;
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        uint32_t dev = 0;
        uint64_t ino = 0;
        std::string path;
        if (!(iss >> dev >> ino))
            continue;
        if (!(iss >> path))
            path.clear();
        InodeId id {};
        id.ino = ino;
        id.dev = dev;
        entries[id] = path;
    }
    return entries;
}

static int write_deny_db(const DenyEntries &entries)
{
    if (ensure_db_dir())
        return -1;
    std::ofstream out(kDenyDbPath, std::ios::trunc);
    if (!out.is_open())
        return -1;
    for (const auto &kv : entries) {
        out << kv.first.dev << " " << kv.first.ino;
        if (!kv.second.empty())
            out << " " << kv.second;
        out << "\n";
    }
    return 0;
}

static int record_applied_policy(const std::string &path, const std::string &hash)
{
    if (ensure_db_dir())
        return -1;

    std::error_code ec;
    if (std::filesystem::exists(kPolicyAppliedPath, ec)) {
        std::filesystem::copy_file(kPolicyAppliedPath, kPolicyAppliedPrevPath,
                                   std::filesystem::copy_options::overwrite_existing, ec);
        if (ec)
            return -1;
    }

    std::ifstream in(path);
    if (!in.is_open())
        return -1;
    std::ofstream out(kPolicyAppliedPath, std::ios::trunc);
    if (!out.is_open())
        return -1;
    out << in.rdbuf();
    if (!out.good())
        return -1;

    if (!hash.empty()) {
        std::ofstream hout(kPolicyAppliedHashPath, std::ios::trunc);
        if (!hout.is_open())
            return -1;
        hout << hash << "\n";
    } else {
        std::error_code rm_ec;
        std::filesystem::remove(kPolicyAppliedHashPath, rm_ec);
        if (rm_ec)
            return -1;
    }
    return 0;
}

static bool read_sha256_file(const std::string &path, std::string &hash)
{
    std::ifstream in(path);
    if (!in.is_open())
        return false;
    std::string line;
    if (!std::getline(in, line))
        return false;
    return parse_sha256_token(line, hash);
}

static bool verify_policy_hash(const std::string &path, const std::string &expected, std::string &computed)
{
    if (!sha256_file_hex(path, computed))
        return false;
    return computed == expected;
}

static int reuse_pinned_map(bpf_map *map, const char *path, bool &reused)
{
    int fd = bpf_obj_get(path);
    if (fd < 0)
        return 0;
    int err = bpf_map__reuse_fd(map, fd);
    if (err) {
        close(fd);
        return err;
    }
    reused = true;
    return 0;
}

static int pin_map(bpf_map *map, const char *path)
{
    return bpf_map__pin(map, path);
}

static void cleanup_bpf(BpfState &state)
{
    for (auto *link : state.links)
        bpf_link__destroy(link);
    if (state.obj)
        bpf_object__close(state.obj);
    state.obj = nullptr;
}

static int attach_prog(bpf_program *prog, BpfState &state)
{
    bpf_link *link = bpf_program__attach(prog);
    int err = libbpf_get_error(link);
    if (err)
        return err;
    state.links.push_back(link);
    return 0;
}

static int load_bpf(bool reuse_pins, bool attach_links, BpfState &state)
{
    std::string obj_path = resolve_bpf_obj_path();
    state.obj = bpf_object__open_file(obj_path.c_str(), nullptr);
    if (!state.obj)
        return -errno;

    state.events = bpf_object__find_map_by_name(state.obj, "events");
    state.deny_inode = bpf_object__find_map_by_name(state.obj, "deny_inode_map");
    state.deny_path = bpf_object__find_map_by_name(state.obj, "deny_path_map");
    state.allow_cgroup = bpf_object__find_map_by_name(state.obj, "allow_cgroup_map");
    state.block_stats = bpf_object__find_map_by_name(state.obj, "block_stats");
    state.deny_cgroup_stats = bpf_object__find_map_by_name(state.obj, "deny_cgroup_stats");
    state.deny_inode_stats = bpf_object__find_map_by_name(state.obj, "deny_inode_stats");
    state.deny_path_stats = bpf_object__find_map_by_name(state.obj, "deny_path_stats");
    state.agent_meta = bpf_object__find_map_by_name(state.obj, "agent_meta_map");
    state.config_map = bpf_object__find_map_by_name(state.obj, "agent_config_map");
    if (!state.events || !state.deny_inode || !state.deny_path || !state.allow_cgroup || !state.block_stats ||
        !state.deny_cgroup_stats || !state.deny_inode_stats || !state.deny_path_stats || !state.agent_meta ||
        !state.config_map) {
        cleanup_bpf(state);
        return -ENOENT;
    }

    if (reuse_pins) {
        int err = reuse_pinned_map(state.deny_inode, kDenyInodePin, state.inode_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
        err = reuse_pinned_map(state.deny_path, kDenyPathPin, state.deny_path_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
        err = reuse_pinned_map(state.allow_cgroup, kAllowCgroupPin, state.cgroup_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
        err = reuse_pinned_map(state.block_stats, kBlockStatsPin, state.block_stats_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
        err = reuse_pinned_map(state.deny_cgroup_stats, kDenyCgroupStatsPin, state.deny_cgroup_stats_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
        err = reuse_pinned_map(state.deny_inode_stats, kDenyInodeStatsPin, state.deny_inode_stats_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
        err = reuse_pinned_map(state.deny_path_stats, kDenyPathStatsPin, state.deny_path_stats_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
        err = reuse_pinned_map(state.agent_meta, kAgentMetaPin, state.agent_meta_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
    }

    if (!kernel_bpf_lsm_enabled()) {
        bpf_program *lsm_prog = bpf_object__find_program_by_name(state.obj, "handle_file_open");
        if (lsm_prog)
            bpf_program__set_autoload(lsm_prog, false);
    }

    int err = bpf_object__load(state.obj);
    if (err) {
        cleanup_bpf(state);
        return err;
    }

    if (!state.inode_reused || !state.deny_path_reused || !state.cgroup_reused || !state.block_stats_reused ||
        !state.deny_cgroup_stats_reused || !state.deny_inode_stats_reused || !state.deny_path_stats_reused ||
        !state.agent_meta_reused) {
        if (ensure_pin_dir()) {
            cleanup_bpf(state);
            return -errno;
        }
        if (!state.inode_reused) {
            err = pin_map(state.deny_inode, kDenyInodePin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
        if (!state.deny_path_reused) {
            err = pin_map(state.deny_path, kDenyPathPin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
        if (!state.cgroup_reused) {
            err = pin_map(state.allow_cgroup, kAllowCgroupPin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
        if (!state.block_stats_reused) {
            err = pin_map(state.block_stats, kBlockStatsPin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
        if (!state.deny_cgroup_stats_reused) {
            err = pin_map(state.deny_cgroup_stats, kDenyCgroupStatsPin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
        if (!state.deny_inode_stats_reused) {
            err = pin_map(state.deny_inode_stats, kDenyInodeStatsPin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
        if (!state.deny_path_stats_reused) {
            err = pin_map(state.deny_path_stats, kDenyPathStatsPin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
        if (!state.agent_meta_reused) {
            err = pin_map(state.agent_meta, kAgentMetaPin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
    }

    if (attach_links) {
        // Legacy path: attach immediately.
        // Prefer using attach_all after any required map seeding.
        bpf_program *prog = bpf_object__find_program_by_name(state.obj, "handle_execve");
        if (!prog) {
            cleanup_bpf(state);
            return -ENOENT;
        }
        err = attach_prog(prog, state);
        if (err) {
            cleanup_bpf(state);
            return err;
        }

        prog = bpf_object__find_program_by_name(state.obj, "handle_file_open");
        if (!prog) {
            cleanup_bpf(state);
            return -ENOENT;
        }
        err = attach_prog(prog, state);
        if (err) {
            cleanup_bpf(state);
            return err;
        }

        prog = bpf_object__find_program_by_name(state.obj, "handle_fork");
        if (!prog) {
            cleanup_bpf(state);
            return -ENOENT;
        }
        err = attach_prog(prog, state);
        if (err) {
            cleanup_bpf(state);
            return err;
        }

        prog = bpf_object__find_program_by_name(state.obj, "handle_exit");
        if (!prog) {
            cleanup_bpf(state);
            return -ENOENT;
        }
        err = attach_prog(prog, state);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
    }

    return 0;
}

static int attach_all(BpfState &state, bool lsm_enabled)
{
    int err;
    bpf_program *prog = bpf_object__find_program_by_name(state.obj, "handle_execve");
    if (!prog)
        return -ENOENT;
    err = attach_prog(prog, state);
    if (err)
        return err;

    if (lsm_enabled) {
        prog = bpf_object__find_program_by_name(state.obj, "handle_file_open");
    } else {
        prog = bpf_object__find_program_by_name(state.obj, "handle_openat");
    }
    if (!prog)
        return -ENOENT;
    err = attach_prog(prog, state);
    if (err)
        return err;

    prog = bpf_object__find_program_by_name(state.obj, "handle_fork");
    if (!prog)
        return -ENOENT;
    err = attach_prog(prog, state);
    if (err)
        return err;

    prog = bpf_object__find_program_by_name(state.obj, "handle_exit");
    if (!prog)
        return -ENOENT;
    err = attach_prog(prog, state);
    if (err)
        return err;

    return 0;
}

static std::string to_string(const char *buf, size_t sz)
{
    return std::string(buf, strnlen(buf, sz));
}

static std::string json_escape(const std::string &in)
{
    std::string out;
    out.reserve(in.size() + 4);
    for (char c : in) {
        switch (c) {
        case '\\':
            out += "\\\\";
            break;
        case '"':
            out += "\\\"";
            break;
        default:
            out += c;
            break;
        }
    }
    return out;
}

static std::string build_exec_id(uint32_t pid, uint64_t start_time)
{
    if (pid == 0 || start_time == 0)
        return {};
    return std::to_string(start_time) + "-" + std::to_string(pid);
}

static std::string prometheus_escape_label(const std::string &in)
{
    std::string out;
    out.reserve(in.size() + 4);
    for (char c : in) {
        switch (c) {
        case '\\':
            out += "\\\\";
            break;
        case '"':
            out += "\\\"";
            break;
        case '\n':
            out += "\\n";
            break;
        default:
            out += c;
            break;
        }
    }
    return out;
}

static bool sink_wants_stdout(EventLogSink sink)
{
    return sink == EventLogSink::Stdout || sink == EventLogSink::StdoutAndJournald;
}

static bool sink_wants_journald(EventLogSink sink)
{
    return sink == EventLogSink::Journald || sink == EventLogSink::StdoutAndJournald;
}

static bool set_event_log_sink(const std::string &value)
{
    if (value == "stdout") {
        g_event_sink = EventLogSink::Stdout;
        return true;
    }
#ifdef HAVE_SYSTEMD
    if (value == "journal" || value == "journald") {
        g_event_sink = EventLogSink::Journald;
        return true;
    }
    if (value == "both") {
        g_event_sink = EventLogSink::StdoutAndJournald;
        return true;
    }
#else
    if (value == "journal" || value == "journald" || value == "both") {
        std::cerr << "Journald logging requested but libsystemd support is unavailable at build time."
                  << std::endl;
        return false;
    }
#endif
    return false;
}

#ifdef HAVE_SYSTEMD
static void journal_report_error(int rc)
{
    static bool reported = false;
    if (rc >= 0 || reported)
        return;
    reported = true;
    std::cerr << "journald logging failed: " << std::strerror(-rc) << std::endl;
}

static void journal_send_exec(const exec_event &ev, const std::string &payload, const std::string &cgpath,
                              const std::string &comm, const std::string &exec_id)
{
    int rc = sd_journal_send("MESSAGE=%s", payload.c_str(), "SYSLOG_IDENTIFIER=aegisbpf", "AEGIS_TYPE=exec",
                             "AEGIS_PID=%u", ev.pid, "AEGIS_PPID=%u", ev.ppid, "AEGIS_START_TIME=%llu",
                             static_cast<unsigned long long>(ev.start_time), "AEGIS_EXEC_ID=%s", exec_id.c_str(),
                             "AEGIS_CGID=%llu",
                             static_cast<unsigned long long>(ev.cgid), "AEGIS_CGROUP_PATH=%s", cgpath.c_str(),
                             "AEGIS_COMM=%s", comm.c_str(), "PRIORITY=%i", LOG_INFO,
                             static_cast<const char *>(nullptr));
    journal_report_error(rc);
}

static void journal_send_block(const block_event &ev, const std::string &payload, const std::string &cgpath,
                               const std::string &path, const std::string &resolved_path, const std::string &action,
                               const std::string &comm, const std::string &exec_id,
                               const std::string &parent_exec_id)
{
    int priority = (action == "AUDIT") ? LOG_INFO : LOG_WARNING;
    int rc =
        sd_journal_send("MESSAGE=%s", payload.c_str(), "SYSLOG_IDENTIFIER=aegisbpf", "AEGIS_TYPE=block",
                        "AEGIS_PID=%u", ev.pid, "AEGIS_PPID=%u", ev.ppid, "AEGIS_START_TIME=%llu",
                        static_cast<unsigned long long>(ev.start_time), "AEGIS_EXEC_ID=%s", exec_id.c_str(),
                        "AEGIS_PARENT_START_TIME=%llu", static_cast<unsigned long long>(ev.parent_start_time),
                        "AEGIS_PARENT_EXEC_ID=%s", parent_exec_id.c_str(), "AEGIS_CGID=%llu",
                        static_cast<unsigned long long>(ev.cgid), "AEGIS_CGROUP_PATH=%s", cgpath.c_str(),
                        "AEGIS_INO=%llu", static_cast<unsigned long long>(ev.ino), "AEGIS_DEV=%u", ev.dev,
                        "AEGIS_PATH=%s", path.c_str(), "AEGIS_RESOLVED_PATH=%s", resolved_path.c_str(),
                        "AEGIS_ACTION=%s", action.c_str(), "AEGIS_COMM=%s", comm.c_str(), "PRIORITY=%i", priority,
                        static_cast<const char *>(nullptr));
    journal_report_error(rc);
}
#endif

static void print_exec_event(const exec_event &ev)
{
    std::ostringstream oss;
    std::string cgpath = resolve_cgroup_path(ev.cgid);
    std::string comm = to_string(ev.comm, sizeof(ev.comm));
    std::string exec_id = build_exec_id(ev.pid, ev.start_time);
    oss << "{\"type\":\"exec\",\"pid\":" << ev.pid << ",\"ppid\":" << ev.ppid
        << ",\"start_time\":" << ev.start_time;
    if (!exec_id.empty())
        oss << ",\"exec_id\":\"" << json_escape(exec_id) << "\"";
    oss << ",\"cgid\":" << ev.cgid
        << ",\"cgroup_path\":\"" << json_escape(cgpath) << "\""
        << ",\"comm\":\"" << json_escape(comm) << "\"}";
    std::string payload = oss.str();
    if (sink_wants_stdout(g_event_sink))
        std::cout << payload << std::endl;
#ifdef HAVE_SYSTEMD
    if (sink_wants_journald(g_event_sink))
        journal_send_exec(ev, payload, cgpath, comm, exec_id);
#endif
}

static void print_block_event(const block_event &ev)
{
    std::ostringstream oss;
    std::string cgpath = resolve_cgroup_path(ev.cgid);
    std::string path = to_string(ev.path, sizeof(ev.path));
    std::string resolved_path = resolve_relative_path(ev.pid, ev.start_time, path);
    std::string action = to_string(ev.action, sizeof(ev.action));
    std::string comm = to_string(ev.comm, sizeof(ev.comm));
    std::string exec_id = build_exec_id(ev.pid, ev.start_time);
    std::string parent_exec_id = build_exec_id(ev.ppid, ev.parent_start_time);
    oss << "{\"type\":\"block\",\"pid\":" << ev.pid << ",\"ppid\":" << ev.ppid
        << ",\"start_time\":" << ev.start_time;
    if (!exec_id.empty())
        oss << ",\"exec_id\":\"" << json_escape(exec_id) << "\"";
    oss << ",\"parent_start_time\":" << ev.parent_start_time;
    if (!parent_exec_id.empty())
        oss << ",\"parent_exec_id\":\"" << json_escape(parent_exec_id) << "\"";
    oss << ",\"cgid\":" << ev.cgid << ",\"cgroup_path\":\"" << json_escape(cgpath) << "\"";
    if (!path.empty())
        oss << ",\"path\":\"" << json_escape(path) << "\"";
    if (!resolved_path.empty() && resolved_path != path)
        oss << ",\"resolved_path\":\"" << json_escape(resolved_path) << "\"";
    oss << ",\"ino\":" << ev.ino << ",\"dev\":" << ev.dev << ",\"action\":\"" << json_escape(action)
        << "\",\"comm\":\"" << json_escape(comm) << "\"}";
    std::string payload = oss.str();
    if (sink_wants_stdout(g_event_sink))
        std::cout << payload << std::endl;
#ifdef HAVE_SYSTEMD
    if (sink_wants_journald(g_event_sink))
        journal_send_block(ev, payload, cgpath, path, resolved_path, action, comm, exec_id, parent_exec_id);
#endif
}

static int handle_event(void *, void *data, size_t)
{
    const auto *e = static_cast<const event *>(data);
    if (e->type == EVENT_EXEC) {
        print_exec_event(e->exec);
    } else if (e->type == EVENT_BLOCK) {
        print_block_event(e->block);
    }
    return 0;
}

static int set_agent_config(BpfState &state, bool audit_only)
{
    if (!state.config_map)
        return -ENOENT;

    uint32_t key = 0;
    AgentConfig cfg {};
    cfg.audit_only = audit_only ? 1 : 0;
    if (bpf_map_update_elem(bpf_map__fd(state.config_map), &key, &cfg, BPF_ANY)) {
        std::cerr << "Failed to configure BPF audit mode: " << std::strerror(errno) << std::endl;
        return -errno;
    }
    return 0;
}

static int ensure_layout_version(BpfState &state)
{
    if (!state.agent_meta)
        return -ENOENT;

    uint32_t key = 0;
    AgentMeta meta {};
    int fd = bpf_map__fd(state.agent_meta);
    if (bpf_map_lookup_elem(fd, &key, &meta) && errno != ENOENT) {
        std::cerr << "Failed to read agent_meta_map: " << std::strerror(errno) << std::endl;
        return -errno;
    }
    if (meta.layout_version == 0) {
        meta.layout_version = kLayoutVersion;
        if (bpf_map_update_elem(fd, &key, &meta, BPF_ANY)) {
            std::cerr << "Failed to set agent layout version: " << std::strerror(errno) << std::endl;
            return -errno;
        }
        return 0;
    }
    if (meta.layout_version != kLayoutVersion) {
        std::cerr << "Pinned maps layout version mismatch (found " << meta.layout_version
                  << ", expected " << kLayoutVersion << "). Run 'sudo ./build/aegisbpf block clear' to reset pins."
                  << std::endl;
        return -EINVAL;
    }
    return 0;
}

static bool check_prereqs(bool &lsm_enabled)
{
    if (!std::filesystem::exists("/sys/fs/cgroup/cgroup.controllers")) {
        std::cerr << "cgroup v2 is required at /sys/fs/cgroup" << std::endl;
        return false;
    }
    if (!std::filesystem::exists("/sys/fs/bpf")) {
        std::cerr << "bpffs is not mounted at /sys/fs/bpf" << std::endl;
        return false;
    }
    lsm_enabled = kernel_bpf_lsm_enabled();
    return true;
}

static int run(bool audit_only)
{
    bool lsm_enabled = false;
    if (!check_prereqs(lsm_enabled))
        return 1;

    if (!lsm_enabled) {
        if (!audit_only) {
            std::cerr << "BPF LSM not enabled; falling back to tracepoint audit-only mode" << std::endl;
            audit_only = true;
        } else {
            std::cerr << "BPF LSM not enabled; running in tracepoint audit-only mode" << std::endl;
        }
    }

    if (bump_memlock_rlimit()) {
        std::cerr << "Failed to raise memlock rlimit: " << std::strerror(errno) << std::endl;
        return 1;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    BpfState state;
    int err = load_bpf(true, false, state);
    if (err) {
        std::cerr << "Failed to load BPF object: " << std::strerror(-err) << std::endl;
        return 1;
    }

    err = ensure_layout_version(state);
    if (err) {
        cleanup_bpf(state);
        return 1;
    }

    err = set_agent_config(state, audit_only);
    if (err) {
        cleanup_bpf(state);
        return 1;
    }

    if (setup_agent_cgroup(state)) {
        cleanup_bpf(state);
        return 1;
    }

    err = attach_all(state, lsm_enabled);
    if (err) {
        std::cerr << "Failed to attach programs: " << std::strerror(-err) << std::endl;
        cleanup_bpf(state);
        return 1;
    }

    ring_buffer *rb = ring_buffer__new(bpf_map__fd(state.events), handle_event, nullptr, nullptr);
    if (!rb) {
        std::cerr << "Failed to create ring buffer" << std::endl;
        cleanup_bpf(state);
        return 1;
    }

    while (!exiting) {
        err = ring_buffer__poll(rb, 250);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            std::cerr << "Ring buffer poll failed: " << std::strerror(-err) << std::endl;
            break;
        }
    }

    ring_buffer__free(rb);
    cleanup_bpf(state);
    return err < 0 ? 1 : 0;
}

static int add_deny_inode(BpfState &state, const InodeId &id, DenyEntries &entries)
{
    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.deny_inode), &id, &one, BPF_ANY)) {
        std::cerr << "Failed to update deny_inode_map: " << std::strerror(errno) << std::endl;
        return 1;
    }
    if (entries.find(id) == entries.end())
        entries[id] = "";
    return 0;
}

static int add_deny_path(BpfState &state, const std::string &path, DenyEntries &entries)
{
    if (path.empty()) {
        std::cerr << "Path is empty" << std::endl;
        return 1;
    }

    std::error_code ec;
    std::filesystem::path resolved = std::filesystem::canonical(path, ec);
    if (ec) {
        std::cerr << "Failed to resolve path '" << path << "': " << ec.message() << std::endl;
        return 1;
    }

    struct stat st {};
    if (stat(resolved.c_str(), &st) != 0) {
        std::cerr << "stat failed for " << resolved << ": " << std::strerror(errno) << std::endl;
        return 1;
    }

    InodeId id {};
    id.ino = st.st_ino;
    id.dev = static_cast<uint32_t>(st.st_dev);

    if (add_deny_inode(state, id, entries))
        return 1;

    uint8_t one = 1;
    std::string resolved_str = resolved.string();
    PathKey path_key {};
    fill_path_key(resolved_str, path_key);
    if (bpf_map_update_elem(bpf_map__fd(state.deny_path), &path_key, &one, BPF_ANY)) {
        std::cerr << "Failed to update deny_path_map: " << std::strerror(errno) << std::endl;
        return 1;
    }
    if (path != resolved_str) {
        PathKey raw_key {};
        fill_path_key(path, raw_key);
        if (bpf_map_update_elem(bpf_map__fd(state.deny_path), &raw_key, &one, BPF_ANY)) {
            std::cerr << "Failed to update deny_path_map (raw): " << std::strerror(errno) << std::endl;
            return 1;
        }
    }

    entries[id] = resolved_str;
    return 0;
}

static int add_allow_cgroup(BpfState &state, uint64_t cgid)
{
    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.allow_cgroup), &cgid, &one, BPF_ANY)) {
        std::cerr << "Failed to update allow_cgroup_map: " << std::strerror(errno) << std::endl;
        return 1;
    }
    return 0;
}

static int add_allow_cgroup_path(BpfState &state, const std::string &path)
{
    uint64_t cgid = 0;
    if (!path_to_cgid(path, cgid))
        return 1;
    return add_allow_cgroup(state, cgid);
}

// Populate the inode deny map using a real path (symlinks resolved).
static int block_file(const std::string &path)
{
    if (bump_memlock_rlimit()) {
        std::cerr << "Failed to raise memlock rlimit: " << std::strerror(errno) << std::endl;
        return 1;
    }

    BpfState state;
    int err = load_bpf(true, false, state);
    if (err) {
        std::cerr << "Failed to load BPF object: " << std::strerror(-err) << std::endl;
        return 1;
    }

    auto entries = read_deny_db();
    if (add_deny_path(state, path, entries)) {
        cleanup_bpf(state);
        return 1;
    }
    write_deny_db(entries);

    cleanup_bpf(state);
    return 0;
}

static int read_block_stats_map(bpf_map *map, BlockStats &out)
{
    int fd = bpf_map__fd(map);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        std::cerr << "libbpf_num_possible_cpus failed" << std::endl;
        return 1;
    }
    std::vector<BlockStats> vals(cpu_cnt);
    uint32_t key = 0;
    if (bpf_map_lookup_elem(fd, &key, vals.data())) {
        std::cerr << "Failed to read block_stats: " << std::strerror(errno) << std::endl;
        return 1;
    }
    out = {};
    for (const auto &v : vals) {
        out.blocks += v.blocks;
        out.ringbuf_drops += v.ringbuf_drops;
    }
    return 0;
}

static int read_cgroup_block_counts(bpf_map *map, std::vector<std::pair<uint64_t, uint64_t>> &out)
{
    int fd = bpf_map__fd(map);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        std::cerr << "libbpf_num_possible_cpus failed" << std::endl;
        return 1;
    }
    std::vector<uint64_t> vals(cpu_cnt);
    uint64_t key = 0;
    uint64_t next_key = 0;
    int rc = bpf_map_get_next_key(fd, nullptr, &key);
    while (!rc) {
        if (bpf_map_lookup_elem(fd, &key, vals.data())) {
            std::cerr << "Failed to read deny_cgroup_stats: " << std::strerror(errno) << std::endl;
            return 1;
        }
        uint64_t sum = 0;
        for (uint64_t v : vals)
            sum += v;
        out.emplace_back(key, sum);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return 0;
}

static int read_inode_block_counts(bpf_map *map, std::vector<std::pair<InodeId, uint64_t>> &out)
{
    int fd = bpf_map__fd(map);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        std::cerr << "libbpf_num_possible_cpus failed" << std::endl;
        return 1;
    }
    std::vector<uint64_t> vals(cpu_cnt);
    InodeId key {};
    InodeId next_key {};
    int rc = bpf_map_get_next_key(fd, nullptr, &key);
    while (!rc) {
        if (bpf_map_lookup_elem(fd, &key, vals.data())) {
            std::cerr << "Failed to read deny_inode_stats: " << std::strerror(errno) << std::endl;
            return 1;
        }
        uint64_t sum = 0;
        for (uint64_t v : vals)
            sum += v;
        out.emplace_back(key, sum);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return 0;
}

static int read_path_block_counts(bpf_map *map, std::vector<std::pair<std::string, uint64_t>> &out)
{
    int fd = bpf_map__fd(map);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        std::cerr << "libbpf_num_possible_cpus failed" << std::endl;
        return 1;
    }
    std::vector<uint64_t> vals(cpu_cnt);
    PathKey key {};
    PathKey next_key {};
    int rc = bpf_map_get_next_key(fd, nullptr, &key);
    while (!rc) {
        if (bpf_map_lookup_elem(fd, &key, vals.data())) {
            std::cerr << "Failed to read deny_path_stats: " << std::strerror(errno) << std::endl;
            return 1;
        }
        uint64_t sum = 0;
        for (uint64_t v : vals)
            sum += v;
        std::string path = to_string(key.path, sizeof(key.path));
        out.emplace_back(path, sum);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return 0;
}

static int read_allow_cgroup_ids(bpf_map *map, std::vector<uint64_t> &out)
{
    int fd = bpf_map__fd(map);
    uint64_t key = 0;
    uint64_t next_key = 0;
    int rc = bpf_map_get_next_key(fd, nullptr, &key);
    while (!rc) {
        out.push_back(key);
        rc = bpf_map_get_next_key(fd, &key, &next_key);
        key = next_key;
    }
    return 0;
}

static int reset_block_stats_map(bpf_map *map)
{
    int fd = bpf_map__fd(map);
    int cpu_cnt = libbpf_num_possible_cpus();
    if (cpu_cnt <= 0) {
        std::cerr << "libbpf_num_possible_cpus failed" << std::endl;
        return 1;
    }
    std::vector<BlockStats> zeros(cpu_cnt);
    uint32_t key = 0;
    if (bpf_map_update_elem(fd, &key, zeros.data(), BPF_ANY)) {
        std::cerr << "Failed to reset block_stats: " << std::strerror(errno) << std::endl;
        return 1;
    }
    return 0;
}

static int block_add(const std::string &path)
{
    return block_file(path);
}

// Place current process into a dedicated cgroup v2 and allow that cgroup in the BPF map.
static int setup_agent_cgroup(BpfState &state)
{
    static constexpr const char *kAgentCgroup = "/sys/fs/cgroup/aegis_agent";

    std::error_code ec;
    std::filesystem::create_directories(kAgentCgroup, ec);
    if (ec) {
        std::cerr << "Failed to create cgroup " << kAgentCgroup << ": " << ec.message() << std::endl;
        return 1;
    }

    std::ofstream procs(std::string(kAgentCgroup) + "/cgroup.procs", std::ios::out | std::ios::trunc);
    if (!procs.is_open()) {
        std::cerr << "Failed to open cgroup.procs for " << kAgentCgroup << std::endl;
        return 1;
    }
    procs << getpid();
    procs.close();

    struct stat st {};
    if (stat(kAgentCgroup, &st) != 0) {
        std::cerr << "stat failed for " << kAgentCgroup << ": " << std::strerror(errno) << std::endl;
        return 1;
    }

    uint64_t cgid = static_cast<uint64_t>(st.st_ino);

    if (bump_memlock_rlimit()) {
        std::cerr << "Failed to raise memlock rlimit: " << std::strerror(errno) << std::endl;
        return 1;
    }

    uint8_t one = 1;
    if (bpf_map_update_elem(bpf_map__fd(state.allow_cgroup), &cgid, &one, BPF_ANY)) {
        std::cerr << "Failed to update allow_cgroup_map: " << std::strerror(errno) << std::endl;
        return 1;
    }

    return 0;
}

static int block_del(const std::string &path)
{
    InodeId id {};
    if (!path_to_inode(path, id))
        return 1;

    int map_fd = bpf_obj_get(kDenyInodePin);
    if (map_fd < 0) {
        std::cerr << "deny_inode_map not found" << std::endl;
        return 1;
    }
    bpf_map_delete_elem(map_fd, &id);
    close(map_fd);

    std::error_code ec;
    std::filesystem::path resolved = std::filesystem::canonical(path, ec);
    std::string resolved_path = ec ? path : resolved.string();
    PathKey path_key {};
    fill_path_key(resolved_path, path_key);
    int path_fd = bpf_obj_get(kDenyPathPin);
    if (path_fd >= 0) {
        bpf_map_delete_elem(path_fd, &path_key);
        if (resolved_path != path) {
            PathKey raw_key {};
            fill_path_key(path, raw_key);
            bpf_map_delete_elem(path_fd, &raw_key);
        }
        close(path_fd);
    } else {
        std::cerr << "deny_path_map not found" << std::endl;
    }

    auto entries = read_deny_db();
    entries.erase(id);
    write_deny_db(entries);
    return 0;
}

static int block_list()
{
    BpfState state;
    int err = load_bpf(true, false, state);
    if (err) {
        std::cerr << "Failed to load BPF object: " << std::strerror(-err) << std::endl;
        return 1;
    }

    auto db = read_deny_db();
    InodeId key {};
    InodeId next_key {};
    int rc = bpf_map_get_next_key(bpf_map__fd(state.deny_inode), nullptr, &key);
    while (!rc) {
        auto it = db.find(key);
        if (it != db.end() && !it->second.empty())
            std::cout << it->second << " (" << inode_to_string(key) << ")" << std::endl;
        else
            std::cout << inode_to_string(key) << std::endl;
        rc = bpf_map_get_next_key(bpf_map__fd(state.deny_inode), &key, &next_key);
        key = next_key;
    }

    cleanup_bpf(state);
    return 0;
}

static int block_clear()
{
    std::remove(kDenyInodePin);
    std::remove(kDenyPathPin);
    std::remove(kAllowCgroupPin);
    std::remove(kDenyCgroupStatsPin);
    std::remove(kDenyInodeStatsPin);
    std::remove(kDenyPathStatsPin);
    std::remove(kAgentMetaPin);
    std::filesystem::remove(kDenyDbPath);
    std::filesystem::remove(kPolicyAppliedPath);
    std::filesystem::remove(kPolicyAppliedPrevPath);
    std::filesystem::remove(kPolicyAppliedHashPath);

    if (bump_memlock_rlimit()) {
        std::cerr << "Failed to raise memlock rlimit: " << std::strerror(errno) << std::endl;
        return 1;
    }

    BpfState state;
    int err = load_bpf(true, false, state);
    if (err) {
        std::cerr << "Failed to reload BPF object: " << std::strerror(-err) << std::endl;
        return 1;
    }
    if (state.block_stats)
        reset_block_stats_map(state.block_stats);
    cleanup_bpf(state);
    return 0;
}

static int allow_add(const std::string &path)
{
    if (bump_memlock_rlimit()) {
        std::cerr << "Failed to raise memlock rlimit: " << std::strerror(errno) << std::endl;
        return 1;
    }

    BpfState state;
    int err = load_bpf(true, false, state);
    if (err) {
        std::cerr << "Failed to load BPF object: " << std::strerror(-err) << std::endl;
        return 1;
    }

    if (add_allow_cgroup_path(state, path)) {
        cleanup_bpf(state);
        return 1;
    }

    cleanup_bpf(state);
    return 0;
}

static int allow_del(const std::string &path)
{
    uint64_t cgid = 0;
    if (!path_to_cgid(path, cgid))
        return 1;

    int fd = bpf_obj_get(kAllowCgroupPin);
    if (fd < 0) {
        std::cerr << "allow_cgroup_map not found" << std::endl;
        return 1;
    }
    bpf_map_delete_elem(fd, &cgid);
    close(fd);
    return 0;
}

static int allow_list()
{
    BpfState state;
    int err = load_bpf(true, false, state);
    if (err) {
        std::cerr << "Failed to load BPF object: " << std::strerror(-err) << std::endl;
        return 1;
    }

    std::vector<uint64_t> ids;
    read_allow_cgroup_ids(state.allow_cgroup, ids);
    for (uint64_t id : ids)
        std::cout << id << std::endl;

    cleanup_bpf(state);
    return 0;
}

static int health()
{
    bool ok = true;
    std::error_code ec;
    bool cgroup_ok = path_exists("/sys/fs/cgroup/cgroup.controllers", ec);
    bool bpffs_ok = path_exists("/sys/fs/bpf", ec);
    bool btf_ok = path_exists("/sys/kernel/btf/vmlinux", ec);
    std::string obj_path = resolve_bpf_obj_path();
    bool obj_ok = path_exists(obj_path.c_str(), ec);

    if (!cgroup_ok || !bpffs_ok || !btf_ok || !obj_ok)
        ok = false;

    bool is_root = geteuid() == 0;
    std::cout << "euid: " << geteuid() << "\n";
    std::cout << "cgroup_v2: " << (cgroup_ok ? "ok" : "missing") << "\n";
    std::cout << "bpffs: " << (bpffs_ok ? "ok" : "missing") << "\n";
    std::cout << "btf: " << (btf_ok ? "ok" : "missing") << "\n";
    std::cout << "bpf_obj_path: " << obj_path << (obj_ok ? "" : " (missing)") << "\n";

    bool lsm_enabled = kernel_bpf_lsm_enabled();
    std::cout << "bpf_lsm_enabled: " << (lsm_enabled ? "yes" : "no") << "\n";

    std::string lsm_list = read_file_first_line("/sys/kernel/security/lsm");
    if (!lsm_list.empty())
        std::cout << "lsm_list: " << lsm_list << "\n";

    struct KernelConfigCheck {
        const char *key;
        const char *label;
    };
    const KernelConfigCheck config_checks[] = {
        {"CONFIG_BPF", "kernel_config_bpf"},
        {"CONFIG_BPF_SYSCALL", "kernel_config_bpf_syscall"},
        {"CONFIG_BPF_JIT", "kernel_config_bpf_jit"},
        {"CONFIG_BPF_LSM", "kernel_config_bpf_lsm"},
        {"CONFIG_CGROUPS", "kernel_config_cgroups"},
        {"CONFIG_CGROUP_BPF", "kernel_config_cgroup_bpf"},
    };
    for (const auto &check : config_checks) {
        std::string value = kernel_config_value(check.key);
        if (value.empty())
            value = "unknown";
        std::cout << check.label << ": " << value << "\n";
    }

    struct PinInfo {
        const char *name;
        const char *path;
    };
    const PinInfo pins[] = {
        {"deny_inode", kDenyInodePin},
        {"deny_path", kDenyPathPin},
        {"allow_cgroup", kAllowCgroupPin},
        {"block_stats", kBlockStatsPin},
        {"deny_cgroup_stats", kDenyCgroupStatsPin},
        {"deny_inode_stats", kDenyInodeStatsPin},
        {"deny_path_stats", kDenyPathStatsPin},
        {"agent_meta", kAgentMetaPin},
    };
    if (is_root) {
        std::vector<std::string> present;
        std::vector<std::string> missing;
        std::vector<std::string> unreadable;
        for (const auto &pin : pins) {
            bool exists = path_exists(pin.path, ec);
            if (ec) {
                unreadable.emplace_back(pin.name);
            } else if (exists) {
                present.emplace_back(pin.name);
            } else {
                missing.emplace_back(pin.name);
            }
        }
        if (!present.empty())
            std::cout << "pins_present: " << join_list(present) << "\n";
        if (!missing.empty())
            std::cout << "pins_missing: " << join_list(missing) << "\n";
        if (!unreadable.empty())
            std::cout << "pins_unreadable: " << join_list(unreadable) << "\n";

        if (path_exists(kAgentMetaPin, ec)) {
            int fd = bpf_obj_get(kAgentMetaPin);
            if (fd < 0) {
                std::cout << "layout_version: unreadable (" << std::strerror(errno) << ")\n";
            } else {
                uint32_t key = 0;
                AgentMeta meta {};
                if (bpf_map_lookup_elem(fd, &key, &meta) == 0) {
                    if (meta.layout_version == kLayoutVersion) {
                        std::cout << "layout_version: ok (" << meta.layout_version << ")\n";
                    } else {
                        std::cout << "layout_version: mismatch (found " << meta.layout_version << ", expected "
                                  << kLayoutVersion << ")\n";
                    }
                } else {
                    std::cout << "layout_version: unavailable (" << std::strerror(errno) << ")\n";
                }
                close(fd);
            }
        }
    } else {
        std::cout << "pins_present: skipped (requires root)" << "\n";
        std::cout << "layout_version: skipped (requires root)" << "\n";
    }

    return ok ? 0 : 1;
}

static int reset_policy_maps(BpfState &state)
{
    if (clear_map_entries(state.deny_inode)) {
        std::cerr << "Failed to clear deny_inode_map" << std::endl;
        return 1;
    }
    if (clear_map_entries(state.deny_path)) {
        std::cerr << "Failed to clear deny_path_map" << std::endl;
        return 1;
    }
    if (clear_map_entries(state.allow_cgroup)) {
        std::cerr << "Failed to clear allow_cgroup_map" << std::endl;
        return 1;
    }
    if (clear_map_entries(state.deny_cgroup_stats)) {
        std::cerr << "Failed to clear deny_cgroup_stats" << std::endl;
        return 1;
    }
    if (clear_map_entries(state.deny_inode_stats)) {
        std::cerr << "Failed to clear deny_inode_stats" << std::endl;
        return 1;
    }
    if (clear_map_entries(state.deny_path_stats)) {
        std::cerr << "Failed to clear deny_path_stats" << std::endl;
        return 1;
    }
    if (state.block_stats)
        reset_block_stats_map(state.block_stats);

    std::error_code ec;
    std::filesystem::remove(kDenyDbPath, ec);
    return 0;
}

static int policy_lint(const std::string &path)
{
    Policy policy {};
    PolicyIssues issues;
    bool ok = parse_policy_file(path, policy, issues);
    report_policy_issues(issues);
    return ok ? 0 : 1;
}

static int apply_policy_internal(const std::string &path, const std::string &computed_hash, bool reset, bool record)
{
    Policy policy {};
    PolicyIssues issues;
    bool ok = parse_policy_file(path, policy, issues);
    report_policy_issues(issues);
    if (!ok)
        return 1;

    if (bump_memlock_rlimit()) {
        std::cerr << "Failed to raise memlock rlimit: " << std::strerror(errno) << std::endl;
        return 1;
    }

    BpfState state;
    int err = load_bpf(true, false, state);
    if (err) {
        std::cerr << "Failed to load BPF object: " << std::strerror(-err) << std::endl;
        return 1;
    }

    err = ensure_layout_version(state);
    if (err) {
        cleanup_bpf(state);
        return 1;
    }

    if (reset) {
        if (reset_policy_maps(state)) {
            cleanup_bpf(state);
            return 1;
        }
    }

    DenyEntries entries = reset ? DenyEntries {} : read_deny_db();

    for (const auto &deny_path : policy.deny_paths) {
        if (add_deny_path(state, deny_path, entries)) {
            cleanup_bpf(state);
            return 1;
        }
    }
    for (const auto &id : policy.deny_inodes) {
        if (add_deny_inode(state, id, entries)) {
            cleanup_bpf(state);
            return 1;
        }
    }
    for (const auto &cgid : policy.allow_cgroup_ids) {
        if (add_allow_cgroup(state, cgid)) {
            cleanup_bpf(state);
            return 1;
        }
    }
    for (const auto &cgpath : policy.allow_cgroup_paths) {
        if (add_allow_cgroup_path(state, cgpath)) {
            cleanup_bpf(state);
            return 1;
        }
    }

    write_deny_db(entries);
    if (record) {
        if (record_applied_policy(path, computed_hash)) {
            std::cerr << "Failed to record applied policy at " << kPolicyAppliedPath << std::endl;
            cleanup_bpf(state);
            return 1;
        }
    }
    cleanup_bpf(state);
    return 0;
}

static int policy_apply(const std::string &path, bool reset, const std::string &cli_hash,
                        const std::string &cli_hash_file, bool rollback_on_failure)
{
    std::string expected_hash = cli_hash;
    std::string hash_file = cli_hash_file;

    if (expected_hash.empty()) {
        const char *env = std::getenv("AEGIS_POLICY_SHA256");
        if (env && *env)
            expected_hash = env;
    }
    if (hash_file.empty()) {
        const char *env = std::getenv("AEGIS_POLICY_SHA256_FILE");
        if (env && *env)
            hash_file = env;
    }

    if (!expected_hash.empty() && !hash_file.empty()) {
        std::cerr << "Provide either --sha256 or --sha256-file (not both)" << std::endl;
        return 1;
    }

    if (!hash_file.empty()) {
        if (!read_sha256_file(hash_file, expected_hash)) {
            std::cerr << "Failed to read sha256 file " << hash_file << std::endl;
            return 1;
        }
    }

    if (!expected_hash.empty()) {
        if (!parse_sha256_token(expected_hash, expected_hash)) {
            std::cerr << "Invalid sha256 value format" << std::endl;
            return 1;
        }
    }

    std::string computed_hash;
    if (!expected_hash.empty()) {
        if (!verify_policy_hash(path, expected_hash, computed_hash)) {
            std::cerr << "Policy sha256 mismatch" << std::endl;
            return 1;
        }
    } else if (!sha256_file_hex(path, computed_hash)) {
        std::cerr << "Failed to compute policy sha256; continuing without hash" << std::endl;
        computed_hash.clear();
    }

    int rc = apply_policy_internal(path, computed_hash, reset, true);
    if (rc && rollback_on_failure) {
        std::error_code ec;
        if (std::filesystem::exists(kPolicyAppliedPath, ec)) {
            std::cerr << "Apply failed; rolling back to last applied policy" << std::endl;
            int rollback_rc = apply_policy_internal(kPolicyAppliedPath, std::string(), true, false);
            if (rollback_rc)
                std::cerr << "Rollback failed; maps may be inconsistent" << std::endl;
        }
    }
    return rc;
}

static int write_policy_file(const std::string &path, std::vector<std::string> deny_paths,
                             std::vector<std::string> deny_inodes, std::vector<std::string> allow_cgroups)
{
    std::sort(deny_paths.begin(), deny_paths.end());
    deny_paths.erase(std::unique(deny_paths.begin(), deny_paths.end()), deny_paths.end());
    std::sort(deny_inodes.begin(), deny_inodes.end());
    deny_inodes.erase(std::unique(deny_inodes.begin(), deny_inodes.end()), deny_inodes.end());
    std::sort(allow_cgroups.begin(), allow_cgroups.end());
    allow_cgroups.erase(std::unique(allow_cgroups.begin(), allow_cgroups.end()), allow_cgroups.end());

    std::ofstream out(path, std::ios::trunc);
    if (!out.is_open()) {
        std::cerr << "Failed to write policy file '" << path << "'" << std::endl;
        return 1;
    }
    out << "version=1\n";
    if (!deny_paths.empty()) {
        out << "\n[deny_path]\n";
        for (const auto &p : deny_paths)
            out << p << "\n";
    }
    if (!deny_inodes.empty()) {
        out << "\n[deny_inode]\n";
        for (const auto &p : deny_inodes)
            out << p << "\n";
    }
    if (!allow_cgroups.empty()) {
        out << "\n[allow_cgroup]\n";
        for (const auto &p : allow_cgroups)
            out << p << "\n";
    }
    return 0;
}

static int policy_export(const std::string &path)
{
    if (bump_memlock_rlimit()) {
        std::cerr << "Failed to raise memlock rlimit: " << std::strerror(errno) << std::endl;
        return 1;
    }

    BpfState state;
    int err = load_bpf(true, false, state);
    if (err) {
        std::cerr << "Failed to load BPF object: " << std::strerror(-err) << std::endl;
        return 1;
    }

    auto db = read_deny_db();
    std::vector<std::string> deny_paths;
    std::vector<std::string> deny_inodes;
    for (const auto &kv : db) {
        if (!kv.second.empty())
            deny_paths.push_back(kv.second);
        else
            deny_inodes.push_back(inode_to_string(kv.first));
    }

    std::vector<uint64_t> allow_ids;
    read_allow_cgroup_ids(state.allow_cgroup, allow_ids);
    std::vector<std::string> allow_entries;
    for (uint64_t id : allow_ids) {
        std::string path = resolve_cgroup_path(id);
        if (!path.empty())
            allow_entries.push_back(path);
        else
            allow_entries.push_back("cgid:" + std::to_string(id));
    }

    int rc = write_policy_file(path, deny_paths, deny_inodes, allow_entries);
    cleanup_bpf(state);
    return rc;
}

static int policy_show()
{
    std::ifstream in(kPolicyAppliedPath);
    if (!in.is_open()) {
        std::cerr << "No applied policy found at " << kPolicyAppliedPath << std::endl;
        return 1;
    }
    std::string hash = read_file_first_line(kPolicyAppliedHashPath);
    if (!hash.empty())
        std::cout << "# applied_sha256: " << hash << "\n";
    std::cout << in.rdbuf();
    return 0;
}

static int policy_rollback()
{
    if (!std::filesystem::exists(kPolicyAppliedPrevPath)) {
        std::cerr << "No rollback policy found at " << kPolicyAppliedPrevPath << std::endl;
        return 1;
    }
    std::string computed_hash;
    sha256_file_hex(kPolicyAppliedPrevPath, computed_hash);
    return apply_policy_internal(kPolicyAppliedPrevPath, computed_hash, true, true);
}

static int print_metrics(const std::string &out_path)
{
    BpfState state;
    int err = load_bpf(true, false, state);
    if (err) {
        std::cerr << "Failed to load BPF object: " << std::strerror(-err) << std::endl;
        return 1;
    }

    BlockStats stats {};
    if (read_block_stats_map(state.block_stats, stats)) {
        cleanup_bpf(state);
        return 1;
    }

    std::vector<std::pair<uint64_t, uint64_t>> cgroup_blocks;
    if (read_cgroup_block_counts(state.deny_cgroup_stats, cgroup_blocks)) {
        cleanup_bpf(state);
        return 1;
    }

    std::vector<std::pair<InodeId, uint64_t>> inode_blocks;
    if (read_inode_block_counts(state.deny_inode_stats, inode_blocks)) {
        cleanup_bpf(state);
        return 1;
    }

    std::vector<std::pair<std::string, uint64_t>> path_blocks;
    if (read_path_block_counts(state.deny_path_stats, path_blocks)) {
        cleanup_bpf(state);
        return 1;
    }

    size_t deny_sz = map_entry_count(state.deny_inode);
    size_t deny_path_sz = map_entry_count(state.deny_path);
    size_t allow_sz = map_entry_count(state.allow_cgroup);

    std::ostringstream oss;
    oss << "# HELP aegisbpf_blocks_total Total number of block events.\n";
    oss << "# TYPE aegisbpf_blocks_total counter\n";
    oss << "aegisbpf_blocks_total " << stats.blocks << "\n";
    oss << "# HELP aegisbpf_ringbuf_drops_total Total ringbuf drops.\n";
    oss << "# TYPE aegisbpf_ringbuf_drops_total counter\n";
    oss << "aegisbpf_ringbuf_drops_total " << stats.ringbuf_drops << "\n";
    oss << "# HELP aegisbpf_deny_inode_entries Number of deny inode entries.\n";
    oss << "# TYPE aegisbpf_deny_inode_entries gauge\n";
    oss << "aegisbpf_deny_inode_entries " << deny_sz << "\n";
    oss << "# HELP aegisbpf_deny_path_entries Number of deny path entries.\n";
    oss << "# TYPE aegisbpf_deny_path_entries gauge\n";
    oss << "aegisbpf_deny_path_entries " << deny_path_sz << "\n";
    oss << "# HELP aegisbpf_allow_cgroup_entries Number of allow cgroup entries.\n";
    oss << "# TYPE aegisbpf_allow_cgroup_entries gauge\n";
    oss << "aegisbpf_allow_cgroup_entries " << allow_sz << "\n";

    if (!cgroup_blocks.empty()) {
        oss << "# HELP aegisbpf_blocks_by_cgroup_total Block events by cgroup.\n";
        oss << "# TYPE aegisbpf_blocks_by_cgroup_total counter\n";
        for (const auto &kv : cgroup_blocks) {
            std::string path = resolve_cgroup_path(kv.first);
            oss << "aegisbpf_blocks_by_cgroup_total{cgid=\"" << kv.first << "\",cgroup_path=\""
                << prometheus_escape_label(path) << "\"} " << kv.second << "\n";
        }
    }
    if (!inode_blocks.empty()) {
        oss << "# HELP aegisbpf_blocks_by_inode_total Block events by inode.\n";
        oss << "# TYPE aegisbpf_blocks_by_inode_total counter\n";
        for (const auto &kv : inode_blocks) {
            oss << "aegisbpf_blocks_by_inode_total{dev=\"" << kv.first.dev << "\",ino=\"" << kv.first.ino << "\"} "
                << kv.second << "\n";
        }
    }
    if (!path_blocks.empty()) {
        oss << "# HELP aegisbpf_blocks_by_path_total Block events by path.\n";
        oss << "# TYPE aegisbpf_blocks_by_path_total counter\n";
        for (const auto &kv : path_blocks) {
            if (kv.first.empty())
                continue;
            oss << "aegisbpf_blocks_by_path_total{path=\"" << prometheus_escape_label(kv.first) << "\"} "
                << kv.second << "\n";
        }
    }

    if (out_path.empty() || out_path == "-") {
        std::cout << oss.str();
    } else {
        std::ofstream out(out_path, std::ios::trunc);
        if (!out.is_open()) {
            std::cerr << "Failed to write metrics to '" << out_path << "'" << std::endl;
            cleanup_bpf(state);
            return 1;
        }
        out << oss.str();
    }

    cleanup_bpf(state);
    return 0;
}

static int print_stats()
{
    BpfState state;
    int err = load_bpf(true, false, state);
    if (err) {
        std::cerr << "Failed to load BPF object: " << std::strerror(-err) << std::endl;
        return 1;
    }

    BlockStats stats {};
    if (read_block_stats_map(state.block_stats, stats)) {
        cleanup_bpf(state);
        return 1;
    }

    std::vector<std::pair<uint64_t, uint64_t>> cgroup_blocks;
    if (read_cgroup_block_counts(state.deny_cgroup_stats, cgroup_blocks)) {
        cleanup_bpf(state);
        return 1;
    }

    std::vector<std::pair<InodeId, uint64_t>> inode_blocks;
    if (read_inode_block_counts(state.deny_inode_stats, inode_blocks)) {
        cleanup_bpf(state);
        return 1;
    }

    std::vector<std::pair<std::string, uint64_t>> path_blocks;
    if (read_path_block_counts(state.deny_path_stats, path_blocks)) {
        cleanup_bpf(state);
        return 1;
    }

    size_t deny_sz = map_entry_count(state.deny_inode);
    size_t deny_path_sz = map_entry_count(state.deny_path);
    size_t allow_sz = map_entry_count(state.allow_cgroup);

    std::cout << "deny_inode entries: " << deny_sz << "\n"
              << "deny_path entries: " << deny_path_sz << "\n"
              << "allow_cgroup entries: " << allow_sz << "\n"
              << "blocks: " << stats.blocks << "\n"
              << "ringbuf_drops: " << stats.ringbuf_drops << std::endl;

    if (!cgroup_blocks.empty()) {
        std::cout << "blocks_by_cgroup:\n";
        for (const auto &kv : cgroup_blocks) {
            std::string path = resolve_cgroup_path(kv.first);
            if (!path.empty())
                std::cout << "  " << path << " (" << kv.first << "): " << kv.second << "\n";
            else
                std::cout << "  " << kv.first << ": " << kv.second << "\n";
        }
    }
    if (!inode_blocks.empty()) {
        auto db = read_deny_db();
        std::cout << "blocks_by_inode:\n";
        for (const auto &kv : inode_blocks) {
            auto it = db.find(kv.first);
            if (it != db.end() && !it->second.empty())
                std::cout << "  " << it->second << " (" << inode_to_string(kv.first) << "): " << kv.second << "\n";
            else
                std::cout << "  " << inode_to_string(kv.first) << ": " << kv.second << "\n";
        }
    }
    if (!path_blocks.empty()) {
        std::cout << "blocks_by_path:\n";
        for (const auto &kv : path_blocks) {
            if (!kv.first.empty())
                std::cout << "  " << kv.first << ": " << kv.second << "\n";
        }
    }

    cleanup_bpf(state);
    return 0;
}

static int usage(const char *prog)
{
    std::cerr << "Usage: " << prog
              << " run [--audit|--enforce] [--log=stdout|journald|both]"
              << " | block {add|del|list|clear} [path]"
              << " | allow {add|del} <cgroup_path> | allow list"
              << " | policy {lint|apply|export} <file> [--reset] [--sha256 <hex>|--sha256-file <path>] [--no-rollback]"
              << " | policy {show|rollback}"
              << " | stats"
              << " | metrics [--out <path>]"
              << " | health" << std::endl;
    return 1;
}

int main(int argc, char **argv)
{
    if (argc == 1)
        return run(false);

    std::string cmd = argv[1];
    if (cmd == "run") {
        bool audit_only = false;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--audit" || arg == "--mode=audit") {
                audit_only = true;
            } else if (arg == "--enforce" || arg == "--mode=enforce") {
                audit_only = false;
            } else if (arg.rfind("--log=", 0) == 0) {
                std::string value = arg.substr(std::strlen("--log="));
                if (!set_event_log_sink(value))
                    return usage(argv[0]);
            } else if (arg == "--log") {
                if (i + 1 >= argc)
                    return usage(argv[0]);
                std::string value = argv[++i];
                if (!set_event_log_sink(value))
                    return usage(argv[0]);
            } else {
                return usage(argv[0]);
            }
        }
        return run(audit_only);
    }
    if (cmd == "block") {
        if (argc < 3)
            return usage(argv[0]);
        std::string sub = argv[2];
        if (sub == "add") {
            if (argc < 4)
                return usage(argv[0]);
            return block_add(argv[3]);
        } else if (sub == "del") {
            if (argc < 4)
                return usage(argv[0]);
            return block_del(argv[3]);
        } else if (sub == "list") {
            return block_list();
        } else if (sub == "clear") {
            return block_clear();
        } else {
            return usage(argv[0]);
        }
    }
    if (cmd == "allow") {
        if (argc < 3)
            return usage(argv[0]);
        std::string sub = argv[2];
        if (sub == "add") {
            if (argc < 4)
                return usage(argv[0]);
            return allow_add(argv[3]);
        } else if (sub == "del") {
            if (argc < 4)
                return usage(argv[0]);
            return allow_del(argv[3]);
        } else if (sub == "list") {
            if (argc > 3)
                return usage(argv[0]);
            return allow_list();
        } else {
            return usage(argv[0]);
        }
    }
    if (cmd == "policy") {
        std::string sub = argv[2];
        if (sub == "lint") {
            if (argc != 4)
                return usage(argv[0]);
            return policy_lint(argv[3]);
        }
        if (sub == "apply") {
            if (argc < 4)
                return usage(argv[0]);
            bool reset = false;
            bool rollback_on_failure = true;
            std::string sha256;
            std::string sha256_file;
            for (int i = 4; i < argc; ++i) {
                std::string arg = argv[i];
                if (arg == "--reset") {
                    reset = true;
                } else if (arg == "--no-rollback") {
                    rollback_on_failure = false;
                } else if (arg == "--sha256") {
                    if (i + 1 >= argc)
                        return usage(argv[0]);
                    sha256 = argv[++i];
                } else if (arg == "--sha256-file") {
                    if (i + 1 >= argc)
                        return usage(argv[0]);
                    sha256_file = argv[++i];
                } else {
                    return usage(argv[0]);
                }
            }
            return policy_apply(argv[3], reset, sha256, sha256_file, rollback_on_failure);
        }
        if (sub == "export") {
            if (argc != 4)
                return usage(argv[0]);
            return policy_export(argv[3]);
        }
        if (sub == "show") {
            if (argc != 3)
                return usage(argv[0]);
            return policy_show();
        }
        if (sub == "rollback") {
            if (argc != 3)
                return usage(argv[0]);
            return policy_rollback();
        }
        return usage(argv[0]);
    }
    if (cmd == "health") {
        if (argc > 2)
            return usage(argv[0]);
        return health();
    }
    if (cmd == "metrics") {
        std::string out_path;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--out") {
                if (i + 1 >= argc)
                    return usage(argv[0]);
                out_path = argv[++i];
            } else {
                return usage(argv[0]);
            }
        }
        return print_metrics(out_path);
    }
    if (cmd == "stats") {
        if (argc > 2)
            return usage(argv[0]);
        return print_stats();
    }

    return usage(argv[0]);
}
