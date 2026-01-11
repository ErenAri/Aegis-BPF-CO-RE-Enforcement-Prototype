#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <errno.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

static constexpr size_t kPathMax = 256;
static constexpr const char *kPinRoot = "/sys/fs/bpf/aegisbpf";
static constexpr const char *kDenyBloomPin = "/sys/fs/bpf/aegisbpf/deny_bloom";
static constexpr const char *kDenyExactPin = "/sys/fs/bpf/aegisbpf/deny_exact";
static constexpr const char *kConfigPin = "/sys/fs/bpf/aegisbpf/config";
static constexpr const char *kAllowlistPin = "/sys/fs/bpf/aegisbpf/allowlist";
static constexpr const char *kBpfObjPath = AEGIS_BPF_OBJ_PATH;
static constexpr const char *kDenyDbDir = "/var/lib/aegisbpf";
static constexpr const char *kDenyDbPath = "/var/lib/aegisbpf/deny.db";

enum EventType : uint32_t {
    EVENT_EXEC = 1,
    EVENT_BLOCK = 2
};

struct exec_event {
    uint32_t pid;
    uint32_t ppid;
    uint64_t start_time;
    char comm[16];
};

struct block_event {
    uint32_t pid;
    char comm[16];
    char filename[kPathMax];
    char action[8];
};

struct event {
    uint32_t type;
    union {
        exec_event exec;
        block_event block;
    };
};

struct BpfState {
    bpf_object *obj = nullptr;
    bpf_map *events = nullptr;
    bpf_map *deny_bloom = nullptr;
    bpf_map *deny_exact = nullptr;
    bpf_map *config = nullptr;
    bpf_map *allowlist = nullptr;
    std::vector<bpf_link *> links;
    bool bloom_reused = false;
    bool exact_reused = false;
    bool config_reused = false;
    bool allow_reused = false;
};

static volatile sig_atomic_t exiting;

static void handle_signal(int)
{
    exiting = 1;
}

static int bump_memlock_rlimit()
{
    rlimit rlim;
    std::memset(&rlim, 0, sizeof(rlim));
    rlim.rlim_cur = RLIM_INFINITY;
    rlim.rlim_max = RLIM_INFINITY;
    return setrlimit(RLIMIT_MEMLOCK, &rlim);
}

static uint64_t hash_path(const std::string &path)
{
    uint64_t hash = 1469598103934665603ULL;
    size_t max = path.size();
    if (max > kPathMax - 1)
        max = kPathMax - 1;
    for (size_t i = 0; i < max; i++) {
        uint8_t c = static_cast<uint8_t>(path[i]);
        if (!c)
            break;
        hash ^= c;
        hash *= 1099511628211ULL;
    }
    return hash;
}

static std::string hash_to_hex(uint64_t h)
{
    std::ostringstream oss;
    oss << std::hex << std::nouppercase;
    oss.width(16);
    oss.fill('0');
    oss << h;
    return oss.str();
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

static std::unordered_map<uint64_t, std::string> read_deny_db()
{
    std::unordered_map<uint64_t, std::string> entries;
    std::ifstream in(kDenyDbPath);
    if (!in.is_open())
        return entries;
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        std::string hex;
        std::string path;
        if (!(iss >> hex))
            continue;
        if (!(iss >> path))
            path.clear();
        try {
            uint64_t h = std::stoull(hex, nullptr, 16);
            entries[h] = path;
        } catch (...) {
            continue;
        }
    }
    return entries;
}

static int write_deny_db(const std::unordered_map<uint64_t, std::string> &entries)
{
    if (ensure_db_dir())
        return -1;
    std::ofstream out(kDenyDbPath, std::ios::trunc);
    if (!out.is_open())
        return -1;
    for (const auto &kv : entries) {
        out << hash_to_hex(kv.first);
        if (!kv.second.empty())
            out << " " << kv.second;
        out << "\n";
    }
    return 0;
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
    state.obj = bpf_object__open_file(kBpfObjPath, nullptr);
    if (!state.obj)
        return -errno;

    state.events = bpf_object__find_map_by_name(state.obj, "events");
    state.deny_bloom = bpf_object__find_map_by_name(state.obj, "deny_bloom");
    state.deny_exact = bpf_object__find_map_by_name(state.obj, "deny_exact");
    state.config = bpf_object__find_map_by_name(state.obj, "cfg_map");
    state.allowlist = bpf_object__find_map_by_name(state.obj, "allowlist");
    if (!state.events || !state.deny_bloom || !state.deny_exact || !state.config || !state.allowlist) {
        cleanup_bpf(state);
        return -ENOENT;
    }

    if (reuse_pins) {
        int err = reuse_pinned_map(state.deny_bloom, kDenyBloomPin, state.bloom_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
        err = reuse_pinned_map(state.deny_exact, kDenyExactPin, state.exact_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
        err = reuse_pinned_map(state.config, kConfigPin, state.config_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
        err = reuse_pinned_map(state.allowlist, kAllowlistPin, state.allow_reused);
        if (err) {
            cleanup_bpf(state);
            return err;
        }
    }

    int err = bpf_object__load(state.obj);
    if (err) {
        cleanup_bpf(state);
        return err;
    }

    if (!state.bloom_reused || !state.exact_reused || !state.config_reused || !state.allow_reused) {
        if (ensure_pin_dir()) {
            cleanup_bpf(state);
            return -errno;
        }
        if (!state.bloom_reused) {
            err = pin_map(state.deny_bloom, kDenyBloomPin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
        if (!state.exact_reused) {
            err = pin_map(state.deny_exact, kDenyExactPin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
        if (!state.config_reused) {
            err = pin_map(state.config, kConfigPin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
        if (!state.allow_reused) {
            err = pin_map(state.allowlist, kAllowlistPin);
            if (err) {
                cleanup_bpf(state);
                return err;
            }
        }
    }

    if (attach_links) {
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

        prog = bpf_object__find_program_by_name(state.obj, "handle_openat");
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

static int handle_event(void *, void *data, size_t)
{
    const auto *e = static_cast<const event *>(data);
    if (e->type == EVENT_EXEC) {
        std::cout << "[EXEC] pid=" << e->exec.pid << " ppid=" << e->exec.ppid
                  << " comm=" << e->exec.comm << std::endl;
    } else if (e->type == EVENT_BLOCK) {
        std::cout << "[BLOCK] pid=" << e->block.pid << " comm=" << e->block.comm
                  << " file=" << e->block.filename << " action=" << e->block.action << std::endl;
    }
    return 0;
}

static int run(bool enforce_mode)
{
    if (bump_memlock_rlimit()) {
        std::cerr << "Failed to raise memlock rlimit: " << std::strerror(errno) << std::endl;
        return 1;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    BpfState state;
    int err = load_bpf(true, true, state);
    if (err) {
        std::cerr << "Failed to load BPF object: " << std::strerror(-err) << std::endl;
        return 1;
    }

    uint32_t key = 0;
    uint8_t enforce = enforce_mode ? 1 : 0;
    if (bpf_map_update_elem(bpf_map__fd(state.config), &key, &enforce, BPF_ANY)) {
        std::cerr << "Failed to set config: " << std::strerror(errno) << std::endl;
        cleanup_bpf(state);
        return 1;
    }

    auto ensure_allow = [&](const std::string &c) -> int {
        char keybuf[16] = {};
        size_t len = c.size();
        if (len >= sizeof(keybuf))
            len = sizeof(keybuf) - 1;
        std::memcpy(keybuf, c.data(), len);
        uint8_t one = 1;
        if (bpf_map_update_elem(bpf_map__fd(state.allowlist), keybuf, &one, BPF_ANY))
            return -errno;
        return 0;
    };

    if (ensure_allow("sudo")) {
        std::cerr << "Failed to seed allowlist" << std::endl;
        cleanup_bpf(state);
        return 1;
    }
    if (ensure_allow("aegisbpf")) {
        std::cerr << "Failed to seed allowlist" << std::endl;
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

static int deny_path(const std::string &path)
{
    return 0;
}

static int allow_add(const std::string &comm)
{
    if (comm.empty() || comm.size() >= 16) {
        std::cerr << "comm too long" << std::endl;
        return 1;
    }

    int fd = bpf_obj_get(kAllowlistPin);
    BpfState state;
    if (fd < 0) {
        int err = load_bpf(true, false, state);
        if (err) {
            std::cerr << "Failed to load BPF object: " << std::strerror(-err) << std::endl;
            return 1;
        }
        fd = bpf_map__fd(state.allowlist);
        char keybuf[16] = {};
        std::memcpy(keybuf, comm.data(), comm.size());
        uint8_t one = 1;
        int rc = bpf_map_update_elem(fd, keybuf, &one, BPF_ANY);
        cleanup_bpf(state);
        if (rc) {
            std::cerr << "Failed to add allow: " << std::strerror(errno) << std::endl;
            return 1;
        }
        return 0;
    }

    char keybuf[16] = {};
    std::memcpy(keybuf, comm.data(), comm.size());
    uint8_t one = 1;
    if (bpf_map_update_elem(fd, keybuf, &one, BPF_ANY)) {
        std::cerr << "Failed to add allow: " << std::strerror(errno) << std::endl;
        close(fd);
        return 1;
    }
    close(fd);
    return 0;
}

static int allow_del(const std::string &comm)
{
    if (comm.empty() || comm.size() >= 16) {
        std::cerr << "comm too long" << std::endl;
        return 1;
    }
    int fd = bpf_obj_get(kAllowlistPin);
    if (fd < 0) {
        std::cerr << "Allowlist not found" << std::endl;
        return 1;
    }
    char keybuf[16] = {};
    std::memcpy(keybuf, comm.data(), comm.size());
    if (bpf_map_delete_elem(fd, keybuf)) {
        std::cerr << "Failed to delete allow: " << std::strerror(errno) << std::endl;
        close(fd);
        return 1;
    }
    close(fd);
    return 0;
}

static int allow_list()
{
    int fd = bpf_obj_get(kAllowlistPin);
    if (fd < 0) {
        std::cerr << "Allowlist not found" << std::endl;
        return 1;
    }

    char key[16] = {};
    char next_key[16] = {};
    uint8_t val;
    int rc = bpf_map_get_next_key(fd, nullptr, key);
    while (!rc) {
        if (!bpf_map_lookup_elem(fd, key, &val))
            std::cout << key << std::endl;
        rc = bpf_map_get_next_key(fd, key, next_key);
        std::memcpy(key, next_key, sizeof(key));
    }
    close(fd);
    return 0;
}

static int deny_add(const std::string &path)
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

    uint64_t hash = hash_path(path);
    uint8_t one = 1;

    if (bpf_map_update_elem(bpf_map__fd(state.deny_bloom), nullptr, &hash, BPF_ANY)) {
        std::cerr << "Failed to update deny_bloom: " << std::strerror(errno) << std::endl;
        cleanup_bpf(state);
        return 1;
    }
    if (bpf_map_update_elem(bpf_map__fd(state.deny_exact), &hash, &one, BPF_ANY)) {
        std::cerr << "Failed to update deny_exact: " << std::strerror(errno) << std::endl;
        cleanup_bpf(state);
        return 1;
    }

    auto entries = read_deny_db();
    entries[hash] = path;
    write_deny_db(entries);

    cleanup_bpf(state);
    return 0;
}

static int deny_del(const std::string &path)
{
    uint64_t hash = hash_path(path);
    int exact_fd = bpf_obj_get(kDenyExactPin);
    if (exact_fd < 0) {
        std::cerr << "Deny maps not found" << std::endl;
        return 1;
    }
    bpf_map_delete_elem(exact_fd, &hash);
    close(exact_fd);

    auto entries = read_deny_db();
    entries.erase(hash);
    write_deny_db(entries);
    return 0;
}

static int deny_list()
{
    BpfState state;
    int err = load_bpf(true, false, state);
    if (err) {
        std::cerr << "Failed to load BPF object: " << std::strerror(-err) << std::endl;
        return 1;
    }

    auto db = read_deny_db();
    uint64_t key = 0;
    uint64_t next_key = 0;
    int rc = bpf_map_get_next_key(bpf_map__fd(state.deny_exact), nullptr, &key);
    while (!rc) {
        auto it = db.find(key);
        if (it != db.end())
            std::cout << it->second << " (" << hash_to_hex(key) << ")" << std::endl;
        else
            std::cout << hash_to_hex(key) << std::endl;
        rc = bpf_map_get_next_key(bpf_map__fd(state.deny_exact), &key, &next_key);
        key = next_key;
    }

    cleanup_bpf(state);
    return 0;
}

static int deny_clear()
{
    std::remove(kDenyBloomPin);
    std::remove(kDenyExactPin);
    std::filesystem::remove(kDenyDbPath);

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
    cleanup_bpf(state);
    return 0;
}

static int usage(const char *prog)
{
    std::cerr << "Usage: " << prog << " run [--enforce] | deny {add|del|list|clear} [path] | allow {add|del|list} [comm]" << std::endl;
    return 1;
}

int main(int argc, char **argv)
{
    if (argc == 1)
        return run(false);

    std::string cmd = argv[1];
    if (cmd == "run") {
        bool enforce_mode = false;
        if (argc == 3) {
            if (std::string(argv[2]) == "--enforce")
                enforce_mode = true;
            else
                return usage(argv[0]);
        } else if (argc > 3) {
            return usage(argv[0]);
        }
        return run(enforce_mode);
    }
    if (cmd == "deny") {
        if (argc < 3)
            return usage(argv[0]);
        std::string sub = argv[2];
        if (sub == "add") {
            if (argc < 4)
                return usage(argv[0]);
            return deny_add(argv[3]);
        } else if (sub == "del") {
            if (argc < 4)
                return usage(argv[0]);
            return deny_del(argv[3]);
        } else if (sub == "list") {
            return deny_list();
        } else if (sub == "clear") {
            return deny_clear();
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
            return allow_list();
        } else {
            return usage(argv[0]);
        }
    }

    return usage(argv[0]);
}
