#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define PATH_MAX 256
#define SIGKILL 9

enum event_type {
    EVENT_EXEC = 1,
    EVENT_BLOCK = 2,
};

struct process_info {
    __u32 pid;
    __u32 ppid;
    __u64 start_time;
    __u64 parent_start_time;
};

struct exec_event {
    __u32 pid;
    __u32 ppid;
    __u64 start_time;
    char comm[16];
};

struct event {
    __u32 type;
    union {
        struct exec_event exec;
        struct {
            __u32 pid;
            char comm[16];
            char filename[PATH_MAX];
            char action[8];
        } block;
    };
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct process_info);
} process_tree SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} cfg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[16]);
    __type(value, __u8);
} allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
    __uint(max_entries, 16384);
    __uint(key_size, 0);
    __uint(value_size, sizeof(__u64));
    __uint(map_extra, 5);
} deny_bloom SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u8);
} deny_exact SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline __u64 hash_path(const char *buf)
{
    __u64 hash = 1469598103934665603ULL;

#pragma unroll
    for (int i = 0; i < PATH_MAX; i++) {
        char c = buf[i];
        if (!c)
            break;
        hash ^= (__u8)c;
        hash *= 1099511628211ULL;
    }

    return hash;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct process_info info = {};
    struct process_info *existing;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 start_time = 0;
    __u64 parent_start_time = 0;
    __u32 ppid = 0;
    struct task_struct *task = bpf_get_current_task_btf();

    if (task) {
        start_time = BPF_CORE_READ(task, start_time);
        parent_start_time = BPF_CORE_READ(task, real_parent, start_time);
        ppid = BPF_CORE_READ(task, real_parent, tgid);
    }

    existing = bpf_map_lookup_elem(&process_tree, &pid);
    if (existing) {
        info.pid = existing->pid;
        info.ppid = existing->ppid;
        info.start_time = existing->start_time;
        info.parent_start_time = existing->parent_start_time;
    }

    info.pid = pid;
    if (ppid)
        info.ppid = ppid;
    if (start_time)
        info.start_time = start_time;
    if (parent_start_time)
        info.parent_start_time = parent_start_time;

    bpf_map_update_elem(&process_tree, &pid, &info, BPF_ANY);

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_EXEC;
    e->exec.pid = pid;
    e->exec.ppid = info.ppid;
    e->exec.start_time = info.start_time;
    bpf_get_current_comm(e->exec.comm, sizeof(e->exec.comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[1];
    char buf[PATH_MAX];
    __u64 hash;
    struct event *e;
    __u32 pid;
    __u32 uid;
    __u32 euid = 0;
    struct task_struct *task = bpf_get_current_task_btf();
    __u32 key = 0;
    __u8 *cfg;
    bool enforce = false;
    char comm[16] = {};

    uid = bpf_get_current_uid_gid();
    if (task)
        euid = BPF_CORE_READ(task, cred, euid.val);
    if (uid == 0 || euid == 0)
        return 0;
    bpf_get_current_comm(comm, sizeof(comm));
    if (!__builtin_memcmp(comm, "sudo", 5))
        return 0;
    if (!__builtin_memcmp(comm, "aegisbpf", 8))
        return 0;
    if (bpf_map_lookup_elem(&allowlist, comm))
        return 0;
    cfg = bpf_map_lookup_elem(&cfg_map, &key);
    if (cfg && *cfg)
        enforce = true;
    if (bpf_probe_read_str(buf, sizeof(buf), filename) <= 0)
        return 0;

    hash = hash_path(buf);

    if (bpf_map_peek_elem(&deny_bloom, &hash))
        return 0;
    if (!bpf_map_lookup_elem(&deny_exact, &hash))
        return 0;

    if (enforce)
        bpf_send_signal(SIGKILL);

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    pid = bpf_get_current_pid_tgid() >> 32;
    e->type = EVENT_BLOCK;
    e->block.pid = pid;
    bpf_get_current_comm(e->block.comm, sizeof(e->block.comm));
    __builtin_memcpy(e->block.filename, buf, sizeof(e->block.filename));
    if (enforce)
        __builtin_memcpy(e->block.action, "SIGKILL", sizeof("SIGKILL"));
    else
        __builtin_memcpy(e->block.action, "AUDIT", sizeof("AUDIT"));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct process_info info = {};
    __u32 child_pid = ctx->child_pid;
    __u32 parent_pid = ctx->parent_pid;
    struct task_struct *task = bpf_get_current_task_btf();

    info.pid = child_pid;
    info.ppid = parent_pid;
    if (task)
        info.parent_start_time = BPF_CORE_READ(task, start_time);

    bpf_map_update_elem(&process_tree, &child_pid, &info, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    bpf_map_delete_elem(&process_tree, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
