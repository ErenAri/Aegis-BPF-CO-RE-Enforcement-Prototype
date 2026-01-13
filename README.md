# AegisBPF

eBPF LSM agent that enforces inode-based deny rules in `lsm/file_open`, kills offenders synchronously (SIGKILL + `-EPERM`), and exempts trusted workloads via cgroup-based allowlisting. Events are emitted over a ring buffer and per-CPU counters track blocks and ringbuf drops.

## Requirements

- Kernel with BPF LSM, cgroup v2 (unified hierarchy mounted at `/sys/fs/cgroup`), bpffs at `/sys/fs/bpf`, and BTF at `/sys/kernel/btf/vmlinux`.
- Verify `/sys/kernel/security/lsm` contains `bpf`; otherwise BPF LSM hooks will not fire.
- If `bpf` is missing from `/sys/kernel/security/lsm`, enable it by adding `bpf` to the kernel `lsm=` boot parameter (e.g., `lsm=landlock,lockdown,yama,bpf,integrity,apparmor`) or rebuilding with `CONFIG_BPF_LSM=y`.
- Root privileges (CAP_SYS_ADMIN) to load LSM programs and manage cgroups.
- Ubuntu build deps:
  ```
  sudo apt-get update
  sudo apt-get install -y clang llvm libbpf-dev bpftool libelf-dev zlib1g-dev libzstd-dev pkg-config cmake make g++ linux-headers-$(uname -r)
  ```

## Build

```
cmake -S . -B build -G Ninja
cmake --build build
```

## Run the agent

```
sudo ./build/aegisbpf run
# Audit-only (log without kill/EPERM)
sudo ./build/aegisbpf run --audit
```

Startup does the following:
- Verifies cgroup v2 and bpffs mounts.
- Loads BPF and pins maps under `/sys/fs/bpf/aegisbpf`.
- Creates `/sys/fs/cgroup/aegis_agent`, moves the agent PID into it, and allows that cgroup via `allow_cgroup_map`.
- Attaches `lsm/path_open` (enforcement) plus fork/exit/exec lineage tracking.

## Manage deny rules (inode/device based)

```
sudo ./build/aegisbpf block add /etc/shadow
sudo ./build/aegisbpf block list
sudo ./build/aegisbpf block del /etc/shadow
sudo ./build/aegisbpf block clear   # clears pins and DB, resets counters
```

State is persisted in:
- `/sys/fs/bpf/aegisbpf/deny_inode`
- `/sys/fs/bpf/aegisbpf/allow_cgroup`
- `/sys/fs/bpf/aegisbpf/block_stats`
- `/var/lib/aegisbpf/deny.db` (dev/ino + optional path notes)

## Manage allowlist (cgroup based)

```
sudo ./build/aegisbpf allow add /sys/fs/cgroup/my_service
sudo ./build/aegisbpf allow list
sudo ./build/aegisbpf allow del /sys/fs/cgroup/my_service
```

## Stats

```
sudo ./build/aegisbpf stats
```

Outputs counts of deny/allow entries plus per-CPU aggregated `blocks` and `ringbuf_drops`, and per-cgroup/per-inode block counters (with best-effort cgroup path resolution).

## Event format

Ring buffer events are newline-delimited JSON:
- EXEC: `{"type":"exec","pid":123,"ppid":1,"start_time":1234567890,"cgid":987,"cgroup_path":"/sys/fs/cgroup/...", "comm":"bash"}`
- BLOCK: `{"type":"block","pid":123,"ppid":1,"start_time":1234,"parent_start_time":5678,"cgid":987,"cgroup_path":"/sys/fs/cgroup/...", "ino":42,"dev":2049,"action":"KILL","comm":"cat"}` (action is `AUDIT` when running with `--audit`)

## Smoke test

A runnable smoke test (needs root, will start the agent):

```
sudo scripts/smoke_block.sh
```

It starts the agent, blocks a temp file, attempts to read it (expects KILL/EPERM), prints stats, and cleans up.
