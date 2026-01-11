# AegisBPF

A minimal eBPF CO-RE + C++20 program that tracks process lineage in-kernel, enforces deny rules on sys_enter_openat using a bloom filter fast-path (SIGKILL on match) while skipping uid/euid 0 to avoid self-denial, and prints exec and block events from a ring buffer. Deny state is pinned under /sys/fs/bpf/aegisbpf.

This build expects BTF at /sys/kernel/btf/vmlinux.

## Ubuntu packages

```
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev bpftool libelf-dev zlib1g-dev libzstd-dev pkg-config cmake make g++ linux-headers-$(uname -r)
```

## Build

```
cmake -S . -B build -G Ninja
cmake --build build
sudo ./build/aegisbpf run
```

If no args are provided, it defaults to run mode.

Manage deny rules:

```
sudo ./build/aegisbpf deny add /etc/shadow
sudo ./build/aegisbpf deny list
sudo ./build/aegisbpf deny del /etc/shadow
sudo ./build/aegisbpf deny clear
```

Example output:

```
[EXEC] pid=1234 ppid=567 comm=bash
[BLOCK] pid=1234 comm=cat file=/etc/shadow action=AUDIT
```

## Demo

Terminal 1:

```
sudo ./build/aegisbpf run
```

Terminal 2:

```
sudo ./build/aegisbpf deny add /etc/shadow
cat /etc/shadow
```

Recovery:
- To clear state without killing sudo/agent, allowlist handles it: `sudo ./build/aegisbpf allow list` to inspect, `sudo ./build/aegisbpf allow add <comm>` to add, `sudo ./build/aegisbpf allow del <comm>` to drop.
- To reset all pinned maps: `sudo rm -rf /sys/fs/bpf/aegisbpf` then rebuild/run.
