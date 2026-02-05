# AegisBPF Architecture

This document describes the internal architecture of AegisBPF, an eBPF-based runtime security agent.

## Overview

AegisBPF uses eBPF (extended Berkeley Packet Filter) to monitor and optionally block process executions at the kernel level. It leverages the BPF LSM (Linux Security Module) hooks for enforcement and tracepoints for audit-only monitoring.

```
+-----------------------------------------------------------------+
|                        User Space                               |
|  +----------------------------------------------------------+   |
|  |                     aegisbpf daemon                      |   |
|  |  +---------+ +---------+ +---------+ +-----------------+ |   |
|  |  | Policy  | |  BPF    | | Event   | |    Metrics      | |   |
|  |  | Manager | |  Ops    | | Handler | |    (Prometheus) | |   |
|  |  +----+----+ +----+----+ +----+----+ +--------+--------+ |   |
|  |       |           |           |               |          |   |
|  |       |      +----+-----------+---------------+          |   |
|  |       |      |                                           |   |
|  |       |      v                                           |   |
|  |       |  +-------------------------------------------+   |   |
|  |       +->|            libbpf                         |   |   |
|  |          +-------------------------------------------+   |   |
|  +----------------------------------------------------------+   |
|                              |                                  |
|                              | bpf() syscall                    |
+------------------------------+----------------------------------+
|                        Kernel Space                             |
|                              |                                  |
|  +---------------------------+-------------------------------+  |
|  |                    BPF Subsystem                          |  |
|  |  +-------------+  +-------------+  +---------------------+|  |
|  |  | LSM Hook    |  | Tracepoint  |  |      BPF Maps       ||  |
|  |  | file_open   |  | sched_exec  |  |  +---------------+  ||  |
|  |  |             |  |             |  |  | deny_inode    |  ||  |
|  |  |  (enforce)  |  |  (audit)    |  |  | deny_path     |  ||  |
|  |  |             |  |             |  |  | allow_cgroup  |  ||  |
|  |  +------+------+  +------+------+  |  | events (ring) |  ||  |
|  |         |                |         |  | block_stats   |  ||  |
|  |         +----------------+---------+--+---------------+--+|  |
|  +-----------------------------------------------------------+  |
|                              |                                  |
|                              v                                  |
|  +-----------------------------------------------------------+  |
|  |                    exec() syscall                         |  |
|  +-----------------------------------------------------------+  |
+-----------------------------------------------------------------+
```

## Components

### Kernel Space (BPF Programs)

#### bpf/aegis.bpf.c

The BPF program runs in kernel context and implements:

1. **LSM Hook (file_open)**
   - Called on file open attempts
   - Can return -EPERM to block access
   - Checks deny_inode and allow_cgroup maps
   - Only active when BPF LSM is enabled

2. **Tracepoints**
   - `sched_process_exec`: emits EXEC events for process executions
   - `sys_enter_openat`: emits audit-only BLOCK events for deny_path matches
   - Works without BPF LSM (audit-only paths)

3. **BPF Maps**
   - `deny_inode`: Hash map of blocked (dev, inode) pairs
   - `deny_path`: Hash map of blocked path hashes
   - `allow_cgroup`: Hash map of allowed cgroup IDs
   - `events`: Ring buffer for sending events to userspace
   - `block_stats`: Global counters for blocks and drops
   - `deny_cgroup_stats`: Per-cgroup block counters
   - `deny_inode_stats`: Per-inode block counters
   - `deny_path_stats`: Per-path block counters
   - `agent_meta`: Agent metadata (layout version)

### User Space

#### src/main.cpp

Entry point and CLI interface:
- Parses command-line arguments
- Initializes logging
- Dispatches to appropriate command handler
- Manages signal handling for graceful shutdown

#### src/bpf_ops.cpp

BPF operations layer:
- Loads BPF object file
- Attaches programs to hooks
- Manages map operations
- Handles BPF filesystem pins

Key functions:
- `load_bpf()`: Load and optionally pin BPF objects
- `attach_all()`: Attach programs to LSM/tracepoints
- `add_deny_inode()`: Add entry to deny list
- `read_block_stats_map()`: Read statistics

#### src/policy.cpp

Policy file management:
- Parses policy files (INI-style format)
- Validates policy syntax and semantics
- Applies policies to BPF maps
- Handles policy rollback

#### src/events.cpp

Event handling:
- Receives events from BPF ring buffer
- Formats events for output (JSON/text)
- Sends events to journald or stdout

#### src/utils.cpp

Utility functions:
- Path validation and canonicalization
- Cgroup path resolution
- Inode-to-path mapping
- String manipulation

#### src/sha256.cpp

SHA256 implementation:
- Pure C++ implementation (no external deps)
- Used for policy file verification
- Used for path-based hash lookups

#### src/seccomp.cpp

Seccomp filter:
- Applies syscall allowlist after initialization
- Reduces attack surface if agent is compromised

#### src/logging.hpp

Structured logging:
- Chainable API for field addition
- Text and JSON output formats
- Log level filtering
- Thread-safe singleton

#### src/result.hpp

Error handling:
- `Result<T>` type for success/failure
- `Error` class with code, message, context
- `TRY()` macro for early return

## Data Flow

### File Access Blocking (Enforce Mode)

```
1. Process calls open("/etc/shadow")
           |
           v
2. Kernel invokes file_open LSM hook
           |
           v
3. BPF program handle_file_open runs
           |
           +--- Check allow_cgroup map
           |    +- If cgroup allowed → ALLOW
           |
           +--- Check deny_inode map
                +- If inode blocked → DENY + emit event
           |
           v
4. Return 0 (allow) or -EPERM (deny)
           |
           v
5. If denied, ring buffer event sent to userspace
           |
           v
6. aegisbpf daemon receives event
           |
           v
7. Event logged to journald/stdout
```

### Audit Mode

```
1. Process executes a binary (execve)
           |
           v
2. execve() completes successfully
           |
           v
3. Kernel fires sched_process_exec tracepoint
           |
           v
4. BPF program handle_execve runs
           |
           v
5. EXEC event emitted to ring buffer
           |
           v
6. aegisbpf daemon receives event
           |
           v
7. Event logged to journald/stdout
```

```
1. Process opens a file (open/openat)
           |
           v
2. Kernel fires sys_enter_openat tracepoint
           |
           v
3. BPF program handle_openat runs
           |
           v
4. If path is in deny_path, emit audit-only BLOCK event
           |
           v
5. aegisbpf daemon receives event
           |
           v
6. Event logged to journald/stdout
```

## BPF Map Pinning

Maps are pinned to /sys/fs/bpf/aegis/ for persistence:

```
/sys/fs/bpf/aegis/
+-- deny_inode          # Blocked inodes
+-- deny_path           # Blocked paths
+-- allow_cgroup        # Allowed cgroups
+-- events              # Ring buffer (not pinned)
+-- block_stats         # Global counters
+-- deny_cgroup_stats   # Per-cgroup stats
+-- deny_inode_stats    # Per-inode stats
+-- deny_path_stats     # Per-path stats
+-- agent_meta          # Layout version
```

Pinning allows:
- Persistent deny lists across agent restarts
- Multiple agent instances sharing state
- External tools to inspect/modify maps

## Error Handling Strategy

AegisBPF uses a Result<T> monad pattern:

```cpp
Result<InodeId> path_to_inode(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return Error::system(errno, "stat failed");
    }
    return InodeId{static_cast<uint32_t>(st.st_dev), st.st_ino};
}

// Usage with TRY macro
Result<void> block_file(const std::string& path) {
    auto inode = TRY(path_to_inode(path));
    TRY(add_to_deny_map(inode));
    return {};
}
```

Benefits:
- Explicit error handling at every call site
- Error context preservation through the call stack
- No exceptions (suitable for signal handlers)

## Concurrency Model

- **Single-threaded main loop**: Ring buffer polling
- **Thread-safe caches**: CgroupPathCache and CwdCache use mutex
- **Atomic counters**: std::atomic for journal error state
- **No shared mutable state**: BPF operations are inherently safe

## Security Considerations

1. **Principle of Least Privilege**
   - Minimal capability set (SYS_ADMIN, BPF, PERFMON)
   - Seccomp filter restricts syscalls
   - AppArmor/SELinux confine file access

2. **Input Validation**
   - All CLI paths validated before use
   - Policy files parsed with strict error handling
   - SHA256 verification for policy integrity

3. **Defense in Depth**
   - Multiple security layers (BPF, seccomp, MAC)
   - RAII for resource cleanup
   - Crash-safe persistent state

## Performance Characteristics

- **BPF overhead**: ~100-500ns per file open
- **Map lookups**: O(1) hash table operations
- **Ring buffer**: Lock-free producer-consumer
- **Memory usage**: ~10MB base + map sizes
- **CPU usage**: Minimal when idle, proportional to exec rate

## Kernel Requirements

| Feature | Minimum Version | Notes |
|---------|----------------|-------|
| BPF CO-RE | 5.5 | Compile-once, run-everywhere |
| BPF LSM | 5.7 | Required for enforce mode |
| Ring buffer | 5.8 | More efficient than perf buffer |
| CAP_BPF | 5.8 | Dedicated capability |
| BTF | 5.2 | Type information |
