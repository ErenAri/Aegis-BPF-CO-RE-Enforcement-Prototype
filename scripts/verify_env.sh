#!/usr/bin/env bash
set -euo pipefail

strict=0
if [[ "${1:-}" == "--strict" ]]; then
    strict=1
fi

fail=0

check_path() {
    local label="$1"
    local path="$2"
    local required="$3"
    if [[ -e "$path" ]]; then
        echo "${label}: ok"
    else
        echo "${label}: missing (${path})"
        if [[ "$required" == "required" ]]; then
            fail=1
        fi
    fi
}

check_cmd() {
    local label="$1"
    local cmd="$2"
    local required="$3"
    if command -v "$cmd" >/dev/null 2>&1; then
        echo "${label}: ok"
    else
        echo "${label}: missing (${cmd})"
        if [[ "$required" == "required" ]]; then
            fail=1
        fi
    fi
}

check_file_content() {
    local label="$1"
    local file="$2"
    local needle="$3"
    local required="$4"
    if [[ -r "$file" ]] && grep -qw "$needle" "$file" 2>/dev/null; then
        echo "${label}: ok"
    else
        echo "${label}: missing (${needle} in ${file})"
        if [[ "$required" == "required" ]]; then
            fail=1
        fi
    fi
}

echo "AegisBPF environment check"
check_path "cgroup_v2" /sys/fs/cgroup/cgroup.controllers required
check_path "bpffs" /sys/fs/bpf required
check_path "btf" /sys/kernel/btf/vmlinux required
check_file_content "bpf_lsm" /sys/kernel/security/lsm bpf optional
check_cmd "clang" clang optional
check_cmd "bpftool" bpftool optional

if [[ $strict -eq 1 && $fail -ne 0 ]]; then
    echo "Environment check failed"
    exit 1
fi
