# eBPF Network Security Assignment

This repository contains two Linux eBPF projects focused on network traffic filtering and access control.

## Problem Statements

### Problem 1: TCP Port Blocking
Implementation of an eBPF-based network traffic filtering mechanism to block traffic on a specified TCP port.
1st I drop TCP traffic from port 4040 then with userspace change it to 8080 and drop files from 8080.

**Source files:**
- `drop_port.bpf.c`
- `loader.c`

### Problem 2: Process-Based TCP Port Filtering
Implementation of process-specific TCP port filtering using the Linux cgroup eBPF hook.

**Features:**
- Identifies a target process by its name (`myprocess`).
- Allows outgoing IPv4 TCP connections to port 4040.
- Blocks outgoing IPv4 TCP connections to other ports for the target process.
- Leaves other processes unaffected.

**Source files:**
- `process_filter.bpf.c`
- `loader.c`
- `test_client.py`

## Technologies Used
- Linux
- eBPF
- C
- Python
- Clang / LLVM
- libbpf
- Linux cgroup v2
- Kali Linux

## Repository Structure

```text
ebpf-assignment/
├── problem1/
├── problem2/
├── README.md
└── .gitignore
```

## Environment
Developed and tested on Kali Linux with Linux cgroup v2.

## Purpose
Hands-on implementation of kernel-level network filtering using eBPF.
