
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TARGET_COMM "myprocess"
#define ALLOWED_PORT 4040

SEC("cgroup/connect4")
int allow_only_port(struct bpf_sock_addr *ctx)
{
    char comm[16] = {};

    // Get current process name
    bpf_get_current_comm(comm, sizeof(comm));

    // Check target process name
    if (__builtin_memcmp(comm, TARGET_COMM,
                         sizeof(TARGET_COMM)) != 0)
    {
        return 1;
    }

    // Apply filtering only to TCP
    if (ctx->protocol != IPPROTO_TCP)
    {
        return 1;
    }

    // Compare destination port in network byte order
    if (ctx->user_port == bpf_htons(ALLOWED_PORT))
    {
        return 1;  // Allow TCP port 4040
    }

    return 0;      // Block all other TCP ports
}

char LICENSE[] SEC("license") = "GPL";
