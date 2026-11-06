
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Configuration map */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

/* TC ingress eBPF program */
SEC("tc")
int drop_tcp_port(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Read Ethernet header */
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    /* Only process IPv4 packets */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* Read IPv4 header */
    struct iphdr *ip =
        (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    /* Only process TCP packets */
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    /* Ignore non-initial IP fragments */
    if (ip->frag_off & bpf_htons(0x1FFF))
   	 return TC_ACT_OK;

    /* Calculate IPv4 header length */
    __u32 ip_header_length = ip->ihl * 4;

    if (ip_header_length < sizeof(*ip))
        return TC_ACT_OK;

    /* Locate TCP header */
    struct tcphdr *tcp =
        (void *)ip + ip_header_length;

    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    /* Read configured port from BPF map */
    __u32 key = 0;
    __u32 *blocked_port =
        bpf_map_lookup_elem(&config_map, &key);

    if (!blocked_port)
        return TC_ACT_OK;

    /* Convert destination port to host byte order */
    __u32 destination_port = bpf_ntohs(tcp->dest);

    /* Drop packet if destination port matches */
    if (destination_port == *blocked_port)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
