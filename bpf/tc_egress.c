// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "scion.h"
#include "maps.h"
#include "scion_mac.h"

#define SCION_UDP_PORT 30041
#define MAX_PATH_LEN 256

// Cilium security identity carried in the SCION E2E extension header.
struct cilium_e2e_ext
{
    __u8 ext_type; // SCION end-to-end extension type
    __u8 ext_len;  // Extension length in 4-byte units
    __u16 reserved;
    __u32 security_identity; // Cilium numeric identity of the source Pod
};

// ---------------------------------------------------------------------------
// Static helper stubs
// ---------------------------------------------------------------------------

static __always_inline struct ethhdr *
parse_eth(void *data, void *data_end, int *off)
{
    struct ethhdr *eth = data;
    *off += sizeof(*eth);
    if ((void *)eth + *off > data_end)
        return NULL;
    return eth;
}

static __always_inline struct iphdr *
parse_ipv4(void *data, void *data_end, int *off)
{
    struct iphdr *iph = data + *off;
    if ((void *)(iph + 1) > data_end)
        return NULL;
    *off += iph->ihl * 4;
    if ((void *)data + *off > data_end)
        return NULL;
    return iph;
}

// Clamp the TCP MSS option in a SYN segment to avoid post-encapsulation fragmentation.
static __always_inline int
clamp_tcp_mss(struct __sk_buff *skb, int tcp_off, __u32 encap_len)
{
    // Phase 5 work item: Decrease MSS by exactly `encap_len`
    (void)skb;
    (void)tcp_off;
    (void)encap_len;
    return 0;
}

// ---------------------------------------------------------------------------
// Encapsulation Logic
// ---------------------------------------------------------------------------

// Write the full outer header stack into the newly opened headroom.
static __always_inline int
write_scion_headers(struct __sk_buff *skb,
                    const struct scion_path_entry *path,
                    __u32 encap_len)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 1. Re-evaluate Ethernet header after adjust_room
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    // 2. Overwrite the Destination MAC to the SCION Border Router (Next-Hop)
    // The source MAC remains the node's physical NIC MAC.
    __builtin_memcpy(eth->h_dest, path->next_hop_mac, ETH_ALEN);
    eth->h_proto = bpf_htons(ETH_P_IP);

    // 3. Construct Outer IPv4 Header
    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return -1;

    outer_ip->ihl = 5;
    outer_ip->version = 4;
    outer_ip->tos = 0;
    // Total length is the new entire packet minus the Ethernet header
    outer_ip->tot_len = bpf_htons(skb->len - sizeof(struct ethhdr));
    outer_ip->id = 0;
    outer_ip->frag_off = 0;
    outer_ip->ttl = 64;
    outer_ip->protocol = IPPROTO_UDP;
    outer_ip->check = 0; // Checksum calculation deferred/offloaded

    // In a production environment, the Node IP should be passed via the map.
    // For now, we rely on SNAT or leave the pod IP if Hetzner routes it.
    outer_ip->daddr = path->next_hop_ip;

    // 4. Construct Outer UDP Header
    struct udphdr *outer_udp = (void *)(outer_ip + 1);
    if ((void *)(outer_udp + 1) > data_end)
        return -1;

    outer_udp->source = bpf_htons(SCION_UDP_PORT); // Ephemeral or static
    outer_udp->dest = bpf_htons(SCION_UDP_PORT);
    outer_udp->len = bpf_htons(skb->len - sizeof(struct ethhdr) - sizeof(struct iphdr));
    outer_udp->check = 0; // UDP checksum of 0 is valid in IPv4

    // 5. TODO: Build SCION Common, Address, and Path headers
    // Full SCION header is done in control plane, need to copy this here

    // Locate the Info Field and our Hop Field
    struct scion_info_field *inf = (void *)((__u8 *)scion + sizeof(struct scion_hdr) + sizeof(struct scion_addr_hdr_v4) + sizeof(struct scion_path_meta_hdr));
    struct scion_hop_field *hf = (void *)((__u8 *)inf + (meta->num_inf * sizeof(struct scion_info_field)));

    // Egress Border Router Duty:
    // If the Global Controller didn't pre-compute the MAC, compute it now!
    // path->mac_key is fetched from our scion_path_cache eBPF map.
    if (calculate_scion_mac(path->mac_key, inf, hf, hf->mac) < 0)
    {
        return -1;
    }

    return 0;
}

// ---------------------------------------------------------------------------
// TC Egress Entry Point (Attached to Physical Interface e.g., eth0)
// ---------------------------------------------------------------------------

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    int off = 0;

    struct ethhdr *eth = parse_eth(data, data_end, &off);
    if (!eth)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = parse_ipv4(data, data_end, &off);
    if (!iph)
        return TC_ACT_OK;

    // 1. Map Lookup: Does this cleartext Pod IP have a SCION routing policy?
    __u32 src_ip = iph->saddr;
    __u32 *pol_id = bpf_map_lookup_elem(&pod_policy_map, &src_ip);
    if (!pol_id)
        return TC_ACT_OK; // No policy; let standard BGP/Linux routing handle it.

    // 2. Fetch the pre-computed SCION path
    struct scion_path_entry *path = bpf_map_lookup_elem(&scion_path_cache, pol_id);
    if (!path)
        return TC_ACT_OK; // Policy exists, but Agent hasn't fetched the path yet.

    // 3. Verifier Safety bounds check
    __u32 path_len = path->path_len;
    if (path_len > MAX_PATH_LEN)
        return TC_ACT_SHOT;

    // 4. Dynamically calculate exact encapsulation length
    __u32 encap_len = sizeof(struct iphdr) +
                      sizeof(struct udphdr) +
                      sizeof(struct scion_hdr) +
                      sizeof(struct scion_addr_hdr_v4) +
                      path_len +
                      sizeof(struct cilium_e2e_ext);

    // 5. Clamp MSS on outgoing TCP SYNs before we add header overhead
    if (iph->protocol == IPPROTO_TCP)
    {
        clamp_tcp_mss(skb, off, encap_len);
    }

    // 6. Open headroom for the complete SCION encapsulation header stack.
    // BPF_ADJ_ROOM_MAC inserts the space *between* the MAC and IP headers,
    // which is perfect for IP-in-IP / UDP tunneling.
    if (bpf_skb_adjust_room(skb, encap_len, BPF_ADJ_ROOM_MAC, 0) < 0)
        return TC_ACT_SHOT;

    // 7. Write the Headers
    if (write_scion_headers(skb, path, encap_len) < 0)
        return TC_ACT_SHOT;

    bpf_printk("CilION [Egress] | Encapsulated Pod IP %x -> SCION Gateway %x\n", src_ip, path->next_hop_ip);

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";