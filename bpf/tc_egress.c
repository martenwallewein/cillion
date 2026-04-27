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

// Byte count of the header stack prepended during encapsulation:
//   outer IPv4 + outer UDP + SCION common header + SCION IPv4 address header
#define SCION_ENCAP_LEN ((__u32)(sizeof(struct iphdr)          \
                               + sizeof(struct udphdr)         \
                               + sizeof(struct scion_hdr)      \
                               + sizeof(struct scion_addr_hdr_v4)))

// Cilium security identity carried in the SCION E2E extension header.
struct cilium_e2e_ext {
    __u8  ext_type;          // SCION end-to-end extension type
    __u8  ext_len;           // Extension length in 4-byte units
    __u16 reserved;
    __u32 security_identity; // Cilium numeric identity of the source Pod
};

// ---------------------------------------------------------------------------
// Static helper stubs
// ---------------------------------------------------------------------------

// Validate and return a pointer to the Ethernet header; advances *off past it.
// Returns NULL when the frame is too short.
static __always_inline struct ethhdr *
parse_eth(void *data, void *data_end, int *off)
{
    struct ethhdr *eth = data;
    *off += sizeof(*eth);
    if ((void *)eth + *off > data_end)
        return NULL;
    return eth;
}

// Validate and return a pointer to the IPv4 header starting at *off.
// Advances *off to the first byte after the IP options.
// Returns NULL on bounds violation or non-IPv4.
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

// Clamp the TCP MSS option in a SYN segment to avoid post-encapsulation
// fragmentation.  The overhead budget is SCION_ENCAP_LEN bytes.
// TODO: implement full TCP option walk and MSS rewrite via bpf_skb_store_bytes.
static __always_inline int
clamp_tcp_mss(struct __sk_buff *skb, int tcp_off)
{
    // Phase 5 work item.
    (void)skb; (void)tcp_off;
    return 0;
}

// Compute the AES-CMAC over a hop field using the cached mac_key.
// Phase 5: initially the Go agent pre-computes the MAC and bakes it into
// hop_fields[]; this stub is reserved for a future in-kernel implementation.
static __always_inline int
compute_hop_mac(const struct scion_path_entry *entry __attribute__((unused)),
                const struct scion_hop_field   *hf    __attribute__((unused)),
                __u64 *out_mac)
{
    // TODO: implement via bpf_crypto_ctx or delegate to control plane.
    *out_mac = 0;
    return 0;
}

// Write the full outer header stack (outer IPv4, outer UDP, SCION common,
// SCION address header, and Cilium E2E extension) into the headroom that
// bpf_skb_adjust_room() just opened up.
// inner_iph and path must still be valid at call time (caller re-checks bounds).
static __always_inline int
write_scion_headers(struct __sk_buff *skb,
                    const struct iphdr            *inner_iph,
                    const struct scion_path_entry *path,
                    __u32                          policy_id)
{
    // TODO:
    //  1. Build struct iphdr  (src = node IP, dst = path->next_hop_ip,
    //                          proto = UDP, tot_len covers everything below).
    //  2. Build struct udphdr (sport = ephemeral, dport = DISPATCHER_PORT).
    //  3. Build struct scion_hdr from path metadata.
    //  4. Build struct scion_addr_hdr_v4 (local ISD-AS → remote ISD-AS).
    //  5. Copy path->hop_fields[0..path->path_len] for the path header.
    //  6. Append struct cilium_e2e_ext with the Pod's Cilium identity.
    //  7. Write each struct with bpf_skb_store_bytes().
    //  8. Fix outer IPv4 checksum with bpf_l3_csum_replace().
    (void)skb; (void)inner_iph; (void)path; (void)policy_id;
    return 0;
}

// ---------------------------------------------------------------------------
// TC egress entry point
// ---------------------------------------------------------------------------

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
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

    // Lookup the SCION policy for this Pod's source IP.
    __u32 src_ip   = iph->saddr;
    __u32 *pol_id  = bpf_map_lookup_elem(&pod_policy_map, &src_ip);
    if (!pol_id)
        return TC_ACT_OK; // Pod has no SCION policy; let normal routing handle it.

    struct scion_path_entry *path = bpf_map_lookup_elem(&scion_path_cache, pol_id);
    if (!path)
        return TC_ACT_OK; // No active path yet; control plane hasn't converged.

    // Clamp MSS on outgoing TCP SYNs before we add header overhead.
    if (iph->protocol == IPPROTO_TCP) {
        clamp_tcp_mss(skb, off);
        // Re-fetch after potential store (clamp_tcp_mss is a no-op stub for now).
        data     = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
    }

    // Open headroom for the complete SCION encapsulation header stack.
    if (bpf_skb_adjust_room(skb, SCION_ENCAP_LEN, BPF_ADJ_ROOM_MAC, 0) < 0)
        return TC_ACT_SHOT;

    // Pointers are stale after adjust_room; write_scion_headers uses offsets.
    if (write_scion_headers(skb, iph, path, *pol_id) < 0)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
