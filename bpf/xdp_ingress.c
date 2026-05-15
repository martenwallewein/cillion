// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "scion.h"
#include "maps.h"
#include "scion_mac.h"

#define SCION_UDP_PORT 30041

// Cilium security identity carried in the SCION E2E extension header.
struct cilium_e2e_ext
{
    __u8 ext_type;
    __u8 ext_len;
    __u16 reserved;
    __u32 security_identity;
};

// ---------------------------------------------------------------------------
// Static helper stubs
// ---------------------------------------------------------------------------

static __always_inline struct scion_path_meta_hdr *
parse_path_meta(void *data, void *data_end, int scion_off)
{
    int meta_off = scion_off + (int)sizeof(struct scion_hdr) + (int)sizeof(struct scion_addr_hdr_v4);
    struct scion_path_meta_hdr *meta = data + meta_off;
    if ((void *)(meta + 1) > data_end)
        return NULL;
    return meta;
}

static __always_inline struct scion_hop_field *
get_current_hop_field(void *data, void *data_end,
                      int scion_off, const struct scion_path_meta_hdr *meta)
{
    int path_off = scion_off + (int)sizeof(struct scion_hdr) + (int)sizeof(struct scion_addr_hdr_v4) + (int)sizeof(struct scion_path_meta_hdr) + (int)(meta->num_inf * sizeof(struct scion_info_field)) + (int)(meta->cur_hf * sizeof(struct scion_hop_field));
    struct scion_hop_field *hf = data + path_off;
    if ((void *)(hf + 1) > data_end)
        return NULL;
    return hf;
}

// ---------------------------------------------------------------------------
// XDP Ingress Entry Point (Attached to Physical Interface e.g., eth0)
// ---------------------------------------------------------------------------

SEC("xdp")
int xdp_ingress(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Fast bounds check
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // --- Outer IPv4 ---
    struct iphdr *outer_iph = (void *)(eth + 1);
    if ((void *)(outer_iph + 1) > data_end)
        return XDP_PASS;
    if (outer_iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // --- Outer UDP ---
    int udp_off = sizeof(struct ethhdr) + (outer_iph->ihl * 4);
    struct udphdr *outer_udp = data + udp_off;
    if ((void *)(outer_udp + 1) > data_end)
        return XDP_PASS;

    // Filter: Is this SCION WAN traffic?
    if (outer_udp->dest != bpf_htons(SCION_UDP_PORT))
        return XDP_PASS;

    // --- SCION common header ---
    int scion_off = udp_off + (int)sizeof(struct udphdr);
    struct scion_hdr *scion = data + scion_off;
    if ((void *)(scion + 1) > data_end)
        return XDP_DROP; // Drop malformed SCION traffic

    // --- SCION path meta header ---
    struct scion_path_meta_hdr *meta = parse_path_meta(data, data_end, scion_off);
    if (!meta)
        return XDP_DROP;

    // --- Current hop field (MAC validation in Phase 5) ---
    struct scion_hop_field *hf = get_current_hop_field(data, data_end, scion_off, meta);
    if (!hf)
        return XDP_DROP;
    (void)hf;

    // --- Calculate exact encapsulation length ---
    // This is everything BETWEEN the Ethernet header and the Inner IP header.
    int path_hdr_len = (int)sizeof(struct scion_path_meta_hdr) + (int)(meta->num_inf * sizeof(struct scion_info_field)) + (int)(meta->num_hf * sizeof(struct scion_hop_field));

    int encap_len = (outer_iph->ihl * 4) + sizeof(struct udphdr) + sizeof(struct scion_hdr) + sizeof(struct scion_addr_hdr_v4) + path_hdr_len + sizeof(struct cilium_e2e_ext);

    // Ensure we don't read past the end of the packet before adjusting
    if (data + sizeof(struct ethhdr) + encap_len > data_end)
        return XDP_DROP;

    // --- Info Field ---
    // We also need the Info Field to verify the MAC
    struct scion_info_field *inf = (void *)((__u8 *)data + scion_off + sizeof(struct scion_hdr) + sizeof(struct scion_addr_hdr_v4) + sizeof(struct scion_path_meta_hdr));
    if ((void *)(inf + 1) > data_end)
        return XDP_DROP;

    // We need the MAC key for our Local AS.
    // In a real implementation, you would lookup the MAC key from an eBPF map
    // using the Interface ID or AS number from the packet headers.
    __u32 local_as_key_id = 0; // Example map key
    struct scion_path_entry *local_crypto = bpf_map_lookup_elem(&scion_path_cache, &local_as_key_id);
    if (!local_crypto)
        return XDP_DROP;

    // Ingress Border Router Duty: MAC VERIFICATION
    if (verify_scion_mac(local_crypto->mac_key, inf, hf) != 0)
    {
        bpf_printk("CilION [Ingress XDP] | DROP: Invalid SCION MAC detected!\n");
        return XDP_DROP;
    }

    // -----------------------------------------------------------------------
    // XDP Decapsulation Magic (The Ethernet Shift)
    // -----------------------------------------------------------------------

    // 1. Copy the original Ethernet header to the eBPF stack (14 bytes)
    // We need to preserve the MAC addresses so the kernel accepts the inner IP packet.
    struct ethhdr orig_eth = *eth;
    orig_eth.h_proto = bpf_htons(ETH_P_IP); // Ensure inner protocol is set correctly

    // 2. Shrink the packet by `encap_len`.
    // This moves `ctx->data` forward, chopping off BOTH the original ETH header
    // and the entire SCION/UDP encapsulation stack.
    if (bpf_xdp_adjust_head(ctx, encap_len) != 0)
        return XDP_DROP;

    // 3. Re-evaluate pointers after adjustment!
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    // 4. Verify we have enough room to write the Ethernet header back
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_DROP;

    // 5. Write the Ethernet header back onto the front of the inner packet
    struct ethhdr *new_eth = data;
    *new_eth = orig_eth;

    // Check that the Inner payload is actually an IP packet
    struct iphdr *inner_iph = (void *)(new_eth + 1);
    if ((void *)(inner_iph + 1) > data_end)
        return XDP_DROP;

    // bpf_printk("CilION [Ingress XDP] | Decapsulated! Inner Dst IP: %x\n", bpf_ntohl(inner_iph->daddr));

    // Pass the clean inner IP packet up the Linux stack.
    // It will be allocated an SKB and hit Cilium's ingress TC program natively.
    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";