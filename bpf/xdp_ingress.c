// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "scion.h"
#include "maps.h"

// Minimum outer header bytes that must be present before the inner IP packet:
//   outer IPv4 + outer UDP + SCION common header + SCION IPv4 address header
// The path header size is variable; actual strip length is computed at runtime.
#define SCION_BASE_DECAP_LEN (sizeof(struct iphdr)          \
                            + sizeof(struct udphdr)         \
                            + sizeof(struct scion_hdr)      \
                            + sizeof(struct scion_addr_hdr_v4))

// ---------------------------------------------------------------------------
// Static helper stubs
// ---------------------------------------------------------------------------

// Return a pointer to the SCION path meta header given the byte offset of the
// SCION common header inside the XDP frame, or NULL on bounds violation.
static __always_inline struct scion_path_meta_hdr *
parse_path_meta(void *data, void *data_end, int scion_off)
{
    int meta_off = scion_off
                 + (int)sizeof(struct scion_hdr)
                 + (int)sizeof(struct scion_addr_hdr_v4);
    struct scion_path_meta_hdr *meta = data + meta_off;
    if ((void *)(meta + 1) > data_end)
        return NULL;
    return meta;
}

// Locate the active hop field described by meta->cur_hf.
// Returns NULL if the field would exceed data_end.
static __always_inline struct scion_hop_field *
get_current_hop_field(void *data, void *data_end,
                      int scion_off, const struct scion_path_meta_hdr *meta)
{
    // Path header layout: [info fields …][hop fields …]
    // Each info field is sizeof(struct scion_info_field); each hop field is
    // sizeof(struct scion_hop_field).  cur_hf is the index into the hop fields
    // array (0-based) counting from after all info fields.
    int path_off = scion_off
                 + (int)sizeof(struct scion_hdr)
                 + (int)sizeof(struct scion_addr_hdr_v4)
                 + (int)sizeof(struct scion_path_meta_hdr)
                 + (int)(meta->num_inf * sizeof(struct scion_info_field))
                 + (int)(meta->cur_hf  * sizeof(struct scion_hop_field));
    struct scion_hop_field *hf = data + path_off;
    if ((void *)(hf + 1) > data_end)
        return NULL;
    return hf;
}

// Verify the MAC of the current hop field.
// Phase 5 work item: requires retrieving the mac_key from scion_path_cache
// (keyed by the remote AS derived from the SCION address header) and computing
// AES-CMAC over the hop field.
static __always_inline int
verify_hop_mac(const struct scion_path_entry *path __attribute__((unused)),
               const struct scion_hop_field   *hf   __attribute__((unused)))
{
    // TODO: implement AES-CMAC verification or delegate to control plane.
    return 0; // 0 = OK
}

// Compute the total outer header length to strip, including the variable-length
// path header derived from the path meta.
// Returns a negative value if bounds check fails.
static __always_inline int
scion_decap_len(const struct scion_path_meta_hdr *meta)
{
    int path_hdr_len = (int)sizeof(struct scion_path_meta_hdr)
                     + (int)(meta->num_inf * sizeof(struct scion_info_field))
                     + (int)(meta->num_hf  * sizeof(struct scion_hop_field));
    return (int)SCION_BASE_DECAP_LEN + path_hdr_len;
}

// ---------------------------------------------------------------------------
// XDP ingress entry point
// ---------------------------------------------------------------------------

SEC("xdp")
int xdp_ingress(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Fast-path minimum size check before any pointer arithmetic.
    if (data + SCION_BASE_DECAP_LEN + sizeof(struct ethhdr) > data_end)
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
    int udp_off = sizeof(struct ethhdr) + outer_iph->ihl * 4;
    struct udphdr *outer_udp = data + udp_off;
    if ((void *)(outer_udp + 1) > data_end)
        return XDP_PASS;

    // Ignore anything that is not SCION traffic.
    if (outer_udp->dest != bpf_htons(DISPATCHER_PORT))
        return XDP_PASS;

    // --- SCION common header ---
    int scion_off = udp_off + (int)sizeof(struct udphdr);
    struct scion_hdr *scion = data + scion_off;
    if ((void *)(scion + 1) > data_end)
        return XDP_DROP;

    // --- SCION path meta header ---
    struct scion_path_meta_hdr *meta = parse_path_meta(data, data_end, scion_off);
    if (!meta)
        return XDP_DROP;

    // --- Current hop field ---
    struct scion_hop_field *hf = get_current_hop_field(data, data_end, scion_off, meta);
    if (!hf)
        return XDP_DROP;

    // MAC verification (stub; enabled once Phase 5 key lookup is in place).
    // if (verify_hop_mac(path, hf) < 0)
    //     return XDP_DROP;
    (void)hf;

    // Calculate exact strip length including the variable-length path header.
    int strip = scion_decap_len(meta);
    if (strip < 0)
        return XDP_DROP;

    // Strip the Ethernet header offset as well; bpf_xdp_adjust_head moves
    // ctx->data forward, exposing the inner IP packet directly.
    strip += (int)sizeof(struct ethhdr);

    // Verify the inner IP packet fits before committing the strip.
    if (data + strip + (int)sizeof(struct iphdr) > data_end)
        return XDP_DROP;

    if (bpf_xdp_adjust_head(ctx, strip) != 0)
        return XDP_DROP;

    // The inner IP packet is now at ctx->data; pass it up to the base CNI.
    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
