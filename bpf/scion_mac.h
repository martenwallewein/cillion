// SPDX-License-Identifier: GPL-2.0
#ifndef __SCION_MAC_H__
#define __SCION_MAC_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "scion.h"

// The SCION MAC is a 6-byte truncation of an AES-CMAC
#define SCION_MAC_LEN 6

/**
 * Calculates the SCION MAC for a given Hop Field.
 * In SCION, the MAC is calculated over:
 * - The Info Field (Timestamp)
 * - The Hop Field (Flags, Expiry, Ingress/Egress Interfaces)
 */
static __always_inline int
calculate_scion_mac(const __u8 *mac_key,
                    const struct scion_info_field *inf,
                    const struct scion_hop_field *hf,
                    __u8 *out_mac)
{
    // PHASE 5 TODO: Implement actual AES-CMAC.
    // Option A: Use bpf_crypto_ctx (Linux 6.1+)
    // Option B: A lightweight unrolled pure-BPF software implementation.

    // For the MVP, we just zero out or copy a dummy value.
    __builtin_memset(out_mac, 0, SCION_MAC_LEN);

    return 0; // Return 0 on success
}

/**
 * Validates the MAC of an incoming Hop Field.
 * Returns 0 if valid, or a negative error code if invalid.
 */
static __always_inline int
verify_scion_mac(const __u8 *mac_key,
                 const struct scion_info_field *inf,
                 const struct scion_hop_field *hf)
{
    __u8 computed_mac[SCION_MAC_LEN];

    if (calculate_scion_mac(mac_key, inf, hf, computed_mac) < 0)
    {
        return -1; // Crypto failure
    }

    // Compare the computed MAC with the MAC embedded in the packet's Hop Field
    // SCION Hop Field MACs are exactly 6 bytes.
    if (computed_mac[0] != hf->mac[0] ||
        computed_mac[1] != hf->mac[1] ||
        computed_mac[2] != hf->mac[2] ||
        computed_mac[3] != hf->mac[3] ||
        computed_mac[4] != hf->mac[4] ||
        computed_mac[5] != hf->mac[5])
    {
        return -2; // MAC Mismatch (Spoofed packet!)
    }

    return 0; // MAC is valid
}

#endif // __SCION_MAC_H__