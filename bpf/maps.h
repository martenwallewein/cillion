#ifndef MAPS_H
#define MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Pre-computed SCION path entry pushed by the Go control plane.
struct scion_path_entry {
    __u32 next_hop_ip;     // IP of the SCION Core AS border router
    __u8  next_hop_mac[6]; // Next-hop L2 address for the underlay
    __u16 path_len;        // Valid bytes in hop_fields[]
    __u8  hop_fields[256]; // Serialised SCION info + hop fields
    __u8  mac_key[16];     // AES-CMAC key for per-hop MAC computation
};

// Maps Pod source IPv4 → Policy ID (populated by K8s controller).
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(key_size,    sizeof(__u32));
    __uint(value_size,  sizeof(__u32));
    __uint(max_entries, 10000);
} pod_policy_map SEC(".maps");

// Maps Policy ID → scion_path_entry (populated by SCION path watcher).
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(key_size,    sizeof(__u32));
    __uint(value_size,  sizeof(struct scion_path_entry));
    __uint(max_entries, 1024);
} scion_path_cache SEC(".maps");

#endif /* MAPS_H */
