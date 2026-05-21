package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ScionPathEntry mirrors struct scion_path_entry from bpf/maps.h.
// The field order, sizes, and alignment must match the C struct exactly so
// that cilium/ebpf can serialise it directly into the scion_path_cache map.
//
//	C layout (284 bytes, no padding):
//	  __u32  next_hop_ip      4
//	  __u8   next_hop_mac[6]  6
//	  __u16  path_len         2
//	  __u8   hop_fields[256] 256
//	  __u8   mac_key[16]     16
type ScionPathEntry struct {
	NextHopIP  [4]byte
	NextHopMAC [6]byte
	PathLen    uint16
	HopFields  [256]byte
	MACKey     [16]byte
}

// IPToKey converts an IPv4 address to the uint32 map key that the eBPF
// program stores when it reads iph->saddr.
//
// The kernel stores saddr in network byte order (big-endian) as raw bytes.
// cilium/ebpf serialises uint32 map keys with native byte order, so on a
// little-endian host we read the 4 IP bytes as little-endian to produce the
// same in-memory representation that the BPF program wrote.
func IPToKey(ip net.IP) (uint32, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("IPToKey: not an IPv4 address: %v", ip)
	}
	return binary.NativeEndian.Uint32(ip4), nil
}

// IPFromKey is the inverse of IPToKey, useful for debugging map dumps.
func IPFromKey(key uint32) net.IP {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, key)
	return net.IP(b)
}
