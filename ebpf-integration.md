# eBPF Integration — pkg/bpf/

This document describes the Go-side eBPF loading layer that bridges the CilION
C data-plane programs (`bpf/tc_egress.c`, `bpf/xdp_ingress.c`) with the
cilion-agent control plane.

---

## Overview

The `pkg/bpf/` package uses [`cilium/ebpf`](https://github.com/cilium/ebpf)
and its `bpf2go` code generator to load, attach, and interact with the two
eBPF programs at runtime.

```
pkg/bpf/
├── headers/scion.h      — SCION protocol C structs (shared with C programs)
├── gen.go               — //go:generate directives for bpf2go
├── types.go             — Go mirror of scion_path_entry + map key helpers
└── loader.go            — Loader struct: Load, AttachTC, AttachXDP, map ops, Close
```

---

## Dependencies

| Module | Version | Purpose |
|--------|---------|---------|
| `github.com/cilium/ebpf` | v0.21.0 | Core BPF loading, map operations, `link.AttachXDP` |
| `github.com/vishvananda/netlink` | v1.3.1 | Classic TC clsact qdisc and BPF filter management |
| `golang.org/x/sys` | v0.37.0 | `unix.ETH_P_ALL`, `unix.EEXIST` (transitive) |

`tc_egress.c` uses `SEC("tc")` (classic TC hook). `cilium/ebpf/link` only
supports `AttachTCX` for the newer TCX hook (kernel ≥ 6.6), so
`vishvananda/netlink` is required for classic TC filter management.

---

## Code Generation

`pkg/bpf/gen.go` holds two `//go:generate` directives that invoke `bpf2go`:

```
go generate ./pkg/bpf/
# or
make generate
```

This compiles both C source files with `clang -O2 -g -target bpf -Wall` and
embeds the resulting ELF objects as Go byte literals, producing per-endian
source files:

| Generated file | Contents |
|----------------|----------|
| `tc_egress_bpfel.go` | `TcEgressObjects`, `TcEgressPrograms`, `TcEgressMaps`, `LoadTcEgressObjects()` |
| `tc_egress_bpfeb.go` | big-endian variant |
| `xdp_ingress_bpfel.go` | `XdpIngressObjects`, `XdpIngressPrograms`, `XdpIngressMaps`, `LoadXdpIngressObjects()` |
| `xdp_ingress_bpfeb.go` | big-endian variant |

> **Note:** `loader.go` references these generated types and will not compile
> until `make generate` has been run on a BPF-capable Linux host.

---

## Types — pkg/bpf/types.go

### `ScionPathEntry`

Go mirror of `struct scion_path_entry` from `bpf/maps.h`. Field order, sizes,
and alignment match the C struct exactly (284 bytes, no padding) so
`cilium/ebpf` can serialise it directly into the `scion_path_cache` map.

```go
type ScionPathEntry struct {
    NextHopIP  [4]byte    // IP of SCION Core AS border router
    NextHopMAC [6]byte    // L2 next-hop address
    PathLen    uint16     // Valid byte count in HopFields
    HopFields  [256]byte  // Serialised SCION info + hop fields
    MACKey     [16]byte   // AES-CMAC key for hop field verification
}
```

### Helpers

| Function | Description |
|----------|-------------|
| `IPToKey(ip net.IP) (uint32, error)` | Converts an IPv4 address to the `uint32` map key that the eBPF program stores when reading `iph->saddr`. Uses `binary.NativeEndian` to match the kernel's in-memory representation. |
| `IPFromKey(key uint32) net.IP` | Inverse of `IPToKey`; useful for map dump debugging. |

---

## Loader — pkg/bpf/loader.go

`Loader` wraps the bpf2go-generated objects and exposes the lifecycle and map
API consumed by `cmd/cilion-agent`.

### Struct

```go
type Loader struct {
    tcObjs  TcEgressObjects    // generated — programs + maps for tc_egress
    xdpObjs XdpIngressObjects  // generated — programs + maps for xdp_ingress
    xdpLink link.Link          // cilium/ebpf XDP link handle
}
```

> **Map sharing note:** `pod_policy_map` and `scion_path_cache` are defined in
> both ELF objects (via `bpf/maps.h`). After `Load()`, each object holds
> independent kernel map instances. The TC objects' maps are used as the
> canonical write targets. **TODO:** pin maps to bpffs and use
> `CollectionOptions.MapReplacements` so TC and XDP operate on a single shared
> kernel map instance.

### Methods

| Method | Description |
|--------|-------------|
| `New() *Loader` | Allocate a zero-value Loader. |
| `Load() error` | Call `LoadTcEgressObjects` + `LoadXdpIngressObjects` with default options. |
| `AttachTC(ifaceName string) error` | 1. Resolve interface. 2. Ensure `clsact` qdisc (EEXIST ignored). 3. Add direct-action BPF filter on egress. |
| `DetachTC(ifaceName string) error` | List egress filters, remove the one named `"tc_egress"`. |
| `AttachXDP(ifaceName string) error` | `link.AttachXDP` in generic/SKB mode (compatible with all drivers including virtual interfaces). |
| `UpdatePodPolicy(podIP net.IP, policyID uint32) error` | Insert/replace entry in `pod_policy_map`. |
| `DeletePodPolicy(podIP net.IP) error` | Remove entry from `pod_policy_map`. |
| `UpdateScionPath(policyID uint32, entry *ScionPathEntry) error` | Insert/replace entry in `scion_path_cache`. |
| `DeleteScionPath(policyID uint32) error` | Remove entry from `scion_path_cache`. |
| `Close()` | Detach XDP link, close all program and map file descriptors. TC filters must be removed via `DetachTC` before calling `Close`. |

---

## Makefile Targets

| Target | Command | Description |
|--------|---------|-------------|
| `generate` | `go generate ./pkg/bpf/` | Compile C sources and emit generated Go bindings. |
| `bpf` | `make generate && clang …` | Run generation, then compile `.o` objects. |

---

## Usage Example (cilion-agent)

```go
import bpfpkg "github.com/martenwallewein/cilion/pkg/bpf"

loader := bpfpkg.New()
if err := loader.Load(); err != nil {
    log.Fatal(err)
}
defer loader.Close()

// Attach TC egress to each Pod veth, XDP ingress to the physical NIC.
loader.AttachTC("veth-pod-abc123")
loader.AttachXDP("eth0")

// When the K8s controller sees a new Pod:
loader.UpdatePodPolicy(net.ParseIP("10.0.1.5"), 42)

// When the SCION path watcher has a fresh path:
loader.UpdateScionPath(42, &bpfpkg.ScionPathEntry{
    NextHopIP:  [4]byte{198, 51, 100, 42},
    NextHopMAC: [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
    PathLen:    64,
    // HopFields and MACKey populated by pkg/scion path translation logic.
})
```

---

## Verification Steps

1. `go get github.com/cilium/ebpf@latest github.com/vishvananda/netlink@latest` — resolve deps.
2. `make generate` — runs `bpf2go`, produces `*_bpfel.go` files.
3. `go build ./pkg/bpf/` — succeeds after generation.
4. `go vet ./pkg/bpf/` — no issues.
