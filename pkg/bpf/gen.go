// Package bpf provides Go bindings for the CilION eBPF programs and the
// Loader that attaches them to network interfaces.
//
// Run `go generate ./pkg/bpf/` (or `make generate`) to compile the C sources
// and embed the resulting ELF objects as typed Go code.
package bpf

// bpf2go compiles tc_egress.c and emits TcEgressObjects / TcEgressPrograms /
// TcEgressMaps wrappers together with the ELF embedded as a []byte literal.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -target bpf -Wall" -go-package bpf TcEgress ../../bpf/tc_egress.c -- -I../../bpf -I../../pkg/bpf/headers

// bpf2go compiles xdp_ingress.c and emits XdpIngressObjects / XdpIngressPrograms /
// XdpIngressMaps wrappers.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -target bpf -Wall" -go-package bpf XdpIngress ../../bpf/xdp_ingress.c -- -I../../bpf -I../../pkg/bpf/headers
