// Stub for bpf2go-generated bindings for xdp_ingress.c.
// Run 'go generate ./pkg/bpf/' (requires clang) to replace this file with the
// real output that embeds the compiled xdp_ingress_bpfel.o ELF.

package bpf

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
)

// XdpIngressObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadXdpIngressObjects or ebpf.CollectionSpec.LoadAndAssign.
type XdpIngressObjects struct {
	XdpIngressPrograms
	XdpIngressMaps
}

func (o *XdpIngressObjects) Close() error {
	return _XdpIngressClose(
		o.XdpIngress,
		o.PodPolicyMap,
		o.ScionPathCache,
	)
}

// XdpIngressPrograms contains all programs after they have been loaded into the kernel.
type XdpIngressPrograms struct {
	XdpIngress *ebpf.Program `ebpf:"xdp_ingress"`
}

func (p *XdpIngressPrograms) Close() error {
	return _XdpIngressClose(p.XdpIngress)
}

// XdpIngressMaps contains all maps after they have been loaded into the kernel.
// Both maps are also present in TcEgressMaps; the TC object's FDs are the
// canonical write targets. See the Loader comment in loader.go.
type XdpIngressMaps struct {
	PodPolicyMap   *ebpf.Map `ebpf:"pod_policy_map"`
	ScionPathCache *ebpf.Map `ebpf:"scion_path_cache"`
}

func (m *XdpIngressMaps) Close() error {
	return _XdpIngressClose(m.PodPolicyMap, m.ScionPathCache)
}

// LoadXdpIngressObjects loads the xdp_ingress eBPF programs and maps into the kernel.
//
// _XdpIngressBytes must be populated (via bpf2go's //go:embed) before calling
// this. Until 'go generate ./pkg/bpf/' has been run, this returns an error.
func LoadXdpIngressObjects(obj *XdpIngressObjects, opts *ebpf.CollectionOptions) error {
	if len(_XdpIngressBytes) == 0 {
		return fmt.Errorf("xdp_ingress eBPF object not compiled: run 'go generate ./pkg/bpf/'")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(_XdpIngressBytes))
	if err != nil {
		return fmt.Errorf("load xdp_ingress: %w", err)
	}
	return spec.LoadAndAssign(obj, opts)
}

// _XdpIngressBytes holds the compiled ELF blob for xdp_ingress.
// bpf2go replaces this variable with a //go:embed xdp_ingress_bpfel.o directive.
var _XdpIngressBytes []byte

// _XdpIngressClose closes each non-nil eBPF object, returning the first error.
func _XdpIngressClose(closers ...interface{ Close() error }) error {
	for _, c := range closers {
		if err := c.Close(); err != nil {
			return err
		}
	}
	return nil
}
