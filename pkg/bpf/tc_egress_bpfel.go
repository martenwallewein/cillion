// Stub for bpf2go-generated bindings for tc_egress.c.
// Run 'go generate ./pkg/bpf/' (requires clang) to replace this file with the
// real output that embeds the compiled tc_egress_bpfel.o ELF.

package bpf

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
)

// TcEgressObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadTcEgressObjects or ebpf.CollectionSpec.LoadAndAssign.
type TcEgressObjects struct {
	TcEgressPrograms
	TcEgressMaps
}

func (o *TcEgressObjects) Close() error {
	return _TcEgressClose(
		o.TcEgress,
		o.PodPolicyMap,
		o.ScionPathCache,
	)
}

// TcEgressPrograms contains all programs after they have been loaded into the kernel.
type TcEgressPrograms struct {
	TcEgress *ebpf.Program `ebpf:"tc_egress"`
}

func (p *TcEgressPrograms) Close() error {
	return _TcEgressClose(p.TcEgress)
}

// TcEgressMaps contains all maps after they have been loaded into the kernel.
type TcEgressMaps struct {
	PodPolicyMap   *ebpf.Map `ebpf:"pod_policy_map"`
	ScionPathCache *ebpf.Map `ebpf:"scion_path_cache"`
}

func (m *TcEgressMaps) Close() error {
	return _TcEgressClose(m.PodPolicyMap, m.ScionPathCache)
}

// LoadTcEgressObjects loads the tc_egress eBPF programs and maps into the kernel.
//
// _TcEgressBytes must be populated (via bpf2go's //go:embed) before calling
// this. Until 'go generate ./pkg/bpf/' has been run, this returns an error.
func LoadTcEgressObjects(obj *TcEgressObjects, opts *ebpf.CollectionOptions) error {
	if len(_TcEgressBytes) == 0 {
		return fmt.Errorf("tc_egress eBPF object not compiled: run 'go generate ./pkg/bpf/'")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(_TcEgressBytes))
	if err != nil {
		return fmt.Errorf("load tc_egress: %w", err)
	}
	return spec.LoadAndAssign(obj, opts)
}

// _TcEgressBytes holds the compiled ELF blob for tc_egress.
// bpf2go replaces this variable with a //go:embed tc_egress_bpfel.o directive.
var _TcEgressBytes []byte

// _TcEgressClose closes each non-nil eBPF object, returning the first error.
// Nil-receiver safety is delegated to each type's own Close method.
func _TcEgressClose(closers ...interface{ Close() error }) error {
	for _, c := range closers {
		if err := c.Close(); err != nil {
			return err
		}
	}
	return nil
}
