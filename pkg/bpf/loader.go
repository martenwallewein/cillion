package bpf

// loader.go wrappers the bpf2go-generated objects (TcEgressObjects,
// XdpIngressObjects) and provides a clean API for the cilion-agent to:
//   - load both eBPF programs from their embedded ELF objects,
//   - attach them to network interfaces, and
//   - update / delete entries in the shared eBPF maps.
//
// Prerequisites: run `go generate ./pkg/bpf/` (or `make generate`) before
// building; the generated *_bpfel.go files must exist for this file to compile.

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Loader owns the loaded eBPF programs, their map file descriptors, and the
// kernel link handles that keep the programs attached.
//
// Map ownership: pod_policy_map and scion_path_cache are defined in both ELF
// objects (they share bpf/maps.h). After Load(), each object holds independent
// kernel map instances. The TC objects' maps are used as the canonical write
// targets; the XDP program reads the same logical maps but via separate FDs.
// TODO: pin maps to bpffs and pass them via CollectionOptions.MapReplacements
//
//	so TC and XDP operate on a single shared kernel map.
type Loader struct {
	tcObjs  TcEgressObjects
	xdpObjs XdpIngressObjects
	xdpLink link.Link
}

// New allocates a zero-value Loader. Call Load() before any other method.
func New() *Loader {
	return &Loader{}
}

// Load reads both eBPF ELF objects from their embedded byte literals and
// instantiates the kernel programs and maps.
func (l *Loader) Load() error {
	if err := LoadTcEgressObjects(&l.tcObjs, nil); err != nil {
		return fmt.Errorf("load tc_egress: %w", err)
	}
	if err := LoadXdpIngressObjects(&l.xdpObjs, nil); err != nil {
		l.tcObjs.Close()
		return fmt.Errorf("load xdp_ingress: %w", err)
	}
	return nil
}

// AttachTC attaches the TC egress program to ifaceName using a classic clsact
// qdisc and a direct-action BPF filter. Safe to call when the qdisc already
// exists (EEXIST is ignored).
func (l *Loader) AttachTC(ifaceName string) error {
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("AttachTC: link %q not found: %w", ifaceName, err)
	}

	// Ensure a clsact qdisc exists on the interface.
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("AttachTC: add clsact qdisc on %q: %w", ifaceName, err)
	}

	fd := l.tcObjs.TcEgressPrograms.TcEgress.FD()
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           fd,
		Name:         "tc_egress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("AttachTC: add BPF filter on %q: %w", ifaceName, err)
	}
	return nil
}

// DetachTC removes the CilION BPF filter and the clsact qdisc from ifaceName.
func (l *Loader) DetachTC(ifaceName string) error {
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("DetachTC: link %q not found: %w", ifaceName, err)
	}
	filters, err := netlink.FilterList(iface, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return fmt.Errorf("DetachTC: list filters on %q: %w", ifaceName, err)
	}
	for _, f := range filters {
		if bf, ok := f.(*netlink.BpfFilter); ok && bf.Name == "tc_egress" {
			if err := netlink.FilterDel(bf); err != nil {
				return fmt.Errorf("DetachTC: del filter on %q: %w", ifaceName, err)
			}
		}
	}
	return nil
}

// AttachXDP attaches the XDP ingress program to ifaceName in generic (SKB)
// mode, which works on all drivers including virtual interfaces.
func (l *Loader) AttachXDP(ifaceName string) error {
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("AttachXDP: link %q not found: %w", ifaceName, err)
	}
	l.xdpLink, err = link.AttachXDP(link.XDPOptions{
		Program:   l.xdpObjs.XdpIngressPrograms.XdpIngress,
		Interface: iface.Attrs().Index,
		Flags:     link.XDPGenericMode, // SKB mode; use XDPDriverMode for production NICs
	})
	if err != nil {
		return fmt.Errorf("AttachXDP: attach to %q: %w", ifaceName, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Map operations — pod_policy_map
// ---------------------------------------------------------------------------

// UpdatePodPolicy maps a Pod's IPv4 address to a SCION policy ID.
func (l *Loader) UpdatePodPolicy(podIP net.IP, policyID uint32) error {
	key, err := IPToKey(podIP)
	if err != nil {
		return err
	}
	return l.tcObjs.TcEgressMaps.PodPolicyMap.Put(key, policyID)
}

// DeletePodPolicy removes a Pod's entry from the policy map.
func (l *Loader) DeletePodPolicy(podIP net.IP) error {
	key, err := IPToKey(podIP)
	if err != nil {
		return err
	}
	return l.tcObjs.TcEgressMaps.PodPolicyMap.Delete(key)
}

// ---------------------------------------------------------------------------
// Map operations — scion_path_cache
// ---------------------------------------------------------------------------

// UpdateScionPath stores or replaces the pre-computed SCION path for a policy ID.
func (l *Loader) UpdateScionPath(policyID uint32, entry *ScionPathEntry) error {
	return l.tcObjs.TcEgressMaps.ScionPathCache.Put(policyID, entry)
}

// DeleteScionPath removes a SCION path cache entry.
func (l *Loader) DeleteScionPath(policyID uint32) error {
	return l.tcObjs.TcEgressMaps.ScionPathCache.Delete(policyID)
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// Close detaches the XDP link and closes all program and map file descriptors.
// TC filters must be removed explicitly via DetachTC before calling Close.
func (l *Loader) Close() {
	if l.xdpLink != nil {
		l.xdpLink.Close()
	}
	l.tcObjs.Close()
	l.xdpObjs.Close()
}
