# 📝 CilION Implementation Plan (To-Dos)

## Phase 1: Environment Setup & Scaffolding
*Goal: Get the basic tools installed and a simulated environment running.*

- [x] **Initialize the Project:**
  - Run `go mod init github.com/yourusername/cilion`.
  - Create the directory structure outlined in the project architecture.
- [x] **Install eBPF Toolchain:**
  - Install `clang`, `llvm`, `libbpf-dev`, and `bpftool` on your Linux development machine.
- [x] **Setup KinD (Kubernetes in Docker):**
  - Write a bash script (`test/kind/setup.sh`) to spin up two local KinD clusters (Cluster A and Cluster B). 
  - **Note:** Leave the default CNI (`kindnet`) enabled so it can handle IPAM and local `veth` wiring. CilION will run as an overlay on top of it.
- [ ] **Setup Local SCION Topology:**
  - Clone the official `scion-proto/scion` repository. Add as submodule.
  - Run their local topology generator to create a simulated 3-AS network on your host machine.
- [x] **Makefile eBPF Compilation:**
  - `make bpf/tc_egress.o` — compiles `bpf/tc_egress.c` into `bpf/tc_egress.o` via `clang -O2 -target bpf`.
  - `make bpf/xdp_ingress.o` — compiles `bpf/xdp_ingress.c` into `bpf/xdp_ingress.o` via `clang -O2 -target bpf`.
  - `make bpf` — builds both objects.

## Phase 2: The eBPF Data Plane (Static Encapsulation)
*Goal: Successfully wrap a packet in a SCION header using eBPF, bypassing the Go control plane for now.*

- [ ] **Define C Headers (`bpf/headers/scion.h`):**
  - Write the C structs for the SCION Common Header, Address Header, and Path Header.
- [ ] **Define eBPF Maps (`bpf/maps.h`):**
  - Create the `pod_policy_map` (Key: Pod IP, Value: Policy ID).
  - Create the `scion_path_cache` (Key: Policy ID, Value: Raw SCION Header Bytes).
- [ ] **Write TC Egress Program (`bpf/tc_egress.c`):**
  - Parse the Ethernet, IPv4, and UDP headers of outgoing packets.
  - Implement a basic map lookup using the source IP.
  - Use `bpf_skb_adjust_room()` to expand the packet buffer.
  - Inject a **hardcoded** SCION-over-UDP header (copy a valid hex dump from Wireshark/SCION tools).
  - Recalculate the outer IP and UDP checksums using `bpf_l3_csum_replace()` and `bpf_l4_csum_replace()`.
- [ ] **Write XDP Ingress Program (`bpf/xdp_ingress.c`):**
  - Intercept UDP port 30041.
  - Strip the outer IP, UDP, and SCION headers using `bpf_xdp_adjust_head()`.
  - Pass the inner IP packet up the stack to the base CNI.
- [ ] **Manual Testing:**
  - Load the eBPF programs manually via `bpftool` or `tc` CLI onto a `veth` interface.
  - Ping from a pod, capture traffic with `tcpdump`, and verify the SCION header is correctly formed.

## Phase 3: The Go Control Plane (K8s to eBPF Sync)
*Goal: Write the agent that listens to K8s and populates the eBPF maps dynamically.*

- [ ] **Generate eBPF Go Bindings:**
  - Use the `cilium/ebpf/cmd/bpf2go` tool to automatically generate Go code from your `tc_egress.c` and `xdp_ingress.c` files.
- [ ] **Initialize the CilION Agent (`cmd/cilion-agent`):**
  - Write the startup logic to watch for `veth` interfaces created by the base CNI and attach the TC eBPF program to them.
  - Attach the XDP program to the host's physical interface (`eth0`).
- [ ] **Build the Kubernetes Controller (`pkg/controller`):**
  - Use `controller-runtime` (or raw `client-go`) to watch the Kubernetes API for `Pod` creations/deletions.
  - When a Pod is assigned an IP, push its IP and a default Policy ID into the `pod_policy_map` via Go.
- [ ] **Create the CRDs (`api/v1alpha1`):**
  - Define the `ScionLink` and `ScionPathPolicy` structs.
  - Generate the Kubernetes CRD manifests.

## Phase 4: SCION Integration
*Goal: Connect the agent to the real SCION network to fetch dynamic paths.*

- [ ] **Implement the SCION Client (`pkg/scion`):**
  - Import `github.com/scionproto/scion/pkg/daemon`.
  - Write a function that connects to the local `sciond` API.
  - Request available paths to a remote AS (e.g., Cluster B's AS).
- [ ] **Path Translation (`pkg/datapath`):**
  - Write logic to take a `snet.Path` (from the SCION Go library) and serialize it into the exact raw byte array required by your C `scion_path_entry` struct.
  - Push this byte array into the eBPF `scion_path_cache` map.
- [ ] **Implement App-Aware Routing logic:**
  - Update the Kubernetes Controller to read `ScionPathPolicy` CRDs.
  - Filter the paths fetched from `sciond` based on the CRD constraints (e.g., latency, allowed ASes).
  - Update the eBPF maps with the chosen path.

## Phase 5: Advanced eBPF & Cryptography
*Goal: Handle the hardest technical hurdles for a production-ready datapath.*

- [ ] **Dynamic AES-MAC Generation (The Boss Fight):**
  - SCION requires a MAC to validate hop fields.
  - *Option A (Easier):* Pre-compute the MAC in Go (userspace) for the specific path and push it to the eBPF map. (Good for static paths).
  - *Option B (Harder, Ideal):* Implement AES-CMAC directly in eBPF C code using kernel crypto APIs or lightweight implementations to compute it per-packet.
- [ ] **MTU Clamping (TCP MSS):**
  - The SCION header adds ~50-100 bytes. Standard 1500 MTU packets will drop.
  - Update `tc_egress.c` to parse TCP SYN packets and modify the TCP MSS option down to ~1350 bytes to prevent WAN fragmentation.
- [ ] **Cilium Identity Embedding:**
  - Modify the datapath to append a SCION End-to-End (E2E) Extension header.
  - Embed a mock "Security Identity ID" in this header on Egress.
  - Extract and log it on Ingress.

## Phase 6: Finalization & Demo
- [ ] **End-to-End Test:**
  - Deploy Cluster A and Cluster B via KinD.
  - Deploy CilION DaemonSet to both.
  - Deploy an Nginx pod on B, curl it from A.
  - Verify traffic flows over the local SCION topology.
- [ ] **Link Failover Test:**
  - Manually kill one of the SCION links in your local topology.
  - Verify the Go control plane detects it and updates the eBPF map, restoring the curl connection automatically.
- [ ] **Write Documentation:** Update README with compilation and deployment instructions.