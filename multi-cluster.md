Here is the comprehensive architectural design document for the **CilION Multi-Cluster Routing** mechanism. You can use this directly as the core documentation (e.g., `ARCHITECTURE.md`) for your repository.

***

# 🌍 CilION: Multi-Cluster eBPF/SCION Routing Architecture

**CilION** (Cilium + SCION) provides Application-Aware, Cryptographic WAN Routing for Kubernetes. By leveraging eBPF and the SCION Next-Generation Internet architecture, CilION extends Kubernetes network policies across the global public internet, completely bypassing the limitations and vulnerabilities of standard BGP.

This document details the exact multi-cluster routing architecture, explaining how CilION interacts with the underlying CNI (Cilium), the Linux kernel, and the SCION network.

---

## 1. The Core Paradigm: Native Routing & Underlay Interception

The biggest challenge in multi-cluster networking is that CNIs (like Cilium) typically wrap cross-cluster traffic in encrypted overlays (VXLAN or IPsec). Once a packet is encapsulated, external routing logic cannot see which Pod sent it, making Application-Aware WAN routing impossible.

**The CilION Solution:**
CilION operates alongside **Cilium in Native Routing Mode** (with tunnels like VXLAN explicitly disabled). 
1. Cilium handles local pod routing, security identities, and L3-L7 firewalls.
2. Because VXLAN is disabled, Cilium sends cross-cluster packets out of the node's physical interface (e.g., `enp7s0` or `eth0`) in **absolute cleartext** (Standard IPv4).
3. CilION attaches an eBPF program to the **physical interface**, intercepting these raw Pod IPs *microseconds* before they hit the wire, and encapsulates them in SCION-over-UDP.

This creates a perfect separation of concerns: **Cilium manages the K8s Overlay; CilION manages the SCION Underlay.**

---

## 2. The Control Plane (Intent vs. State)

To prevent a "thundering herd" of nodes querying the SCION network simultaneously, CilION splits its control plane into a Global Controller and Local Agents, synchronized entirely via Kubernetes CRDs.

### A. The Global Controller (Deployment)
*   **Role:** The brain of the cluster.
*   **Action:** Watches user-defined `ScionPathPolicy` CRDs. When a user requests a specific route (e.g., *"Low latency to EU"*), the Controller queries the global SCION Control Service.
*   **State Generation:** It mathematically computes the SCION cryptographic hop fields and saves them back into the Kubernetes API as a system-level CRD: `ScionComputedPath`.

### B. The Node Agent (Privileged DaemonSet)
*   **Role:** The kernel injector.
*   **Action:** Runs on every worker node. It watches local Pod scheduling and the `ScionComputedPath` CRDs.
*   **Map Injection:** It compiles the active paths and injects them directly into the Linux Kernel's eBPF maps (e.g., `pod_policy_map`), mapping a specific local Pod IP directly to a raw SCION byte array. The Agent has *zero* communication with the external SCION network.

---

## 3. The eBPF Datapath: Step-by-Step Packet Walkthrough

Imagine **Pod A (`10.244.1.5`)** on Cluster 1 wants to communicate with **Pod B (`10.244.2.50`)** on Cluster 2. 

### Step 1: Egress from the Pod
Pod A initiates a TCP connection to `10.244.2.50`. The packet leaves the Pod's network namespace and hits the `veth` interface (`lxc*`) on the worker node.

### Step 2: Cilium Processing (The Firewall)
Cilium’s eBPF program on the `lxc` interface evaluates the packet. It verifies that Pod A is allowed to talk to Pod B (Zero-Trust Network Policy). Since it is, Cilium allows the packet and hands it to the Linux routing table.

### Step 3: Linux Routing (The Handoff)
The Linux kernel looks up `10.244.2.50`. Because we use Native Routing (and have configured our cloud provider routes, e.g., in Hetzner), the kernel routes the packet to the physical interface (`enp7s0`).

### Step 4: CilION Egress Interception (The eBPF TC Hook)
Exactly as the packet enters the physical interface's egress queue, the **CilION `tc` eBPF program** catches it.
1.  **Parse:** eBPF reads the cleartext Inner Source IP (`10.244.1.5`).
2.  **Map Lookup:** eBPF queries the `pod_policy_map` (O(1) time).
3.  **Match:** It finds that `10.244.1.5` has a highly specific SCION path assigned to it.

### Step 5: SCION Encapsulation (The Transformation)
Using `bpf_skb_adjust_room()`, the CilION eBPF program pushes a massive new header onto the packet:
*   It writes the SCION Common Header and the Cryptographic Hop Fields (fetched from the map).
*   It wraps the SCION header in an Outer UDP/IPv4 header.
*   **Crucial:** It overwrites the Outer Destination IP to the public IP of the **SCION Transit Provider (Border Router)**.

**The Packet Transformation:**
```text
BEFORE CilION (Cleartext Pod IP):
[ MAC ] [ IP: 10.244.1.5 -> 10.244.2.50 ] [ TCP Payload ]

AFTER CilION (SCION-over-UDP):
[ MAC ] [ IP: Host IP -> SCION Transit IP ] [ UDP Port 30041 ] [ SCION Headers & Path ] [ IP: 10.244.1.5 -> 10.244.2.50 ] [ TCP Payload ]
```

### Step 6: Global SCION Transit
The packet leaves the Hetzner network and hits the SCION Transit Provider. From this point on, **BGP is bypassed**. The global internet routers look *only* at the SCION Header to forward the packet across international ISPs, following the exact geographic path mathematically dictated by the Global Controller.

### Step 7: Ingress Decapsulation (XDP / TC Ingress)
The packet arrives at Cluster 2's worker node.
1.  The **CilION XDP (or TC Ingress) eBPF program** catches the incoming UDP port 30041 packet.
2.  It mathematically validates the SCION MAC to prove the packet wasn't spoofed.
3.  It strips off the Outer IP, UDP, and SCION headers entirely.
4.  It hands the pristine, original IP packet (`10.244.1.5 -> 10.244.2.50`) up to the Linux networking stack.
5.  Cilium takes over, completely unaware that the packet traversed the SCION internet, applies its ingress policies, and delivers it to Pod B.

---

## 4. Why This Architecture Wins

1.  **No Chokepoints (Fully Distributed):** There are no centralized "SCION Gateways." Every worker node encapsulates its own traffic at the kernel level, operating at line-rate speeds.
2.  **Application-Aware WAN:** Because we intercept the *cleartext Pod IP* before encryption/encapsulation, we can map specific K8s labels (e.g., `app: database`) to physical internet paths (e.g., low-latency dark fiber).
3.  **Hetzner / Cloud Native:** By aligning with the cloud provider's Native Routing (L3 routing tables) instead of fighting it with L2 overlays, CilION ensures maximum compatibility and performance on bare-metal clouds.
4.  **Bulletproof Sync:** The Controller/Agent CRD synchronization model (`ScionComputedPath`) guarantees that if the SCION Control plane goes offline, the local nodes continue routing traffic using the last known good cryptographic paths.

----

### 1. Extending Cluster Mesh: From "Blind Transit" to "Path Control"
**Cilium natively:** Cilium Cluster Mesh solves IP synchronization, service discovery, and identity sharing across multiple clusters. However, it relies on standard IPsec/WireGuard tunnels thrown over the public internet (BGP). If a BGP route flaps or takes a high-latency geographic detour, Cilium cannot prevent it.

**CilION Extension:** CilION uses Cilium Cluster Mesh as the foundation (to sync Pod IPs) but intercepts the cross-cluster traffic at the exact moment it leaves the node. 
*   **IP-to-ASN Resolution:** CilION introduces the `ScionClusterPeer` CRD. When Cilium says *"Route this to remote Pod 10.2.1.50"*, the CilION Agent realizes that IP falls under the `10.2.0.0/16` CIDR mapped to SCION `ISD-AS 64-ffaa:0:1102`.
*   **Cryptographic Transit:** Instead of a blind VPN tunnel, CilION’s eBPF datapath encapsulates the packet with a highly specific SCION cryptographic path. The cluster now actively dictates the physical internet hops the cross-cluster traffic will take.

### 2. Extending Network Policy: Cryptographic Geofencing
**Cilium natively:** Cilium’s `CiliumNetworkPolicy` allows you to enforce zero-trust security based on labels (e.g., `frontend` can talk to `backend`) or DNS names, rather than brittle IP addresses.

**CilION Extension:** CilION introduces a completely new dimension to Kubernetes network policies: **Physical Geography and Path Constraints**.
*   Using the `ScionPathPolicy` CRD, K8s administrators can extend label-based policies into the physical world. 
*   **Example:** A database pod (`app: db-sync`) can be mathematically constrained to only use transit paths that remain entirely within the European Union (`requireISDs: [ 64 ]`). This makes GDPR compliance a network-level guarantee, something standard Cilium cannot do.

### 3. Extending Identity: Security Without VPNs
**Cilium natively:** Cilium attaches a 32-bit security identity to every packet, allowing the receiving node to apply L3-L7 firewall rules without needing the source IP. Over the WAN, this identity is preserved by wrapping the traffic in IPsec/WireGuard.

**CilION Extension:** Because SCION supports **Extension Headers**, CilION can embed the internal Cilium Security Identity directly into the SCION packet header.
*   This achieves **Identity-Aware WAN Routing without heavy mTLS or VPN encapsulations**. 
*   The receiving cluster’s XDP hook reads the SCION extension header, validates the cryptographic MAC (proving it wasn't spoofed over the internet), extracts the Cilium identity, and passes it cleanly to the local Cilium policy engine.

### 4. Extending the Datapath: Egress & Ingress Symbiosis
**Cilium natively:** Uses `veth` attachments, TC hooks, and XDP for local routing and Load Balancing (e.g., Maglev, DSR).

**CilION Extension:** CilION layers seamlessly *on top* of Cilium’s eBPF hooks without conflicting.
*   **Egress (TC Egress Hook):** After Cilium has done its local processing and determined the packet is destined for a remote cluster, CilION’s TC hook catches it. It performs a Longest-Prefix Match (LPM) lookup in the `pod_policy_map` to find the SCION path, pushes the SCION-over-UDP headers onto the `skb`, and sends it to the Transit Provider.
*   **Ingress (XDP Hook):** CilION intercepts incoming SCION packets at the lowest possible level (the NIC driver). It mathematically validates the SCION MAC, strips the UDP/SCION headers, and hands a clean, native IPv4 packet up to the standard Linux networking stack—where Cilium takes over, completely unaware that the packet just traversed the global SCION internet.

---

### The Symbiotic Flow: How a Packet Travels using Cilium + CilION

Imagine Pod A (Cluster 1) wants to talk to Pod B (Cluster 2).

1.  **Service Discovery (Cilium):** Pod A resolves the service name. Cilium Cluster Mesh provides the IP of Pod B (`10.2.1.50`).
2.  **Routing Match (CilION Agent):** The CilION Agent reads the `ScionClusterPeer` CRD and maps `10.2.1.50` to SCION AS `64-ffaa:0:1102`.
3.  **Path Selection (CilION Agent):** The Agent reads the K8s labels of Pod A (`app: sensitive-data`). It matches a `ScionPathPolicy` demanding a low-latency, dark-fiber path. The Agent fetches this specific path from the SCION daemon and writes it to the local node's eBPF map.
4.  **Local Execution (Cilium eBPF):** Pod A sends the packet. Cilium’s eBPF program applies local egress firewall rules.
5.  **WAN Encapsulation (CilION eBPF):** Right before the packet leaves the physical node interface, CilION’s eBPF program encapsulates it with the chosen SCION header.
6.  **Global Transit (SCION):** The internet routes the packet over the exact ISPs dictated by the header. BGP is bypassed.
7.  **Decapsulation (CilION eBPF):** Cluster 2's worker node receives the packet. CilION's XDP hook strips the SCION header and verifies authenticity.
8.  **Local Delivery (Cilium eBPF):** The clean inner packet is passed to Cilium on Cluster 2, which applies local ingress policies and delivers it to Pod B.

By combining the two, you get the ultimate K8s networking stack: **Cilium manages the applications and security; CilION manages the physics of the global internet.**


# 🌍 Multi-Cluster Pod-to-Pod Communication: Existing Approaches vs. CilION

Moving from a single Kubernetes cluster to a multi-cluster, multi-cloud architecture introduces significant networking complexity. Connecting a pod in Cluster A directly to a pod in Cluster B across the Wide Area Network (WAN) requires crossing NAT boundaries, bridging disparate networks, and securing data in transit.

This document outlines the general challenges of multi-cluster networking, how the industry currently solves them, and how **CilION** introduces a paradigm shift by leveraging the SCION architecture.

---

## 1. General Challenges in Multi-Cluster Communication

Before two pods in different geographic locations can communicate, the network architecture must solve several fundamental problems:

1.  **IP Address Management (IPAM) & Overlap:** Clusters must be provisioned with non-overlapping Pod and Service CIDRs. If Cluster A and Cluster B both assign `10.1.x.x` to their pods, direct L3 communication is impossible without complex NAT translations.
2.  **Service Discovery & Endpoint Sync:** Kubernetes has no native concept of "remote" clusters. If Pod A wants to talk to Pod B, Cluster A's DNS and routing tables must somehow learn the exact IP address of Pod B.
3.  **Identity Preservation:** In zero-trust networks, firewall rules are based on labels (e.g., `app: frontend`), not IPs. When traffic leaves a cluster, it typically passes through NAT gateways, losing its source IP and making remote identity verification extremely difficult.
4.  **WAN Transit & Path Control:** The public internet relies on BGP (Border Gateway Protocol). Packets leaving the cluster are subjected to unpredictable latency, BGP hijacks, and geographic detours over which Kubernetes has absolutely zero control.

---

## 2. How Existing Approaches Solve This

The industry currently solves connectivity, encryption, and identity, but *fails* to solve WAN Transit. 

### A. CNI-Level Meshing (L3/L4)
*   **Examples:** Cilium ClusterMesh, Submariner.
*   **How it works:** These tools create encrypted overlay networks (VXLAN/WireGuard/IPsec) between clusters. Cilium uses a shared `etcd` database to sync Pod IPs and identities across clusters. 
*   **Pros:** Bare-metal eBPF performance; preserves zero-trust identity; transparent to the application.
*   **Cons:** **Blind Transit.** The encrypted tunnels are thrown over the standard BGP internet. If an ISP cable is cut or a BGP route is hijacked, the tunnel drops. You have no control over the physical path the data takes.

### B. Service Meshes (L7 Proxies)
*   **Examples:** Istio Multi-Cluster, Linkerd.
*   **How it works:** Injects an Envoy sidecar into every pod. Cross-cluster traffic is routed through local proxies, out to an East-West Gateway, across the internet via mTLS, and into a remote Gateway.
*   **Pros:** Advanced L7 routing (retries, circuit breaking), strong mTLS identity spanning multiple networks.
*   **Cons:** **Massive Overhead.** A single hop requires traversing multiple user-space proxies, adding significant latency and CPU overhead. Still reliant on standard BGP transit.

### C. Infrastructure Underlays
*   **Examples:** AWS VPC Peering, DirectConnect, Tailscale/Wireguard overlays.
*   **How it works:** Pushes the multi-cluster routing down to the cloud provider hardware or external VPN nodes.
*   **Pros:** Fast and stable.
*   **Cons:** **Context Loss.** The cloud router doesn't know what a Kubernetes Pod is. You cannot apply label-based policies. Direct cloud interconnects are also prohibitively expensive.

---

## 3. How CilION Solves This (The Next-Generation WAN)

CilION delegates local IPAM and Service Discovery to existing tools (like Cilium ClusterMesh), and focuses entirely on solving the missing piece: **Application-Aware WAN Path Control**.

Because standard K8s networking knows nothing about SCION Autonomous Systems (ASNs) or Isolation Domains (ISDs), CilION introduces a Control Plane Service to bridge K8s IP routing with SCION cryptographic routing.

### The Mechanism: K8s CIDR to SCION ISD-AS Mapping
To route a packet to a remote pod, the CilION eBPF datapath needs to know the SCION destination and the cryptographic path to get there. This is solved via the **`ScionClusterPeer` CRD**.

```yaml
apiVersion: cilion.io/v1alpha1
kind: ScionClusterPeer
metadata:
  name: azure-cluster-b
spec:
  remoteISD: 64
  remoteAS: "ffaa:0:1102"
  podCIDRs: 
    - "10.2.0.0/16"       # Pod subnet of Cluster B
```

### The CilION Multi-Cluster Workflow
1.  **IP Synchronization (The Base Layer):** Cilium ClusterMesh (or a custom CilION endpoint watcher) syncs the remote Pod IPs so `frontend-pod` (Cluster A) knows the IP of `backend-pod` (`10.2.1.50` in Cluster B).
2.  **Control Plane Translation (The DaemonSet):**
    *   The CilION Go Agent reads the `ScionClusterPeer` CRD. 
    *   It sees that any IP in `10.2.0.0/16` belongs to SCION AS `64-ffaa:0:1102`.
    *   It queries the local SCION daemon (`sciond`) for active, cryptographic paths to that AS.
    *   It compiles the SCION Path Headers and pushes a Longest-Prefix Match (LPM) entry into the kernel's eBPF maps mapping `10.2.0.0/16` to the raw SCION headers.
3.  **eBPF Datapath Interception (Egress):**
    *   A packet from the local pod destined for `10.2.1.50` hits the `eth0` `tc` egress hook.
    *   CilION's eBPF program performs an LPM map lookup and instantly retrieves the SCION path.
    *   The packet is encapsulated in SCION-over-UDP and fired over the physical wire.
4.  **SCION Transit:** The packet routes across global SCION Transit Providers based purely on the cryptographic path embedded by eBPF, completely bypassing BGP routing tables.
5.  **eBPF Decapsulation (Ingress):** The receiving node in Cluster B catches the packet at the `XDP` hook, validates the MAC, strips the SCION header, and hands the clean IP packet to the local CNI for delivery to `10.2.1.50`.

### The CilION Advantage
By separating IP discovery from WAN transit, CilION achieves the holy grail of multi-cluster networking:
*   **Zero-Trust Identity:** Compatible with Cilium's identity embedding.
*   **eBPF Performance:** No heavy Envoy proxies or Gateway bottlenecks.
*   **BGP-Bypass:** Total geographic and physical control over how cross-cluster traffic traverses the internet.

Yes, this is **absolutely possible in practice**, but it touches on one of the most notoriously tricky areas of eBPF development: **Program Chaining and Coexistence**.

When you have two massive networking applications (Cilium and CilION) fighting for the same kernel hooks (`TC` and `XDP` on `eth0`), you cannot just blindly attach them. If Cilium processes a packet and returns an "accept" or "redirect" code (like `TC_ACT_OK` or `XDP_REDIRECT`), the kernel halts the chain, and your CilION program might never see the packet.

To ensure packets are processed in the correct order, you have **two practical architectural approaches**. The first is the "Modern eBPF" approach, and the second is the "Linux Routing" approach (which is highly recommended for building this without forking Cilium).

---

### Approach 1: The "Virtual Interface" Method (Highly Recommended)

Instead of fighting Cilium on the exact same `eth0` hook, you use standard Linux routing to elegantly hand off the packet between the two systems. You create a virtual interface (e.g., a `tun`/`dummy` device called `cilion_wg` or `cilion0`).

**The Egress Flow (Cilium -> CilION):**
1. **The Route:** The CilION Agent injects a route into the host's Linux routing table: *"Traffic for remote Cluster B (`10.2.0.0/16`) goes to device `cilion0`"*.
2. **Cilium's Job:** Pod A sends a packet. Cilium’s eBPF program on the pod's `veth` interface evaluates Network Policies, applies the security identity, and looks up the route. It sees the destination is via `cilion0`. Cilium says, *"Great, I'm done, send it to `cilion0`."*
3. **CilION's Job:** Your CilION eBPF program is attached to the `TC Egress` hook of `cilion0` (where it has exclusive control). It intercepts the packet, performs the SCION-over-UDP encapsulation, changes the destination IP to the SCION Transit Provider, and routes it out `eth0`. 

*Why this is perfect:* It creates a strict, un-hackable boundary. Cilium completes 100% of its logic before CilION ever touches the packet.

---

### Approach 2: The Modern eBPF Chaining Method (TCX & libxdp)

If you strictly want to run everything on the physical `eth0` interface for absolute maximum bare-metal performance, you must use modern eBPF chaining frameworks.

#### 1. Ingress (XDP): Using `libxdp`
On Ingress, the order must be **CilION First -> Cilium Second**. 
CilION needs to catch the SCION/UDP packet, validate the cryptographic MAC, strip the headers, and reveal the inner IP packet so Cilium can process it normally.

Historically, the Linux kernel only allowed one XDP program per interface. To solve this, the community built `libxdp` (the XDP Dispatcher). 
* Cilium natively supports `libxdp` for multi-program coexistence.
* When your CilION Agent loads its XDP program, it uses `libxdp` to attach it with a **higher priority number** (e.g., Priority 10). Cilium runs at a lower priority (e.g., Priority 50).
* CilION strips the header and returns `XDP_PASS`. The `libxdp` dispatcher then automatically feeds the modified packet into Cilium's XDP program.

#### 2. Egress (TC): Using `tcx` (TC eXpress)
On Egress, the order must be **Cilium First -> CilION Second**.
Historically, if you attached two `clsact` filters to TC and the first one returned `TC_ACT_OK`, the kernel stopped evaluating.

However, in **Linux Kernel 6.6+**, the kernel introduced **`tcx` (TC eXpress)**.
* `tcx` is the modern replacement for the old `qdisc` TC hooks. It natively supports multi-program attachment with explicit ordering.
* Your Go Agent would attach your egress program using the `BPF_F_AFTER` flag (or an equivalent priority mechanism), explicitly telling the kernel: *"Run my SCION encapsulation program only after Cilium's egress program finishes."*

---

### The Verdict for CilION Development

For a research and development initiative, **Approach 1 (Virtual Interface Handoff) is the industry standard for safely extending CNIs.** 

This is exactly how tools like Tailscale, WireGuard, and even some of Cilium's own IPsec implementations work. They don't try to cram everything into `eth0`. They create a virtual device, let the CNI route to it, and do the heavy cryptographic encapsulation on the virtual device's eBPF hook before kicking it out to the physical wire.

By doing this, you guarantee that:
1. You won't accidentally break Cilium's internal state machine.
2. Cilium will naturally handle the local K8s Service Load Balancing *before* you encapsulate it.
3. You bypass the nightmare of debugging kernel return codes clashing between two different eBPF objects.