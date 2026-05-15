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

## 4. Benefits

1.  **No Chokepoints (Fully Distributed):** There are no centralized "SCION Gateways." Every worker node encapsulates its own traffic at the kernel level, operating at line-rate speeds.
2.  **Application-Aware WAN:** Because we intercept the *cleartext Pod IP* before encryption/encapsulation, we can map specific K8s labels (e.g., `app: database`) to physical internet paths (e.g., low-latency dark fiber).
3.  **Hetzner / Cloud Native:** By aligning with the cloud provider's Native Routing (L3 routing tables) instead of fighting it with L2 overlays, CilION ensures maximum compatibility and performance on bare-metal clouds.
4.  **Bulletproof Sync:** The Controller/Agent CRD synchronization model (`ScionComputedPath`) guarantees that if the SCION Control plane goes offline, the local nodes continue routing traffic using the last known good cryptographic paths.

