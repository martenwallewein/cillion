# 🌌 Project Cillion

**eBPF-Powered Application-Aware WAN Routing for Kubernetes**

## Overview
**Cillion** (Cilium + SCION) is a research Container Network Interface (CNI) and Cloud-WAN architecture. It extends the micro-segmentation and high-performance eBPF dataplane of standard Kubernetes networking out into the global Wide Area Network (WAN) by integrating the **[SCION Internet Architecture](https://scion-architecture.net/)**.

Traditionally, a K8s CNI hands packets off to the host's default gateway, treating the internet as a "dumb," untrusted pipe subject to BGP hijacks, congestion, and geographic unpredictability. 

CilION flips this paradigm. By turning every Kubernetes worker node into a distributed **SCION Border Router (BR)** via eBPF, CilION empowers the cluster to actively participate in global routing. It allows Kubernetes administrators to cryptographically dictate the exact physical ISPs and geographic paths their inter-cluster traffic will take, directly mapped to application labels.

## Architecture
![Cilion WAN and Local Architecture Overview](docs/cilion-architecture.svg "Cilion WAN and Local Architecture Overview")

## Why CilION?
*   **BGP-Bypass:** Inter-cluster traffic paths are explicitly defined by eBPF. The underlay internet (BGP) is only used as a link-local hop to reach the SCION network, rendering your traffic immune to BGP hijacks and routing leaks.
*   **Application-Aware WAN Routing:** Standard networks send all node traffic over the same ISP. CilION can send `app: billing` traffic over a low-latency dark fiber path, and `app: video` over a public internet multipath, originating from the *exact same host*.
*   **Cryptographic Geofencing:** Mathematically guarantee that cross-cloud data replication stays within specific geographic boundaries (e.g., GDPR compliance).
*   **Zero-Trust Identity Extension:** CilION embeds the internal Kubernetes security identity into the SCION Extension Header, allowing L4-L7 network policies to span globally without standard VPN appliances.

## High-Level Architecture
1.  **The Edge AS:** The Kubernetes cluster acts as a SCION "Edge" Autonomous System (AS). 
2.  **The Distributed Egress:** There is no centralized SCION Gateway bottleneck. Every worker node runs native eBPF programs attached to `tc` and `XDP` hooks, processing SCION encapsulations at line rate.
3.  **The Transit Uplink:** Nodes route SCION-over-UDP packets to global SCION Transit Providers (Core ASes), fully connecting the cluster to the next-generation internet.

## Roadmap and Current Status
Cilion is currently in an early stage, we're tackling the technical challenges at architectual level before implementing the core feature set.

Current Status: Active Prototyping
- [x] [Architecture setup and WAN routing defined](./multi-cluster.md).
- [x] [Technical specification](./specification.md)
- [x] Kubebuilder setup and operator basics
- [ ] Connect SCION Control Plane to controller
- [ ] Kubernetes Operator scaffolding (WIP).
- [ ] eBPF XDP/tc hook design for SCION packet encapsulation (WIP).
- [ ] Datapath testing and eBPF map integration.

## Other links
Please see the following documentation to understand the architecture and research goals:
*   [🌍 Sophisticated Use Cases](use-cases.md)

---
*Project CilION is a research initiative exploring the intersection of eBPF kernel programming and next-generation cryptographic internet architectures.*
