#ifndef SCION_H
#define SCION_H

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <endian.h>

// See SCION header specification:
struct scion_hdr
{
    __u32 info;        // version, qos, flow_id etc
    __u8 next_hdr;     // Next header pointer
    __u8 hdr_len;      // Length of scion header
    __u16 payload_len; // Packet payload len after scion header
    __u8 path_type;    // Type of the path
    __u8 dt : 2;       // Type of destination address
    __u8 dl : 2;       // Destination address length
    __u8 st : 2;       // Type of source address
    __u8 sl : 2;       // Source address length
    __u16 reserved;
};

struct scion_addr_hdr_v4
{
    __u16 dst_isd;       // Destination ISD
    __u64 dst_ia : 48;   // Destination IA (ISD-AS)
    __u16 src_isd;       // Source ISD
    __u64 src_ia : 48;   // Source IA (ISD-AS)
    __u32 dst_host_addr; // Destination host address
    __u32 src_host_addr; // Source host address
};

struct scion_addr_hdr_v6
{
    __u16 dst_isd;     // Destination ISD
    __u64 dst_ia : 48; // Destination IA (ISD-AS)
    __u16 src_isd;     // Source ISD
    __u64 src_ia : 48; // Source IA (ISD-AS)
    /* TODO: Find a matching type for 16byte int */
    __u32 dst_host_addr[4]; // Destination host address
    __u32 src_host_addr[4]; // Source host address
};

struct scion_path_meta_hdr
{
    __u8 cur_inf : 2;   // Current info field pointer. Points to the current info field in the path header.
    __u8 cur_hf : 6;    // Current hop field pointer. Points to the current hop field in the path header.
    __u8 rsv : 6;       // Reserved flags
    __u8 seg_0_len : 6; // Segment 0 length (up-segment length)
    __u8 seg_1_len : 6; // Segment 1 length (core-segment length)
    __u8 seg_2_len : 6; // Segment 2 length (down-segment length)

    // additional fields
    __u8 num_hf;  // Number of hop fields in the path header. This is used to determine the total number of hop fields in the path header, which is needed for parsing the path header.
    __u8 num_inf; // Number of info fields in the path header. This is used to determine the total number of info fields in the path header, which is needed for parsing the path header.
};

struct scion_info_field
{
    __u8 rsv : 6;         // Reserved flags
    __u8 peering : 1;     // Peering flag. If set to true, then the forwarding path is built as a peering path, which requires special processing on the dataplane.
    __u8 constr_dir : 1;  // Construction direction flag. If set to true then the hop fields are arranged in the direction they have been constructed during beaconing.
    __u8 rsv2 : 8;        // Reserved flags
    __u16 seg_id : 16;    // Id of the segment this info field belongs to.
    __u32 timestamp : 32; // For verification
};

struct scion_hop_field
{
    __u8 rsv : 8; // Reserved flags
    //__u8 cons_ingr_alert: 1;
    //__u8 cons_egr_alert: 1;
    __u16 cons_ingr_interface : 16; // Ingress interface ID of the hop field. This is used for forwarding the packet to the next hop.
    __u16 cons_egr_interface : 16;  // Egress interface ID of the hop field. This is used for forwarding the packet to the next hop.
    __u64 mac : 48;                 // MAC for verification. This is used for verifying the integrity of the path header and the authenticity of the path header. The MAC is computed over the entire path header, including the info fields and hop fields, but excluding the MAC field itself.
};

struct scion_br_info
{
    __u64 *mac_key;         // Local forwarding secret
    __u16 local_isd;        // Local ISD
    __u64 local_ia : 48;    // Local IA (ISD-AS)
    __u16 *link_ingr_ids;   // Ingress link IDs
    __u16 *link_egr_ids;    // Egress link IDs
    __u32 *link_ingr_ips;   // Ingress link IPs
    __u32 *link_egr_ips;    // Egress link IPs
    __u32 *link_egr_ports;  // Egress link ports
    __u32 *link_ingr_ports; // Ingress link ports
    __u32 num_links;
};

#define MIN_PACKET_SIZE 62    // 14 (eth) + 20 (IP) + 8 (UDP) + 12 (SCION) + 8 (UDP)
#define DISPATCHER_PORT 30041 // Fix, but might be omitted in future

#endif /* SCION_H */