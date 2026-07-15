#ifndef _HEADERS_
#define _HEADERS_

const bit<24> PTHR = 162500;    // Pthr
const bit<24> kPTHR = 1625000;    // k * Pthr
const bit<2> RHO_LINE_RATE = 2;   // rho * line_rate Bytes/ns
const bit<19> IsEMPTY_THRESHOLD = 37;   // rho * line_rate Bytes/ns

#define PPASS_PORT 9001

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;
const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;

typedef bit<48>   mac_addr_t;
typedef bit<32>   ipv4_addr_t;

/* Standard ethernet header */
header ethernet_h {
    mac_addr_t    dst_addr;
    mac_addr_t    src_addr;
    bit<16>  ether_type;
}

header ipv4_h {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      total_len;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      frag_offset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdr_checksum;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;
}

header tcp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<4>   res;
    bit<8>   flags;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header ppass_h {
    bit<8>     msg_type;    //0:credit_req 1:credit 2:request 3:reply
    bit<4>     host_marked;
    bit<4>     nw_marked;
    bit<32>    credit_req;
    bit<32>    credit;
    bit<16>    ingress_port;
}

struct headers_t {
    ethernet_h          ethernet;
    ipv4_h              ipv4;
    tcp_h               tcp;
    udp_h               udp;
    ppass_h           ppass;
}

#endif /* _HEADERS_ */