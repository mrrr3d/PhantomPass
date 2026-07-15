#include <core.p4>
#include <tna.p4>

#include "common/headers.p4"
#include "common/util.p4"


struct my_ingress_metadata_t {
}

parser EtherIPTCPUDPParser(packet_in        pkt,
    /* User */
    out headers_t          hdr
    )
{
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 :  parse_ipv4;
            default :  accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            PPASS_PORT: parse_ppass;
            default: accept;
        }
    }

    state parse_ppass {
        pkt.extract(hdr.ppass);
        transition accept;
    }
}

parser IngressParser(
        packet_in pkt,
        out headers_t hdr,
        out my_ingress_metadata_t meta,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;
    EtherIPTCPUDPParser() layer4_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        layer4_parser.apply(pkt, hdr);
        transition accept;
    }
}

control Ingress(
    /* User */
    inout headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    //table forward
    action forward(PortId_t port){
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ppass.ingress_port = (bit<16>)ig_intr_md.ingress_port;
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.qid = 0;
    }
    action drop(){
        ig_dprsr_md.drop_ctl = 0x1;
    }

    table table_forward{
        key = {
            hdr.ipv4.dst_addr: exact;
        }

        actions = {
            forward;
            drop;
        }
        const default_action = drop();   
        size = 512;
    }

   apply {
        if (hdr.ipv4.isValid()) {
            table_forward.apply();
       }
    }
}

control IngressDeparser(packet_out pkt,
   /* User */
   inout headers_t                       hdr,
   in    my_ingress_metadata_t                      meta,
   /* Intrinsic */
   in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Checksum() ipv4_checksum;
   apply {

        if(hdr.ipv4.isValid()){
            // update the IPv4 checksum
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        }
        pkt.emit(hdr);
   }
}


struct my_egress_metadata_t {
    bit<32> pkt_credit;
    bit<32> pkt_len;
    bit<24> pqlen;
    bit<32> interval;
    bit<32> reduce_unit;
    bit<32> ppass_unit;
    bit<24> nw_marked;
    bit<19> is_empty;
}

parser EgressParser(packet_in        pkt,
   /* User */
   out headers_t          hdr,
   out my_egress_metadata_t         meta_eg,
   /* Intrinsic */
   out egress_intrinsic_metadata_t  eg_intr_md)
{
   /* This is a mandatory state, required by Tofino Architecture */
    EtherIPTCPUDPParser() layer4_parser;
    state start {
       pkt.extract(eg_intr_md);
       layer4_parser.apply(pkt,hdr);
       transition accept;
   }
}


control Egress(
   /* User */
   inout headers_t                          hdr,
   inout my_egress_metadata_t                         meta_eg,
   /* Intrinsic */
   in    egress_intrinsic_metadata_t                  eg_intr_md,
   in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
   inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
   inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    action get_reduce_uint_action(){
        meta_eg.reduce_unit = meta_eg.interval << RHO_LINE_RATE;
    }
    table get_reduce_uint{
        actions = { get_reduce_uint_action;}
        default_action = get_reduce_uint_action();
        size = 1;
    }
    action get_ppass_uint_action(){
        meta_eg.ppass_unit = meta_eg.reduce_unit - meta_eg.pkt_len;
    }
    table get_ppass_uint{
        actions = { get_ppass_uint_action;}
        default_action = get_ppass_uint_action();
        size = 1;
    }
    action nw_marked_action(){
        meta_eg.nw_marked = min(PTHR, meta_eg.pqlen);
    }
    table nw_marked_table{
        actions = { nw_marked_action;}
        default_action = nw_marked_action();
        size = 1;   
    }
    action is_empty_action(){
        meta_eg.is_empty = min(IsEMPTY_THRESHOLD, eg_intr_md.deq_qdepth);
    }
    table is_empty_table{
        actions = { is_empty_action;}
        default_action = is_empty_action();
        size = 1;   
    }
    //timestamp:
    Register<bit<32>,bit<9>> (32,0) Timestamp_Reg;
    RegisterAction<bit<32>,bit<9>,bit<32>> (Timestamp_Reg) get_and_update_timestamp = {
        void apply(inout bit<32> value,out bit<32> result){ 
            result = eg_prsr_md.global_tstamp[31:0] - value;
            value = eg_prsr_md.global_tstamp[31:0];
        }
    }; 

     //Phantom Queue
    Register<bit<32>,bit<9>> (32,0) Phantom_Queue_Reg;
    RegisterAction<bit<32>,bit<9>,bit<32>> (Phantom_Queue_Reg) ppass_credit_pkt_action = {
        void apply(inout bit<32> value,out bit<32> result){
            if(value + meta_eg.pkt_credit > (bit<32>)kPTHR){
                value = (bit<32>)kPTHR;
            }
            else{
                value = value + meta_eg.pkt_credit;
            }
        }
    };
    RegisterAction<bit<32>,bit<9>,bit<32>> (Phantom_Queue_Reg) ppass_other_pkt_action = {
        void apply(inout bit<32> value,out bit<32> result){
            if(value < meta_eg.ppass_unit){
                value = 0;
            }
            else{
                value = value - meta_eg.ppass_unit;
            }
            result = value;
        }
    };


   apply {
	   if(hdr.ppass.isValid()){
            if(hdr.ppass.msg_type == 0x1){
                meta_eg.pkt_credit = hdr.ppass.credit;
                ppass_credit_pkt_action.execute((bit<9>)hdr.ppass.ingress_port);
            }
            else{
                meta_eg.pkt_len = (bit<32>)hdr.ipv4.total_len;
                meta_eg.interval = get_and_update_timestamp.execute((bit<9>)eg_intr_md.egress_port);
                get_reduce_uint.apply();
                get_ppass_uint.apply();
                meta_eg.pqlen = (bit<24>)ppass_other_pkt_action.execute((bit<9>)eg_intr_md.egress_port);
                nw_marked_table.apply();
                is_empty_table.apply();
                if(meta_eg.nw_marked == PTHR && meta_eg.is_empty == IsEMPTY_THRESHOLD){
                    hdr.ppass.nw_marked = 0x1;
                }
            }
  	    }
   }
}

control EgressDeparser(packet_out pkt,
   /* User */
   inout headers_t                       hdr,
   in    my_egress_metadata_t                      meta_eg,
   /* Intrinsic */
   in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
   apply {
        pkt.emit(hdr);
   }
}

/************ F I N A L   P A C K A G E ******************************/
Pipeline(
   IngressParser(),
   Ingress(),
   IngressDeparser(),
   EgressParser(),
   Egress(),
   EgressDeparser()
) pipe;
Switch(pipe) main;
