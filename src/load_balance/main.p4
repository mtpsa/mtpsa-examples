#include <mtpsa.p4>

const bit<16> ETHERTYPE_IP4  = 0x0800;

const bit<8> IPPROTO_TCP  = 6;
const bit<8> IPPROTO_UDP  = 17;

typedef bit<48> EthernetAddress_t;

header ethernet_t {
    EthernetAddress_t dst_addr;
    EthernetAddress_t src_addr;
    bit<16>           type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header tcp_t {
        bit<16> sport;
        bit<16> dport;
        bit<32> seq_no;
        bit<32> ack_no;
        bit<4>  data_offset;
        bit<3>  res;
        bit<3>  ecn;
        bit<6>  ctrl;
        bit<16> window;
        bit<16> checksum;
        bit<16> urgent_ptr;
}

header udp_t {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> checksum;
}

struct empty_metadata_t { }
struct metadata_t { }

struct headers_t {
    ethernet_t       ethernet;
    ipv4_t           ipv4;
    tcp_t            tcp;
    udp_t            udp;
}

parser IngressParserImpl(packet_in packet,
                         out headers_t hdr,
                         inout metadata_t user_meta,
                         in mtpsa_ingress_parser_input_metadata_t istd,
                         in empty_metadata_t resubmit_meta,
                         in empty_metadata_t recirculate_meta)
{
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.type) {
            ETHERTYPE_IP4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPPROTO_TCP: parse_tcp;
            IPPROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition  accept;
    }
}

control ingress(inout headers_t hdr,
                inout metadata_t user_meta,
                in    mtpsa_ingress_input_metadata_t  istd,
                inout mtpsa_ingress_output_metadata_t ostd)
{
    action drop() {
        ingress_drop(ostd);
    }

    action set_user_id(bit<16> user_id) {
        ostd.user_id = user_id;
    }

    table set_user_id_table {
        key = {
            istd.ingress_port: exact;
        }
        actions = {
            set_user_id;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        ostd.drop = false;
        set_user_id_table.apply();
    }
}

control IngressDeparserImpl(packet_out packet,
                            out empty_metadata_t clone_i2e_meta,
                            out empty_metadata_t resubmit_meta,
                            out empty_metadata_t normal_meta,
                            inout headers_t hdr,
                            in metadata_t meta,
                            in mtpsa_ingress_output_metadata_t istd)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

parser EgressParserImpl(packet_in packet,
                        out headers_t hdr,
                        inout metadata_t user_meta,
                        in mtpsa_egress_parser_input_metadata_t istd,
                        in empty_metadata_t normal_meta,
                        in empty_metadata_t clone_i2e_meta,
                        in empty_metadata_t clone_e2e_meta)
{
    state start {
        transition accept;
    }
}

control egress(inout headers_t hdr,
               inout metadata_t user_meta,
               in    mtpsa_egress_input_metadata_t  istd,
               inout mtpsa_egress_output_metadata_t ostd)
{
    apply { }
}

control EgressDeparserImpl(packet_out packet,
                           out empty_metadata_t clone_e2e_meta,
                           out empty_metadata_t recirculate_meta,
                           inout headers_t hdr,
                           in metadata_t meta,
                           in mtpsa_egress_output_metadata_t istd,
                           in mtpsa_egress_deparser_input_metadata_t edstd)
{
    apply { }
}

IngressPipeline(IngressParserImpl(), ingress(), IngressDeparserImpl()) ip;

MTPSA_Switch(
    ip,
    PacketReplicationEngine(),
    EgressParserImpl(),
    egress(),
    EgressDeparserImpl(),
    BufferingQueueingEngine()
) main;
