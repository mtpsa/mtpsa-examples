#include <mtpsa_user.p4>

typedef bit<48> EthernetAddress_t;
const bit<8> PROTO_TCP  = 6;

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


struct empty_metadata_t { }
struct metadata_t { }

struct headers_t {
    ethernet_t       ethernet;
    ipv4_t           ipv4;
    tcp_t            tcp;
}

parser ParserImpl(packet_in packet,
                  out headers_t hdr,
                  inout metadata_t user_meta,
                  in mtpsa_parser_input_metadata_t istd)
{
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.type) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }


}

control ingress(inout headers_t hdr,
                     inout metadata_t user_meta,
                     in    mtpsa_input_metadata_t  istd,
                     inout mtpsa_output_metadata_t ostd)
{
    action ipv4_forward(PortId_t port) {
        send_to_port(ostd, port);
    }

    table ipv4_forward_table {
        key = {
            hdr.ipv4.dst_addr: lpm;
            hdr.tcp.sport[0:0]: exact;
        }
        actions = {
            ipv4_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.ethernet.isValid()) {
            ipv4_forward_table.apply();
        }
    }
}

control DeparserImpl(packet_out packet,
                     out empty_metadata_t normal_meta,
                     inout headers_t hdr,
                     in metadata_t meta,
                     in mtpsa_output_metadata_t istd)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

MTPSA_User_Switch(
    ParserImpl(),
    ingress(),
    DeparserImpl()
) main;
