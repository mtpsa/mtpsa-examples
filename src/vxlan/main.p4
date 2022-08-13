#include <mtpsa.p4>

const bit<16> ETHERTYPE_IP4  = 0x0800;

const bit<8> IPPROTO_TCP  = 6;
const bit<8> IPPROTO_UDP  = 17;

const bit<16> VXLAN_UDP_DPORT = 4789;

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

header vxlan_t {
    bit<8>  flags;
    bit<24> reserved;
    bit<24> vni;
    bit<8>  reserved2;
}

struct empty_metadata_t { }
struct metadata_t { }

struct headers_t {
    ethernet_t       outer_ethernet;
    ipv4_t           outer_ipv4;
    udp_t            outer_udp;
    vxlan_t          vxlan;
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
        transition select(hdr.udp.dport) {
            VXLAN_UDP_DPORT: parse_vxlan;
            default: accept;
        }
    }
    state parse_vxlan {
        packet.extract(hdr.vxlan);
        transition accept;
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

    action add_vxlan(bit<16> user_id) {
        hdr.outer_ethernet.setValid();
        hdr.outer_ethernet.dst_addr = hdr.ethernet.dst_addr;
        hdr.outer_ethernet.src_addr = hdr.ethernet.src_addr;
        hdr.outer_ethernet.type = hdr.ethernet.type;

        hdr.outer_ipv4.setValid();
        hdr.outer_ipv4.version = hdr.ipv4.version;
        hdr.outer_ipv4.ihl = hdr.ipv4.ihl;
        hdr.outer_ipv4.diffserv = hdr.ipv4.diffserv;
        hdr.outer_ipv4.totalLen = hdr.ipv4.totalLen;
        hdr.outer_ipv4.identification = hdr.ipv4.identification;
        hdr.outer_ipv4.flags = hdr.ipv4.flags;
        hdr.outer_ipv4.fragOffset = hdr.ipv4.fragOffset;
        hdr.outer_ipv4.ttl = hdr.ipv4.ttl;
        hdr.outer_ipv4.hdrChecksum = hdr.ipv4.hdrChecksum;
        hdr.outer_ipv4.src_addr = hdr.ipv4.src_addr;
        hdr.outer_ipv4.dst_addr = hdr.ipv4.dst_addr;

        hdr.outer_ipv4.protocol = IPPROTO_UDP;

        hdr.outer_udp.setValid();
        hdr.outer_udp.sport = VXLAN_UDP_DPORT;
        hdr.outer_udp.dport = VXLAN_UDP_DPORT;

        hdr.vxlan.setValid();
        hdr.vxlan.vni = (bit<24>)user_id;
        hdr.vxlan.flags = 1;
        hdr.vxlan.reserved = 0;
        hdr.vxlan.reserved2 = 0;
    }

    table add_vxlan_header {
        key = {
            istd.ingress_port: ternary;
            hdr.ethernet.src_addr: ternary;
            hdr.ethernet.dst_addr: ternary;
            hdr.ethernet.type: ternary;
            hdr.ipv4.src_addr: ternary;
            hdr.ipv4.dst_addr: ternary;
            hdr.tcp.sport: ternary;
            hdr.tcp.dport: ternary;
            hdr.udp.sport: ternary;
            hdr.udp.dport: ternary;
        }
        actions = {
            add_vxlan;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        ostd.drop = false;
        if (!hdr.vxlan.isValid()) {
            add_vxlan_header.apply();
        }
        ostd.user_id = hdr.vxlan.vni[15:0];
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
        packet.emit(hdr.outer_ethernet);
        packet.emit(hdr.outer_ipv4);
        packet.emit(hdr.outer_udp);
        packet.emit(hdr.vxlan);
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
        transition parse_outer_ethernet;
    }

    state parse_outer_ethernet {
        packet.extract(hdr.outer_ethernet);
        transition select(hdr.outer_ethernet.type) {
            ETHERTYPE_IP4: parse_outer_ipv4;
            default: accept;
        }
    }

    state parse_outer_ipv4 {
        packet.extract(hdr.outer_ipv4);
        transition select(hdr.outer_ipv4.protocol) {
            IPPROTO_UDP: parse_outer_udp;
            default: accept;
        }
    }

    state parse_outer_udp {
        packet.extract(hdr.outer_udp);
        transition select(hdr.outer_udp.dport) {
            VXLAN_UDP_DPORT: parse_vxlan;
            default: accept;
        }
    }

    state parse_vxlan {
        packet.extract(hdr.vxlan);
        transition accept;
    }
}

control egress(inout headers_t hdr,
               inout metadata_t user_meta,
               in    mtpsa_egress_input_metadata_t  istd,
               inout mtpsa_egress_output_metadata_t ostd)
{
    action remove_vxlan() {
        hdr.vxlan.setInvalid();
        hdr.outer_udp.setInvalid();
        hdr.outer_ipv4.setInvalid();
        hdr.outer_ethernet.setInvalid();
    }

    table remove_vxlan_header {
        key = {
            hdr.outer_ethernet.dst_addr: exact;
            istd.egress_port: exact;
        }
        actions = {
            remove_vxlan;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        remove_vxlan_header.apply();
    }
}

control EgressDeparserImpl(packet_out packet,
                           out empty_metadata_t clone_e2e_meta,
                           out empty_metadata_t recirculate_meta,
                           inout headers_t hdr,
                           in metadata_t meta,
                           in mtpsa_egress_output_metadata_t istd,
                           in mtpsa_egress_deparser_input_metadata_t edstd)
{
    apply {
        packet.emit(hdr.outer_ethernet);
        packet.emit(hdr.outer_ipv4);
        packet.emit(hdr.outer_udp);
        packet.emit(hdr.vxlan);
    }
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
