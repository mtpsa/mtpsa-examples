#include <mtpsa_user.p4>

const bit<16> ETHERTYPE_IP4  = 0x0800;
const bit<16> ETHERTYPE_IP6  = 0x86dd;

const bit<8> PROTO_ICMP = 1;
const bit<8> PROTO_TCP  = 6;
const bit<8> PROTO_UDP  = 17;

typedef bit<48> EthernetAddress_t;

typedef bit<48> ByteCounter_t;
typedef bit<32> PacketCounter_t;
typedef bit<80> PacketByteCounter_t;

const bit<32> NUM_PORTS = 512;


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

header ipv6_t {
    bit<4>   version;
    bit<8>   trafficClass;
    bit<20>  flowLabel;
    bit<16>  payloadLen;
    bit<8>   nextHdr;
    bit<8>   hopLimit;
    bit<128> src_addr;
    bit<128> dst_addr;
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

header icmp_t {
    bit<8>  icmp_type;
    bit<8>  icmp_code;
    bit<16> checksum;
    bit<16> identifier;
    bit<16> sequence_number;
    bit<64> timestamp;
}

struct empty_metadata_t { }
struct metadata_t { }

struct headers_t {
    ethernet_t       ethernet;
    ipv4_t           ipv4;
    ipv6_t           ipv6;
    icmp_t           icmp;
    tcp_t            tcp;
    udp_t            udp;
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
            ETHERTYPE_IP4: parse_ipv4;
            ETHERTYPE_IP6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP:  parse_tcp;
            PROTO_UDP:  parse_udp;
            PROTO_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMP: parse_icmp;
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

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
}

control ingress(inout headers_t hdr,
                inout metadata_t user_meta,
                in    mtpsa_input_metadata_t  istd,
                inout mtpsa_output_metadata_t ostd)
{
    Counter<ByteCounter_t, PortId_t>(NUM_PORTS, MTPSA_CounterType_t.BYTES) port_data;

    action ipv4_forward(PortId_t port) {
        send_to_port(ostd, port);
    }

    action drop() {
        mark_to_drop(ostd);
    }

    table ipv4_forward_table {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {

        /*
         * $ mtpsa_switch_CLI
         * RuntimeCmd: switch_context 1
         * RuntimeCmd: counter_read port_data 0
         */
        port_data.count(istd.port);

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
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
    }
}

MTPSA_User_Switch(
    ParserImpl(),
    ingress(),
    DeparserImpl()
) main;
