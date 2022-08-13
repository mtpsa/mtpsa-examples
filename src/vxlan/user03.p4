#include <mtpsa_user.p4>

typedef bit<48> EthernetAddress_t;

header ethernet_t {
    EthernetAddress_t dst_addr;
    EthernetAddress_t src_addr;
    bit<16>           type;
}

struct empty_metadata_t { }
struct metadata_t { }

struct headers_t {
    ethernet_t       ethernet;
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
        transition accept;
    }
}

control PipelineImpl(inout headers_t hdr,
                     inout metadata_t user_meta,
                     in    mtpsa_input_metadata_t  istd,
                     inout mtpsa_output_metadata_t ostd)
{
    action forward(PortId_t port) {
        send_to_port(ostd, port);
    }

    table forward_table {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.ethernet.isValid()) {
            forward_table.apply();
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
    }
}

MTPSA_User_Switch(
    ParserImpl(),
    PipelineImpl(),
    DeparserImpl()
) main;
