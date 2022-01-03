#include <mtpsa_user.p4>

typedef bit<48> EthernetAddress_t;
const bit<8> PROTO_TCP  = 6;

/*
 * P4 Calculator
 *
 * This program implements a simple protocol. It can be carried over Ethernet
 * (Ethertype 0x1234).
 *
 * The Protocol header looks like this:
 *
 *        0                1                  2              3
 * +----------------+----------------+----------------+---------------+
 * |      P         |       4        |     Version    |     Op        |
 * +----------------+----------------+----------------+---------------+
 * |                              Operand A                           |
 * +----------------+----------------+----------------+---------------+
 * |                              Operand B                           |
 * +----------------+----------------+----------------+---------------+
 * |                              Result                              |
 * +----------------+----------------+----------------+---------------+
 *
 * P is an ASCII Letter 'P' (0x50)
 * 4 is an ASCII Letter '4' (0x34)
 * Version is currently 0.1 (0x01)
 * Op is an operation to Perform:
 *   '+' (0x2b) Result = OperandA + OperandB
 *   '-' (0x2d) Result = OperandA - OperandB
 *   '&' (0x26) Result = OperandA & OperandB
 *   '|' (0x7c) Result = OperandA | OperandB
 *   '^' (0x5e) Result = OperandA ^ OperandB
 *
 * The device receives a packet, performs the requested operation, fills in the
 * result and sends the packet back out of the same port it came in on, while
 * swapping the source and destination addresses.
 *
 * If an unknown operation is specified or the header is not valid, the packet
 * is dropped
 */


/*
 * This is a custom protocol header for the calculator. We'll use
 * ethertype 0x1234 for is (see parser)
 */
const bit<16> P4CALC_ETYPE = 0x1234;
const bit<8>  P4CALC_P     = 0x50;   // 'P'
const bit<8>  P4CALC_4     = 0x34;   // '4'
const bit<8>  P4CALC_VER   = 0x01;   // v0.1
const bit<8>  P4CALC_PLUS  = 0x2b;   // '+'
const bit<8>  P4CALC_MINUS = 0x2d;   // '-'
const bit<8>  P4CALC_AND   = 0x26;   // '&'
const bit<8>  P4CALC_OR    = 0x7c;   // '|'
const bit<8>  P4CALC_CARET = 0x5e;   // '^'

header p4calc_t {
    bit<8>  op;
    bit<32> operand_a;
    bit<32> operand_b;
    bit<32> res;
}

header ethernet_t {
    EthernetAddress_t dst_addr;
    EthernetAddress_t src_addr;
    bit<16>           type;
}

struct empty_metadata_t { }
struct metadata_t { }

struct headers_t {
    ethernet_t   ethernet;
    p4calc_t     p4calc;
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
            P4CALC_ETYPE: parse_p4calc;
            default: accept;
        }
    }

      state parse_p4calc {
          packet.extract(hdr.p4calc);
          transition accept;
      }
}

control ingress(inout headers_t hdr,
                     inout metadata_t user_meta,
                     in    mtpsa_input_metadata_t  istd,
                     inout mtpsa_output_metadata_t ostd)
{

    action send_back(bit<32> result) {
        bit<48> tmp;

        /* Put the result back in */
        hdr.p4calc.res = result;

        /* Swap the MAC addresses */
        tmp = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = hdr.ethernet.src_addr;
        hdr.ethernet.src_addr = tmp;

        /* Send the packet back to the port it came from */
        send_to_port(ostd, (PortId_t) 32w4);
    }

    action operation_add() {
        send_back(hdr.p4calc.operand_a + hdr.p4calc.operand_b);
    }

    action operation_sub() {
        send_back(hdr.p4calc.operand_a - hdr.p4calc.operand_b);
    }

    action operation_and() {
        send_back(hdr.p4calc.operand_a & hdr.p4calc.operand_b);
    }

    action operation_or() {
        send_back(hdr.p4calc.operand_a | hdr.p4calc.operand_b);
    }

    action operation_xor() {
        send_back(hdr.p4calc.operand_a ^ hdr.p4calc.operand_b);
    }

    action operation_drop() {
        mark_to_drop(ostd);
    }

    table calculate {
        key = {
            hdr.p4calc.op : exact;
        }
        actions = {
            operation_add;
            operation_sub;
            operation_and;
            operation_or;
            operation_xor;
            operation_drop;
        }

        const default_action = operation_drop();
        const entries = {
            P4CALC_PLUS : operation_add();
            P4CALC_MINUS: operation_sub();
            P4CALC_AND  : operation_and();
            P4CALC_OR   : operation_or();
            P4CALC_CARET: operation_xor();
        }
    }

    apply {
        if (hdr.p4calc.isValid()) {
            calculate.apply();
        } else {
            operation_drop();
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
        packet.emit(hdr.p4calc);
    }
}

MTPSA_User_Switch(
    ParserImpl(),
    ingress(),
    DeparserImpl()
) main;
