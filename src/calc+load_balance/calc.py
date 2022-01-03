#!/usr/bin/env python3

import re

from scapy.all import srp1, Packet, Ether, StrFixedLenField, IntField, bind_layers


class P4calc(Packet):
    name = "P4calc"
    fields_desc = [
        StrFixedLenField("op", "+", length=1),
        IntField("operand_a", 0),
        IntField("operand_b", 0),
        IntField("result", 0)
    ]


class NumParseError(Exception):
    pass


class OpParseError(Exception):
    pass


class Token:
    def __init__(self, type, value=None):
        self.type = type
        self.value = value


def num_parser(s, i, ts):
    pattern = "^\s*([0-9]+)\s*"
    match = re.match(pattern, s[i:])
    if match:
        ts.append(Token('num', match.group(1)))
        return i + match.end(), ts
    raise NumParseError('Expected number literal.')


def op_parser(s, i, ts):
    pattern = "^\s*([-+&|^])\s*"
    match = re.match(pattern, s[i:])
    if match:
        ts.append(Token('num', match.group(1)))
        return i + match.end(), ts
    raise OpParseError("Expected binary operator '-', '+', '&', '|', or '^'.")


def make_seq(p1, p2):
    def parse(s, i, ts):
        i, ts2 = p1(s, i, ts)
        return p2(s, i, ts2)
    return parse


if __name__ == '__main__':
    bind_layers(Ether, P4calc, type=0x1234)
    parser = make_seq(num_parser, make_seq(op_parser, num_parser))

    while True:
        user_input = input('> ')
        if user_input == "quit":
            break
        print(user_input)
        try:
            i, ts = parser(user_input, 0, [])
            pkt = Ether(dst='08:00:00:00:02:00', type=0x1234)
            pkt /= P4calc(
                op=ts[1].value,
                operand_a=int(ts[0].value),
                operand_b=int(ts[2].value)
            )
            pkt /= ' '

            pkt.show()
            resp = srp1(pkt, iface='eth0', timeout=1, verbose=False)
            if resp:
                p4calc = resp[P4calc]
                if p4calc:
                    print("Result: {}".format(p4calc.result))
                else:
                    print("cannot find P4calc header in the packet")
            else:
                print("Didn't receive response")
        except Exception as error:
            print(error)
