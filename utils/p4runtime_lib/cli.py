#!/usr/bin/env python
from __future__ import print_function

import atexit
import readline
import argparse
import json
import os
import sys
import signal

from switch import Bmv2SwitchConnection
from helper import P4InfoHelper

def keyboardInterruptHandler(signal, frame):
    exit(0)

try: # Python 2/3 compatibility
    input = raw_input
except NameError:
    pass

def error(msg):
    print('\n[ERROR] ' + str(msg), file=sys.stderr)

def info(msg):
    print('\n[INFO] ' + str(msg), file=sys.stdout)

def _byteify(data):
    try: # Python 2/3 compatability
        unicode_string = unicode
    except:
        unicode_string = bytes
    if isinstance(data, unicode_string):
        return data.encode('utf-8')
    if isinstance(data, list):
        return [_byteify(item) for item in data]
    if isinstance(data, dict):
        return {
            _byteify(k): _byteify(v) for k, v in data.items()
        }
    return data

def parse_args():
    parser = argparse.ArgumentParser(description='P4Runtime Simple Controller')

    parser.add_argument("-i", '--p4info', help="path to input P4Info file",
                        type=str, action="store", required=True)

    args = parser.parse_args()
    if not os.path.exists(args.p4info):
        parser.error("File %s does not exist!" % args.p4info)
    return args


class ControllerCli(object):
    def __init__(self):
        self.args = parse_args()
        self.p4info_helper = P4InfoHelper(self.args.p4info)
        self.sw = None
        self.connect()

    def connect(self):
        info("Connecting to P4Runtime server ...")
        self.sw = Bmv2SwitchConnection()
        try:
            self.sw.MasterArbitrationUpdate()
        except:
            self.disconnect()
            exit(1)

    def insert_entry(self, table_name, action_name, action_params, match_fields, default_action=None, priority=None):
        table_entry = self.p4info_helper.buildTableEntry(
            table_name=table_name,
            match_fields=match_fields,
            default_action=default_action,
            action_name=action_name,
            action_params=action_params,
            priority=priority)
        self.sw.WriteTableEntry(table_entry)

    def disconnect(self):
        if self.sw:
            info("Disconnecting from P4Runtime server ...")
            self.sw.shutdown()
            self.sw = None


if __name__ == '__main__':
    signal.signal(signal.SIGINT, keyboardInterruptHandler)
    args = parse_args()

    readline.parse_and_bind('tab: complete')
    histfile = os.path.join(os.path.expanduser("~"), ".controller_cli_history")
    try:
        readline.read_history_file(histfile)
    except:
        pass

    atexit.register(readline.write_history_file, histfile)
    readline.set_history_length(50)

    ctr = ControllerCli()
    atexit.register(ctr.disconnect)

    while True:
        try:
            line = input('> ').strip()
        except (EOFError):
            exit(0)

        try:
            if line in ['exit', 'quit', 'q']:
                exit(0)
            elif line == 'clear':
                os.system('clear')
            elif line in ['history', 'h']:
                for i in range(1, readline.get_current_history_length()):
                    print(readline.get_history_item(i))
            elif line in ['history clear', 'hc']:
                readline.clear_history()
            elif line == 'table_add':
                table_name = input('table: ')
                action_name = input('action_name: ')
                action_params = _byteify(json.loads(input('action_params (json): ')))
                match_fields = _byteify(json.loads(input('match_fields (json): ')))
                priority = input('priority [None]: ') or None
                default_action=input('default_action [None]: ') or None

                if isinstance(priority, str):
                    priority = int(priority)

                ctr.insert_entry(
                    table_name,
                    action_name,
                    action_params,
                    match_fields,
                    priority,
                    default_action,
                )
            else:
                print(
                    "\nCommand".ljust(15) + "Description\n" +
                    "===============================================\n" +
                    "help".ljust(15) + "Print this message\n" +
                    "q, quit".ljust(15) + "Cause interactive terminal to exit\n" +
                    "clear".ljust(15) + "Clear screen\n" +
                    "table_add".ljust(15) + "Add entry to a match table\n"
                )
        except Exception as error_msg:
                error(error_msg)

