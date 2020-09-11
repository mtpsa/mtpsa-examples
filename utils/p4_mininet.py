import os
import tempfile
import socket
from sys import exit

from mininet.net import Mininet
from mininet.node import Switch, Host
from mininet.moduledeps import pathCheck

class P4Host(Host):
    def config(self, **params):
        r = super(Host, self).config(**params)

        self.defaultIntf().rename("eth0")

        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload eth0 %s off" % off
            self.cmd(cmd)

        # disable IPv6
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

        return r

    def describe(self):
        print("**********\n%s\ndefault interface: %s\t%s\t%s\n**********" % (
                self.name,
                self.defaultIntf().name,
                self.defaultIntf().IP(),
                self.defaultIntf().MAC()
            )
        )

class P4Switch(Switch):
    """P4 virtual switch"""
    device_id = 0

    def __init__(self, name, sw_path = None, json_path = None,
                 thrift_port = None,
                 pcap_dump = False,
                 log_console = False,
                 verbose = False,
                 device_id = None,
                 enable_debugger = False,
                 user = None,
                 **kwargs):
        Switch.__init__(self, name, **kwargs)
        assert(sw_path)
        assert(json_path)
        # make sure that the provided sw_path is valid
        pathCheck(sw_path)
        # make sure that the provided JSON file exists
        if not os.path.isfile(json_path):
            print("Error: Invalid JSON file.\n")
            exit(1)
        self.sw_path = sw_path
        self.json_path = json_path
        self.verbose = verbose
        logfile = "/tmp/p4s.{}.log".format(self.name)
        self.output = open(logfile, 'w')
        self.thrift_port = thrift_port
        self.pcap_dump = pcap_dump
        self.enable_debugger = enable_debugger
        self.log_console = log_console
        self.user = user
        if device_id is not None:
            self.device_id = device_id
            P4Switch.device_id = max(P4Switch.device_id, device_id)
        else:
            self.device_id = P4Switch.device_id
            P4Switch.device_id += 1
        self.nanomsg = "ipc:///tmp/bm-{}-log.ipc".format(self.device_id)

    @classmethod
    def setup(cls):
        pass

    def check_switch_started(self, pid):
        """While the process is running (pid exists), we check if the Thrift
        server has been started. If the Thrift server is ready, we assume that
        the switch was started successfully. This is only reliable if the Thrift
        server is started at the end of the init process"""
        while True:
            if not os.path.exists(os.path.join("/proc", str(pid))):
                return False
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(0.5)
                result = sock.connect_ex(("localhost", self.thrift_port))
            finally:
                sock.close()
            if result == 0:
                return  True

    def start(self, controllers):
        "Start up a new P4 switch"
        print("Starting P4 switch {}.".format(self.name))
        args = [self.sw_path]
        for port, intf in self.intfs.items():
            if not intf.IP():
                args.extend(['-i', str(port) + "@" + intf.name])
        if self.pcap_dump:
            args += ["--pcap", self.pcap_dump]
        if self.thrift_port:
            args.extend(['--thrift-port', str(self.thrift_port)])
        if self.nanomsg:
            args.extend(['--nanolog', self.nanomsg])
        args.extend(['--device-id', str(self.device_id)])
        P4Switch.device_id += 1
        args.append(self.json_path)

        if self.enable_debugger:
            args.append("--debugger")
        if self.log_console:
            args.append("--log-console")

        if self.user:
            for usr in self.user:
                args.extend(["--user", usr[0]])

        logfile = "/tmp/p4s.{}.log".format(self.name)
        print("Log file: " + logfile)
        print("Command: " + ' '.join(args))

        pid = None
        with tempfile.NamedTemporaryFile() as f:
            self.cmd(' '.join(args) + ' >' + logfile + ' 2>&1 & echo $! >> ' + f.name)
            pid = int(f.read())
        print("P4 switch {} PID is {}.".format(self.name, pid))
        if not self.check_switch_started(pid):
            print("Error: P4 switch {} did not start correctly.\n".format(self.name))
            exit(1)
        print("P4 switch {} has been started.".format(self.name))

    def stop(self):
        "Terminate P4 switch."
        self.output.flush()
        self.cmd('kill %' + self.sw_path)
        self.cmd('wait')
        self.deleteIntfs()

    def attach(self, intf):
        "Connect a data port"
        assert(0)

    def detach(self, intf):
        "Disconnect a data port"
        assert(0)
