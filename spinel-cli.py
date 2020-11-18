#!/usr/bin/env python3
#
#  Copyright (c) 2016-2019, The OpenThread Authors.
#  All rights reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
"""
Shell tool for controlling OpenThread NCP instances.
"""

import os
import sys
import time
import traceback
import random
import importlib

import optparse

import binascii
import socket
import struct
import string
import textwrap

import logging
import logging.config
import logging.handlers

from cmd import Cmd

from spinel.const import SPINEL
from spinel.const import kThread
from spinel.codec import WpanApi
from spinel.codec import SpinelCodec
from spinel.stream import StreamOpen
from spinel.tun import TunInterface
import spinel.config as CONFIG
import spinel.util as util

import ipaddress

__copyright__ = "Copyright (c) 2016 The OpenThread Authors."
__version__ = "0.1.0"

MASTER_PROMPT = "spinel-cli"

import io
import spinel.ipv6 as ipv6
import spinel.common as common

DEFAULT_BAUDRATE = 115200


class IcmpV6Factory(object):

    ipv6_factory = ipv6.IPv6PacketFactory(
        ehf={
            0:
                ipv6.HopByHopFactory(
                    hop_by_hop_options_factory=ipv6.HopByHopOptionsFactory(
                        options_factories={109: ipv6.MPLOptionFactory()}))
        },
        ulpf={
            58:
                ipv6.ICMPv6Factory(
                    body_factories={129: ipv6.ICMPv6EchoBodyFactory()})
        })

    def _any_identifier(self):
        return random.getrandbits(16)

    def _seq_number(self):
        seq_number = 0

        while True:
            yield seq_number
            seq_number += 1
            seq_number if seq_number < (1 << 16) else 0

    def build_icmp_echo_request(self,
                                src,
                                dst,
                                data,
                                hop_limit=64,
                                identifier=None,
                                sequence_number=None):
        identifier = self._any_identifier(
        ) if identifier is None else identifier
        sequence_number = next(
            self._seq_number()) if sequence_number is None else sequence_number

        ping_req = ipv6.IPv6Packet(
            ipv6_header=ipv6.IPv6Header(source_address=src,
                                        destination_address=dst,
                                        hop_limit=hop_limit),
            upper_layer_protocol=ipv6.ICMPv6(
                header=ipv6.ICMPv6Header(_type=ipv6.ICMP_ECHO_REQUEST, code=0),
                body=ipv6.ICMPv6EchoBody(identifier=identifier,
                                         sequence_number=sequence_number,
                                         data=data)))

        return ping_req.to_bytes()

    def from_bytes(self, data):
        return self.ipv6_factory.parse(io.BytesIO(data), common.MessageInfo())


class SpinelCliCmd(Cmd, SpinelCodec):
    """
    A command line shell for controlling OpenThread NCP nodes
    via the Spinel protocol.
    """

    VIRTUAL_TIME = os.getenv('VIRTUAL_TIME') == '1'

    icmp_factory = IcmpV6Factory()

    def _init_virtual_time(self):
        """
        compute addresses used for virtual time.
        """
        BASE_PORT = 9000
        MAX_NODES = 34
        PORT_OFFSET = int(os.getenv("PORT_OFFSET", "0"))

        self._addr = ('127.0.0.1', BASE_PORT * 2 + MAX_NODES * PORT_OFFSET)
        self._simulator_addr = ('127.0.0.1',
                                BASE_PORT + MAX_NODES * PORT_OFFSET)

    def __init__(self, stream, nodeid, vendor_module, *_a, **kw):
        if self.VIRTUAL_TIME:
            self._init_virtual_time()
        self.nodeid = nodeid
        self.tun_if = None

        self.wpan_api = WpanApi(stream, nodeid, vendor_module=vendor_module)
        self.wpan_api.queue_register(SPINEL.HEADER_DEFAULT)
        self.wpan_api.callback_register(SPINEL.PROP_STREAM_NET,
                                        self.wpan_callback)

        Cmd.__init__(self)
        Cmd.identchars = string.ascii_letters + string.digits + '-'

        if sys.stdin.isatty():
            self.prompt = MASTER_PROMPT + " > "
        else:
            self.use_rawinput = 0
            self.prompt = ""

        SpinelCliCmd.command_names.sort()

        self.history_filename = os.path.expanduser("~/.spinel-cli-history")

        try:
            import readline
            try:
                readline.read_history_file(self.history_filename)
            except IOError:
                pass
        except ImportError:
            print("Module readline unavailable")
        else:
            import rlcompleter
            if 'libedit' in readline.__doc__:
                readline.parse_and_bind('bind ^I rl_complete')
            else:
                readline.parse_and_bind('tab: complete')

        if hasattr(stream, 'pipe'):
            self.wpan_api.queue_wait_for_prop(SPINEL.PROP_LAST_STATUS,
                                              SPINEL.HEADER_ASYNC)
        self.prop_set_value(SPINEL.PROP_IPv6_ICMP_PING_OFFLOAD, 1)
        self.prop_set_value(SPINEL.PROP_THREAD_RLOC16_DEBUG_PASSTHRU, 1)

    command_names = [
        # Shell commands
        'exit',
        'quit',
        'clear',
        'history',
        'debug',
        'debug-mem',
        'v',
        'h',
        'q',

        # OpenThread CLI commands
        'help',
        'bufferinfo',
        'channel',
        'child',
        'childmax',
        'childtimeout',
        'commissioner',
        'contextreusedelay',
        'counters',
        'diag',
        'discover',
        'eidcache',
        'extaddr',
        'extpanid',
        'ifconfig',
        'ipaddr',
        'joiner',
        'keysequence',
        'leaderdata',
        'leaderweight',
        'mac',
        'macfilter',
        'masterkey',
        'mfg',
        'mode',
        'netdata',
        'networkidtimeout',
        'networkname',
        'panid',
        'parent',
        'ping',
        'prefix',
        'releaserouterid',
        'reset',
        'rloc16',
        'route',
        'router',
        'routerselectionjitter',
        'routerupgradethreshold',
        'routerdowngradethreshold',
        'scan',
        'state',
        'thread',
        'txpower',
        'version',
        'vendor',

        # OpenThread Spinel-specific commands
        'ncp-ml64',
        'ncp-ll64',
        'ncp-tun',
        'ncp-raw',
        'ncp-filter',
    ]

    @classmethod
    def wpan_callback(cls, prop, value, tid):
        consumed = False

        if prop == SPINEL.PROP_STREAM_NET:
            consumed = True

            try:
                pkt = cls.icmp_factory.from_bytes(value)

                if CONFIG.DEBUG_LOG_PKT:
                    CONFIG.LOGGER.debug(pkt)

                timenow = int(round(time.time() * 1000)) & 0xFFFFFFFF
                timestamp = (pkt.upper_layer_protocol.body.identifier << 16 |
                             pkt.upper_layer_protocol.body.sequence_number)
                timedelta = (timenow - timestamp)
                print("\n%d bytes from %s: icmp_seq=%d hlim=%d time=%dms" %
                      (len(pkt.upper_layer_protocol.body.data),
                       pkt.ipv6_header.source_address,
                       pkt.upper_layer_protocol.body.sequence_number,
                       pkt.ipv6_header.hop_limit, timedelta))
            except RuntimeError:
                pass

        return consumed

    @classmethod
    def log(cls, text):
        """ Common log handler. """
        CONFIG.LOGGER.info(text)

    def parseline(self, line):
        cmd, arg, line = Cmd.parseline(self, line)
        if cmd:
            cmd = self.short_command_name(cmd)
            line = cmd + ' ' + arg
        return cmd, arg, line

    def completenames(self, text, *ignored):
        return [
            name + ' '
            for name in SpinelCliCmd.command_names
            if name.startswith(text) or
            self.short_command_name(name).startswith(text)
        ]

    @classmethod
    def short_command_name(cls, cmd):
        return cmd.replace('-', '')

    def postloop(self):
        try:
            import readline
            try:
                readline.write_history_file(self.history_filename)
            except IOError:
                pass
        except ImportError:
            pass

    def prop_get_value(self, prop_id):
        """ Blocking helper to return value for given propery identifier. """
        return self.wpan_api.prop_get_value(prop_id)

    def prop_set_value(self, prop_id, value, py_format='B'):
        """ Blocking helper to set value for given propery identifier. """
        return self.wpan_api.prop_set_value(prop_id, value, py_format)

    def prop_insert_value(self, prop_id, value, py_format='B'):
        """ Blocking helper to insert entry for given list property. """
        return self.wpan_api.prop_insert_value(prop_id, value, py_format)

    def prop_remove_value(self, prop_id, value, py_format='B'):
        """ Blocking helper to remove entry for given list property. """
        return self.wpan_api.prop_remove_value(prop_id, value, py_format)

    def prop_get_or_set_value(self, prop_id, line, mixed_format='B'):
        """ Helper to get or set a property value based on line arguments. """
        if line:
            value = self.prep_line(line, mixed_format)
            py_format = self.prep_format(value, mixed_format)
            value = self.prop_set_value(prop_id, value, py_format)
        else:
            value = self.prop_get_value(prop_id)
        return value

    @classmethod
    def prep_line(cls, line, mixed_format='B'):
        """ Convert a command line argument to proper binary encoding (pre-pack). """
        value = line
        if line != None:
            if mixed_format == 'U':  # For UTF8, just a pass through line unmodified
                line += '\0'
                value = line.encode('utf-8')
            elif mixed_format in (
                    'D',
                    'E'):  # Expect raw data to be hex string w/o delimeters
                value = util.hex_to_bytes(line)
            elif isinstance(line, str):
                # Most everything else is some type of integer
                value = int(line, 0)
        return value

    @classmethod
    def prep_format(cls, value, mixed_format='B'):
        """ Convert a spinel format to a python pack format. """
        py_format = mixed_format
        if value == "":
            py_format = '0s'
        elif mixed_format in ('D', 'U', 'E'):
            py_format = str(len(value)) + 's'
        return py_format

    def prop_get(self, prop_id, mixed_format='B'):
        """ Helper to get a propery and output the value with Done or Error. """
        value = self.prop_get_value(prop_id)
        if value is None:
            print("Error")
            return None

        if (mixed_format == 'D') or (mixed_format == 'E'):
            print(util.hexify_str(value, ''))
        else:
            print(str(value))
        print("Done")

        return value

    def prop_set(self, prop_id, line, mixed_format='B', output=True):
        """ Helper to set a propery and output Done or Error. """
        value = self.prep_line(line, mixed_format)
        py_format = self.prep_format(value, mixed_format)
        result = self.prop_set_value(prop_id, value, py_format)

        if not output:
            return result

        if result is None:
            print("Error")
        else:
            print("Done")

        return result

    def handle_property(self, line, prop_id, mixed_format='B', output=True):
        """ Helper to set property when line argument passed, get otherwise. """
        value = self.prop_get_or_set_value(prop_id, line, mixed_format)
        if not output:
            return value

        if value is None or value == "":
            print("Error")
            return None

        if line is None or line == "":
            # Only print value on PROP_VALUE_GET
            if mixed_format == '6':
                print(str(ipaddress.IPv6Address(value)))
            elif (mixed_format == 'D') or (mixed_format == 'E'):
                print(binascii.hexlify(value).decode('utf8'))
            elif mixed_format == 'H':
                if prop_id == SPINEL.PROP_MAC_15_4_PANID:
                    print("0x%04x" % value)
                else:
                    print("%04x" % value)
            else:
                print(str(value))

        print("Done")
        return value

    def do_help(self, line):
        if line:
            cmd, _arg, _unused = self.parseline(line)
            try:
                doc = getattr(self, 'do_' + cmd).__doc__
            except AttributeError:
                doc = None
            if doc:
                self.log("%s\n" % textwrap.dedent(doc))
            else:
                self.log("No help on %s\n" % (line))
        else:
            self.print_topics(
                "\nAvailable commands (type help <name> for more information):",
                SpinelCliCmd.command_names, 15, 80)

    def do_v(self, _line):
        """
        version
            Shows detailed version information on spinel-cli tool:
        """
        self.log(MASTER_PROMPT + " ver. " + __version__)
        self.log(__copyright__)

    @classmethod
    def do_clear(cls, _line):
        """ Clean up the display. """
        os.system('reset')

    def do_history(self, _line):
        """
        history

          Show previously executed commands.
        """

        try:
            import readline
            hist = readline.get_current_history_length()
            for idx in range(1, hist + 1):
                self.log(readline.get_history_item(idx))
        except ImportError:
            pass

    def do_h(self, line):
        """ Shortcut for history. """
        self.do_history(line)

    def do_exit(self, _line):
        """ Exit the shell. """
        self.log("exit")
        return True

    def do_quit(self, line):
        """ Exit the shell. """
        return self.do_exit(line)

    def do_q(self, line):
        """ Exit the shell. """
        return self.do_exit(line)

    def do_EOF(self, _line):
        """ End of file handler for when commands are piped into shell. """
        self.log("\n")
        return True

    def emptyline(self):
        pass

    def default(self, line):
        if line[0] == "#":
            CONFIG.LOGGER.debug(line)
        else:
            CONFIG.LOGGER.info(line + ": command not found")
            # exec(line)

    def do_debug(self, line):
        """
        Enables detail logging of bytes over the wire to the radio modem.
        Usage: debug <1=enable | 0=disable>
        """

        if line != None and line != "":
            level = int(line)
        else:
            level = 0

        CONFIG.debug_set_level(level)

    def do_debugmem(self, _line):
        """ Profile python memory usage. """
        from guppy import hpy
        heap_stats = hpy()
        print(heap_stats.heap())
        print()
        print(heap_stats.heap().byrcs)

    def do_bufferinfo(self, line):
        """
        \033[1mbufferinfo\033[0m

            Get the mesh forwarder buffer info.
        \033[2m
            > bufferinfo
            total: 128
            free: 128
            6lo send: 0 0
            6lo reas: 0 0
            ip6: 0 0
            mpl: 0 0
            mle: 0 0
            arp: 0 0
            coap: 0 0
            Done
        \033[0m
        """

        result = self.prop_get_value(SPINEL.PROP_MSG_BUFFER_COUNTERS)
        if result != None:
            print("total: %d" % result[0])
            print("free: %d" % result[1])
            print("6lo send: %d %d" % result[2:4])
            print("6lo reas: %d %d" % result[4:6])
            print("ip6: %d %d" % result[6:8])
            print("mpl: %d %d" % result[8:10])
            print("mle: %d %d" % result[10:12])
            print("arp: %d %d" % result[12:14])
            print("coap: %d %d" % result[14:16])
            print("Done")
        else:
            print("Error")

    def do_channel(self, line):
        """
        \033[1mchannel\033[0m

            Get the IEEE 802.15.4 Channel value.
        \033[2m
            > channel
            11
            Done
        \033[0m
        \033[1mchannel <channel>\033[0m

            Set the IEEE 802.15.4 Channel value.
        \033[2m
            > channel 11
            Done
        \033[0m
        """
        self.handle_property(line, SPINEL.PROP_PHY_CHAN)

    def do_child(self, line):
        """\033[1m
        child list
        \033[0m
            List attached Child IDs
        \033[2m
            > child list
            1 2 3 6 7 8
            Done
        \033[0m\033[1m
        child <id>
        \033[0m
            Print diagnostic information for an attached Thread Child.
            The id may be a Child ID or an RLOC16.
        \033[2m
            > child 1
            Child ID: 1
            Rloc: 9c01
            Ext Addr: e2b3540590b0fd87
            Mode: rsn
            Net Data: 184
            Timeout: 100
            Age: 0
            LQI: 3
            RSSI: -20
            Done
        \033[0m
        """
        child_table = self.prop_get_value(SPINEL.PROP_THREAD_CHILD_TABLE)[0]

        if line == 'list':
            result = ''
            for child_data in child_table:
                child_data = child_data[0]
                child_id = child_data[1] & 0x1FF
                result += '{} '.format(child_id)
            print(result)
            print("Done")

        else:
            try:
                child_id = int(line)
                printed = False
                for child_data in child_table:
                    child_data = child_data[0]
                    id = child_data[1] & 0x1FF

                    if id == child_id:
                        mode = ''
                        if child_data[7] & 0x08:
                            mode += 'r'
                        if child_data[7] & 0x04:
                            mode += 's'
                        if child_data[7] & 0x02:
                            mode += 'd'
                        if child_data[7] & 0x01:
                            mode += 'n'

                        print("Child ID: {}".format(id))
                        print("Rloc: {:04x}".format(child_data[1]))
                        print("Ext Addr: {}".format(
                            binascii.hexlify(child_data[0])))
                        print("Mode: {}".format(mode))
                        print("Net Data: {}".format(child_data[4]))
                        print("Timeout: {}".format(child_data[2]))
                        print("Age: {}".format(child_data[3]))
                        print("LQI: {}".format(child_data[5]))
                        print("RSSI: {}".format(child_data[6]))
                        print("Done")

                        printed = True

                if not printed:
                    print("Error")
            except ValueError:
                print("Error")

    def do_childmax(self, line):
        """\033[1m
        childmax
        \033[0m
            Get the Thread Child Count Max value.
        \033[2m
            > childmax
            10
            Done
        \033[0m\033[1m
        childmax <timeout>
        \033[0m
            Set the Thread Child Count Max value.
        \033[2m
            > childmax 5
            Done
        \033[0m
        """
        self.handle_property(line, SPINEL.PROP_THREAD_CHILD_COUNT_MAX)

    def do_childtimeout(self, line):
        """\033[1m
        childtimeout
        \033[0m
            Get the Thread Child Timeout value.
        \033[2m
            > childtimeout
            300
            Done
        \033[0m\033[1m
        childtimeout <timeout>
        \033[0m
            Set the Thread Child Timeout value.
        \033[2m
            > childtimeout 300
            Done
        \033[0m
        """
        self.handle_property(line, SPINEL.PROP_THREAD_CHILD_TIMEOUT, 'L')

    def do_commissioner(self, line):
        """
        These commands are enabled when configuring with --enable-commissioner.

        \033[1m
        commissioner start
        \033[0m
            Start the Commissioner role on this node.
        \033[2m
            > commissioner start
            Done
        \033[0m\033[1m
        commissioner stop
        \033[0m
            Stop the Commissioner role on this node.
        \033[2m
            > commissioner stop
            Done
        \033[0m\033[1m
        commissioner panid <panid> <mask> <destination>
        \033[0m
            Perform panid query.
        \033[2m
            > commissioner panid 57005 4294967295 ff33:0040:fdde:ad00:beef:0:0:1
            Conflict: dead, 00000800
            Done
        \033[0m\033[1m
        commissioner energy <mask> <count> <period> <scanDuration>
        \033[0m
            Perform energy scan.
        \033[2m
            > commissioner energy 327680 2 32 1000 fdde:ad00:beef:0:0:ff:fe00:c00
            Energy: 00050000 0 0 0 0
            Done
        \033[0m
        """
        pass

    def do_contextreusedelay(self, line):
        """
        contextreusedelay

            Get the CONTEXT_ID_REUSE_DELAY value.

            > contextreusedelay
            11
            Done

        contextreusedelay <delay>

            Set the CONTEXT_ID_REUSE_DELAY value.

            > contextreusedelay 11
            Done
        """
        self.handle_property(line, SPINEL.PROP_THREAD_CONTEXT_REUSE_DELAY, 'L')

    def do_counters(self, line):
        """
        counters

            Get the supported counter names.

            > counters
            mac
            mle
            Done

        counters <countername>

            Get the counter value.

            > counters mac
            TxTotal: 10
                TxUnicast: 3
                TxBroadcast: 7
                TxAckRequested: 3
                TxAcked: 3
                TxNoAckRequested: 7
                TxData: 10
                TxDataPoll: 0
                TxBeacon: 0
                TxBeaconRequest: 0
                TxOther: 0
                TxRetry: 0
                    TxDirectRetrySuccess: [ 0:2, 1:2, 2:1 ]
                    TxDirectMaxRetryExpiry: 1
                    TxIndirectRetrySuccess: [ 0:0 ]
                    TxIndirectMaxRetryExpiry: 1
                TxErrCca: 0
                TxAbort: 0
                TxErrBusyChannel: 0
            RxTotal: 2
                RxUnicast: 1
                RxBroadcast: 1
                RxData: 2
                RxDataPoll: 0
                RxBeacon: 0
                RxBeaconRequest: 0
                RxOther: 0
                RxAddressFiltered: 0
                RxDestAddrFiltered: 0
                RxDuplicated: 0
                RxErrNoFrame: 0
                RxErrNoUnknownNeighbor: 0
                RxErrInvalidSrcAddr: 0
                RxErrSec: 0
                RxErrFcs: 0
                RxErrOther: 0
            Done
            > counters mle
            Role Disabled: 0
            Role Detached: 1
            Role Child: 0
            Role Router: 0
            Role Leader: 1
            Attach Attempts: 1
            Partition Id Changes: 1
            Better Partition Attach Attempts: 0
            Parent Changes: 0
            Done

        counters <countername> reset

            Reset the counter value.

            > counters mac reset
            Done
            > counters mle reset
            Done

        """

        params = line.split(" ")

        if params[0] == "mac":

            if len(params) == 1:
                histogram = None
                result = self.prop_get_value(SPINEL.PROP_CNTR_ALL_MAC_COUNTERS)
                caps_list = self.prop_get_value(SPINEL.PROP_CAPS)

                for caps in caps_list[0]:
                    if SPINEL.CAP_MAC_RETRY_HISTOGRAM == caps[0][0]:
                        histogram = self.prop_get_value(
                            SPINEL.PROP_CNTR_MAC_RETRY_HISTOGRAM)

                if result != None:
                    counters_tx = result[0][0]
                    counters_rx = result[1][0]

                    print("TxTotal: %d" % counters_tx[0])
                    print("    TxUnicast: %d" % counters_tx[1])
                    print("    TxBroadcast: %d" % counters_tx[2])
                    print("    TxAckRequested: %d" % counters_tx[3])
                    print("    TxAcked: %d" % counters_tx[4])
                    print("    TxNoAckRequested: %d" % counters_tx[5])
                    print("    TxData: %d" % counters_tx[6])
                    print("    TxDataPoll: %d" % counters_tx[7])
                    print("    TxBeacon: %d" % counters_tx[8])
                    print("    TxBeaconRequest: %d" % counters_tx[9])
                    print("    TxOther: %d" % counters_tx[10])
                    print("    TxRetry: %d" % counters_tx[11])
                    if histogram != None:
                        histogram_direct = histogram[0][0]
                        if len(histogram_direct) != 0:
                            print("        TxDirectRetrySuccess: [", end='')
                            for retry in range(len(histogram_direct)):
                                print(" %d:%s" %
                                      (retry, histogram_direct[retry][0]),
                                      end=',' if retry !=
                                      (len(histogram_direct) - 1) else " ]\n")
                    print("        TxDirectMaxRetryExpiry: %s" %
                          (counters_tx[15][0]))
                    if histogram != None:
                        histogram_indirect = histogram[1][0]
                        if len(histogram_indirect) != 0:
                            print("        TxIndirectRetrySuccess: [", end='')
                            for retry in range(len(histogram_indirect)):
                                print(" %d:%s" %
                                      (retry, histogram_indirect[retry][0]),
                                      end=',' if retry !=
                                      (len(histogram_indirect) - 1) else " ]\n")
                    print("        TxIndirectMaxRetryExpiry: %s" %
                          (counters_tx[16][0]))
                    print("    TxErrCca: %d" % counters_tx[12])
                    print("    TxAbort: %d" % counters_tx[13])
                    print("    TxErrBusyChannel: %d" % counters_tx[14])
                    print("RxTotal: %d" % counters_rx[0])
                    print("    RxUnicast: %d" % counters_rx[1])
                    print("    RxBroadcast: %d" % counters_rx[2])
                    print("    RxData: %d" % counters_rx[3])
                    print("    RxDataPoll: %d" % counters_rx[4])
                    print("    RxBeacon: %d" % counters_rx[5])
                    print("    RxBeaconRequest: %d" % counters_rx[6])
                    print("    RxOther: %d" % counters_rx[7])
                    print("    RxAddressFiltered: %d" % counters_rx[8])
                    print("    RxDestAddrFiltered: %d" % counters_rx[9])
                    print("    RxDuplicated: %d" % counters_rx[10])
                    print("    RxErrNoFrame: %d" % counters_rx[11])
                    print("    RxErrNoUnknownNeighbor: %d" % counters_rx[12])
                    print("    RxErrInvalidSrcAddr: %d" % counters_rx[13])
                    print("    RxErrSec: %d" % counters_rx[14])
                    print("    RxErrFcs: %d" % counters_rx[15])
                    print("    RxErrOther: %d" % counters_rx[16])
                    print("Done")
                else:
                    print("Error")

            elif len(params) == 2:
                if params[1] == "reset":
                    self.prop_set_value(SPINEL.PROP_CNTR_ALL_MAC_COUNTERS, 1)
                    self.prop_set_value(SPINEL.PROP_CNTR_MAC_RETRY_HISTOGRAM, 1)
                    print("Done")
            else:
                print("Error")

        elif params[0] == "mle":

            if len(params) == 1:
                result = self.prop_get_value(SPINEL.PROP_CNTR_MLE_COUNTERS)
                if result != None:
                    print("Role Disabled: %d" % result[0])
                    print("Role Detached: %d" % result[1])
                    print("Role Child: %d" % result[2])
                    print("Role Router: %d" % result[3])
                    print("Role Leader: %d" % result[4])
                    print("Attach Attempts: %d" % result[5])
                    print("Partition Id Changes: %d" % result[6])
                    print("Better Partition Attach Attempts: %d" % result[7])
                    print("Parent Changes: %d" % result[8])
                    print("Done")
                else:
                    print("Error")

            elif len(params) == 2:
                if params[1] == "reset":
                    self.prop_set_value(SPINEL.PROP_CNTR_MLE_COUNTERS, 1)
                    print("Done")
            else:
                print("Error")

        elif params[0] is None or params[0] == "":
            print("mac")
            print("mle")
            print("Done")
        else:
            print("Error")

    def do_discover(self, line):
        """
        discover [channel]

             Perform an MLE Discovery operation.

        channel: The channel to discover on. If no channel is provided,
        the discovery will cover all valid channels.

        > discover
        | J | Network Name     | Extended PAN     | PAN  | MAC Address      | Ch | dBm | LQI |
        +---+------------------+------------------+------+------------------+----+-----+-----+
        | 0 | OpenThread       | dead00beef00cafe | ffff | f1d92a82c8d8fe43 | 11 | -20 |   0 |
        Done
        """
        pass

    def do_eidcache(self, line):
        """
        eidcache

            Print the EID-to-RLOC cache entries.

            > eidcache
            fdde:ad00:beef:0:bb1:ebd6:ad10:f33 ac00
            fdde:ad00:beef:0:110a:e041:8399:17cd 6000
            Done
        """
        pass

    def do_extaddr(self, line):
        """
        extaddr

            Get the IEEE 802.15.4 Extended Address.

            > extaddr
            dead00beef00cafe
            Done

        extaddr <extaddr>

            Set the IEEE 802.15.4 Extended Address.

            > extaddr dead00beef00cafe
            dead00beef00cafe
            Done
        """
        self.handle_property(line, SPINEL.PROP_MAC_15_4_LADDR, 'E')

    def do_extpanid(self, line):
        """
        extpanid

            Get the Thread Extended PAN ID value.

            > extpanid
            dead00beef00cafe
            Done

        extpanid <extpanid>

            Set the Thread Extended PAN ID value.

            > extpanid dead00beef00cafe
            Done
        """
        self.handle_property(line, SPINEL.PROP_NET_XPANID, 'D')

    def do_joiner(self, line):
        """
        These commands are enabled when configuring with --enable-joiner.

        joiner start <pskd> <provisioningUrl>

            Start the Joiner role.

            * pskd: Pre-Shared Key for the Joiner.
            * provisioningUrl: Provisioning URL for the Joiner (optional).

            This command will cause the device to perform an MLE Discovery and
            initiate the Thread Commissioning process.

            > joiner start PSK
            Done

        joiner stop

            Stop the Joiner role.

            > joiner stop
            Done
        """
        PSKd = ""

        params = line.split(" ")
        if len(params) > 0:
            sub_command = params[0]
        if len(params) > 1:
            PSKd = params[1]

        PSKd = self.prep_line(PSKd, 'U')

        if sub_command == "":
            pass

        elif sub_command == "start":
            py_format = self.prep_format(PSKd, 'U')
            self.prop_set_value(SPINEL.PROP_MESHCOP_JOINER_CREDENTIAL, PSKd,
                                py_format)
            self.prop_set_value(SPINEL.PROP_MESHCOP_JOINER_ENABLE, 1)
            print("Done")
            return

        elif sub_command == "stop":
            self.prop_set_value(SPINEL.PROP_MESHCOP_JOINER_ENABLE, 0)
            print("Done")
            return

        print("Error")

    def complete_ifconfig(self, text, _line, _begidx, _endidx):
        """ Subcommand completion handler for ifconfig command. """
        map_sub_commands = ('up', 'down')
        return [i for i in map_sub_commands if i.startswith(text)]

    def do_ifconfig(self, line):
        """
        ifconfig up

            Bring up the IPv6 interface.

            > ifconfig up
            Done

        ifconfig down

            Bring down the IPv6 interface.

            > ifconfig down
            Done

        ifconfig

            Show the status of the IPv6 interface.

            > ifconfig
            down
            Done
        """

        params = line.split(" ")

        if params[0] == "":
            value = self.prop_get_value(SPINEL.PROP_NET_IF_UP)
            if value != None:
                map_arg_value = {
                    0: "down",
                    1: "up",
                }
                print(map_arg_value[value])

        elif params[0] == "up":
            self.prop_set(SPINEL.PROP_NET_IF_UP, '1')
            return

        elif params[0] == "down":
            self.prop_set(SPINEL.PROP_NET_IF_UP, '0')
            return

        print("Done")

    def complete_ipaddr(self, text, _line, _begidx, _endidx):
        """ Subcommand completion handler for ipaddr command. """
        map_sub_commands = ('add', 'remove')
        return [i for i in map_sub_commands if i.startswith(text)]

    def do_ipaddr(self, line):
        """
        ipaddr

            List all IPv6 addresses assigned to the Thread interface.

            > ipaddr
            fdde:ad00:beef:0:0:ff:fe00:0
            fe80:0:0:0:0:ff:fe00:0
            fdde:ad00:beef:0:558:f56b:d688:799
            fe80:0:0:0:f3d9:2a82:c8d8:fe43
            Done

        ipaddr add <ipaddr>

            Add an IPv6 address to the Thread interface.

            > ipaddr add 2001::dead:beef:cafe
            Done

        ipaddr del <ipaddr>

            Delete an IPv6 address from the Thread interface.

            > ipaddr del 2001::dead:beef:cafe
            Done
        """
        params = line.split(" ")
        valid = 1
        preferred = 1
        flags = 0
        # always use /64, as prefix.network.prefixlen returns /128.
        prefix_len = 64

        num = len(params)
        if num > 1:
            ipaddr = params[1]
            prefix = ipaddress.IPv6Interface(str(ipaddr))
            arr = prefix.ip.packed

        if params[0] == "":
            addrs = self.wpan_api.get_ipaddrs()
            for addr in addrs:
                print(str(addr))

        elif params[0] == "add":
            arr += self.wpan_api.encode_fields('CLLC', prefix_len, valid,
                                               preferred, flags)

            self.prop_insert_value(SPINEL.PROP_IPV6_ADDRESS_TABLE, arr,
                                   str(len(arr)) + 's')

            if self.tun_if:
                self.tun_if.addr_add(ipaddr)

        elif params[0] == "remove":
            arr += self.wpan_api.encode_fields('CLLC', prefix_len, valid,
                                               preferred, flags)

            self.prop_remove_value(SPINEL.PROP_IPV6_ADDRESS_TABLE, arr,
                                   str(len(arr)) + 's')
            if self.tun_if:
                self.tun_if.addr_del(ipaddr)

        print("Done")

    def do_keysequence(self, line):
        """
        keysequence counter

            Get the Thread Key Sequence Counter.

            > keysequence counter
            10
            Done

        keysequence counter <counter>

            Set the Thread Key Sequence Counter.

            > keysequence counter 10
            Done

        keysequence guardtime

            Get the thrKeySwitchGuardTime (in hours).

            > keysequence guardtime
            0
            Done

        keysequence guardtime <guardtime>

            Set the thrKeySwitchGuardTime (in hours).

            > keysequence guardtime 0
            Done
        """

        args = line.split(" ")

        if args[0] == "counter":
            newline = line.replace("counter", "")
            self.handle_property(newline, SPINEL.PROP_NET_KEY_SEQUENCE_COUNTER,
                                 'L')

        elif args[0] == "guardtime":
            newline = line.replace("guardtime", "")
            self.handle_property(newline, SPINEL.PROP_NET_KEY_SWITCH_GUARDTIME,
                                 'L')

    def do_leaderdata(self, line):
        """
        leaderdata

            Get the Thread network Leader Data.

            > leaderdata
            Partition ID: 1987912443
            Weighting: 64
            Data Version: 4
            Stable Data Version: 129
            Leader Router ID: 47
            Done
        """
        partition_id = self.prop_get_value(SPINEL.PROP_NET_PARTITION_ID)
        weighting = self.prop_get_value(SPINEL.PROP_THREAD_LEADER_WEIGHT)
        data_version = self.prop_get_value(
            SPINEL.PROP_THREAD_NETWORK_DATA_VERSION)
        stable_version = self.prop_get_value(
            SPINEL.PROP_THREAD_STABLE_NETWORK_DATA_VERSION)
        leader_id = self.prop_get_value(SPINEL.PROP_THREAD_LEADER_RID)

        if partition_id   is None or \
           weighting      is None or \
           data_version   is None or \
           stable_version is None or \
           leader_id is None:
            print("Error")
        else:
            print("Partition ID: %d" % partition_id)
            print("Weighting: %d" % weighting)
            print("Data Version: %d" % data_version)
            print("Stable Data Version: %d" % stable_version)
            print("Leader Router ID: %d" % leader_id)
            print("Done")

    def do_leaderweight(self, line):
        """
        leaderweight

            Get the Thread Leader Weight.

            > leaderweight
            128
            Done

        leaderweight <weight>

            Set the Thread Leader Weight.

            > leaderweight 128
            Done
        """
        self.handle_property(line, SPINEL.PROP_THREAD_LOCAL_LEADER_WEIGHT)

    def do_masterkey(self, line):
        """
        masterkey

            Get the Thread Master Key value.

            > masterkey
            00112233445566778899aabbccddeeff
            Done

        masterkey <key>

            Set the Thread Master Key value.

            > masterkey 00112233445566778899aabbccddeeff
            Done
        """
        self.handle_property(line, SPINEL.PROP_NET_MASTER_KEY, 'D')

    def do_mfg(self, line):
        """
        mfg <diagnostic command>

        Check all the factory diagnostic commands here:
        https://github.com/openthread/openthread/blob/master/src/core/diags/README.md

        For example:

            Start the diagnostic module.

                > mfg start
                start diagnostics mode
                status 0x00

            Retrieved radio statistics.

                > mfg stats
                received packets: 0
                sent packets: 0
                first received packet: rssi=0, lqi=0
                last received packet: rssi=0, lqi=0
        """
        result = self.prop_set(SPINEL.PROP_NEST_STREAM_MFG, line, 'U', False)
        if result != None:
            print(result.rstrip())
        else:
            print("Error")

    def do_mode(self, line):
        """
        mode

            Get the Thread Device Mode value.

              r: rx-on-when-idle
              d: Full Function Device
              n: Full Network Data

            > mode
            rdn
            Done

        mode [rdn]

            Set the Thread Device Mode value.

              r: rx-on-when-idle
              d: Full Function Device
              n: Full Network Data

            > mode rsdn
            Done
        """
        map_arg_value = {
            0x00: "-",
            0x01: "n",
            0x02: "d",
            0x03: "dn",
            0x08: "r",
            0x09: "rn",
            0x0A: "rd",
            0x0B: "rdn",
        }

        map_arg_name = {
            "-": "0",
            "n": 0x01,
            "d": 0x02,
            "dn": 0x03,
            "r": 0x08,
            "rn": 0x09,
            "rd": 0x0A,
            "rdn": 0x0B,
        }

        if line:
            try:
                # remap string state names to integer
                line = map_arg_name[line]
            except KeyError:
                print("Error")
                return

        result = self.prop_get_or_set_value(SPINEL.PROP_THREAD_MODE, line)
        if result != None:
            if not line:
                print(map_arg_value[result])
            print("Done")
        else:
            print("Error")

    def do_netdata(self, line):
        """
        netdata

            Register local network data with Thread Leader.

            > netdata register
            Done
        """
        params = line.split(" ")
        if params[0] == "register":
            self.prop_set_value(SPINEL.PROP_THREAD_ALLOW_LOCAL_NET_DATA_CHANGE,
                                1)
            self.handle_property("0",
                                 SPINEL.PROP_THREAD_ALLOW_LOCAL_NET_DATA_CHANGE)

    def do_networkidtimeout(self, line):
        """
        networkidtimeout

            Get the NETWORK_ID_TIMEOUT parameter used in the Router role.

            > networkidtimeout
            120
            Done

        networkidtimeout <timeout>

            Set the NETWORK_ID_TIMEOUT parameter used in the Router role.

            > networkidtimeout 120
            Done
        """
        self.handle_property(line, SPINEL.PROP_THREAD_NETWORK_ID_TIMEOUT)

    def do_networkname(self, line):
        """
        networkname

            Get the Thread Network Name.

            > networkname
            OpenThread
            Done

        networkname <name>

            Set the Thread Network Name.

            > networkname OpenThread
            Done
        """
        self.handle_property(line, SPINEL.PROP_NET_NETWORK_NAME, 'U')

    def do_panid(self, line):
        """
        panid

            Get the IEEE 802.15.4 PAN ID value.

            > panid
            0xdead
            Done

        panid <panid>

            Set the IEEE 802.15.4 PAN ID value.

            > panid 0xdead
            Done
        """
        self.handle_property(line, SPINEL.PROP_MAC_15_4_PANID, 'H')

    def do_parent(self, line):
        """
        parent

            Get the addresses of the parent node.

            > parent
            Ext Addr: 3ad35f9846ceb9c7
            Rloc: bc00
            Done
        """
        ext_addr, rloc = self.prop_get_value(SPINEL.PROP_THREAD_PARENT)

        if ext_addr is None or\
           rloc is None:
            print("Error")
        else:
            print("Ext Addr: {}".format(binascii.hexlify(ext_addr)))
            print("Rloc: {:04x}".format(rloc))

    def do_ping(self, line):
        """
        ping <ipaddr> [size] [count] [interval]

            Send an ICMPv6 Echo Request.

            > ping fdde:ad00:beef:0:558:f56b:d688:799
            16 bytes from fdde:ad00:beef:0:558:f56b:d688:799: icmp_seq=1 hlim=64 time=28ms
        """
        params = line.split(" ")
        addr = "::1"
        _size = "56"
        _count = "1"
        _interval = "1"
        if len(params) > 0:
            addr = params[0]
        if len(params) > 1:
            _size = params[1]
        if len(params) > 2:
            _count = params[2]
        if len(params) > 3:
            _interval = params[3]

        try:
            # Generate local ping packet and send directly via spinel.
            ml64 = self.prop_get_value(SPINEL.PROP_IPV6_ML_ADDR)
            ml64 = str(ipaddress.IPv6Address(ml64))
            timenow = int(round(time.time() * 1000)) & 0xFFFFFFFF
            data = bytearray(int(_size))

            ping_req = self.icmp_factory.build_icmp_echo_request(
                ml64,
                addr,
                data,
                identifier=(timenow >> 16),
                sequence_number=(timenow & 0xffff))

            self.wpan_api.ip_send(ping_req)
            # Let handler print result
        except:
            print("Fail")
            print(traceback.format_exc())

    def complete_prefix(self, text, _line, _begidx, _endidx):
        """ Subcommand completion handler for prefix command. """
        map_sub_commands = ('add', 'remove')
        return [i for i in map_sub_commands if i.startswith(text)]

    def do_prefix(self, line):
        """
        prefix add <prefix> [pvdcsr] [prf]

            Add a valid prefix to the Network Data.

              p: Preferred flag
              a: Stateless IPv6 Address Autoconfiguration flag
              d: DHCPv6 IPv6 Address Configuration flag
              c: DHCPv6 Other Configuration flag
              r: Default Route flag
              o: On Mesh flag
              s: Stable flag
              prf: Default router preference, which may be 'high', 'med', or 'low'.
            > prefix add 2001:dead:beef:cafe::/64 paros med
            Done

        prefix remove <prefix>

            Invalidate a prefix in the Network Data.

            > prefix remove 2001:dead:beef:cafe::/64
            Done
        """
        params = line.split(" ")
        stable = 0
        flags = 0
        arr = ""

        num = len(params)
        if num > 1:
            prefix = ipaddress.IPv6Interface(str(params[1]))
            arr = prefix.ip.packed

        if num > 2:
            map_param_to_flag = {
                'p': kThread.PrefixPreferredFlag,
                'a': kThread.PrefixSlaacFlag,
                'd': kThread.PrefixDhcpFlag,
                'c': kThread.PrefixConfigureFlag,
                'r': kThread.PrefixDefaultRouteFlag,
                'o': kThread.PrefixOnMeshFlag,
            }
            for char in params[2]:
                if char == 's':
                    stable = 1  # Stable flag
                else:
                    flag = map_param_to_flag.get(char, None)
                    if flag is not None:
                        flags |= flag

        if num > 3:
            map_arg_name = {
                "high": 2,
                "med": 1,
                "low": 0,
            }
            prf = map_arg_name[params[3]]
            flags |= (prf << kThread.PrefixPreferenceOffset)

        if params[0] == "":
            self.prop_get_value(SPINEL.PROP_THREAD_ON_MESH_NETS)

        elif params[0] == "add":
            arr += self.wpan_api.encode_fields('CbC', prefix.network.prefixlen,
                                               stable, flags)

            self.prop_set_value(SPINEL.PROP_THREAD_ALLOW_LOCAL_NET_DATA_CHANGE,
                                1)
            self.prop_insert_value(SPINEL.PROP_THREAD_ON_MESH_NETS, arr,
                                   str(len(arr)) + 's')

        elif params[0] == "remove":
            arr += self.wpan_api.encode_fields('CbC', prefix.network.prefixlen,
                                               stable, flags)

            self.prop_set_value(SPINEL.PROP_THREAD_ALLOW_LOCAL_NET_DATA_CHANGE,
                                1)
            self.prop_remove_value(SPINEL.PROP_THREAD_ON_MESH_NETS, arr,
                                   str(len(arr)) + 's')

        print("Done")

    def do_releaserouterid(self, line):
        """
        releaserouterid <routerid>

            Release a Router ID that has been allocated by the device in the Leader role.

            > releaserouterid 16
            Done
        """
        if line:
            value = int(line)
            self.prop_remove_value(SPINEL.PROP_THREAD_ACTIVE_ROUTER_IDS, value)
        print("Done")

    def do_rloc16(self, line):
        """
        rloc16

            Get the Thread RLOC16 value.

            > rloc16
            0xdead
            Done
        """
        self.handle_property(line, SPINEL.PROP_THREAD_RLOC16, 'H')

    def do_reset(self, line):
        """
        reset

            Reset the NCP.

            > reset
        """
        self.wpan_api.cmd_reset()

        self.prop_set_value(SPINEL.PROP_IPv6_ICMP_PING_OFFLOAD, 1)
        self.prop_set_value(SPINEL.PROP_THREAD_RLOC16_DEBUG_PASSTHRU, 1)

    def complete_route(self, text, _line, _begidx, _endidx):
        """ Subcommand completion handler for route command. """
        map_sub_commands = ('add', 'remove')
        return [i for i in map_sub_commands if i.startswith(text)]

    def do_route(self, line):
        """
        route add <prefix> [s] [prf]

            Add a valid prefix to the Network Data.

              s: Stable flag
              prf: Default Router Preference, which may be: 'high', 'med', or 'low'.

            > route add 2001:dead:beef:cafe::/64 s med
            Done

        route remove <prefix>

            Invalidate a prefix in the Network Data.

            > route remove 2001:dead:beef:cafe::/64
            Done
        """
        params = line.split(" ")
        stable = 0
        prf = 0

        num = len(params)
        if num > 1:
            prefix = ipaddress.IPv6Interface(str(params[1]))
            arr = prefix.ip.packed

        if params[0] == "":
            self.prop_get_value(SPINEL.PROP_THREAD_LOCAL_ROUTES)

        elif params[0] == "add":
            arr += self.wpan_api.encode_fields('CbC', prefix.network.prefixlen,
                                               stable, prf)

            self.prop_set_value(SPINEL.PROP_THREAD_ALLOW_LOCAL_NET_DATA_CHANGE,
                                1)
            self.prop_insert_value(SPINEL.PROP_THREAD_LOCAL_ROUTES, arr,
                                   str(len(arr)) + 's')

        elif params[0] == "remove":
            self.prop_set_value(SPINEL.PROP_THREAD_ALLOW_LOCAL_NET_DATA_CHANGE,
                                1)
            self.prop_remove_value(SPINEL.PROP_THREAD_LOCAL_ROUTES, arr,
                                   str(len(arr)) + 's')

        print("Done")

    def do_router(self, line):
        """
        router list

            List allocated Router IDs

            > router list
            8 24 50
            Done

        router <id>

            Print diagnostic information for a Thread Router.
            The id may be a Router ID or an RLOC16.

            > router 50
            Alloc: 1
            Router ID: 50
            Rloc: c800
            Next Hop: c800
            Link: 1
            Ext Addr: e2b3540590b0fd87
            Cost: 0
            LQI In: 3
            LQI Out: 3
            Age: 3
            Done

            > router 0xc800
            Alloc: 1
            Router ID: 50
            Rloc: c800
            Next Hop: c800
            Link: 1
            Ext Addr: e2b3540590b0fd87
            Cost: 0
            LQI In: 3
            LQI Out: 3
            Age: 7
            Done
        """
        pass

    def do_routerselectionjitter(self, line):
        """
        routerselectionjitter

            Get the ROUTER_SELECTION_JITTER value.

            > routerselectionjitter
            120
            Done

        routerselectionjitter <threshold>

            Set the ROUTER_SELECTION_JITTER value.

            > routerselectionjitter 120
            Done
        """
        self.handle_property(line, SPINEL.PROP_THREAD_ROUTER_SELECTION_JITTER)

    def do_routerupgradethreshold(self, line):
        """
        routerupgradethreshold

            Get the ROUTER_UPGRADE_THRESHOLD value.

            > routerupgradethreshold
            16
            Done

        routerupgradethreshold <threshold>

            Set the ROUTER_UPGRADE_THRESHOLD value.

            > routerupgradethreshold 16
            Done
        """
        self.handle_property(line, SPINEL.PROP_THREAD_ROUTER_UPGRADE_THRESHOLD)

    def do_routerdowngradethreshold(self, line):
        """
        routerdowngradethreshold

            Get the ROUTER_DOWNGRADE_THRESHOLD value.

            > routerdowngradethreshold
            16
            Done

        routerdowngradethreshold <threshold>

            Set the ROUTER_DOWNGRADE_THRESHOLD value.

            > routerdowngradethreshold 16
            Done
        """
        self.handle_property(line,
                             SPINEL.PROP_THREAD_ROUTER_DOWNGRADE_THRESHOLD)

    def do_scan(self, _line):
        """
        scan [channel]

            Perform an IEEE 802.15.4 Active Scan.

              channel: The channel to scan on. If no channel is provided,
              the active scan will cover all valid channels.

            > scan
            | J | Network Name     | Extended PAN     | PAN  | MAC Address      | Ch | dBm | LQI |
            +---+------------------+------------------+------+------------------+----+-----+-----+
            | 0 | OpenThread       | dead00beef00cafe | ffff | f1d92a82c8d8fe43 | 11 | -20 |   0 |
        Done
        """
        # Initial mock-up of scan
        self.handle_property("15", SPINEL.PROP_MAC_SCAN_MASK)
        self.handle_property("4", SPINEL.PROP_MAC_SCAN_PERIOD, 'H')
        self.handle_property("1", SPINEL.PROP_MAC_SCAN_STATE)
        time.sleep(5)
        self.handle_property("", SPINEL.PROP_MAC_SCAN_BEACON, 'U')

    def complete_thread(self, text, _line, _begidx, _endidx):
        """ Subcommand completion handler for thread command. """
        map_sub_commands = ('start', 'stop')
        return [i for i in map_sub_commands if i.startswith(text)]

    def do_thread(self, line):
        """
        thread start

            Enable Thread protocol operation and attach to a Thread network.

            > thread start
            Done

        thread stop

            Disable Thread protocol operation and detach from a Thread network.

            > thread stop
            Done
        """
        map_arg_value = {
            0: "stop",
            1: "start",
        }

        map_arg_name = {
            "stop": "0",
            "start": "1",
        }

        if line:
            try:
                # remap string state names to integer
                line = map_arg_name[line]
            except:
                print("Error")
                return

        result = self.prop_get_or_set_value(SPINEL.PROP_NET_STACK_UP, line)
        if result != None:
            if not line:
                print(map_arg_value[result])
            print("Done")
        else:
            print("Error")

    def do_state(self, line):
        """
        state
        """
        map_arg_value = {
            0: "detached",
            1: "child",
            2: "router",
            3: "leader",
        }

        map_arg_name = {
            "disabled": "0",
            "detached": "0",
            "child": "1",
            "router": "2",
            "leader": "3",
        }

        if line:
            try:
                # remap string state names to integer
                line = map_arg_name[line]
            except:
                print("Error")
                return

        result = self.prop_get_or_set_value(SPINEL.PROP_NET_ROLE, line)
        if result != None:
            if not line:
                state = map_arg_value[result]
                # TODO: if state="disabled": get NET_STATE to determine
                #       whether "disabled" or "detached"
                print(state)
            print("Done")
        else:
            print("Error")

    def do_txpower(self, line):
        """
        txpower

            Get the transmit power in dBm.

            > txpower
            0
            Done

        txpower <txpower>

            Set the transmit power in dBm.

            > txpower -10
            Done
        """
        self.handle_property(line, SPINEL.PROP_PHY_TX_POWER, mixed_format='b')

    def do_version(self, line):
        """
        version

            Print the build version information.

            > version
            OPENTHREAD/gf4f2f04; Jul  1 2016 17:00:09
            Done
        """
        self.handle_property(line, SPINEL.PROP_NCP_VERSION, 'U')

    def complete_macfilter(self, text, _line, _begidx, _endidx):
        """ Subcommand completion handler for macfilter command. """
        #TODO: autocomplete the secondary sub commands
        #for 'addr': 'disable', 'denylist', 'allowlist', 'add', 'remove', 'clear'
        #for 'rss' : 'add', 'remove', 'clear'
        map_sub_commands = ('addr', 'rss')
        return [i for i in map_sub_commands if i.startswith(text)]

    def do_mac(self, line):
        """
        mac

            Mac related commands.

        mac retries direct

            Get the number of transmit retries on the MAC layer.

            > mac retries direct
            3
            Done

        mac retries direct <number>

            Set the number of direct transmit retries on the MAC layer.

            > mac retries direct 10
            Done

        mac retries indirect

            Get the number of indirect transmit retries on the MAC layer.

            > mac retries indirect
            0
            Done

        mac retries indirect <number>

            Set the number of indirect transmit retries on the MAC layer.

            > mac retries indirect 5
            Done

        mac ccathreshold

            Get the CCA ED Threshold in dBm.

            > mac ccathreshold
            -10
            Done

        mac ccathreshold -70

            Set the CCA ED Threshold in dBm.

            > mac ccathreshold -70
            Done
        """
        params = line.split(" ")
        prop = None

        if params[0] == "retries" and len(params) > 1:
            if params[1] == "direct":
                prop = SPINEL.PROP_MAC_MAX_RETRY_NUMBER_DIRECT
            elif params[1] == "indirect":
                prop = SPINEL.PROP_MAC_MAX_RETRY_NUMBER_INDIRECT
            value = params[2] if len(params) == 3 else None

        elif params[0] == "ccathreshold" and len(params) > 0:
            prop = SPINEL.PROP_PHY_CCA_THRESHOLD
            value = None
            if len(params) == 2:
                value = int(params[1])
                self.prop_set(prop, value, mixed_format='b')
                return

        self.handle_property(value, prop)

    def do_macfilter(self, line):
        """
        macfilter

           List the macfilter status, including address and received signal strength filter settings.

           > macfilter
           Allowlist
           Done

        macfilter addr

            List the address filter status.

            > macfilter addr
            Allowlist
            Done

        macfilter addr disable
            Disable address filter mode.

            > macfilter addr disable
            Done

        macfilter addr allowlist
            Enable allowlist address filter mode.

            > macfilter addr allowlist
            Done

        macfilter addr denylist
            Enable denylist address filter mode.

            > macfilter addr denylist
            Done

        macfilter addr add <extaddr> [rssi]

            Add an IEEE 802.15.4 Extended Address to the address filter.

            > macfilter addr add dead00beef00cafe -85
            Done

            > macfilter addr add dead00beef00caff
            Done

        macfilter addr remove <extaddr>

            Remove an IEEE 802.15.4 Extended Address from the address filter.

            > macfilter addr remove dead00beef00caff
            Done


        macfilter addr clear

            Clear all entries from the address filter.

            > macfilter addr clear
            Done

        macfilter rss

            List the rss filter status.

            > macfilter rss
            Done

        macfilter rss add <extaddr> <rssi>

            Set the received signal strength for the messages from the IEEE802.15.4 Extended Address.
            If extaddr is \*, default received signal strength for all received messages would be set.

            > macfilter rss add * -50
            Done

            > macfilter rss add 0f6127e33af6b404 -85
            Done

        macfilter rss remove <extaddr>

            Removes the received signal strength or received link quality setting on the Extended Address.
            If extaddr is \*, default received signal strength or link quality for all received messages would be unset.

            > macfilter rss remove *
            Done

            > macfilter rss remove 0f6127e33af6b404

        macfilter rss clear

            Clear all the the received signal strength.

            > macfilter rss clear
        """

        map_arg_value = {
            0: "Disabled",
            1: "Allowlist",
            2: "Denylist",
        }

        params = line.split(" ")

        if params[0] == "":
            mode = 0
            value = self.prop_get_value(SPINEL.PROP_MAC_ALLOWLIST_ENABLED)
            if value == 1:
                mode = 1
            else:
                value = self.prop_get_value(SPINEL.PROP_MAC_DENYLIST_ENABLED)
                if value == 1:
                    mode = 2

            print(map_arg_value[mode])

            # TODO: parse and show the content of entries
            value = self.prop_get_value(SPINEL.PROP_MAC_ALLOWLIST)
            value = self.prop_get_value(SPINEL.PROP_MAC_FIXED_RSS)

        if params[0] == "addr":
            if len(params) == 1:
                mode = 0
                value = self.prop_get_value(SPINEL.PROP_MAC_ALLOWLIST_ENABLED)
                if value == 1:
                    mode = 1
                else:
                    value = self.prop_get_value(
                        SPINEL.PROP_MAC_DENYLIST_ENABLED)
                    if value == 1:
                        mode = 2

                print(map_arg_value[mode])
                # TODO: parse and show the content of entries
                value = self.prop_get_value(SPINEL.PROP_MAC_ALLOWLIST)

            elif params[1] == "allowlist":
                self.prop_set(SPINEL.PROP_MAC_ALLOWLIST_ENABLED, '1')
                return

            elif params[1] == "denylist":
                self.prop_set(SPINEL.PROP_MAC_DENYLIST_ENABLED, '1')
                return

            elif params[1] == "disable":
                self.prop_set(SPINEL.PROP_MAC_ALLOWLIST_ENABLED, '0')
                return

            elif params[1] == "add":
                arr = util.hex_to_bytes(params[2])
                try:
                    rssi = int(params[3])
                except:
                    rssi = SPINEL.RSSI_OVERRIDE

                arr += struct.pack('b', rssi)
                self.prop_insert_value(SPINEL.PROP_MAC_ALLOWLIST, arr,
                                       str(len(arr)) + 's')

            elif params[1] == "remove":
                arr = util.hex_to_bytes(params[2])
                self.prop_remove_value(SPINEL.PROP_MAC_ALLOWLIST, arr,
                                       str(len(arr)) + 's')
            elif params[1] == "clear":
                self.prop_set_value(SPINEL.PROP_MAC_ALLOWLIST, b'', '0s')

        elif params[0] == "rss":
            if len(params) == 1:
                # TODO: parse and show the content of entries
                value = self.prop_get_value(SPINEL.PROP_MAC_FIXED_RSS)

            elif params[1] == "add":
                if params[2] == "*":
                    arr = b''
                else:
                    arr = util.hex_to_bytes(params[2])
                rssi = int(params[3])
                arr += struct.pack('b', rssi)
                self.prop_insert_value(SPINEL.PROP_MAC_FIXED_RSS, arr,
                                       str(len(arr)) + 's')

            elif params[1] == "remove":
                if params[2] == "*":
                    arr = b''
                else:
                    arr = util.hex_to_bytes(params[2])
                self.prop_remove_value(SPINEL.PROP_MAC_FIXED_RSS, arr,
                                       str(len(arr)) + 's')

            elif params[1] == "clear":
                self.prop_set_value(SPINEL.PROP_MAC_FIXED_RSS, b'', '0s')

        print("Done")

    def do_ncpll64(self, line):
        """ Display the link local IPv6 address. """
        self.handle_property(line, SPINEL.PROP_IPV6_LL_ADDR, '6')

    def do_ncpml64(self, line):
        """ Display the mesh local IPv6 address. """
        self.handle_property(line, SPINEL.PROP_IPV6_ML_ADDR, '6')

    def do_ncpraw(self, line):
        """ Enable MAC raw stream. """
        self.handle_property(line, SPINEL.PROP_MAC_RAW_STREAM_ENABLED, 'B')

    def do_ncpfilter(self, line):
        """
        Set MAC filter mode:

        0 = MAC_FILTER_MODE_NORMAL	Normal MAC filtering is in place.
        1 = MAC_FILTER_MODE_PROMISCUOUS	All MAC packets matching network are passed up the stack.
        2 = MAC_FILTER_MODE_MONITOR	All decoded MAC packets are passed up the stack.
        """
        self.handle_property(line, SPINEL.PROP_MAC_FILTER_MODE, 'B')

    def complete_ncptun(self, text, _line, _begidx, _endidx):
        """ Subcommand completion handler for ncp-tun command. """
        map_sub_commands = ('up', 'down', 'add', 'remove', 'ping')
        return [i for i in map_sub_commands if i.startswith(text)]

    def do_ncptun(self, line):
        """
        ncp-tun

            Control sideband tunnel interface.

        ncp-tun up

            Bring up Thread TUN interface.

            > ncp-tun up
            Done

        ncp-tun down

            Bring down Thread TUN interface.

            > ncp-tun down
            Done

        ncp-tun add <ipaddr>

            Add an IPv6 address to the Thread TUN interface.

            > ncp-tun add 2001::dead:beef:cafe
            Done

        ncp-tun del <ipaddr>

            Delete an IPv6 address from the Thread TUN interface.

            > ncp-tun del 2001::dead:beef:cafe
            Done

        ncp-tun ping <ipaddr> [size] [count] [interval]

            Send an ICMPv6 Echo Request.

            > ncp-tun ping fdde:ad00:beef:0:558:f56b:d688:799
            16 bytes from fdde:ad00:beef:0:558:f56b:d688:799: icmp_seq=1 hlim=64 time=28ms
        """
        params = line.split(" ")

        num = len(params)
        if num > 1:
            ipaddr = params[1]
            prefix = ipaddress.IPv6Interface(str(ipaddr))
            _arr = prefix.ip.packed

        if params[0] == "":
            pass

        elif params[0] == "add":
            if self.tun_if:
                self.tun_if.addr_add(ipaddr)

        elif params[0] == "remove":
            if self.tun_if:
                self.tun_if.addr_del(ipaddr)

        elif params[0] == "up":
            if os.geteuid() == 0:
                self.tun_if = TunInterface(self.nodeid)
            else:
                print("Warning: superuser required to start tun interface.")

        elif params[0] == "down":
            if self.tun_if:
                self.tun_if.close()
            self.tun_if = None

        elif params[0] == "ping":
            # Use tunnel to send ping
            size = "56"
            count = "1"
            _interval = "1"
            if len(params) > 1:
                size = params[1]
            if len(params) > 2:
                count = params[2]
            if len(params) > 3:
                _interval = params[3]

            if self.tun_if:
                self.tun_if.ping6(" -c " + count + " -s " + size + " " + ipaddr)

        print("Done")

    def do_diag(self, line):
        """
        Follows "mfg" command.
        """
        self.do_mfg(line)

    def _notify_simulator(self):
        """
        notify the simulator that there are no more UART data for the current command.
        """
        OT_SIM_EVENT_POSTCMD = 4

        message = struct.pack('=QBHB', 0, OT_SIM_EVENT_POSTCMD, 1,
                              int(self.nodeid))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(self._addr)
        sock.sendto(message, self._simulator_addr)
        sock.close()

    def postcmd(self, stop, line):
        if self.VIRTUAL_TIME:
            self._notify_simulator()
        return stop


def parse_args():
    """" Send spinel commands to initialize sniffer node. """
    args = sys.argv[1:]

    opt_parser = optparse.OptionParser(usage=optparse.SUPPRESS_USAGE)
    opt_parser.add_option("-u",
                          "--uart",
                          action="store",
                          dest="uart",
                          type="string")
    opt_parser.add_option("-b",
                          "--baudrate",
                          action="store",
                          dest="baudrate",
                          type="int",
                          default=DEFAULT_BAUDRATE)
    opt_parser.add_option("--rtscts",
                          action="store_true",
                          dest="rtscts",
                          default=False),
    opt_parser.add_option("-p",
                          "--pipe",
                          action="store",
                          dest="pipe",
                          type="string")
    opt_parser.add_option("-s",
                          "--socket",
                          action="store",
                          dest="socket",
                          type="string")
    opt_parser.add_option("-n",
                          "--nodeid",
                          action="store",
                          dest="nodeid",
                          type="string",
                          default="1")
    opt_parser.add_option("-q", "--quiet", action="store_true", dest="quiet")
    opt_parser.add_option("-v",
                          "--verbose",
                          action="store_true",
                          dest="verbose")
    opt_parser.add_option("-d",
                          "--debug",
                          action="store",
                          dest="debug",
                          type="int",
                          default=CONFIG.DEBUG_ENABLE)
    opt_parser.add_option("--vendor-path",
                          action="store",
                          dest="vendor_path",
                          type="string")

    return opt_parser.parse_args(args)


def main():
    """ Top-level main for spinel-cli tool. """
    (options, remaining_args) = parse_args()

    if options.debug:
        CONFIG.debug_set_level(options.debug)

    # Obtain the vendor module path, if provided
    if not options.vendor_path:
        options.vendor_path = os.environ.get("SPINEL_VENDOR_PATH")

    if options.vendor_path:
        options.vendor_path = os.path.abspath(options.vendor_path)
        vendor_path, vendor_module = os.path.split(options.vendor_path)
        sys.path.insert(0, vendor_path)
    else:
        vendor_module = "vendor"

    # Set default stream to pipe
    stream_type = 'p'
    stream_descriptor = "../../examples/apps/ncp/ot-ncp-ftd " + options.nodeid

    if options.uart:
        stream_type = 'u'
        stream_descriptor = options.uart
    elif options.socket:
        stream_type = 's'
        stream_descriptor = options.socket
    elif options.pipe:
        stream_type = 'p'
        stream_descriptor = options.pipe
        if options.nodeid:
            stream_descriptor += " " + str(options.nodeid)
    else:
        if len(remaining_args) > 0:
            stream_descriptor = " ".join(remaining_args)

    stream = StreamOpen(stream_type, stream_descriptor, options.verbose,
                        options.baudrate, options.rtscts)
    try:
        vendor_ext = importlib.import_module(vendor_module + '.vendor')
        cls = type(vendor_ext.VendorSpinelCliCmd.__name__,
                   (SpinelCliCmd, vendor_ext.VendorSpinelCliCmd), {})
        shell = cls(stream, nodeid=options.nodeid, vendor_module=vendor_module)
    except ImportError:
        shell = SpinelCliCmd(stream,
                             nodeid=options.nodeid,
                             vendor_module=vendor_module)

    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        CONFIG.LOGGER.info('\nCTRL+C Pressed')

    if shell.wpan_api:
        shell.wpan_api.stream.close()


if __name__ == "__main__":
    main()
