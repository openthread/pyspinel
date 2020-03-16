#!/usr/bin/env python3
#
#  Copyright (c) 2019, The OpenThread Authors.
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
import os
import sys
import tempfile
import argparse
import subprocess
import threading
import logging
import re

from spinel.stream import StreamOpen
from spinel.const import SPINEL
from spinel.codec import WpanApi
from serial.tools.list_ports import comports
from enum import Enum

# Nodeid is required to execute ot-ncp-ftd for its sim radio socket port.
# This is maximum that works for MacOS.
DEFAULT_NODEID = 34
COMMON_BAUDRATE = [460800, 115200, 9600]


class Config(Enum):
    CHANNEL = 0
    BAUDRATE = 1
    TAP = 2


class _StreamCloser:

    def __init__(self, stream):
        self._stream = stream

    def __enter__(self):
        return self._stream

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._stream.close()


def extcap_config(interface, option, extcap_version):
    """List Configuration for the given interface"""
    args = []
    values = []
    args.append(
        (Config.CHANNEL.value, '--channel', 'Channel', 'IEEE 802.15.4 channel',
         'selector', '{required=true}{default=11}'))

    match = re.match(r'^(\d+)(\.\d+)*$', extcap_version)
    if match and int(match.group(1)) >= 3:
        args.append((Config.TAP.value, '--tap',
                     'IEEE 802.15.4 TAP (only for Wireshark3.0 and later)',
                     'IEEE 802.15.4 TAP', 'boolflag', '{default=yes}'))

    for arg in args:
        print('arg {number=%d}{call=%s}{display=%s}{tooltip=%s}{type=%s}%s' %
              arg)

    values = values + [(Config.CHANNEL.value, '%d' % i, '%d' % i,
                        'true' if i == 11 else 'false') for i in range(11, 27)]

    for value in values:
        print('value {arg=%d}{value=%s}{display=%s}{default=%s}' % value)


def extcap_dlts(interface):
    """List DLTs for the given interface"""
    print(
        'dlt {number=195}{name=IEEE802_15_4_WITHFCS}{display=IEEE 802.15.4 with FCS}'
    )
    print('dlt {number=283}{name=IEEE802_15_4_TAP}{display=IEEE 802.15.4 TAP}')


def serialopen(interface, log_file):
    """
    Open serial to indentify OpenThread sniffer
    :param interface: string, eg: '/dev/ttyUSB0 - Zolertia Firefly platform', '/dev/ttyACM1 - nRF52840 OpenThread Device'
    """
    sys.stdout = log_file
    sys.stderr = log_file
    interface = str(interface).split()[0]
    baudrate = None

    for speed in COMMON_BAUDRATE:
        with _StreamCloser(StreamOpen('u', interface, False, baudrate=speed)) as stream, \
                WpanApi(stream, nodeid=DEFAULT_NODEID, timeout=0.1) as wpan_api:

            # result should not be None for both NCP and RCP
            result = wpan_api.prop_get_value(
                SPINEL.PROP_CAPS)  # confirm OpenThread Sniffer

            # check whether or not is OpenThread Sniffer
            if result is not None:
                baudrate = speed
                break

    if baudrate is not None:
        if sys.platform == 'win32':
            # Wireshark only shows the value of key `display`('OpenThread Sniffer').
            # Here intentionally appends interface in the end (e.g. 'OpenThread Sniffer: COM0').
            print('interface {value=%s:%s}{display=OpenThread Sniffer %s}' %
                  (interface, baudrate, interface),
                  file=sys.__stdout__,
                  flush=True)
        else:
            # On Linux or MacOS, wireshark will show the concatenation of the content of `display`
            # and `interface` by default (e.g. 'OpenThread Sniffer: /dev/ttyACM0').
            print('interface {value=%s:%s}{display=OpenThread Sniffer}' %
                  (interface, baudrate),
                  file=sys.__stdout__,
                  flush=True)


def extcap_interfaces():
    """List available interfaces to capture from"""

    log_file = open(
        os.path.join(tempfile.gettempdir(), 'extcap_ot_interfaces.log'), 'w')
    print(
        'extcap {version=1.0.0}{display=OpenThread Sniffer}{help=https://github.com/openthread/pyspinel}'
    )

    threads = []
    for interface in comports():
        th = threading.Thread(target=serialopen, args=(interface, log_file))
        threads.append(th)
        th.start()
    for th in threads:
        th.join()


def extcap_capture(interface, fifo, control_in, control_out, channel, tap):
    """Start the sniffer to capture packets"""
    # baudrate = detect_baudrate(interface)
    interface_port = str(interface).split(':')[0]
    interface_baudrate = str(interface).split(':')[1]

    with _StreamCloser(StreamOpen('u', interface_port, False, baudrate=int(interface_baudrate))) as stream, \
            WpanApi(stream, nodeid=DEFAULT_NODEID) as wpan_api:
        wpan_api.prop_set_value(SPINEL.PROP_PHY_ENABLED, 1)

    if sys.platform == 'win32':
        python_path = subprocess.Popen(
            'py -3 -c "import sys; print(sys.executable)"',
            stdout=subprocess.PIPE,
            shell=True,
        ).stdout.readline().decode().strip()
        sniffer_py = os.path.join(os.path.dirname(python_path), 'Scripts',
                                  'sniffer.py')
        cmd = ['python', sniffer_py]
    else:
        cmd = ['sniffer.py']
    cmd += [
        '-c', channel, '-u', interface_port, '--crc', '--rssi', '-b',
        interface_baudrate, '-o',
        str(fifo), '--is-fifo', '--use-host-timestamp'
    ]
    if tap:
        cmd.append('--tap')

    subprocess.Popen(cmd).wait()


def extcap_close_fifo(fifo):
    """"Close extcap fifo"""
    # This is apparently needed to workaround an issue on Windows/macOS
    # where the message cannot be read. (really?)
    fh = open(fifo, 'wb', 0)
    fh.close()


if __name__ == '__main__':

    # Capture options
    parser = argparse.ArgumentParser(
        description='OpenThread Sniffer extcap plugin')

    # Extcap Arguments
    parser.add_argument('--extcap-interfaces',
                        help='Provide a list of interfaces to capture from',
                        action='store_true')
    parser.add_argument('--extcap-interface',
                        help='Provide the interface to capture from')
    parser.add_argument('--extcap-dlts',
                        help='Provide a list of dlts for the given interface',
                        action='store_true')
    parser.add_argument(
        '--extcap-config',
        help='Provide a list of configurations for the given interface',
        action='store_true')
    parser.add_argument('--extcap-reload-option',
                        help='Reload elements for the given option')
    parser.add_argument('--capture',
                        help='Start the capture routine',
                        action='store_true')
    parser.add_argument(
        '--fifo',
        help='Use together with capture to provide the fifo to dump data to')
    parser.add_argument(
        '--extcap-capture-filter',
        help='Used together with capture to provide a capture filter')
    parser.add_argument('--extcap-control-in',
                        help='Used to get control messages from toolbar')
    parser.add_argument('--extcap-control-out',
                        help='Used to send control messages to toolbar')
    parser.add_argument('--extcap-version', help='Wireshark Version')

    # Interface Arguments
    parser.add_argument('--channel',
                        help='IEEE 802.15.4 capture channel [11-26]')
    parser.add_argument(
        '--tap',
        help='IEEE 802.15.4 TAP (only for Wireshark3.0 and later)',
        action='store_true')

    try:
        args, unknown = parser.parse_known_args()
    except argparse.ArgumentError as e:
        parser.exit('ERROR_ARG: %s' % str(e))

    extcap_version = ''
    version_path = os.path.join(tempfile.gettempdir(), 'extcap_ot_version')
    if args.extcap_version:
        extcap_version = args.extcap_version
        with open(version_path, mode='w') as f:
            f.write(extcap_version)
    else:
        try:
            with open(version_path, mode='r') as f:
                extcap_version = f.read()
        except FileNotFoundError:
            pass

    if len(unknown) > 0:
        parser.exit('Sniffer %d unknown arguments given: %s' %
                    (len(unknown), unknown))

    if len(sys.argv) == 0:
        parser.print_help()
        parser.exit('No arguments given!')

    if not args.extcap_interfaces and args.extcap_interface is None:
        parser.exit(
            'An interface must be provided or the selection must be displayed')

    if args.extcap_interfaces:
        extcap_interfaces()
        sys.exit(0)

    if args.extcap_config:
        extcap_config(args.extcap_interface, '', extcap_version)
    elif args.extcap_dlts:
        extcap_dlts(args.extcap_interface)
    elif args.capture:
        if args.fifo is None:
            parser.exit('The fifo must be provided to capture')
        try:
            extcap_capture(args.extcap_interface, args.fifo,
                           args.extcap_control_in, args.extcap_control_out,
                           args.channel, args.tap)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logging.exception(e)
            parser.exit('ERROR_INTERNAL')
    else:
        parser.print_help()
        parser.exit('ERROR_USAGE')
