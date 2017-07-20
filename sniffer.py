#!/usr/bin/env python -u
#
#  Copyright (c) 2016-2017, The OpenThread Authors.
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
   Sniffer tool that outputs raw pcap.

   Real-time stream to wireshark:
       ./sniffer.py | wireshark -k -i -

   Save stream to file or pipe:
       ./sniffer.py > trace.pcap
"""

import sys
import optparse
from datetime import datetime

import spinel.util as util
import spinel.config as CONFIG
from spinel.const import SPINEL
from spinel.codec import WpanApi
from spinel.stream import StreamOpen
from spinel.pcap import PcapCodec


# Nodeid is required to execute ot-ncp-ftd for its sim radio socket port.
# This is maximum that works for MacOS.
DEFAULT_NODEID = 34    # same as WELLKNOWN_NODE_ID
DEFAULT_CHANNEL = 11

def parse_args():
    """ Parse command line arguments for this applications. """

    args = sys.argv[1:]

    opt_parser = optparse.OptionParser()
    opt_parser.add_option("-u", "--uart", action="store",
                          dest="uart", type="string")
    opt_parser.add_option("-p", "--pipe", action="store",
                          dest="pipe", type="string")
    opt_parser.add_option("-s", "--socket", action="store",
                          dest="socket", type="string")
    opt_parser.add_option("-n", "--nodeid", action="store",
                          dest="nodeid", type="string", default=str(DEFAULT_NODEID))

    opt_parser.add_option("-d", "--debug", action="store",
                          dest="debug", type="int", default=CONFIG.DEBUG_ENABLE)
    opt_parser.add_option("-x", "--hex", action="store_true", dest="hex")

    opt_parser.add_option("-c", "--channel", action="store",
                          dest="channel", type="int", default=DEFAULT_CHANNEL)

    opt_parser.add_option('--crc', action='store_true',
                          dest='crc', default=False )

    return opt_parser.parse_args(args)

def sniffer_init(wpan_api, options):
    """" Send spinel commands to initialize sniffer node. """
    wpan_api.queue_register(SPINEL.HEADER_DEFAULT)
    wpan_api.queue_register(SPINEL.HEADER_ASYNC)

    sys.stderr.write("Initializing sniffer...\n")
    wpan_api.cmd_send(SPINEL.CMD_RESET)

    result = wpan_api.prop_set_value(SPINEL.PROP_PHY_ENABLED, 1)
    if result is None:
        return False

    result = wpan_api.prop_set_value(SPINEL.PROP_MAC_FILTER_MODE, SPINEL.MAC_FILTER_MODE_MONITOR)
    if result is None:
        return False

    result = wpan_api.prop_set_value(SPINEL.PROP_PHY_CHAN, options.channel)
    if result is None:
        return False

    result = wpan_api.prop_set_value(SPINEL.PROP_MAC_15_4_PANID, 0xFFFF, 'H')
    if result is None:
        return False

    result = wpan_api.prop_set_value(SPINEL.PROP_MAC_RAW_STREAM_ENABLED, 1)
    if result is None:
        return False

    return True

def crc( s ):
    # Some chips do not transmit the CRC, here we recalculate the CRC.

    crc = 0
    # remove the last 2 bytes
    for c in s[:-2]:
        c = ord(c)
        q = (crc ^ c) & 0x0f
        crc = (crc >> 4) ^ (q * 0x1081)
        q = (crc ^ (c >> 4)) & 0x0f
        crc = (crc >> 4) ^ (q * 0x1081)
    msb = chr( 0x0ff & (crc >> 8) )
    lsb = chr( 0x0ff & (crc >> 0) )
    s = s[:-2] + lsb + msb
    return s

def main():
    """ Top-level main for sniffer host-side tool. """
    (options, remaining_args) = parse_args()

    if options.debug:
        CONFIG.debug_set_level(options.debug)

    # Set default stream to pipe
    stream_type = 'p'
    stream_descriptor = "../../examples/apps/ncp/ot-ncp-ftd "+options.nodeid

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
            stream_descriptor += " "+str(options.nodeid)
    else:
        if len(remaining_args) > 0:
            stream_descriptor = " ".join(remaining_args)

    stream = StreamOpen(stream_type, stream_descriptor, False)
    if stream is None: exit()
    wpan_api = WpanApi(stream, options.nodeid)
    result = sniffer_init(wpan_api, options)
    if not result:
        sys.stderr.write("ERROR: failed to initialize sniffer\n")
        exit()
    else:
        sys.stderr.write("SUCCESS: sniffer initialized\nSniffing...\n")

    pcap = PcapCodec()
    hdr = pcap.encode_header()
    if options.hex:
        hdr = util.hexify_str(hdr)+"\n"
    sys.stdout.write(hdr)
    sys.stdout.flush()

    epoch = datetime(1970, 1, 1)
    timebase = datetime.utcnow() - epoch
    timebase_sec = timebase.days * 24 * 60 * 60 + timebase.seconds
    timebase_usec = timebase.microseconds

    try:
        tid = SPINEL.HEADER_ASYNC
        prop_id = SPINEL.PROP_STREAM_RAW
        while True:
            result = wpan_api.queue_wait_for_prop(prop_id, tid)
            if result and result.prop == prop_id:
                length = wpan_api.parse_S(result.value)
                pkt = result.value[2:2+length]
                if options.crc:
                    pkt = crc(pkt)

                # metadata format:
                # 0. RSSI(int8)
                # 1. Noise Floor(int8)
                # 2. Flags(uint16)
                # 3. PHY-specific data struct contains:
                #     3.0 Channel(uint8)
                #     3.1 LQI(uint8)
                #     3.2 Timestamp Msec(uint32)
                #     3.3 Timestamp Usec(uint16)
                metadata = wpan_api.parse_fields(result.value[2+length:2+length+14], "ccSt(CCLS)")

                timestamp_usec = timebase_usec + metadata[3][2] * 1000 + metadata[3][3]
                timestamp_sec = timebase_sec + timestamp_usec / 1000000
                timestamp_usec = timestamp_usec % 1000000

                pkt = pcap.encode_frame(pkt, timestamp_sec, timestamp_usec)
                if options.hex:
                    pkt = util.hexify_str(pkt)+"\n"
                sys.stdout.write(pkt)
                sys.stdout.flush()

    except KeyboardInterrupt:
        pass

    if wpan_api:
        wpan_api.stream.close()


if __name__ == "__main__":
    main()
