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
""" Module to provide codec utilities for .pcap formatters. """

import struct
from datetime import datetime

DLT_IEEE802_15_4 = 195
PCAP_MAGIC_NUMBER = 0xa1b2c3d4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4


class PcapCodec(object):
    """ Utility class for .pcap formatters. """

    @classmethod
    def encode_header(cls):
        """ Returns a pcap file header. """
        return struct.pack("<LHHLLLL",
                           PCAP_MAGIC_NUMBER,
                           PCAP_VERSION_MAJOR,
                           PCAP_VERSION_MINOR,
                           0, 0, 256,
                           DLT_IEEE802_15_4)

    @classmethod
    def encode_frame(cls, frame):
        """ Returns a pcap encapsulation of the given frame. """
        # write frame pcap header
        epoch = datetime(1970, 1, 1)
        d_time = datetime.utcnow() - epoch
        sec = d_time.days * 24 * 60 * 60 + d_time.seconds
        usec = d_time.microseconds
        length = len(frame)
        pcap_frame = struct.pack("<LLLL", sec, usec, length, length)
        pcap_frame += frame
        return pcap_frame
