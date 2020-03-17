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
""" Unittest for spinel.codec module. """

import unittest

import spinel.util as util
from spinel.const import SPINEL
from spinel.codec import WpanApi
from spinel.test_stream import MockStream


class TestSniffer(unittest.TestCase):
    """ Unit TestCase class for sniffer relevant portions of spinel.codec.SpinelCodec. """

    HEADER = "800671"  # CMD_PROP_IS RAW_STREAM
    VECTOR = [
        # Some raw 6lo packets: ICMPv6EchoRequest to ff02::1, fe80::1, and MLE Advertisement
        "2d00499880fffffffffeff0d0100000001a7acdf3be9272c2d88765ff76f0bf08a7c3df0a78e9c1b23eb019c58740300800000",
        "3200699c81ffff0100000000000002feff0d030000000198e80cac00f8e0754e7542f5cb1171069f5c9689ef8d1d45a75e26b3f600800000",
        "450041d8980100ffffa8cb25ab2c32a0227f3b01f04d4c4d4cdc3b0015060000000000000001f226cce17968521d92904fec1adb0b94777030b944df65450bc955f05737e3901700800000"
    ]

    def test_prop_get(self):
        """ Unit test of SpinelCodec.prop_get_value. """

        mock_stream = MockStream({})

        nodeid = 1
        use_hdlc = False
        tid = SPINEL.HEADER_ASYNC
        prop_id = SPINEL.PROP_STREAM_RAW

        wpan_api = WpanApi(mock_stream, nodeid, use_hdlc)
        wpan_api.queue_register(tid)

        for truth in self.VECTOR:
            mock_stream.write_child_hex(self.HEADER + truth)
            result = wpan_api.queue_wait_for_prop(prop_id, tid)
            packet = util.hexify_str(result.value, "")
            self.failUnless(packet == truth)
