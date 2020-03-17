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

import time
import unittest

from spinel.const import SPINEL
from spinel.codec import WpanApi
from spinel.test_stream import MockStream


class TestCodec(unittest.TestCase):
    """ Unit TestCase class for spinel.codec.SpinelCodec class. """

    # Tests parsing and format demuxing of various properties with canned
    # values.
    VECTOR = {
        SPINEL.PROP_MAC_15_4_PANID: 65535,
        SPINEL.PROP_NCP_VERSION: "OPENTHREAD",
        SPINEL.PROP_NET_ROLE: 0,
        SPINEL.PROP_NET_KEY_SEQUENCE_COUNTER: 5,
        SPINEL.PROP_NET_NETWORK_NAME: "OpenThread",
        SPINEL.PROP_THREAD_MODE: 0xF,
    }

    def test_prop_get(self):
        """ Unit test of SpinelCodec.prop_get_value. """

        mock_stream = MockStream({
            # Request:  Response
            "810236": "810636ffff",  # get panid = 65535
            "810243": "81064300",  # get state = detached
            "81025e": "81065e0f",  # mode = 0xF
            "810202": "8106024f50454e54485245414400",  # get version
            "810247": "81064705000000",  # get keysequence
            "810244": "8106444f70656e54687265616400",  # get networkname
        })
        nodeid = 1
        use_hdlc = False
        wpan_api = WpanApi(mock_stream, nodeid, use_hdlc)

        for prop_id, truth_value in self.VECTOR.iteritems():
            value = wpan_api.prop_get_value(prop_id)
            self.failUnless(value == truth_value)

    def cb_test_callback(self, prop, value, tid):
        self.test_callback_pass = True

    def test_callback(self):
        """ Unit test of WpanApi.callback_register. """

        vector = [
            "800672340060000000000c3a40fe80000000000000020d6f00055715d3fddead00beef0000cd9bb7814c5619ea8100b0ca00000000267fc789"  # PROP_STREAM_NET
        ]

        mock_stream = MockStream({})
        nodeid = 1
        use_hdlc = False
        wpan_api = WpanApi(mock_stream, nodeid, use_hdlc)

        self.test_callback_pass = False
        wpan_api.callback_register(SPINEL.PROP_STREAM_NET,
                                   self.cb_test_callback)

        for pkt in vector:
            mock_stream.write_child_hex(pkt)
            time.sleep(0.1)

        self.failUnless(self.test_callback_pass)
