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
Unittest for spinel.hdlc module.
"""

import unittest
import binascii

from spinel.hdlc import Hdlc


class TestHdlc(unittest.TestCase):
    """ Unittest class for spinel.hdlc.Hdlc class. """

    VECTOR = {
        # Data    HDLC Encoded
        "810243": "7e810243d3d37e",
        "8103367e7d": "7e8103367d5e7d5d6af97e",
    }

    def test_hdlc_encode(self):
        """ Unit test for Hdle.encode method. """
        hdlc = Hdlc(None)
        for in_hex, out_hex in self.VECTOR.iteritems():
            in_binary = binascii.unhexlify(in_hex)
            out_binary = hdlc.encode(in_binary)
            #print "inHex = "+binascii.hexlify(in_binary)
            #print "outHex = "+binascii.hexlify(out_binary)
            self.failUnless(out_hex == binascii.hexlify(out_binary))

    def test_hdlc_decode(self):
        """ Unit test for Hdle.decode method. """
        pass
