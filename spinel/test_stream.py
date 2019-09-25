#!/usr/bin/env python
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
Tests for spinel.stream and implementation of MockStream class.
"""

import binascii
import logging

import queue

import spinel.util as util
import spinel.config as CONFIG
from spinel.stream import IStream


class MockStream(IStream):
    """ A pluggable IStream class for mock testing input/output data flows. """

    def __init__(self, vector):
        """
        Pass a test vector as dictionary of hexstream outputs keyed on inputs.
        """
        self.vector = vector
        self.rx_queue = queue.Queue()
        self.response = None

    def write(self, out_binary):
        """ Write to the MockStream, triggering a lookup for mock response. """
        if CONFIG.DEBUG_STREAM_TX:
            logging.debug("TX Raw: (%d) %s", len(out_binary),
                          binascii.hexlify(out_binary))
        out_hex = binascii.hexlify(out_binary)
        in_hex = self.vector[out_hex]
        self.rx_queue.put_nowait(binascii.unhexlify(in_hex))

    def read(self, size=None):
        """ Blocking read from the MockStream. """
        if not self.response or len(self.response) == 0:
            self.response = self.rx_queue.get(True)

        if size:
            in_binary = self.response[:size]
            self.response = self.response[size:]
        else:
            in_binary = self.response
            self.response = None

        if CONFIG.DEBUG_STREAM_RX:
            logging.debug("RX Raw: " + binascii.hexlify(in_binary))
        return in_binary

    def write_child(self, out_binary):
        """ Mock asynchronous write from child process. """
        self.rx_queue.put_nowait(out_binary)

    def write_child_hex(self, out_hex):
        """ Mock asynchronous write from child process. """
        self.write_child(binascii.unhexlify(out_hex))
