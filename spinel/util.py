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

import binascii


def hexify_str(s, delim=':'):
    hex_str = binascii.hexlify(s.encode('utf-8')).decode('utf-8')
    return delim.join([hex_str[i:i + 2] for i in range(0, len(hex_str), 2)])


def packed_to_array(packet):
    return list(map(ord, packet))


def asciify_int(i):
    return "%c" % (i)


def hex_to_bytes(s):
    result = bytes()

    for i in range(0, len(s), 2):
        (b1, b2) = s[i:i + 2]
        hex = b1 + b2
        v = int(hex, 16)
        result += bytearray([v])

    return result
