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
import sys

def hexify_chr(s):
    if isinstance(s, str) and sys.version_info[0] == 2:
        s = ord(s)
    return "%02X" % s

def hexify_int(i): return "%02X" % i
def hexify_bytes(data): return str(list(map(hexify_chr,data)))
def hexify_str(s,delim=':'):
    if isinstance(s, str) and sys.version_info[0] == 2:
        return delim.join(x.encode('hex') for x in s)
    else:
        return delim.join(str(binascii.hexlify(bytearray([x])))[2:-1] for x in s)

def pack_bytes(packet): return pack("%dB" % len(packet), *packet)
def packed_to_array(packet): return list(map(ord, packet))

def asciify_int(i): return "%c" % (i)

def hex_to_bytes(s):
    if sys.version_info[0] == 2:
        result = ''
    else:
        result = bytes()
    for i in range(0, len(s), 2):
        (b1, b2) = s[i:i+2]
        hex = b1+b2
        v = int(hex, 16)
        if sys.version_info[0] == 2:
            result += chr(v)
        else:
            result += bytearray([v])
    return result
