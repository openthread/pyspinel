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

def hexify_chr(s): return "%02X" % ord(s)
def hexify_int(i): return "%02X" % i
def hexify_bytes(data): return str(map(hexify_chr,data))
def hexify_str(s,delim=':'):
    return delim.join(x.encode('hex') for x in s)

def pack_bytes(packet): return pack("%dB" % len(packet), *packet)
def packed_to_array(packet): return map(ord, packet)

def asciify_int(i): return "%c" % (i)

def hex_to_bytes(s):
    result = ''
    for i in xrange(0, len(s), 2):
        (b1, b2) = s[i:i+2]
        hex = b1+b2
        v = int(hex, 16)
        result += chr(v)
    return result
