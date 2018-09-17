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
Module providing a generic stream interface.
Also includes adapter implementations for serial, socket, and pipes.
"""

from __future__ import print_function

import sys
import logging
import time
import traceback

import subprocess
import socket
import serial

import spinel.util
import spinel.config as CONFIG


class IStream(object):
    """ Abstract base class for a generic Stream Interface. """

    def read(self, size):
        """ Read an array of byte integers of the given size from the stream. """
        pass

    def write(self, data):
        """ Write the given packed data to the stream. """
        pass

    def close(self):
        """ Close the stream cleanly as needed. """
        pass


class StreamSerial(IStream):
    """ An IStream interface implementation for serial devices. """

    def __init__(self, dev, baudrate=115200):
        try:
            self.serial = serial.Serial(dev, baudrate)
        except:
            logging.error("Couldn't open " + dev)
            traceback.print_exc()

    def write(self, data):
        self.serial.write(data)
        if CONFIG.DEBUG_STREAM_TX:
            logging.debug("TX Raw: " + str(list(map(spinel.util.hexify_chr, data))))

    def read(self, size=1):
        pkt = self.serial.read(size)
        if CONFIG.DEBUG_STREAM_RX:
            logging.debug("RX Raw: " + str(list(map(spinel.util.hexify_chr, pkt))))

        byte = pkt[0]
        if isinstance(byte, str) and sys.version_info[0] == 2:
            byte = ord(byte)

        return byte


class StreamSocket(IStream):
    """ An IStream interface implementation over an internet socket. """

    def __init__(self, hostname, port):
        # Open socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((hostname, port))

    def write(self, data):
        self.sock.send(data)
        if CONFIG.DEBUG_STREAM_TX:
            logging.debug("TX Raw: " + str(list(map(spinel.util.hexify_chr, data))))

    def read(self, size=1):
        pkt = self.sock.recv(size)
        if CONFIG.DEBUG_STREAM_RX:
            logging.debug("RX Raw: " + str(list(map(spinel.util.hexify_chr, pkt))))

        byte = pkt[0]
        if isinstance(byte, str) and sys.version_info[0] == 2:
            byte = ord(byte)

        return byte


class StreamPipe(IStream):
    """ An IStream interface implementation to stdin/out of a piped process. """

    def __init__(self, filename):
        """ Create a stream object from a piped system call """
        try:
            # use exec so that there will be no zombie processes on failure
            self.pipe = subprocess.Popen('exec ' + filename, shell=True,
                                         stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE,
                                         stderr=sys.stderr)
        except:
            logging.error("Couldn't open " + filename)
            traceback.print_exc()

    def __del__(self):
        self.close()

    def write(self, data):
        if CONFIG.DEBUG_STREAM_TX:
            logging.debug("TX Raw: (%d) %s",
                          len(data), spinel.util.hexify_bytes(data))
        self.pipe.stdin.write(data)
        self.pipe.stdin.flush()
        # let the NCP process UART events first
        time.sleep(0)

    def read(self, size=1):
        """ Blocking read on stream object """
        pkt = self.pipe.stdout.read(size)
        if CONFIG.DEBUG_STREAM_RX:
            logging.debug("RX Raw: " + str(list(map(spinel.util.hexify_chr, pkt))))
        if not pkt:
            sys.exit(0)

        byte = pkt[0]
        if isinstance(byte, str) and sys.version_info[0] == 2:
            byte = ord(byte)

        return byte

    def close(self):
        if self.pipe:
            self.pipe.stdin.close()
            self.pipe.wait()
            self.pipe = None


def StreamOpen(stream_type, descriptor, verbose=True, baudrate=115200):
    """
    Factory function that creates and opens a stream connection.

    stream_type:
        'u' = uart (/dev/tty#)
        's' = socket (port #)
        'p' = pipe (stdin/stdout)

    descriptor:
        uart - filename of device (/dev/tty#)
        socket - port to open connection to on localhost
        pipe - filename of command to execute and bind via stdin/stdout
    """

    if stream_type == 'p':
        if verbose:
            print("Opening pipe to " + str(descriptor))
        return StreamPipe(descriptor)

    elif stream_type == 's':
        port = int(descriptor)
        hostname = "localhost"
        if verbose:
            print("Opening socket to " + hostname + ":" + str(port))
        return StreamSocket(hostname, port)

    elif stream_type == 'u':
        dev = str(descriptor)
        if verbose:
            print("Opening serial to " + dev + " @ " + str(baudrate))
        return StreamSerial(dev, baudrate)

    else:
        return None
