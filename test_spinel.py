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
""" Run all unittests for spinel module. """

import sys
import optparse
import unittest

import spinel.config as CONFIG
from spinel.tests import *


def main():
    """ Run all unit tests for spinel module. """
    args = sys.argv[1:]

    opt_parser = optparse.OptionParser()
    opt_parser.add_option("-d",
                          "--debug",
                          action="store",
                          dest="debug",
                          type="int",
                          default=CONFIG.DEBUG_ENABLE)

    (options, remaining_args) = opt_parser.parse_args(args)

    if options.debug:
        CONFIG.debug_set_level(options.debug)

    sys.argv[1:] = remaining_args
    unittest.main()


if __name__ == '__main__':
    main()
