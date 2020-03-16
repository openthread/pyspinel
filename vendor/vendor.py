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
Module providing a specific vendor commands.
"""

from vendor.const import VENDOR_SPINEL


class VendorSpinelCliCmd():
    """
    Extended Vendor Spinel Cli with vendor hooks commands.
    INPUT:
            spinel-cli > vendor help
    OUTPUT:
            Available vendor commands:
            ==============================================
            help
    """
    vendor_command_names = ['help']

    def do_vendor(self, line):
        params = line.split(" ")
        if params[0] == 'help':
            self.print_topics("\nAvailable vendor commands:",
                              VendorSpinelCliCmd.vendor_command_names, 15, 30)
