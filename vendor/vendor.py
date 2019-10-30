from vendor.const import VENDOR_SPINEL

class VendorSpinelCliCmd():
    """
    Extended Vendor Spinel Cli with vendor hooks commands
    INPUT:
            spinel-cli > vendor help
    OUTPUT:
            Available commands from XYZ Vendor:
            ==============================================
            help
    """
    vendor_command_names = ['help']

    def do_vendor(self, line):
        params = line.split(" ")
        if params[0] == 'help':
            self.print_topics(
            "\nAvailable commands from XYZ Vendor:",
            VendorSpinelCliCmd.vendor_command_names, 15, 30)
