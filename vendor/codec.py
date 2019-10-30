from spinel.codec import SpinelCodec
from vendor.const import VENDOR_SPINEL


class VendorSpinelPropertyHandler(SpinelCodec):
    """
    Class to extend Spinel property Handler with new methods.
    Methods define parsers for Vendor Hooks.
    exapmle:
    def VENDOR_HOOK_COMMAND(self, _wpan_api, payload): return self.parse_C(payload)
    """
    pass

WPAN_PROP_HANDLER = VendorSpinelPropertyHandler()

#Parameter to extend SPINEL_PREP_DISPATCH with Vendor properties
#example:
#   VENDOR_SPINEL_PROP_DISPATCH = {VENDOR_SPINEL.PROP_VENDOR_HOOK: WPAN_PROP_HANDLER.VENDOR_HOOK_COMMAND}
VENDOR_SPINEL_PROP_DISPATCH = {}

