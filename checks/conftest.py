"""Make the package importable from a source checkout and re-export the fixtures."""
import os as seal_os
import sys as seal_sys
seal_sys.path.insert(0, seal_os.path.dirname(seal_os.path.dirname(seal_os.path.abspath(__file__))))
from specimens import SEAL_ENTITLEMENTS_PLIST as SEAL_ENTITLEMENTS_PLIST, SEAL_HAVE_TOOLCHAIN as SEAL_HAVE_TOOLCHAIN, seal_bin_entitled as seal_bin_entitled, seal_bin_hardened as seal_bin_hardened, seal_bin_linker_signed as seal_bin_linker_signed, seal_bin_no_pie as seal_bin_no_pie, seal_bin_unsigned as seal_bin_unsigned, seal_requires_toolchain as seal_requires_toolchain, seal_workdir as seal_workdir
