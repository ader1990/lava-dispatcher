# Copyright (C) 2011 Linaro Limited
#
# Author: Michael Hudson-Doyle <michael.hudson@linaro.org>
#
# This file is part of LAVA Dispatcher.
#
# LAVA Dispatcher is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# LAVA Dispatcher is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along
# with this program; if not, see <http://www.gnu.org/licenses>.

import contextlib
import logging
import subprocess
import re

from lava_dispatcher import deployment_data
from lava_dispatcher.device.target import (
    Target
)
from lava_dispatcher.client.lmc_utils import (
    generate_image,
    image_partition_mounted,
)
from lava_dispatcher.downloader import (
    download_image,
)
from lava_dispatcher.utils import (
    ensure_directory,
    extract_tar,
    finalize_process,
    extract_ramdisk,
    extract_overlay,
    create_ramdisk
)
from lava_dispatcher.errors import (
    CriticalError,
    OperationFailed,
)


class HypervTarget(Target):

    def __init__(self, context, config):
        super(HypervTarget, self).__init__(context, config)
        self.proc = None
        self._hyperv_options = None

    def deploy_linaro_kernel(self, kernel, ramdisk, dtb, overlays, rootfs, nfsrootfs, image, bootloader, firmware, bl0, bl1,
                             bl2, bl31, rootfstype, bootloadertype, target_type, qemu_pflash=None):
        pass

    def deploy_linaro(self, hwpack, rootfs, dtb, rootfstype, bootfstype,
                      bootloadertype, qemu_pflash=None):
        pass
    
    def deploy_linaro_prebuilt(self, image, dtb, rootfstype, bootfstype,
                               bootloadertype, qemu_pflash=None):
        pass

    @contextlib.contextmanager
    def file_system(self, partition, directory):
        self._check_power_state()
        with image_partition_mounted(self._sd_image, partition) as mntdir:
            path = '%s/%s' % (mntdir, directory)
            ensure_directory(path)
            yield path

    def extract_tarball(self, tarball_url, partition, directory='/'):
        logging.info('extracting %s to target', tarball_url)

        self._check_power_state()
        with image_partition_mounted(self._sd_image, partition) as mntdir:
            tb = download_image(tarball_url, self.context, decompress=False)
            extract_tar(tb, '%s/%s' % (mntdir, directory))

    def power_on(self):
        self._check_power_state()
        pass

    def power_off(self, proc):
        pass

    def get_device_version(self):
        return "unknown"

    def _check_power_state(self):
        pass


target_class = HypervTarget
