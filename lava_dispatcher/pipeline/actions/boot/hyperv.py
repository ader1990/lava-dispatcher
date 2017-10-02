# Copyright (C) 2014 Linaro Limited
#

import os
from lava_dispatcher.pipeline.action import (
    Pipeline,
    Action,
    InfrastructureError,
    JobError,
)
from lava_dispatcher.pipeline.logical import Boot, RetryAction
from lava_dispatcher.pipeline.actions.boot import BootAction
from lava_dispatcher.pipeline.actions.boot.environment import ExportDeviceEnvironment
from lava_dispatcher.pipeline.shell import (
    ExpectShellSession,
    ShellCommand,
    ShellSession
)
from lava_dispatcher.pipeline.utils.shell import which
from lava_dispatcher.pipeline.utils.strings import substitute
from lava_dispatcher.pipeline.utils.messages import LinuxKernelMessages
from lava_dispatcher.pipeline.actions.boot import AutoLoginAction

import base64
import functools

try:
    import StringIO
except ImportError:
    import io as StringIO

import multiprocessing
from multiprocessing import pool
import time

import six
from winrm import protocol

CODEPAGE_UTF8 = 65001
THREADS = 1
BUFFER_SIZE = 1024

import abc

import six


class BootHyperv(Boot):
    """
    The Boot method prepares the command to run on the dispatcher but this
    command needs to start a new connection and then allow AutoLogin, if
    enabled, and then expect a shell session which can be handed over to the
    test method. self.run_command is a blocking call, so Boot needs to use
    a direct spawn call via ShellCommand (which wraps pexpect.spawn) then
    hand this pexpect wrapper to subsequent actions as a shell connection.
    """

    compatibility = 4

    def __init__(self, parent, parameters):
        super(BootHyperv, self).__init__(parent)
        self.action = BootHypervImageAction()
        self.action.section = self.action_type
        self.action.job = self.job
        parent.add_action(self.action, parameters)

    @classmethod
    def accepts(cls, device, parameters):
        #if 'hyperv' not in device['actions']['boot']['methods']:
        #    return False
        if 'method' not in parameters:
            return False
        if parameters['method'] not in ['hyperv']:
            return False
        return True


class BootHypervImageAction(BootAction):

    def __init__(self):
        super(BootHypervImageAction, self).__init__()
        self.name = 'boot_image_retry'
        self.description = "boot image with retry"
        self.summary = "boot with retry"

    def populate(self, parameters):
        self.internal_pipeline = Pipeline(parent=self, job=self.job, parameters=parameters)
        self.internal_pipeline.add_action(BootHypervRetry())
        if self.has_prompts(parameters):
            self.internal_pipeline.add_action(AutoLoginAction())
            if self.test_has_shell(parameters):
                self.internal_pipeline.add_action(ExpectShellSession())
                self.internal_pipeline.add_action(ExportDeviceEnvironment())


class BootHypervRetry(RetryAction):

    def __init__(self):
        super(BootHypervRetry, self).__init__()
        self.name = 'boot_hyperv_image'
        self.description = "boot image using HyperV winrm"
        self.summary = "boot HyperV image"

    def populate(self, parameters):
        self.internal_pipeline = Pipeline(parent=self, job=self.job, parameters=parameters)
        self.internal_pipeline.add_action(CallHypervAction())


class CallHypervAction(Action):

    def __init__(self):
        super(CallHypervAction, self).__init__()
        self.name = "execute-hyperv-winrm-on-hostname"
        self.description = "call hyperv via winrm to boot the image"
        self.summary = "execute hyperv via winrm to boot the image"
        self.sub_command = []

    def validate(self):
        super(CallHypervAction, self).validate()
        if not self.parameters['method'] == 'hyperv':
            self.errors = "The hyperv booting method is not used."

    def run(self, connection, args=None):
        """
        CommandRunner expects a pexpect.spawn connection which is the return value
        of target.device.power_on executed by boot in the old dispatcher.

        In the new pipeline, the pexpect.spawn is a ShellCommand and the
        connection is a ShellSession. CommandRunner inside the ShellSession
        turns the ShellCommand into a runner which the ShellSession uses via ShellSession.run()
        to run commands issued *after* the device has booted.
        pexpect.spawn is one of the raw_connection objects for a Connection class.
        """
        namespace = self.parameters.get('namespace', 'common')
        for label in self.data[namespace]['download_action'].keys():
            if label == 'offset' or label == 'available_loops' or label == 'uefi':
                continue
            image_path = self.get_namespace_data(action='download_action', label=label, key='file')
        if not image_path:
            raise JobError("Image could not be found")
        self.logger.info("Extending command line for hyperv test overlay with image: %s" % image_path)
        hyperv_platform_path = r"C:\\Users\\avlad\\work\projects\\lis-pipeline\\scripts\\lis_hyperv_platform\\"
        kernel_artifacts_url = self.parameters['kernel_artifacts_url']
        mkisofs_path = r"C:\\bin\\mkisofs.exe"
        instance_name = ("LavaInstance%s" % self.job.job_id)
        kernel_version = self.parameters['kernel_version']
        vm_check_timeout = "200"
        kernel_url = (r'@("%s/hyperv-daemons_%s_amd64.deb",'
                      r'"%s/linux-headers-%s_%s-10.00.Custom_amd64.deb",'
                      r'"%s/linux-image-%s_%s-10.00.Custom_amd64.deb")' % (kernel_artifacts_url, kernel_version,
                                                                                   kernel_artifacts_url,kernel_version,kernel_version,
                                                                                   kernel_artifacts_url,kernel_version,kernel_version))
        config_drive_path = '%sconfigdrive' % hyperv_platform_path
        user_data_path = "%sinstall_kernel.sh" % hyperv_platform_path
        self.sub_command.append("powershell.exe %s\main.ps1 -VHDPath %s "
                                "-ConfigDrivePath %s -UserDataPath %s -KernelURL %s "
                                "-MkIsoFS %s -InstanceName %s -KernelVersion %s "
                                "-VMCheckTimeout %s;" % (hyperv_platform_path, image_path, config_drive_path,
                                                         user_data_path, kernel_url, mkisofs_path,
                                                         instance_name, kernel_version,
                                                         vm_check_timeout))

        shell = ShellCommand(' '.join(self.sub_command), self.timeout, logger=self.logger)

        if shell.exitstatus:
            raise JobError("%s command exited %d: %s" % (self.sub_command, shell.exitstatus, shell.readlines()))
        self.logger.info("Started shell command: %s" %(self.sub_command))

        shell_connection = ShellSession(self.job, shell)
        if not shell_connection.prompt_str and self.parameters['method'] == 'qemu':
            shell_connection.prompt_str = self.parameters['prompts']
        shell_connection = super(CallHypervAction, self).run(shell_connection, args)

        # FIXME: tests with multiple boots need to be handled too.
        res = 'failed' if self.errors else 'success'
        self.set_namespace_data(action='boot', label='shared', key='boot-result', value=res)
        self.set_namespace_data(action='shared', label='shared', key='connection', value=shell_connection)
        return shell_connection
