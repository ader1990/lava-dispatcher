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


@six.add_metaclass(abc.ABCMeta)
class BaseClient(object):
    """Get a remote client to a Windows instance.

    :param hostname:
        A hostname where the client should connect. This can be
        anything that the client needs (an IP, a fully qualified domain
        name etc.).
    """

    def __init__(self, hostname, username, password, cert_pem, cert_key):
        self._hostname = hostname
        self._username = username
        self._password = password
        self._cert_pem = cert_pem
        self._cert_key = cert_key

    @abc.abstractmethod
    def run_remote_cmd(self, command, command_type=None,
                       upper_timeout=None):
        """Run the given remote command.

        The command will be executed on the remote underlying server.
        It will return a tuple of three elements, stdout, stderr
        and the return code of the command.
        """


class WinRemoteClient(BaseClient):
    """Get a remote client to a Windows instance.
    :param hostname: The IP where the client should be connected.
    :param username: The username of the client.
    :param password: The password of the remote client.
    :param transport_protocol:
        The transport for the WinRM protocol. Only HTTP and HTTPS makes
        sense.
    :param cert_pem:
        Client authentication certificate file path in PEM format.
    :param cert_key:
        Client authentication certificate key file path in PEM format.
    """
    def __init__(self, hostname, username, password,
                 transport_protocol='https',
                 cert_pem=None, cert_key=None):
        super(WinRemoteClient, self).__init__(hostname, username, password,
                                              cert_pem, cert_key)
        self._hostname = "{protocol}://{hostname}:{port}/wsman".format(
            protocol=transport_protocol,
            hostname=hostname,
            port=5985 if transport_protocol == 'http' else 5986)

    @staticmethod
    def sanitize_command_output(content):
        """Sanitizes the output got from underlying instances.
        Sanitizes the output by only returning unicode characters,
        any other characters will be ignored, and will also strip
        down the content of unrequired spaces and newlines.
        """
        return six.text_type(content, errors='ignore').strip()

    @staticmethod
    def _run_command(protocol_client, shell_id, command,
                     command_type,
                     upper_timeout=10):
        command_id = None
        bare_command = command
        thread_pool = pool.ThreadPool(processes=THREADS)

        try:
            command_id = protocol_client.run_command(shell_id, command)

            result = thread_pool.apply_async(
                protocol_client.get_command_output,
                args=(shell_id, command_id))
            stdout, stderr, exit_code = result.get(
                timeout=upper_timeout)
            if exit_code:
                output = "\n\n".join([out for out in (stdout, stderr) if out])
                raise exceptions.ArgusError(
                    "Executing command {command!r} with encoded Command"
                    "{encoded_command!r} failed with exit code {exit_code!r}"
                    " and output {output!r}."
                    .format(command=bare_command,
                            encoded_command=command,
                            exit_code=exit_code,
                            output=output))

            return WinRemoteClient.sanitize_command_output(stdout), stderr, exit_code
        except multiprocessing.TimeoutError:
            raise exceptions.ArgusTimeoutError(
                "The command '{cmd}' has timed out.".format(cmd=bare_command))
        finally:
            thread_pool.terminate()
            protocol_client.cleanup_command(shell_id, command_id)

    def _run_commands(self, commands, commands_type,
                      upper_timeout=10):
        protocol_client = self._get_protocol()
        shell_id = protocol_client.open_shell(codepage=CODEPAGE_UTF8)

        try:
            results = [self._run_command(protocol_client, shell_id, command,
                                         commands_type, upper_timeout)
                       for command in commands]
        finally:
            protocol_client.close_shell(shell_id)
        return results

    def _get_protocol(self):
        protocol.Protocol.DEFAULT_TIMEOUT = "PT3600S"
        return protocol.Protocol(endpoint=self._hostname,
                                 transport='plaintext',
                                 username=self._username,
                                 password=self._password,
                                 server_cert_validation='ignore',
                                 cert_pem=self._cert_pem,
                                 cert_key_pem=self._cert_key)

    def run_remote_cmd(self, cmd, command_type,
                       upper_timeout=10):
        """Run the given remote command.
        The command will be executed on the remote underlying server.
        It will return a tuple of three elements, stdout, stderr
        and the return code of the command.
        """
        return self._run_commands([cmd], command_type,
                                  upper_timeout=upper_timeout)[0]


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
        self.sub_command = [r"C:\bin\icaserial.exe", r"read", r"\\localhost\pipe\helloworld"]
        shell = ShellCommand(' '.join(self.sub_command), self.timeout, logger=self.logger)
        if shell.exitstatus:
            raise JobError("%s command exited %d: %s" % (self.sub_command, shell.exitstatus, shell.readlines()))
        self.logger.debug("started a shell command")

        shell_connection = ShellSession(self.job, shell)
        if not shell_connection.prompt_str and self.parameters['method'] == 'qemu':
            shell_connection.prompt_str = self.parameters['prompts']
        shell_connection = super(CallHypervAction, self).run(shell_connection, args)

        # FIXME: tests with multiple boots need to be handled too.
        res = 'failed' if self.errors else 'success'
        self.set_namespace_data(action='boot', label='shared', key='boot-result', value=res)
        self.set_namespace_data(action='shared', label='shared', key='connection', value=shell_connection)
        return shell_connection

