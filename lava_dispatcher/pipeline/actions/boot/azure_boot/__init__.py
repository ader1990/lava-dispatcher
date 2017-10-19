import paramiko
import paramiko_expect

from lava_dispatcher.pipeline.utils.constants import LINE_SEPARATOR
from lava_dispatcher.pipeline.logical import Boot, RetryAction
from lava_dispatcher.pipeline.actions.boot import (
    BootAction,
    AutoLoginAction
)
from lava_dispatcher.pipeline.action import (
    Pipeline,
    Action,
    JobError
)

from lava_dispatcher.pipeline.actions.boot.environment import (
    ExportDeviceEnvironment
)
from lava_dispatcher.pipeline.shell import (
    ExpectShellSession,
    ShellCommand
)
from lava_dispatcher.pipeline.custom_shell import (
    CustomShellSession
)
from lava_dispatcher.pipeline.actions.boot.azure_boot.azure_client import (
    BaseAzureBackend
)

SSH_PRIVATE_PATH_FORMAT = "/tmp/id_rsa_%s.pem"


class ParamikoShellCommand(paramiko_expect.SSHClientInteraction):
    """
    Run a command over a connection using pexpect instead of
    subprocess, i.e. not on the dispatcher itself.
    Takes a Timeout object (to support overrides and logging)
    A ShellCommand is a raw_connection for a ShellConnection instance.
    """

    def __init__(self, username, hostname, pkey, lava_timeout, logger=None, cwd=None):
        self.username = username
        self.hostname = hostname
        self.pkey = pkey
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
        self.client.connect(hostname=self.hostname,
                       port=22, username=self.username,
                       pkey=self.pkey, timeout=self.lava_timeout.duration)

        super(ParamikoShellCommand, self).__init__(client=self.client, timeout=lava_timeout.duration,
                                                   display=True,
                                                   output_callback=lambda m: logger.info(m))
        self.name = "ParamikoShellCommand"
        self.before = None
        self.after = None
        self.logger = logger
        # set a default newline character, but allow actions to override as neccessary
        self.linesep = LINE_SEPARATOR
        self.lava_timeout = lava_timeout

    def reconnect(self):
        if not self.client.get_transport().is_active():
            self.logger.info('Reconnecting to ssh channel')
            try:
                self.client.close()
            except:
                pass
            self.client.connect(hostname=self.hostname,
                       port=22, username=self.username,
                       pkey=self.pkey, timeout=self.lava_timeout.duration)

    def sendline(self, s='', delay=0, send_char=False):  # pylint: disable=arguments-differ
        """
        Extends pexpect.sendline so that it can support the delay argument which allows a delay
        between sending each character to get around slow serial problems (iPXE).
        pexpect sendline does exactly the same thing: calls send for the string then os.linesep.
        :param s: string to send
        :param delay: delay in milliseconds between sending each character
        """
        send_char = False
        if delay > 0:
            self.logger.debug("Sending with %s millisecond of delay", delay)
            send_char = True
        self.logger.info(s + self.linesep)
        self.send(s)
        self.send(self.linesep)

    def sendcontrol(self, char):
        return self.send(char)

    def send(self, string, delay=0, send_char=True):  # pylint: disable=arguments-differ
        """
        Extends pexpect.send to support extra arguments, delay and send by character flags.
        """
        self.reconnect()
        sent = 0
        if not string:
            return sent
        delay = float(delay) / 1000
        if send_char:
            for char in string:
                sent = super(ParamikoShellCommand, self).send(char)
                time.sleep(delay)
        else:
            try:
                sent = super(ParamikoShellCommand, self).send(string)
            except:
                self.reconnect()
                raise TestError("ShellCommand command failed.")
        return sent


    def expect(self, *args, **kw):
        """
        No point doing explicit logging here, the SignalDirector can help
        the TestShellAction make much more useful reports of what was matched
        """
        try:
            self.reconnect()
            proc = super(ParamikoShellCommand, self).expect(*args, **kw)
        except pexpect.TIMEOUT:
            raise TestError("ShellCommand command timed out.")
        except socket.error:
            self.reconnect()
            raise TestError("ShellCommand command failed.")
        except socket.timeout:
            raise TestError("ShellCommand command timed out.")
        except ValueError as exc:
            raise TestError(exc)
        except pexpect.EOF:
            # FIXME: deliberately closing the connection (and starting a new one) needs to be supported.
            raise InfrastructureError("Connection closed")
        return proc

    def empty_buffer(self):
        """Make sure there is nothing in the pexpect buffer."""
        index = 0
        while index == 0:
            index = self.expect(['.+', pexpect.EOF, pexpect.TIMEOUT], timeout=1)


class BootAzure(Boot):
    """
    The Boot method prepares the command to run on the dispatcher but this
    command needs to start a new connection and then allow AutoLogin, if
    enabled, and then expect a shell session which can be handed over to the
    test method. self.run_command is a blocking call, so Boot needs to use
    a direct spawn call via ShellCommand (which wraps pexpect.spawn) then
    hand this pexpect wrapper to subsequent actions as a shell connection.
    """

    def __init__(self, parent, parameters):
        super(BootAzure, self).__init__(parent)
        self.action = BootAzureImageAction()
        self.action.section = self.action_type
        self.action.job = self.job
        parent.add_action(self.action, parameters)

    @classmethod
    def accepts(cls, device, parameters):
        if 'azure' not in device['actions']['boot']['methods']:
            return False
        if 'method' not in parameters:
            return False
        if parameters['method'] not in ['azure']:
            return False
        return True


class BootAzureImageAction(BootAction):

    def __init__(self):
        super(BootAzureImageAction, self).__init__()
        self.name = 'boot_image_retry'
        self.description = "boot image with retry"
        self.summary = "boot with retry"

    def populate(self, parameters):
        self.internal_pipeline = Pipeline(parent=self,
                                          job=self.job,
                                          parameters=parameters)
        self.internal_pipeline.add_action(BootAzureRetry())
        if self.has_prompts(parameters):
            self.internal_pipeline.add_action(AutoLoginAction())
            if self.test_has_shell(parameters):
                self.internal_pipeline.add_action(ExpectShellSession())
                self.internal_pipeline.add_action(ExportDeviceEnvironment())


class BootAzureRetry(RetryAction):

    def __init__(self):
        super(BootAzureRetry, self).__init__()
        self.name = 'boot_azure_image'
        self.description = "boot image using Azure"
        self.summary = "boot image using Azure"

    def populate(self, parameters):
        self.internal_pipeline = Pipeline(parent=self,
                                          job=self.job,
                                          parameters=parameters)
        self.internal_pipeline.add_action(CallAzureAction())


class CallAzureAction(Action):

    def __init__(self):
        super(CallAzureAction, self).__init__()
        self.name = "execute-azure-boot"
        self.description = "call Azure via ARM API to boot the image"
        self.summary = "Call Azure ARM APIs to boot the image"
        self.sub_command = []

    def validate(self):
        super(CallAzureAction, self).validate()
        if not self.parameters['method'] == 'azure':
            self.errors = "The Azure booting method is not used."

    def run(self, connection, args=None):
        azure_params = self.job.device['actions'][
            'boot']['methods']['azure']['parameters']['options']
        azure_credentials = azure_params['credentials']
        # Note(avladu): Parameterize resource/storage/username/location
        config = {
            'subscription_id': azure_credentials['subscription_id'],
            'username': azure_credentials['username'],
            'password': azure_credentials['password'],
            'resource_group_name': azure_params['resource_group_name'],
            'storage_account_name': azure_params['storage_account_name'],
            'resource_group_location': azure_params['resource_group_location'],
            'vm_username': azure_params['vm_username'],
            'resources_prefix': ('lava%s' % self.job.job_id)
        }

        azure_backend = BaseAzureBackend(config, '')
        azure_backend.setup_instance()
        ssh_connection = azure_backend.ssh_connection()
        stdin, stdout, stderr = ssh_connection.exec_command('uname -a')
        for line in stdout:
            self.logger.info(line.strip('\n'))

        self.logger.info('SCPing the test overlay to the machine under test')
        guest = self.get_namespace_data(action='apply-overlay-guest',
                                        label='guest', key='filename')
        if guest:
            overlay_path = ('/var/lib/lava/dispatcher/slave/tmp/'
                            '%s/overlay-1.3.4.tar.gz' % (self.job.job_id))
            scp_command = ('scp -o StrictHostKeyChecking=no -i %s %s '
                           '%s@%s:/home/%s/' % (
                                (SSH_PRIVATE_PATH_FORMAT % (
                                azure_backend.instance_server()['name'])),
                                overlay_path, azure_params['vm_username'],
                                azure_backend.floating_ip(),
                                azure_params['vm_username']))
            shell = ShellCommand(scp_command, self.timeout, logger=self.logger)
            exit_code = shell.wait()
            if exit_code is not 0:
                raise JobError("SCP failed with exit code: %d" % (
                               scp_command, exit_code))

            shell_precommand_list = []
            mountpoint = self.get_namespace_data(action='test',
                                                 label='results',
                                                 key='lava_test_results_dir')
            shell_precommand_list.append('sudo -i')
            shell_precommand_list.append('whoami')
            shell_precommand_list.append('tar -xzvf /home/%s/overlay-'
                                         '1.3.4.tar.gz --directory / > /dev/null' % (
                                             azure_params['vm_username']))
            shell_precommand_list.append('ls /')
            shell_precommand_list.append('ls -la %s/bin/lava-test-runner' % mountpoint)
            self.set_namespace_data(action='test', label='lava-test-shell',
                                    key='pre-command-list', value=shell_precommand_list)

        shell = ParamikoShellCommand(username=azure_params['vm_username'],
                                     hostname = azure_backend.floating_ip(),
                                     pkey = azure_backend.private_key(),
                                     lava_timeout = self.timeout, logger=self.logger)

        shell_connection = CustomShellSession(self.job, shell)
        shell_connection.prompt_str = ['kernel: %s' % self.parameters['kernel_version']]
        shell_connection = super(CallAzureAction, self).run(
            shell_connection, args)

        shell_connection.onfinalise = lambda: azure_backend.cleanup()

        res = 'failed' if self.errors else 'success'
        self.set_namespace_data(
            action='boot', label='shared', key='boot-result', value=res)
        self.set_namespace_data(
            action='shared', label='shared', key='connection',
                   value=shell_connection)

        return shell_connection

