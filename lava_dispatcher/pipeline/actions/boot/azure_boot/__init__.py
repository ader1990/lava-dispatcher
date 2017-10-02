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
        #if 'hyperv' not in device['actions']['boot']['methods']:
        #    return False
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
        #azure_backend.cleanup()
        #interact = paramiko_expect.SSHClientInteraction(ssh_connection)
        #return interact

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

        self.sub_command.append(
            'bash /root/lava-dispatcher/ssh.sh -o StrictHostKeyChecking=no '
            '-i %s -ttt %s@%s'
            % (SSH_PRIVATE_PATH_FORMAT % (azure_backend.instance_server()['name']),
               azure_params['vm_username'], azure_backend.floating_ip()))
        shell = ShellCommand(' '.join(self.sub_command),
                             self.timeout, logger=self.logger)

        if shell.exitstatus:
            raise JobError("%s command exited %d: %s" % (
                self.sub_command, shell.exitstatus, shell.readlines()))
        self.logger.info("Started shell command: %s" % (self.sub_command))

        shell_connection = CustomShellSession(self.job, shell)
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

