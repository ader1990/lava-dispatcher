# Copyright (C) 2014 Linaro Limited
#

import os
import six
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

from azure.common.credentials import UserPassCredentials
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient

PROVISIONING_STATE_CREATING = 'Creating'

import abc
@six.add_metaclass(abc.ABCMeta)
class BaseAzureBackend(object):
    """A back-end which uses Azure as the driving core."""

    def __init__(self, name=None, userdata=None, metadata=None,
                 availability_zone=None):
       self.logger = logging.getLogger('dispatcher') 
       self._azure_client = azure_client.AzureClient(
            CONFIG.azure.subscription_id,
            CONFIG.azure.username,
            CONFIG.azure.password,
            CONFIG.azure.resource_group_name,
            CONFIG.azure.storage_account_name,
            CONFIG.azure.resource_group_location,
            CONFIG.azure.image_vhd_path,
            CONFIG.azure.vm_username,
            CONFIG.azure.vm_password)

    def setup_instance(self):
        self.logger.info("Creating Azure resource group")
        self._azure_client.create_resource_group()
        self.logger.info("Creating Azure storage account")
        self._azure_client.create_storage_account()
        self.logger.info("Creating Azure VM")
        self._azure_client.create_vm()

    def cleanup(self):
        self.logger.info("Destroying Azure VM")
        self._azure_client.destroy_vm()

    def internal_instance_id(self):
        """Get the underlying instance ID.

        Gets the instance ID depending on the internals of the back-end.
        """
        return self._azure_client.vm_name

    def floating_ip(self):
        """Get the underlying floating IP."""
        floating_ip = self._azure_client.get_floating_ip()
        self.logger.info("Floating ip is {}".format(floating_ip))
        return floating_ip

    def instance_output(self, limit=6500):
        """Get the console output, sent from the instance."""
        return ""

    def reboot_instance(self):
        """Reboot the underlying instance."""
        pass

    def instance_password(self):
        """Get the underlying instance password, if any."""
        return self._azure_client.vm_password

    def private_key(self):
        """Get the underlying private key."""
        pass

    def public_key(self):
        """Get the underlying public key."""
        pass

    def instance_server(self):
        """Get the instance server object."""
        return {
            'name': self._azure_client.vm_name,
            'id': self._azure_client.vm_name
        }

    def get_image_by_ref(self):
        """Get the image object by its reference id."""
        return {
            'image': {
                'OS-EXT-IMG-SIZE:size': self._azure_client.vm_disk_size
            }
        }

@six.add_metaclass(abc.ABCMeta)
class BaseAzureClient(object):
    """Class for managing Azure instances

    """
    def __init__(self, subscription_id=None, username=None, password=None,
                 resource_group_name=None, storage_account_name=None,
                 availability_zone=None, image_vhd_path=None, vm_username=None,
                 vm_password=None):
        self.vm_disk_size = 50000
        self._subscription_id = subscription_id
        self._username = username
        self._password = password
        self._resource_group_name = resource_group_name
        self._storage_account_name = storage_account_name
        self._availability_zone = availability_zone
        self._image_vhd_path = image_vhd_path
        self._vm_username = vm_username
        self.vm_password = vm_password
        self._creds = UserPassCredentials(username, password)
        self.res_client = ResourceManagementClient(
            self._creds, subscription_id)
        self._stor_client = StorageManagementClient(
            self._creds, subscription_id)
        self._vm_client = ComputeManagementClient(
            self._creds, subscription_id)
        self.net_client = NetworkManagementClient(
            self._creds, subscription_id)

    @abc.abstractmethod
    def create_vm(self):
        pass

    @abc.abstractmethod
    def destroy_vm(self):
        pass

    @abc.abstractmethod
    def create_resource_group(self):
        pass

    @abc.abstractmethod
    def create_storage_account(self):
        pass

    @abc.abstractmethod
    def create_nic(self):
        pass

    @abc.abstractmethod
    def get_floating_ip(self):
        pass

    @abc.abstractmethod
    def get_vm_state(self):
        pass


class AzureClient(BaseAzureClient):
    """Class for managing Azure instances
    """
    def __init__(self, subscription_id=None, username=None, password=None,
                 resource_group_name=None, storage_account_name=None,
                 availability_zone=None, image_vhd_path=None,
                 vm_username=None, vm_password=None):
        super(AzureClient, self).__init__(
            subscription_id, username, password, resource_group_name,
            storage_account_name, availability_zone, image_vhd_path,
            vm_username, vm_password)

        self.vm_name = "argusvm-" + AzureClient._get_random_id()
        self._os_disk_name = "argusdisk-" + AzureClient._get_random_id()
        self._vnet_name = "argusvnet-" + AzureClient._get_random_id()
        self._sub_net_name = "argussubnet-" + AzureClient._get_random_id()
        self._nic_name = "argusnic-" + AzureClient._get_random_id()
        self._vip_name = "argusvip-" + AzureClient._get_random_id()
        self._ip_config_name = "argusip-" + AzureClient._get_random_id()
        self._sec_group_name = 'argussecgrp-' + AzureClient._get_random_id()

    @staticmethod
    def _get_random_id():
        return str(random.randint(0, 10000))

    def create_vm(self):
        nic = self.create_nic()
        vm_parameters = self._create_vm_parameters(
            self.vm_name, self._vm_username, self.vm_password,
            self._os_disk_name, nic.id)
        self._vm_client.virtual_machines.create_or_update(
            self._resource_group_name, self.vm_name,
            vm_parameters)

        self._vm_client.virtual_machines.start(
            self._resource_group_name, self.vm_name)

    def destroy_vm(self):
        self._vm_client.virtual_machines.delete(
            self._resource_group_name, self.vm_name).result()
        self.net_client.network_interfaces.delete(
            self._resource_group_name, self._nic_name).result()
        self.net_client.virtual_networks.delete(
            self._resource_group_name, self._vnet_name).result()
        self.net_client.network_security_groups.delete(
            self._resource_group_name, self._sec_group_name).result()
        self.net_client.public_ip_addresses.delete(
            self._resource_group_name, self._vip_name).result()

    def create_resource_group(self):
        self.res_client.resource_groups.create_or_update(
            self._resource_group_name,
            {
                'location': self._availability_zone
            })

    def create_storage_account(self):
        async_create = self._stor_client.storage_accounts.create(
            self._resource_group_name,
            self._storage_account_name,
            {
                'location': self._availability_zone,
                'sku': {'name': 'standard_lrs'},
                'kind': 'storage'
            })
        async_create.wait()

    def create_security_group_rule(self, sec_group_name,
                                   rule_name, port, priority, direction):
        self.net_client.security_rules.create_or_update(
            self._resource_group_name,
            sec_group_name, rule_name,
            {
                'access': 'allow',
                'protocol': 'Tcp',
                'direction': direction,
                'source_address_prefix': '*',
                'destination_address_prefix': '*',
                'source_port_range': '*',
                'destination_port_range': port,
                'priority': priority
            }).wait()

    def create_nic(self):
        """Create a Network Interface for a VM.
        """

        # pylint: disable=maybe-no-member
        sec_gr_id = self.net_client.network_security_groups.create_or_update(
            self._resource_group_name,
            self._sec_group_name,
            {
                'location': self._availability_zone
            }).result().id
        self.create_security_group_rule(
            self._sec_group_name, 'secgrrule-1', '3389', 100, 'inbound')
        self.create_security_group_rule(
            self._sec_group_name, 'secgrrule-2', '5985', 101, 'inbound')
        self.create_security_group_rule(
            self._sec_group_name, 'secgrrule-3', '5986', 102, 'inbound')
        self.create_security_group_rule(
            self._sec_group_name, 'secgrrule-4', '*', 103, 'outbound')
        self.net_client.virtual_networks.create_or_update(
            self._resource_group_name,
            self._vnet_name,
            {
                'location': self._availability_zone,
                'address_space': {
                    'address_prefixes': ['10.0.0.0/16']
                }
            }).wait()

        # pylint: disable=maybe-no-member
        subnet_id = self.net_client.subnets.create_or_update(
            self._resource_group_name,
            self._vnet_name,
            self._sub_net_name,
            {
                'address_prefix': '10.0.0.0/24',
                'network_security_group':
                {
                    'id': sec_gr_id
                }
            }).result().id

        # pylint: disable=maybe-no-member
        vip_id = self.net_client.public_ip_addresses.create_or_update(
            self._resource_group_name,
            self._vip_name,
            {
                'location': self._availability_zone,
                'public_ip_allocation_method': 'dynamic'
            }).result().id

        return self.net_client.network_interfaces.create_or_update(
            self._resource_group_name,
            self._nic_name,
            {
                'location': self._availability_zone,
                'ip_configurations': [{
                    'name': self._ip_config_name,
                    'subnet': {
                        'id': subnet_id
                    },
                    'public_ip_address': {
                        'id': vip_id
                    },
                }]
            }).result()

    def _create_vm_parameters(self, vm_name, vm_username, vm_password,
                              os_disk_name, nic_id):
        """Create the VM parameters structure.
        """
        vhd_uri = 'https://{}.blob.core.windows.net/vhds/{}.vhd'.format(
            self._storage_account_name, vm_name)
        return {
            'location': self._availability_zone,
            'os_profile': {
                'computer_name': vm_name,
                'admin_username': vm_username,
                'admin_password': vm_password
            },
            'hardware_profile': {
                'vm_size': 'Standard_D1_v2'
            },
            'storage_profile': {
                'os_disk': {
                    'name': os_disk_name,
                    'os_type': 'Windows',
                    'image': {'uri': self._image_vhd_path},
                    'caching': 'None',
                    'create_option': 'fromImage',
                    'vhd': {
                        'uri': vhd_uri
                    }
                }
            },
            'network_profile': {
                'network_interfaces': [{
                    'id': nic_id,
                }]
            },
        }

    def get_floating_ip(self):
        # pylint: disable=maybe-no-member
        vm_state = self.get_vm_state()
        if vm_state != PROVISIONING_STATE_CREATING:
            raise Exception('VM is not in creating state')
        floating_ip = self.net_client.public_ip_addresses.get(
            self._resource_group_name, self._vip_name).ip_address
        if not floating_ip:
            raise Exception('Floating IP not available')
        return floating_ip

    def get_vm_state(self):
        # pylint: disable=maybe-no-member
        return self._vm_client.virtual_machines.get(
            self._resource_group_name, self.vm_name).provisioning_state

class BootAzure(Boot):
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
        self.internal_pipeline = Pipeline(parent=self, job=self.job, parameters=parameters)
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
        self.internal_pipeline = Pipeline(parent=self, job=self.job, parameters=parameters)
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
        """
        CommandRunner expects a pexpect.spawn connection which is the return value
        of target.device.power_on executed by boot in the old dispatcher.

        In the new pipeline, the pexpect.spawn is a ShellCommand and the
        connection is a ShellSession. CommandRunner inside the ShellSession
        turns the ShellCommand into a runner which the ShellSession uses via ShellSession.run()
        to run commands issued *after* the device has booted.
        pexpect.spawn is one of the raw_connection objects for a Connection class.
        """
        pass
