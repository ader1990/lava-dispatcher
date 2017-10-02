import abc
import base64
import logging
import paramiko
import six

from azure.common.credentials import UserPassCredentials
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient

PROVISIONING_STATE_CREATING = 'Creating'

SSH_PUBKEY_FORMAT = "ssh-rsa %s tmp@msftktest"
SSH_PUBKEY_FILEPATH_FORMAT = "/home/%s/.ssh/authorized_keys"
SSH_PRIVATE_PATH_FORMAT = "/tmp/id_rsa_%s.pem"


@six.add_metaclass(abc.ABCMeta)
class BaseAzureBackend(object):
    """A back-end which uses Azure as the driving core."""

    def __init__(self, config, name=None, userdata=None,
                 metadata=None, availability_zone=None):
       self.logger = logging.getLogger('dispatcher')
       self._azure_client = AzureClient(
           config['subscription_id'],
           config['username'],
           config['password'],
           config['resource_group_name'],
           config['storage_account_name'],
           config['resource_group_location'],
           config['vm_username'],
           config['resources_prefix'])

    def setup_instance(self):
        self._azure_client.create_resource_group()
        self._azure_client.create_storage_account()
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

    def ssh_connection(self):
        """Get the paramiko ssh connection."""
        return self._azure_client.get_ssh_connection()

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
                 availability_zone=None, vm_username=None,
                 resources_prefix=None):
        self.vm_disk_size = 50000
        self._subscription_id = subscription_id
        self._username = username
        self._password = password
        self._resource_group_name = resource_group_name
        self._storage_account_name = storage_account_name
        self._availability_zone = availability_zone
        self._vm_username = vm_username
        self._resources_prefix = resources_prefix
        self._creds = UserPassCredentials(username, password)
        self.res_client = ResourceManagementClient(
            self._creds, subscription_id)
        self._stor_client = StorageManagementClient(
            self._creds, subscription_id)
        self._vm_client = ComputeManagementClient(
            self._creds, subscription_id)
        self.net_client = NetworkManagementClient(
            self._creds, subscription_id)
        self.logger = logging.getLogger('dispatcher')

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

    @abc.abstractmethod
    def get_ssh_connection(self):
        pass


class AzureClient(BaseAzureClient):
    """Class for managing Azure instances
    """
    def __init__(self, subscription_id=None, username=None, password=None,
                 resource_group_name=None, storage_account_name=None,
                 availability_zone=None, vm_username=None,
                 resources_prefix=None):
        super(AzureClient, self).__init__(
            subscription_id, username, password, resource_group_name,
            storage_account_name, availability_zone, vm_username,
            resources_prefix)

        random_prefix = self._resources_prefix
        self.vm_name = random_prefix + "-msftk-vm"
        self._os_disk_name = random_prefix + "-msftk-disk"
        self._vnet_name = random_prefix + "-msftk-vnet"
        self._sub_net_name = random_prefix + "-msftk-subnet"
        self._nic_name = random_prefix + "-msftk-nic"
        self._vip_name = random_prefix + "-msftk-vip"
        self._ip_config_name = random_prefix + "-msftk-ip"
        self._sec_group_name = random_prefix + "-msftk-secgrp"
        self._key = None

    def create_vm(self):
        nic = self.create_nic()
        vm_parameters = self._create_vm_parameters(
            self.vm_name, self._vm_username, self._os_disk_name, nic.id)
        self.logger.info('Creating VM %s' % (self.vm_name))
        async_vm_create = self._vm_client.virtual_machines.create_or_update(
            self._resource_group_name, self.vm_name,
            vm_parameters)
        async_vm_create.wait()

        self.logger.info('Starting VM %s' % (self.vm_name))
        async_vm_start = self._vm_client.virtual_machines.start(
            self._resource_group_name, self.vm_name)
        async_vm_start.wait()

    def destroy_vm(self):
        self.logger.info('Cleaning up the resources'
                         ' for VM %s' % (self.vm_name))
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
        self.logger.info('Creating resource '
                         'group %s' % (self._resource_group_name))
        self.res_client.resource_groups.create_or_update(
            self._resource_group_name,
            {
                'location': self._availability_zone
            })

    def create_storage_account(self):
        self.logger.info('Creating storage '
                         'account %s' % (self._storage_account_name))
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

        self.logger.info('Creating security '
                         'group %s' % (self._sec_group_name))
        # pylint: disable=maybe-no-member
        sec_gr_id = self.net_client.network_security_groups.create_or_update(
            self._resource_group_name,
            self._sec_group_name,
            {
                'location': self._availability_zone
            }).result().id
        self.create_security_group_rule(
            self._sec_group_name, 'secgrrule-0', '22', 104, 'inbound')
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

        self.logger.info('Creating subnet %s' % (self._sub_net_name))
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

        self.logger.info('Creating VIP %s' % (self._vip_name))
        # pylint: disable=maybe-no-member
        vip_id = self.net_client.public_ip_addresses.create_or_update(
            self._resource_group_name,
            self._vip_name,
            {
                'location': self._availability_zone,
                'public_ip_allocation_method': 'dynamic'
            }).result().id

        self.logger.info('Creating NIC %s' % (self._nic_name))
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

    def _create_vm_parameters(self, vm_name, vm_username,
                              os_disk_name, nic_id):
        """Create the VM parameters structure.
        """
        self._key = paramiko.RSAKey.generate(2048)
        self._key.write_private_key_file(SSH_PRIVATE_PATH_FORMAT % (vm_name))
        vhd_uri = 'https://{}.blob.core.windows.net/vhds/{}.vhd'.format(
            self._storage_account_name, vm_name)
        userdata_base64 = None
        userdata_path = '/var/www/html/userdata.sh'
        with open(userdata_path, "r") as userdata_file:
            userdata_base64 = base64.b64encode(userdata_file.read())

        return {
            'location': self._availability_zone,
            'os_profile': {
                'computer_name': vm_name,
                'admin_username': vm_username,
                'custom_data': userdata_base64,
                "linux_configuration": {
                    "disable_password_authentication": True,
                    "ssh": {
                        "public_keys": [{
                            "key_data": (SSH_PUBKEY_FORMAT % (
                                         self._key.get_base64())),
                            "path": SSH_PUBKEY_FILEPATH_FORMAT % vm_username}
                        ]
                    }
                }
            },
            'hardware_profile': {
                'vm_size': 'Standard_D1_v2'
            },
            'storage_profile': {
                'image_reference': {
                    'publisher': 'canonical',
                    'offer': 'ubuntuserver',
                    'sku': '16.04.0-LTS',
                    'version': 'latest'
                },
                "os_disk": {
                    "name": os_disk_name,
                    "vhd": {
                        "uri": vhd_uri,
                    },
                    "caching": "ReadWrite",
                    "create_option": "FromImage"
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
        floating_ip = self.net_client.public_ip_addresses.get(
            self._resource_group_name, self._vip_name).ip_address
        if not floating_ip:
            raise Exception('Floating IP not available')
        return floating_ip

    def get_vm_state(self):
        # pylint: disable=maybe-no-member
        return self._vm_client.virtual_machines.get(
            self._resource_group_name, self.vm_name).provisioning_state

    def get_ssh_connection(self):
       self.logger.info('Creating SSH connection for VM %s' % (self.vm_name))
       ssh_client = paramiko.SSHClient()
       ssh_client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
       ssh_client.connect(hostname=self.get_floating_ip(),
                          port=22, username=self._vm_username,
                          pkey=self._key)
       return ssh_client

