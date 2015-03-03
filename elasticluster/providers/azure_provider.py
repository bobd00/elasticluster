#!/usr/bin/env python
#
# Copyright 2015
#

# dsteinkraus - elasticluster 'azure' package conflicts with azure SDK. This fixes
# it by causing "import azure" to look for a system library module.
from __future__ import absolute_import

# System imports
import base64
import subprocess
import time
import re

# External imports
from azure import WindowsAzureError
from azure.servicemanagement import (ServiceManagementService, OSVirtualHardDisk, SSH, PublicKeys,
                                     PublicKey, LinuxConfigurationSet, ConfigurationSetInputEndpoints,
                                     ConfigurationSetInputEndpoint)

# Elasticluster imports
from elasticluster.providers import AbstractCloudProvider
from elasticluster.exceptions import CloudProviderError

__author__ = 'Bob Davidson <bobd@microsoft.com>'


class AzureCloudProvider(AbstractCloudProvider):
    """This implementation of
    :py:class:`elasticluster.providers.AbstractCloudProvider` uses the
    Azure Python interface connect to the Azure clouds and manage instances.
    """

    def __init__(self,
                 subscription_id,
                 certificate,
                 storage_path=None):
        """The constructor of AzureCloudProvider class is called only
        using keyword arguments.

        Usually these are configuration option of the corresponding
        `setup` section in the configuration file.
        """
        print("azure.py: Entering AzureCloudProvider()")
        self._subscription_id = subscription_id
        self._certificate = certificate
        self._instances = {}
        self._storage_path = storage_path
        self._wait_timeout = 600

        self._key_name = None
        self._public_key_path = None
        self._private_key_path = None
        self._security_group = None
        self._flavor = None
        self._image_id = None
        self._image_userdata = None
        self._cloud_service_name = None
        self._username = None
        self._node_name = None
        self._location = None
        self._storage_account = None
        self._deployment_name = None
        self._hostname = None
        self._affinity_group = None
        self._short_name = None
        self._deployment = None

    def start_instance( self, key_name, public_key_path, private_key_path, security_group, flavor, image_id,
            image_userdata, location, cloud_service_name, username=None, node_name=None, storage_account=None,
            deployment_name=None, hostname=None, affinity_group=None, **kwargs):
        """Starts a new instance on the cloud using the given properties.
        Multiple instances might be started in different threads at the same
        time. The implementation should handle any problems regarding this
        itself.
        :return: str - instance id of the started instance
        """
        self._key_name = key_name
        self._public_key_path = public_key_path
        self._private_key_path = private_key_path
        self._security_group = security_group
        self._flavor = flavor
        self._image_id = image_id
        self._image_userdata = image_userdata
        self._cloud_service_name = cloud_service_name
        self._username = username
        self._node_name = node_name
        self._location = location
        self._storage_account = storage_account
        self._deployment_name = deployment_name
        self._hostname = hostname   # used for what now? vs node_name?
        self._affinity_group = affinity_group

        # azure node names are only significant to 15 chars (???) so create a shortname
        self._short_name = re.sub('^.*-', '', self._node_name)
        self._get_ssh_certificate_tokens(self._public_key_path)

        if len(self._instances) == 0:
            self._create_global_reqs()
            self._create_node_reqs()
            self._create_vm()
        else:
            self._create_node_reqs()
            self._add_vm()

        self._instances[self._short_name] = {'FULL_NAME': self._node_name}
        return self._short_name

    def stop_instance(self, instance_id):
        """Stops the instance gracefully.

        :param str instance_id: instance identifier

        :return: None
        """
        print "azure.py: Entering stop_instance(instance_id=%s)" % instance_id

    def get_ips(self, instance_id):
        """Retrieves the private and public ip addresses for a given instance.

        :return: list (IPs)
        """
        print "azure.py: Entering get_ips(instance_id=%s" % instance_id
        return None

    def is_instance_running(self, instance_id):
        """Checks if the instance is up and running.

        :param str instance_id: instance identifier

        :return: bool - True if running, False otherwise
        """
        node_info = self._instances[instance_id]
        if node_info is None:
            raise Exception("Can't find instance_id %s" % instance_id)

        self._get_deployment()
        for instance in self._deployment.role_instance_list:
            if instance.instance_name == instance_id:
                return instance.power_state == 'Started'
        throw Exception("could not get state for instance %s" % instance_id)

    # -------------------- private members ------------------------------

    def _create_vm(self):
        print "creating vm %s..." % self._node_name
        try:
            result = self._sms.create_virtual_machine_deployment(
                service_name=self._cloud_service_name,
                deployment_name=self._deployment_name,
                deployment_slot='production',
                label=self._short_name,
                role_name=self._short_name,
                system_config=self._linux_config,
                network_config=self._network_config,
                os_virtual_hard_disk=self._vhd,
                role_size=self._flavor,
                role_type='PersistentVMRole',
                virtual_network_name=None
                )
            self._wait_result(result, self._wait_timeout)
        except Exception as e:
            if str(e) == 'Conflict (Conflict)':
                print "virtual machine already exists."
            else:
                print "error creating vm: %s" % e
            raise
        print "created vm %s" % self._node_name

    def _add_vm(self):
        print "adding vm %s..." % self._node_name
        try:
            result = self._sms.add_role(
                service_name=self._cloud_service_name,
                deployment_name=self._deployment_name,
                role_name=self._short_name,
                system_config=self._linux_config,
                network_config=self._network_config,
                os_virtual_hard_disk=self._vhd,
                role_size=self._flavor,
                role_type='PersistentVMRole'
                )
            self._wait_result(result, self._wait_timeout)
        except Exception as e:
            if str(e) == 'Conflict (Conflict)':
                print "virtual machine already exists."
            else:
                print "error adding vm: %s" % e
            raise
        print "added vm %s" % self._node_name

    def _get_deployment(self):
        if self._deployment:
            return
        try:
            self._deployment = self._sms.get_deployment_by_name(
                service_name=self._cloud_service_name, deployment_name=self._deployment_name)
        except WindowsAzureMissingResourceError as e:
            pass  # no such deployment or service
        except WindowsAzureError as e:
            raise CloudProviderError("error getting deployment: %s" % str(e))

    def _delete_deployment(self):
        self._get_deployment()
        result = self._sms.delete_hosted_service(service_name=self._deployment_name)
        self._wait_result(result, self._wait_timeout)

    # TODO: query for what's been built already instead of just catching conflict errors
    def _create_global_reqs(self):
        try:
            self._sms = ServiceManagementService(self._subscription_id, self._certificate)
        except Exception as e:
            print "error initializing azure serice: %s" % e
            raise
        try:
            print "creating affinity group...",
            if self._create_affinity_group():
                print "success"
            else:
                print "already exists"
        except Exception as e:
            print "error creating affinity group: %s" % e
            raise
        try:
            print "creating cloud service...",
            if self._create_cloud_service():
                print "success"
            else:
                print "already exists"
        except Exception as e:
            print "error creating cloud service: %s" % e
            raise
        try:
            print "creating storage account...",
            if self._create_storage_account():
                print "success"
            else:
                print "already exists"
        except Exception as e:
            print "error creating storage account: %s" % e
            raise
        try:
            print "adding certificate...",
            self._add_certificate()
            print "success"
        except Exception as e:
            print "error adding certificate: %s" % e
            raise

    def _create_node_reqs(self):
        try:
            print "creating network config...",
            self._create_network_config()
            print "success"
        except Exception as e:
            print "error creating network config: %s" % e
            raise
        try:
            print "creating vhd...",
            self._create_vhd()
            print "success"
        except Exception as e:
            print "error creating vhd: %s" % e
            raise

    def _get_vm(self, node_name):
        return self._sms.get_role(service_name=self._cloud_service_name, deployment_name=self._deployment_name,
                                        role_name=node_name)

    def _create_affinity_group(self):
        try:
            result = self._sms.create_affinity_group(name=self._affinity_group, label=self._affinity_group,
                                                     location=self._location, description=self._affinity_group)
            self._wait_result(result, self._wait_timeout)
        except WindowsAzureError as e:
            if str(e) == 'Conflict (Conflict)':
                return False
            raise CloudProviderError(msg="error creating affinity group: %s" % e)
        return True

    def _create_cloud_service(self):
        try:
            # result = self._sms.create_hosted_service(service_name=self._cloud_service_name,
            # label=self._cloud_service_name, location=self._location)
            result = self._sms.create_hosted_service(service_name=self._cloud_service_name,
                                                     label=self._cloud_service_name,
                                                     affinity_group=self._affinity_group)
            self._wait_result(result, self._wait_timeout)
        except WindowsAzureError as e:
            if str(e) == 'Conflict (Conflict)':
                return False
            raise CloudProviderError(msg="error creating cloud service: %s" % e)
        return True

    def _create_storage_account(self):
        try:
            result = self._sms.create_storage_account(
                service_name=self._storage_account,
                description='desc',
                label=self._storage_account,
                affinity_group=self._affinity_group,
                # location=self._location,
                account_type='Standard_LRS'
                )
            # this seems to be taking much longer than the others...
            self._wait_result(result, self._wait_timeout * 100)
        except WindowsAzureError as e:
            if str(e) == 'Conflict (Conflict)':
                return False
            raise CloudProviderError("error creating storage account: %s" % str(e))
        return True

    def _add_certificate(self):
        # Add certificate to cloud service
        result = self._sms.add_service_certificate(self._cloud_service_name, self._pkcs12_base64, 'pfx', '')
        self._wait_result(result, self._wait_timeout)

    def _create_network_config(self):
        # Create linux configuration
        self._linux_config = LinuxConfigurationSet(self._short_name, self._username, None,
                                                   disable_ssh_password_authentication=True)
        ssh_config = SSH()
        ssh_config.public_keys = PublicKeys()
        authorized_keys_path = u'/home/%s/.ssh/authorized_keys' % self._username
        ssh_config.public_keys.public_keys.append(PublicKey(path=authorized_keys_path, fingerprint=self._fingerprint))
        self._linux_config.ssh = ssh_config

        # Create network configuration
        self._network_config = ConfigurationSetInputEndpoints()
        self._network_config.configuration_set_type = 'NetworkConfiguration'
        self._network_config.subnet_names = []
        # create endpoints for ssh (22) and http (80). Map them to 1200 + instance index + port # for the public side
        for port in (22, 80):
            public_port = 1200 + (len(self._instances) - 1) + port
            self._network_config.input_endpoints.append(ConfigurationSetInputEndpoint(
                name='TCP-%s' % port, protocol='TCP', port=public_port, local_port=port))

    def _create_vhd(self):
        disk_url = u'http://%s.blob.core.windows.net/vhds/%s.vhd' % (self._storage_account, self._node_name)
        self._vhd = OSVirtualHardDisk(self._image_id, disk_url)

    # TODO replace with elasticluster equivalent
    def _run_command(self, args):
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        return p.returncode, stdout, stderr

    def _wait_result(self, req, timeout):
        if req is None:
            return  # sometimes this happens, seems to mean success
        giveup_time = time.time() + timeout
        while giveup_time > time.time():
            operation_result = self._sms.get_operation_status(req.request_id)
            if operation_result.status == "InProgress":
                time.sleep(10)
                continue
            if operation_result.status == "Succeeded":
                return
            if operation_result.status == "Failed":
                raise CloudProviderError("async operation failed: " + operation_result.error.message)
        raise CloudProviderError('async operation timed out')

    # TODO can't we do this more robustly than with string processing?
    def _get_ssh_certificate_tokens(self, ssh_cert_path):
        rc, stdout, stderr = self._run_command(['openssl', 'x509', '-in', ssh_cert_path, '-fingerprint', '-noout'])
        if rc != 0:
            raise CloudProviderError("error getting fingerprint: %s" % stderr)
        self._fingerprint = stdout.strip()[17:].replace(':', '')

        rc, stdout, stderr = self._run_command(['openssl', 'pkcs12', '-export',
                                                '-in', ssh_cert_path, '-nokeys', '-password', 'pass:'])
        if rc != 0:
            raise CloudProviderError("error getting pkcs12 signature: %s" % stderr)
        self._pkcs12_base64 = base64.b64encode(stdout.strip())


    def __getstate__(self):
        d = self.__dict__.copy()
        del d['_sms']
        return d

    def __setstate__(self, state):
        self.__dict__ = state
        self._sms = None
