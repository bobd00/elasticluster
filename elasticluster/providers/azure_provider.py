#!/usr/bin/env python
#
# Copyright 2015
#

# elasticluster 'azure' package conflicts with azure SDK. This fixes
# it by causing "import azure" to look for a system library module.
from __future__ import absolute_import

# System imports
import base64
import subprocess
import time
import re
import threading

# External imports
from azure import (WindowsAzureError, WindowsAzureMissingResourceError)
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

    __node_start_lock = threading.Lock()  # lock used for node startup

    def __init__(self,
                 subscription_id,
                 certificate,
                 storage_path=None):
        """The constructor of AzureCloudProvider class is called only
        using keyword arguments.

        Usually these are configuration option of the corresponding
        `setup` section in the configuration file.
        """
        print("Entering AzureCloudProvider()")
        # Paramiko debug level
        # logging.getLogger('paramiko').setLevel(logging.DEBUG)
        # logging.basicConfig(level=logging.DEBUG)

        # for winpdb debugging
        # import rpdb2
        # rpdb2.start_embedded_debugger('food')

        # Ansible debug level
        # import ansible
        # import ansible.utils
        # ansible.utils.VERBOSITY = 9

        self._subscription_id = subscription_id
        self._certificate = certificate
        self._instances = {}
        self._storage_path = storage_path
        self._wait_timeout = 600

        self._sms_internal = None
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
        self._short_name = None
        self._deployment = None
        self._load_balancer_ip = None

    def start_instance( self, key_name, public_key_path, private_key_path, security_group, flavor, image_id,
            image_userdata, location, cloud_service_name, username=None, node_name=None, storage_account=None,
            deployment_name=None, hostname=None, **kwargs):
        """Starts a new instance on the cloud using the given properties.
        Multiple instances might be started in different threads at the same
        time. The implementation should handle any problems regarding this
        itself.
        :return: str - instance id of the started instance
        """
        # locking is rudimentary at this point
        with AzureCloudProvider.__node_start_lock:
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

            # azure node names are only significant to 15 chars (???) so create a shortname
            self._short_name = re.sub('^.*-', '', self._node_name)
            self._get_ssh_certificate_tokens(self._public_key_path)

            first = False
            if len(self._instances) == 0:
                first = True
                self._create_global_reqs()
                self._create_node_reqs()
                self._create_vm()
            else:
                self._create_node_reqs()
                self._add_vm()

            self._instances[self._short_name] = {'FULL_NAME': self._node_name, 'SSH_PORT': self._ssh_port,
                                                 'LIVE': True, 'OS_DISK': None}
            if first:
                self._instances[self._short_name]['FIRST'] = True
            self._find_os_disks()
            return self._short_name

    def stop_instance(self, instance_id):
        """Stops the instance gracefully.

        :param str instance_id: instance identifier

        :return: None
        """
        print "Entering stop_instance(instance_id=%s)" % instance_id
        # elasticluster is pretty bad about reporting exceptions, so report any ourselves
        with AzureCloudProvider.__node_start_lock:
            try:
                node_info = self._instances.get(instance_id)
                if node_info is None:
                    raise Exception("could not get state for instance %s" % instance_id)
                if not node_info['LIVE']:
                    print "node %s has already been deleted" % instance_id
                    return
                if node_info.get('FIRST'):
                    # the first vm can only be deleted by deleting the deployment, but
                    # elasticluster doesn't promise to delete it last. Postponing the delete might
                    # lead to unwanted consequences. So, delete the deployment (and all vms)
                    # now,
                    vhds_to_delete = set()
                    for instance_id, node in self._instances.iteritems():
                        if not node['LIVE']:
                            continue
                        node['LIVE'] = False
                        vhds_to_delete.add(node['OS_DISK'])
                        node['OS_DISK'] = None
                    self._delete_deployment()
                    for disk_name in vhds_to_delete:
                        self._delete_vhd(disk_name)
                    self._delete_global_reqs()
                else:
                    node_info['LIVE'] = False
                    vhd_to_delete = node_info['OS_DISK']
                    node_info['OS_DISK'] = None
                    self._delete_vm(instance_id)
                    self._delete_vhd(vhd_to_delete)
            except Exception as e:
                print "error stopping instance %s: %s" % (instance_id, e)
                raise

    def get_ips(self, instance_id):
        """Retrieves the private and public ip addresses for a given instance.
        Note: the Azure provider returns strings of the form ip:port so that
        port mapping to the vms will work.

        :return: list (IPs)
        """
        if self._load_balancer_ip and self._instances[instance_id]['SSH_PORT']:
            return ["%s:%s" % (self._load_balancer_ip, self._instances[instance_id]['SSH_PORT'])]
        self._get_deployment()
        for instance in self._deployment.role_instance_list:
            if instance.instance_name == instance_id:
                for endpoint in instance.instance_endpoints:
                    if endpoint.local_port == '22':    # all should have same vip, but make sure we have ssh
                        self._load_balancer_ip = endpoint.vip
                        return ["%s:%s" % (endpoint.vip, endpoint.public_port)]
        raise Exception("get_ips: couldn't find IP for instance_id %s" % instance_id)


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
        raise Exception("could not get state for instance %s" % instance_id)

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

    def _delete_vm(self, instance_id):
        print "deleting vm %s..." % instance_id
        try:
            result = self._sms.delete_role(service_name=self._cloud_service_name,
                                                     deployment_name=self._deployment_name,
                                                     role_name=instance_id)
            self._wait_result(result, self._wait_timeout)
        except Exception as e:
            print "error deleting vm %s: %s" % (instance_id, e)
            print "TODO DANGER: ignoring error for now!"
            return
            # raise
        print "success"

    def _get_deployment(self):
        try:
            self._deployment = self._sms.get_deployment_by_name(
                service_name=self._cloud_service_name, deployment_name=self._deployment_name)
        except Exception as e:
            raise CloudProviderError("error getting deployment: %s" % str(e))

    def _delete_deployment(self):
        result = self._sms.delete_deployment(service_name=self._cloud_service_name,
                                             deployment_name=self._deployment_name)
        self._wait_result(result, self._wait_timeout)

    @property
    def _sms(self):
        if self._sms_internal is None:
            try:
                self._sms_internal = ServiceManagementService(self._subscription_id, self._certificate)
            except Exception as e:
                print "error initializing azure serice: %s" % e
                raise
        return self._sms_internal

    # TODO: query for what's been built already instead of just catching conflict errors
    def _create_global_reqs(self):
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

    # tear down non-node-specific resources. Current default is to delete everything; this may change.
    def _delete_global_reqs(self):
        print "deleting storage account...",
        self._delete_storage_account()
        print "success"

        print "deleting cloud service...",
        self._delete_cloud_service()
        print "succeeded"

    def _create_node_reqs(self):
        try:
            print "creating network config...",
            self._ssh_port = self._create_network_config()
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

    # TODO unused
    # def _get_vm(self, node_name):
    #    return self._sms.get_role(service_name=self._cloud_service_name, deployment_name=self._deployment_name,
    #                                    role_name=node_name)

    # TODO unused
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

    # note: the method we call is synchronous, but the private method it calls has an async option.
    # this is often the case.
    # TODO unused
    def _delete_affinity_group(self):
        self._sms.delete_affinity_group(affinity_group_name=self._affinity_group)

    def _create_cloud_service(self):
        try:
            result = self._sms.create_hosted_service(service_name=self._cloud_service_name,
            label=self._cloud_service_name, location=self._location)
            self._wait_result(result, self._wait_timeout)
        except WindowsAzureError as e:
            if str(e) == 'Conflict (Conflict)':
                return False
            raise CloudProviderError(msg="error creating cloud service: %s" % e)
        return True

    def _delete_cloud_service(self):
        self._sms.delete_hosted_service(service_name=self._cloud_service_name)

    def _create_storage_account(self):
        try:
            result = self._sms.create_storage_account(
                service_name=self._storage_account,
                description='desc',
                label=self._storage_account,
                location=self._location,
                account_type='Standard_LRS'
                )
            # this seems to be taking much longer than the others...
            self._wait_result(result, self._wait_timeout * 100)
        except WindowsAzureError as e:
            if str(e) == 'Conflict (Conflict)':
                return False
            raise CloudProviderError("error creating storage account: %s" % str(e))
        return True

    def _delete_storage_account(self):
        try:
            self._sms.delete_storage_account(service_name=self._storage_account)
        except Exception as e:
            print "TODO DANGER: ignoring error %s deleting storage account %s" % (e, self._storage_account)

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
        # ssh_config.public_keys.public_keys.append(PublicKey(path=self._public_key_path, fingerprint=self._fingerprint))
        ssh_config.public_keys.public_keys.append(PublicKey(path=authorized_keys_path, fingerprint=self._fingerprint))
        self._linux_config.ssh = ssh_config

        # Create network configuration
        self._network_config = ConfigurationSetInputEndpoints()
        self._network_config.configuration_set_type = 'NetworkConfiguration'
        self._network_config.subnet_names = []
        # create endpoints for ssh (22). Map to 1200 + instance index + port # for the public side
        ssh_port = 22
        public_port = 1200 + (len(self._instances) - 1) + ssh_port
        ret = public_port
        self._network_config.input_endpoints.append(ConfigurationSetInputEndpoint(
            name='TCP-%s' % ssh_port, protocol='TCP', port=public_port, local_port=ssh_port))
        return ret

    def _create_vhd(self):
        disk_url = u'http://%s.blob.core.windows.net/vhds/%s.vhd' % (self._storage_account, self._node_name)
        self._vhd = OSVirtualHardDisk(self._image_id, disk_url)
        return disk_url

    def _delete_vhd(self, name):
        attempts = 100
        for attempt in xrange(1, attempts):
            try:
                # delete_vhd=False doesn't seem to help if the disk is not ready to be deleted yet
                self._sms.delete_disk(disk_name=name, delete_vhd=True)
                print "_delete_vhd: success on attempt %s" % attempt
                return
            except Exception as e:
                print "_delete_vhd: error on attempt #%i to delete disk %s: %s" % (attempt, name, e)
                time.sleep(10)
        print "_delete_vhd: giving up after %i attempts" % attempts
        raise Exception("could not delete vhd %s" % name)

    def _find_os_disks(self):
        try:
            disks = self._sms.list_disks()
            for disk in disks:
                # review - make sure disk is in current storage acct
                if not disk.media_link.split('//')[1].split('.')[0].startswith(self._storage_account):
                    continue
                for instance_id, node in self._instances.iteritems():
                    if node['OS_DISK'] is not None:
                        continue
                    if disk.attached_to is None:
                        continue
                    if disk.attached_to.role_name == instance_id and disk.os == 'Linux':
                        self._instances[instance_id]['OS_DISK'] = disk.name
                        break
        except Exception as e:
            print "error in _find_os_disks: %s" % e
            raise

    # TODO replace with elasticluster or ansible equivalent
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
        del d['_sms_internal']
        return d

    def __setstate__(self, state):
        self.__dict__ = state
        self._sms_internal = None
