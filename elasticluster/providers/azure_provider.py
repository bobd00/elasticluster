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
import logging
import xml.etree.ElementTree as xmltree

# External imports
from azure import WindowsAzureError
from azure.servicemanagement import (ServiceManagementService, OSVirtualHardDisk, SSH, PublicKeys,
                                     PublicKey, LinuxConfigurationSet, ConfigurationSetInputEndpoints,
                                     ConfigurationSetInputEndpoint, PublicIP, PublicIPs, ConfigurationSet,
                                     ConfigurationSets)
from azure.http import HTTPRequest

# Elasticluster imports
from elasticluster import log
from elasticluster.providers import AbstractCloudProvider
from elasticluster.exceptions import CloudProviderError

VNET_NS = 'http://schemas.microsoft.com/ServiceHosting/2011/07/NetworkConfiguration'

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
        # Paramiko debug level
        # logging.getLogger('paramiko').setLevel(logging.DEBUG)
        # logging.basicConfig(level=logging.DEBUG)

        # for winpdb debugging
        #import rpdb2
        #rpdb2.start_embedded_debugger('food')

        # Ansible debug level
        import ansible
        import ansible.utils
        ansible.utils.VERBOSITY = 2

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
        self._storage_account_name = None
        self._deployment_name = None
        self._hostname = None
        self._short_name = None
        self._deployment = None
        self._load_balancer_ip = None
        self._use_public_ips = False
        self._use_short_vm_names = False
        self._created = {}

    def start_instance( self, key_name, public_key_path, private_key_path, security_group, flavor, image_id,
            image_userdata, location, cloud_service_name, username=None, node_name=None, storage_account_name=None,
            deployment_name=None, hostname=None, use_public_ips=None, use_short_vm_names=None, **kwargs):
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
            self._storage_account_name = storage_account_name
            self._deployment_name = deployment_name
            self._hostname = hostname   # used for what now? vs node_name?
            # elasticluster parser doesn't know about bools
            self._use_public_ips = True if use_public_ips == 'True' else False
            self._use_short_vm_names = True if use_short_vm_names == 'True' else False

            # azure node names can only be 64 chars, so trim some name baggage
            self._short_name = self._node_name
            if self._use_short_vm_names:
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
                                                 'LIVE': True, 'OS_DISK': None, 'PAUSED': None, 'PUBLIC_IP' : None}
            if first:
                self._instances[self._short_name]['FIRST'] = True
            self._find_os_disks()
            log.debug('started instance %s' % node_name)
            return self._short_name

    def stop_instance(self, instance_id):
        """Stops the instance gracefully.

        :param str instance_id: instance identifier

        :return: None
        """
        with AzureCloudProvider.__node_start_lock:
            try:
                node_info = self._instances.get(instance_id)
                if node_info is None:
                    raise Exception("could not get state for instance %s" % instance_id)
                if not node_info['LIVE']:
                    log.info("node %s has already been deleted" % instance_id)
                    return
                if node_info.get('FIRST'):
                    # the first vm can only be deleted by deleting the deployment, but
                    # elasticluster doesn't promise to delete it last. Postponing the delete might
                    # lead to unwanted consequences. So, delete the deployment (and all vms)
                    # now,
                    vhds_to_delete = set()
                    for inst_id, node in self._instances.iteritems():
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
                log.error('error stopping instance %s: %s' % (instance_id, e))
                raise
        log.debug('stopped instance %s' % instance_id)

    def get_ips(self, instance_id):
        """Retrieves the private and public ip addresses for a given instance.
        Note: Azure normally provides access to vms from a shared load balancer IP and
        mapping of ssh ports on the vms. So by default, the Azure provider returns strings
        of the form 'ip:port'. However, 'stock' elasticluster and ansible don't support this,
        so _use_public_ips uses Azure PublicIPs to expose each vm on the internet with its own IP
        and using the standard SSH port.

        :return: list (IPs)
        """
        ret = list()
        got_deployment = None
        if instance_id not in self._instances:
            raise Exception("get_ips: instance %s from argument not known" % instance_id)
        if self._use_public_ips:
            if not self._instances[instance_id]['PUBLIC_IP']:
                self._get_deployment()
                got_deployment = True
                for instance in self._deployment.role_instance_list:
                    if instance.instance_name not in self._instances:
                        raise Exception("get_ips (public): instance %s from deployment not known" % instance_id)
                    for public_ip in instance.public_ips:
                        # assume there's just one, take the first
                        self._instances[instance.instance_name]['PUBLIC_IP'] = public_ip.address
                        break
            ret.append(self._instances[instance_id]['PUBLIC_IP'])
        else:
            if not self._load_balancer_ip or not self._instances[instance_id]['SSH_PORT']:
                if not got_deployment:
                    self._get_deployment()
                for instance in self._deployment.role_instance_list:
                    if instance.instance_name not in self._instances:
                        raise Exception("get_ips (port-mapped): instance %s from deployment not known" % instance_id)
                    for endpoint in instance.instance_endpoints:
                        if endpoint.local_port == '22':    # all should have same vip, but make sure we have ssh
                            self._load_balancer_ip = endpoint.vip
                            self._instances[instance.instance_name]['SSH_PORT'] = endpoint.public_port
                            break
            ret.append("%s:%s" % (self._load_balancer_ip, self._instances[instance_id]['SSH_PORT']))
        if not ret:
            raise Exception("get_ips: couldn't find any IP for instance_id %s" % instance_id)
        log.debug('get_ips (instance %s) returning %s' % (instance_id, ', '.join(ret)))
        return ret

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

    # ------------------ add-on methods ---------------------------------
    # (not part of the base class, but useful extensions)

    def pause_instance(self, instance_id, keep_provisioned=True):
        """shuts down the instance without destroying it.

        The AbstractCloudProvider class uses 'stop' to refer to destroying
        a VM, so use 'pause' to mean powering it down while leaving it allocated.

        :param str instance_id: instance identifier

        :return: None
        """
        with AzureCloudProvider.__node_start_lock:
            try:
                node_info = self._instances.get(instance_id)
                if node_info is None:
                    raise Exception("could not get state for instance %s" % instance_id)
                if not node_info['LIVE']:
                    log.debug("node %s has been deleted" % instance_id)
                    return
                if node_info['PAUSED']:
                    log.debug("node %s is already paused" % instance_id)
                    return
                if node_info.get('FIRST'):
                    pass # TODO - determine if any special logic needed for this node
                node_info['PAUSED'] = True
                post_shutdown_action = 'Stopped' if keep_provisioned else 'StoppedDeallocated'
                result = self._sms.shutdown_role(service_name=self._cloud_service_name, deployment_name=self._deployment_name,
                                        role_name=instance_id, post_shutdown_action=post_shutdown_action)
                self._wait_result(result, self._wait_timeout)
            except Exception as e:
                log.error("error pausing instance %s: %s" % (instance_id, e))
                raise
        log.debug('paused instance(instance_id=%s)' % instance_id)

    def restart_instance(self, instance_id):
        """restarts a paused instance.

        :param str instance_id: instance identifier

        :return: None
        """
        with AzureCloudProvider.__node_start_lock:
            try:
                node_info = self._instances.get(instance_id)
                if node_info is None:
                    raise Exception("could not get state for instance %s" % instance_id)
                if not node_info['LIVE']:
                    log.debug('node %s has been deleted, can\'t restart' % instance_id)
                    return
                if not node_info['PAUSED']:
                    log.debug('node %s is not paused, can\'t restart' % instance_id)
                    return
                if node_info.get('FIRST'):
                    pass # TODO - determine if any special logic needed for this node
                node_info['PAUSED'] = False
                result = self._sms.start_role(service_name=self._cloud_service_name, deployment_name=self._deployment_name,
                                        role_name=instance_id)
                self._wait_result(result, self._wait_timeout)
            except Exception as e:
                log.error('error restarting instance %s: %s' % (instance_id, e))
                raise
        log.debug('restarted instance(instance_id=%s)' % instance_id)

    # -------------------- private members ------------------------------

    def _create_vm(self):
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
                log.debug('virtual machine %s already exists.' % self._short_name)
            else:
                log.error('error creating vm %s: %s' % (self._short_name, e))
            raise

    def _add_vm(self):
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
                log.debug('virtual machine %s already exists.' % self._short_name)
            else:
                log.error('error adding vm %s: %s' % (self._short_name, e))
            raise

    def _delete_vm(self, instance_id):
        try:
            result = self._sms.delete_role(service_name=self._cloud_service_name,
                                                     deployment_name=self._deployment_name,
                                                     role_name=instance_id)
            self._wait_result(result, self._wait_timeout)
        except Exception as e:
            log.error('error deleting vm %s: %s' % (instance_id, e))
            raise

    def _get_deployment(self):
        try:
            self._deployment = self._sms.get_deployment_by_name(
                service_name=self._cloud_service_name, deployment_name=self._deployment_name)
        except Exception as e:
            log.error('error getting deployment %s: %s' % (self._deployment_name, e))
            raise

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
                log.error('error initializing azure serice: %s' % e)
                raise
        return self._sms_internal

    def _create_global_reqs(self):
        try:
            if self._create_cloud_service():
                self._created['CLOUD_SERVICE'] = {self._cloud_service_name: True}
                log.debug('created cloud service %s' % self._cloud_service_name)
            else:
                log.debug('cloud service %s already exists' % self._cloud_service_name)
        except Exception as e:
            log.debug('error creating cloud service %s: %s' % (self._cloud_service_name, e))
            raise
        try:
            if self._create_storage_account():
                self._created['STORAGE'] = {self._storage_account_name: True}
                log.debug('created storage account %s' % self._storage_account_name)
            else:
                log.debug('storage account %s already exists' % self._storage_account_name)
        except Exception as e:
            log.error('error creating storage account: %s' % e)
            raise
        try:
            self._add_certificate()
        except Exception as e:
            log.error('error adding certificate: %s' % e)
            raise

    # tear down non-node-specific resources. Current default is to delete everything; this may change.
    def _delete_global_reqs(self):
        if 'STORAGE' in self._created:
            if self._storage_account_name in self._created['STORAGE']:
                self._delete_storage_account()
                log.debug('deleted storage account %s' % self._storage_account_name)
            else:
                log.debug('leaving existing storage account %s intact' % self._storage_account_name)

        if 'CLOUD_SERVICE' in self._created:
            if self._cloud_service_name in self._created['CLOUD_SERVICE']:
                self._delete_cloud_service()
                log.debug('deleted cloud service %s' % self._cloud_service_name)
            else:
                log.debug('leaving existing cloud service %s intact' % self._cloud_service_name)

    def _create_node_reqs(self):
        try:
            (self._network_config, self._ssh_port) = self._create_network_config()
        except Exception as e:
            log.error('error creating network config: %s' % e)
            raise
        try:
            self._create_vhd()
        except Exception as e:
            log.error('error creating vhd: %s' % e)
            raise

    # TODO unused
    def _get_vm(self, instance_name):
        return self._sms.get_role(service_name=self._cloud_service_name, deployment_name=self._deployment_name,
                                        role_name=instance_name)

    def _create_cloud_service(self):
        try:
            result = self._sms.get_hosted_service_properties(service_name=self._cloud_service_name)
            return False    # not created, already exists
        except Exception as e:
            if str(e) != 'Not found (Not Found)':
                log.error('error checking for cloud service %s: %s' % (self._cloud_service_name, str(e)))
                raise
        try:
            result = self._sms.create_hosted_service(service_name=self._cloud_service_name,
                                                label=self._cloud_service_name, location=self._location)
            self._wait_result(result, self._wait_timeout)
        except Exception as e:
            # this shouldn't happen
            # if str(e) == 'Conflict (Conflict)':
            #    return False
            log.error('error creating cloud service %s: %s' % (self._cloud_service_name, e))
            raise
        return True

    def _delete_cloud_service(self):
        try:
            self._sms.delete_hosted_service(service_name=self._cloud_service_name)
        except Exception as e:
            log.error('error deleting cloud service %s: %s' % (self._cloud_service_name, e))
            raise

    def _create_storage_account(self):
        try:
            result = self._sms.get_storage_account_properties(service_name=self._storage_account_name)
            return False    # not created, already exists
        except Exception as e:
            if str(e) != 'Not found (Not Found)':
                log.error('error checking for storage account %s: %s' % (self._storage_account_name, str(e)))
        try:
            result = self._sms.create_storage_account(
                service_name=self._storage_account_name,
                description='desc',
                label=self._storage_account_name,
                location=self._location,
                account_type='Standard_LRS'
                )
            # this seems to be taking much longer than the others...
            self._wait_result(result, self._wait_timeout * 100)
        except Exception as e:
            # this shouldn't happen
            # if str(e) == 'Conflict (Conflict)':
            #    return False
            log.error('error creating storage account: %s' % str(e))
            raise
        return True

    def _delete_storage_account(self):
        try:
            self._sms.delete_storage_account(service_name=self._storage_account_name)
        except Exception as e:
            log.error('error deleting storage account %s' % (e, self._storage_account_name))
            raise

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
        config = ConfigurationSet()
        config.configuration_set_type = 'NetworkConfiguration'
        if self._use_public_ips:
            public_ip = PublicIP(u'pip-%s' % self._node_name)
            public_ip.idle_timeout_in_minutes = 30  # allowed range is 4-30 mins
            public_ips = PublicIPs()
            public_ips.public_ips.append(public_ip)
            config.public_ips = public_ips

        endpoints = ConfigurationSetInputEndpoints()
        endpoints.subnet_names = []
        # create endpoints for ssh (22). Map to 1200 + instance index + port # for the public side
        ssh_port = 22
        public_port = 1200 + (len(self._instances) - 1) + ssh_port
        ret = public_port
        endpoints.input_endpoints.append(ConfigurationSetInputEndpoint(
            name='TCP-%s' % ssh_port, protocol='TCP', port=public_port, local_port=ssh_port))
        config.input_endpoints = endpoints
        return (config, ret)

    def _create_vhd(self):
        disk_url = u'http://%s.blob.core.windows.net/vhds/%s.vhd' % (self._storage_account_name, self._node_name)
        self._vhd = OSVirtualHardDisk(self._image_id, disk_url)
        return disk_url

    def _delete_vhd(self, name):
        attempts = 100
        for attempt in xrange(1, attempts):
            try:
                # delete_vhd=False doesn't seem to help if the disk is not ready to be deleted yet
                self._sms.delete_disk(disk_name=name, delete_vhd=True)
                log.debug('_delete_vhd %s: success on attempt %i' % (name, attempt))
                return
            except Exception as e:
                if str(e) == 'Not found (Not Found)':
                    log.debug("_delete_vhd: 'not found' deleting %s, assuming success" % name)
                    return
                # log.error('_delete_vhd: error on attempt #%i to delete disk %s: %s' % (attempt, name, e))
                time.sleep(10)
        err = '_delete_vhd %s: giving up after %i attempts' % (name, attempts)
        log.error(err)
        raise Exception(err)

    def _find_os_disks(self):
        try:
            disks = self._sms.list_disks()
            for disk in disks:
                # review - make sure disk is in current storage acct
                if not disk.media_link.split('//')[1].split('.')[0].startswith(self._storage_account_name):
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
            log.error('error in _find_os_disks: %s' % e)
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
                err = 'async operation failed: %s' % operation_result.error.message
                log.error(err)
                raise CloudProviderError(err)
        err = 'async operation timed out'
        log.error(err)
        raise CloudProviderError(err)

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

    # support for REST apis not fully supported by Python SDK.
    # experimental.

    def _create_virtual_network(self, location, vnet_name):
        try:
            path = "/%s/services/networking/media" % self._subscription_id
            xml = self._create_vnet_to_xml(location=location, vnet_name=vnet_name)
            result = self._rest_put(path, xml)
        except Exception as e:
            log.error('error in _create_virtual_network: %s' % e)
            raise

    def _rest_put(self, path, xml):
        # need text/plain content-type
        #return self._sms._perform_put(
        #    path,
        #    xml,
        #    async=True)

        request = HTTPRequest()
        request.method = 'PUT'
        request.host = azure.MANAGEMENT_HOST
        request.path = path
        request.body = azure._get_request_body(xml)
        request.path, request.query = _update_request_uri_query(request)
        # request.headers.append(('Content-Length', str(len(request.body))))
        request.headers.append(('Content-Type', 'text/plain'))
        request.headers = self._sms._update_management_header(request, azure.servicemanagement.X_MS_VERSION)
        response = self._sms._perform_request(request)
        return response

    # for testing - see if we can mimic SDK
    def _test_create(self, name):
        try:
            path = self._sms._get_hosted_service_path()
            xml = self._create_hosted_service_to_xml(service_name='alonzo4433', label='fakelabel',
                                                        description='fakedescrip', location='East US')
            result = self._rest_put(path, xml)
            self._wait_result(result, 600)
        except Exception as e:
            log.error('error in _test_create: %s' % e)

    def _deco(self, str):
        return '{%s}%s' % (VNET_NS, str)

    def _create_vnet_to_xml(self, location, vnet_name):
        try:
            template = """<NetworkConfiguration xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.microsoft.com/ServiceHosting/2011/07/NetworkConfiguration">
  <VirtualNetworkConfiguration>
    <Dns>
      <DnsServers>
      </DnsServers>
    </Dns>
    <VirtualNetworkSites>
      <VirtualNetworkSite name="" Location="">
        <AddressSpace>
          <AddressPrefix>10.0.0.0/8</AddressPrefix>
        </AddressSpace>
        <Subnets>
          <Subnet name="subnet1">
            <AddressPrefix>10.0.0.0/11</AddressPrefix>
          </Subnet>
        </Subnets>
        <DnsServersRef>
        </DnsServersRef>
      </VirtualNetworkSite>
    </VirtualNetworkSites>
  </VirtualNetworkConfiguration>
</NetworkConfiguration>"""
            xmltree.register_namespace('', 'http://www.w3.org/2001/XMLSchema')
            xmltree.register_namespace('', 'http://www.w3.org/2001/XMLSchema-instance')
            xmltree.register_namespace('', VNET_NS)
            tree = xmltree.fromstring(template)
            config = tree.find(self._deco('VirtualNetworkConfiguration'))
            sites = config.find(self._deco('VirtualNetworkSites'))
            site = sites.find(self._deco('VirtualNetworkSite'))
            site.set('Location', location)
            site.set('name', vnet_name)
        except Exception as e:
            log.error('_create_vnet_to_xml: %s' % e)
            raise
        print xmltree.tostring(tree)
        return xmltree.tostring(tree)

    # methods to support pickling

    def __getstate__(self):
        d = self.__dict__.copy()
        del d['_sms_internal']
        return d

    def __setstate__(self, state):
        self.__dict__ = state
        self._sms_internal = None
