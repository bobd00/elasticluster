#!/usr/bin/env python
# Azure provider for elasticluster

# elasticluster 'azure' package conflicts with azure SDK. This fixes
# it by causing "import azure" to look for a system library module.
from __future__ import absolute_import

# System imports
from math import floor, ceil
import base64
import subprocess
import time
import re
import threading
import xml.etree.ElementTree as xmltree

# External imports
import azure
import azure.servicemanagement
from azure.http import HTTPRequest

# Elasticluster imports
from elasticluster import log
from elasticluster.providers import AbstractCloudProvider
from elasticluster.exceptions import CloudProviderError

SSH_PORT = 22
PORT_MAP_OFFSET = 1200
DEFAULT_WAIT_TIMEOUT = 600
WAIT_RESULT_SLEEP = 10
VNET_NS = 'http://schemas.microsoft.com/ServiceHosting' \
          '/2011/07/NetworkConfiguration'

# resource-management constants
VMS_PER_CLOUD_SERVICE = 20
VMS_PER_STORAGE_ACCOUNT = 40
VMS_PER_VNET = 2000
CLOUD_SERVICES_PER_SUBSCRIPTION = 20

# helper functions


def _run_command(args):
    p = subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return p.returncode, stdout, stderr


def _check_positive_integer(name, value):
    ret = -1
    try:
        if '.' in value:
            raise ValueError
        ret = int(value)
        if ret < 1:
            raise ValueError
    except Exception:
        err = "invalid value '%s' for %s, must be integer > 0" % (
            value, name)
        log.error(err)
        raise Exception(err)
    return ret


def ceil_div(a, b):
    return int(ceil(float(a) / b))


def floor_div(a, b):
    return int(floor(float(a) / b))


def _rest_put(subscription, path, xml):
    # can't use SDK _perform_put because we need text/plain content-type
    request = HTTPRequest()
    request.method = 'PUT'
    request.host = azure.MANAGEMENT_HOST
    request.path = path
    request.body = azure._get_request_body(xml)
    request.path, request.query = azure._update_request_uri_query(request)
    # request.headers.append(('Content-Length', str(len(request.body))))
    request.headers.append(('Content-Type', 'text/plain'))
    request.headers = subscription._sms._update_management_header(
        request, azure.servicemanagement.X_MS_VERSION)
    response = subscription._sms._perform_request(request)
    return response


class AzureGlobalConfig:

    """Manage all the settings for an Azure cluster which are
    global as opposed to node-specific.

    This does not manage resources (which are dynamic), only settings
    (which are static, or at least are determined at cluster startup).
    """

    # we only get a few pieces of information at this point
    def __init__(self, parent, subscription_id, certificate, storage_path):
        self._setup_done = False

        self._parent = parent
        # if we got a subscription here, use it. if not,
        # a subscription_file has to be
        # included in the cluster parameters passed to setup().
        if subscription_id:
            self._parent._subscriptions.append(
                AzureSubscription(
                    config=self,
                    subscription_id=subscription_id,
                    certificate=certificate, index=0))

        self._key_name = None
        self._public_key_path = None
        self._private_key_path = None
        self._location = None
        self._base_name = None
        self._username = None
        self._subscription_file = None
        self._use_public_ips = None
        self._n_cloud_services = None
        self._n_storage_accounts = None
        self._n_vms_requested = None
        self._n_subscriptions = None

    # called when the first node is about to be created. this is where
    # we get most of the config info
    def setup(
            self,
            key_name,
            public_key_path,
            private_key_path,
            security_group,
            location,
            base_name=None,
            username=None,
            subscription_file=None,
            frontend_nodes=None,
            compute_nodes=None,
            use_public_ips=None,
            wait_timeout=DEFAULT_WAIT_TIMEOUT,
            n_cloud_services=None,
            n_storage_accounts=None,
            **kwargs):
        self._setup_done = True
        self._key_name = key_name
        self._public_key_path = public_key_path
        self._private_key_path = private_key_path
        self._security_group = security_group
        self._location = location
        self._base_name = base_name
        self._username = username
        self._subscription_file = subscription_file
        self._wait_timeout = _check_positive_integer(
            'wait_timeout', wait_timeout)

        # elasticluster parser doesn't know about bools
        self._use_public_ips = True if use_public_ips == 'True' else False

        # subscriptions
        self._read_subscriptions()

        # resource names will be generated based on this string.
        if len(self._base_name) < 3 or len(self._base_name) > 15:
            err = 'base_name %s not between 3 and 15 characters' \
                  % self._base_name
            log.error(err)
            raise Exception(err)
        if re.match('[^a-z0-9]', self._base_name):
            err = 'base_name %s is invalid, only lowercase letters and ' \
                  'digits allowed' % self._base_name
            log.error(err)
            raise Exception(err)

        n_frontend_nodes = n_compute_nodes = 0
        if frontend_nodes:
            n_frontend_nodes = _check_positive_integer('frontend_nodes',
                                                       frontend_nodes)
        if compute_nodes:
            n_compute_nodes = _check_positive_integer('compute_nodes',
                                                      compute_nodes)
        self._n_vms_requested = n_frontend_nodes + n_compute_nodes

        # if we got resource counts, read them. otherwise compute them.
        if n_cloud_services:
            self._n_cloud_services = _check_positive_integer(
                'n_cloud_services', n_cloud_services)
        else:
            self._n_cloud_services = ceil_div(self._n_vms_requested,
                                              VMS_PER_CLOUD_SERVICE)

        if n_storage_accounts:
            self._n_storage_accounts = _check_positive_integer(
                'n_storage_accounts', n_storage_accounts)
        else:
            self._n_storage_accounts = ceil_div(self._n_vms_requested,
                                                VMS_PER_STORAGE_ACCOUNT)

        self._n_subscriptions = len(self._parent._subscriptions)
        min_subscriptions = ceil_div(self._n_cloud_services,
                                     CLOUD_SERVICES_PER_SUBSCRIPTION)
        if self._n_subscriptions < min_subscriptions:
            err = 'Not enough subscriptions available to meet resource' \
                  'requirements (have %i, need %i)' % \
                  (len(self._parent._subscriptions), min_subscriptions)
            log.error(err)
            raise Exception(err)
        log.debug('compute nodes: %i. cloud services: %i. storage accounts:'
                  ' %i. subscriptions: %i.', self._n_vms_requested,
                  self._n_cloud_services, self._n_storage_accounts,
                  self._n_subscriptions)

        # store values needed to map vms to resources
        self._vm_per_cs = ceil_div(
            self._n_vms_requested, self._n_cloud_services)
        self._cs_per_sub = ceil_div(
            self._n_cloud_services, self._n_subscriptions)
        self._vm_per_sub = self._vm_per_cs * self._cs_per_sub

        self._vm_per_sa = ceil_div(
            self._n_vms_requested, self._n_storage_accounts)
        self._sa_per_sub = ceil_div(
            self._n_storage_accounts, self._n_subscriptions)
        if self._vm_per_sub != self._vm_per_sa * self._sa_per_sub:
            err = 'inconsistency, %i != %i' % \
                  (self._vm_per_sub, self._vm_per_sa * self._sa_per_sub)
            log.error(err)
            raise Exception(err)

    # there are three ways to designate a node in the cluster:
    # - by its flat index (0..total nodes - 1)
    # - by its node name (we will use basename_vm%i where %i is the flat index)
    # - by its resources - index of its subscription, its cloud service
    #   (or alternatively its storage account), and its index within that
    #   cloud service or storage account.
    # We need all possible conversions amongst these.

    def _vm_name_to_flat(self, vm_name):
        if vm_name.startswith(self._base_name + '_vm'):
            bare = vm_name[len(self._base_name) + 3:]
            return int(bare)

    def _vm_flat_to_resources(self, vm_index):
        i_sub = floor_div(vm_index, self._vm_per_sub)
        i_cs = floor_div(vm_index % self._vm_per_sub, self._vm_per_cs)
        i_vm_in_cs = vm_index - (i_sub * self._vm_per_sub) - \
            (i_cs * self._vm_per_cs)
        i_sa = floor_div(vm_index % self._vm_per_sub, self._vm_per_sa)
        i_vm_in_sa = vm_index - (i_sub * self._vm_per_sub) - \
            (i_sa * self._vm_per_sa)
        return i_sub, i_cs, i_vm_in_cs, i_sa, i_vm_in_sa

    def _vm_name_to_resources(self, vm_name):
        return self._vm_flat_to_resources(self._vm_name_to_flat(vm_name))

    def _read_subscriptions(self):
        ids = set()
        if self._subscription_file:
            if self._parent._subscriptions:
                log.debug(
                    'subscription was passed in cloud section, and '
                    'subscription_file was '
                    'also passed in cluster section. using both.')
                ids.add(self._parent._subscriptions[0]._subscription_id)
            try:
                pattern = re.compile(
                    'subscription_id=(\S*)\s+certificate=(.*)')
                with open(self._subscription_file) as f:
                    for line in f:
                        m = pattern.match(line)
                        if m:
                            if m.group(1) in ids:
                                log.debug('subscription_id %s has already been'
                                          ' read. ignoring.' % m.group(1))
                            else:
                                ids.add(m.group(1))
                                index = len(self._parent._subscriptions)
                                self._parent._subscriptions.append(
                                    AzureSubscription(config=self,
                                                      subscription_id=m.group(
                                                          1),
                                                      certificate=m.group(2),
                                                      index=index))
                        else:
                            log.debug(
                                'ignoring line in subscription_file %s: %s' %
                                (self._subscription_file, line))
            except Exception as e:
                log.error('error parsing subscription file %s: %s' %
                          (self._subscription_file, e))


class AzureSubscription:

    def __init__(self, config, subscription_id, certificate, index):
        self._do_cleanup = False    # never delete a subscription
        self._config = config
        self._subscription_id = subscription_id
        self._certificate = certificate
        self._index = index
        self._sms_internal = None
        self._resource_lock_internal = None
        self._storage_accounts = list()
        self._cloud_services = list()
        self._vnet = None

        rc, stdout, stderr = _run_command(
            ['openssl', 'x509', '-in', self._certificate,
             '-fingerprint', '-noout'])
        if rc != 0:
            err = "error getting fingerprint: %s" % stderr
            log.error(err)
            raise Exception(err)
        self._fingerprint = stdout.strip()[17:].replace(':', '')

        rc, stdout, stderr = _run_command(
            ['openssl', 'pkcs12', '-export', '-in', self._certificate,
             '-nokeys', '-password', 'pass:'])
        if rc != 0:
            err = "error getting pkcs12 signature: %s" % stderr
            log.error(err)
            raise Exception(err)
        self._pkcs12_base64 = base64.b64encode(stdout.strip())

    @property
    def _resource_lock(self):
        if self._resource_lock_internal is None:
            self._resource_lock_internal = threading.Lock()
        return self._resource_lock_internal

    @property
    def _sms(self):
        with self._resource_lock:
            if self._sms_internal is None:
                try:
                    self._sms_internal = \
                        azure.servicemanagement.ServiceManagementService(
                            self._subscription_id, self._certificate)
                except Exception as e:
                    log.error('error initializing azure serice: %s' % e)
                    raise
            return self._sms_internal

    @property
    def _n_instances(self):
        ret = 0
        for cloud_service in self._cloud_services:
            ret = ret + cloud_service._n_instances
        return ret

    # this needs to be in here because sms is per-subscription
    def _wait_result(self, req, timeout=None):
        if not timeout:
            timeout = self._config._wait_timeout
        if not req:
            return  # sometimes this happens, seems to mean success
        giveup_time = time.time() + timeout
        while giveup_time > time.time():
            operation_result = self._sms.get_operation_status(req.request_id)
            if operation_result.status == "InProgress":
                time.sleep(WAIT_RESULT_SLEEP)
                continue
            if operation_result.status == "Succeeded":
                return
            if operation_result.status == "Failed":
                err = 'async operation failed: %s' \
                      % operation_result.error.message
                log.error(err)
                raise CloudProviderError(err)
        err = 'async operation timed out'
        log.error(err)
        raise CloudProviderError(err)

    def __getstate__(self):
        d = self.__dict__.copy()
        del d['_resource_lock_internal']
        del d['_sms_internal']
        return d

    def __setstate__(self, state):
        self.__dict__ = state
        self._resource_lock_internal = None
        self._sms_internal = None

    def _find_os_disks(self):
        # associate disk names of os vhd's with their nodes.
        try:
            disks = self._sms.list_disks()
            for disk in disks:
                for cloud_service in self._cloud_services:
                    for vm_name, vm in cloud_service._instances.iteritems():
                        if vm._os_vhd_name:
                            continue
                        if vm_name in disk.name and \
                                self._config._base_name in disk.name:
                            vm._os_vhd_name = disk.name
        except Exception as e:
            log.error('error in _find_os_disks: %s' % e)
            raise


class AzureCloudService:

    def __init__(self, config, subscription, index):
        self._do_cleanup = False
        self._config = config
        self._subscription = subscription
        self._location = config._location
        self._index = index
        self._name = "%s0su%ics%i" % (
            self._config._base_name, self._subscription._index, self._index)
        # treat deployment as sub-item of cloud service
        # deployment has same name as cloud service
        # only instances owned by this cloud service:
        self._instances = {}
        self._resource_lock_internal = None

    @property
    def _resource_lock(self):
        if self._resource_lock_internal is None:
            self._resource_lock_internal = threading.Lock()
        return self._resource_lock_internal

    @property
    def _n_instances(self):
        with self._resource_lock:
            return len(self._instances)

    @property
    def _exists(self):
        try:
            result = self._subscription._sms.get_hosted_service_properties(
                service_name=self._name)
            return True    # already exists
        except Exception as e:
            if str(e) != 'Not found (Not Found)':
                log.error('error checking for cloud service %s: %s' %
                          (self._name, str(e)))
                raise
        return False

    def _create(self):
        if not self._exists:
            try:
                result = self._subscription._sms.create_hosted_service(
                    service_name=self._name,
                    label=self._name,
                    location=self._location)
                self._subscription._wait_result(result)
            except Exception as e:
                # this shouldn't happen
                # if str(e) == 'Conflict (Conflict)':
                #    return False
                log.error('error creating cloud service %s: %s' %
                          (self._name, e))
                raise

    def _delete(self):
        if self._deployment:
            log.error("can't delete cloud service %s. It contains a "
                      "deployment and at least one node." % self._name)
            return False
        try:
            self._subscription._sms.delete_hosted_service(
                service_name=self._name)
        except Exception as e:
            log.error('error deleting cloud service %s: %s' %
                      (self._name, e))
            raise
        return True

    # don't call directly. called by an AzureVM when it's being deleted
    # and is the last node in the deployment.
    def _delete_deployment(self):
        try:
            result = self._subscription._sms.delete_deployment(
                service_name=self._name,
                deployment_name=self._name)
            self._subscription._wait_result(result)
        except Exception as e:
            log.error('error deleting deployment from cloud service %s: %s' %
                      (self._name, e))
            raise

    @property
    def _deployment(self):
        try:
            dep = self._subscription._sms.get_deployment_by_name(
                service_name=self._name, deployment_name=self._name)
            if not dep:
                raise Exception('get_deployment_by_name for %s did not return'
                                ' a value' % self._name)
            return dep
        except Exception as exc:
            log.error('error getting deployment %s: %s' % (self._name, exc))
            raise

    def _add_certificate(self):
        # Add certificate to cloud service
        result = self._subscription._sms.add_service_certificate(
            self._name, self._subscription._pkcs12_base64, 'pfx', '')
        self._subscription._wait_result(result)

    def __getstate__(self):
        d = self.__dict__.copy()
        del d['_resource_lock_internal']
        return d

    def __setstate__(self, state):
        self.__dict__ = state
        self._resource_lock_internal = None


class AzureStorageAccount:

    def __init__(self, config, subscription, index):
        self._do_cleanup = False
        self._created = False
        self._config = config
        self._subscription = subscription
        self._index = index
        self._name = "%s0su%ist%i" % (
            self._config._base_name, self._subscription._index, self._index)
        self._resource_lock_internal = None

    @property
    def _resource_lock(self):
        if self._resource_lock_internal is None:
            self._resource_lock_internal = threading.Lock()
        return self._resource_lock_internal

    def _exists(self):
        try:
            result = self._subscription._sms.get_storage_account_properties(
                service_name=self._name)
            # TODO dsteinkraus - make sure it's actually one of ours
            return True
        except Exception as e:
            if str(e) != 'Not found (Not Found)':
                log.error('error checking for storage account %s: %s' %
                          (self._name, str(e)))
                raise
            return False

    def _create(self):
        if not self._exists():
            try:
                result = self._subscription._sms.create_storage_account(
                    service_name=self._name,
                    description=self._name,
                    label=self._name,
                    location=self._config._location,
                    account_type='Standard_LRS'
                )
                # this seems to be taking much longer than the others...
                self._subscription._wait_result(
                    result, self._config._wait_timeout * 10)
                self._config._parent._storage_accounts.add(self)
            except Exception as e:
                # this shouldn't happen
                # if str(e) == 'Conflict (Conflict)':
                #    return False
                log.error('error creating storage account: %s' % str(e))
                raise

    def _delete(self):
        try:
            self._subscription._sms.delete_storage_account(
                service_name=self._name)
        except Exception as exc:
            log.error('error deleting storage account %s: %s' %
                      (self._name, exc))
            raise

    def _create_vhd(self, node_name, image_id):
        disk_url = u'http://%s.blob.core.windows.net/vhds/%s.vhd' % (
            self._name, node_name)
        vhd = azure.servicemanagement.OSVirtualHardDisk(image_id, disk_url)
        return vhd, disk_url

    def _delete_vhd(self, name):
        attempts = 100
        for attempt in range(1, attempts):
            try:
                # delete_vhd=False doesn't seem to help if the disk is not
                # ready to be deleted yet
                self._subscription._sms.delete_disk(
                    disk_name=name, delete_vhd=True)
                log.debug('_delete_vhd %s: success on attempt %i' %
                          (name, attempt))
                return
            except Exception as e:
                if str(e) == 'Not found (Not Found)':
                    log.debug(
                        "_delete_vhd: 'not found' deleting %s, assuming "
                        "success" % name)
                    return
                # log.error('_delete_vhd: error on attempt #%i to delete disk
                # %s: %s' % (attempt, name, e))
                time.sleep(10)
        err = '_delete_vhd %s: giving up after %i attempts' % (name, attempts)
        log.error(err)
        raise Exception(err)

    def __getstate__(self):
        d = self.__dict__.copy()
        del d['_resource_lock_internal']
        return d

    def __setstate__(self, state):
        self.__dict__ = state
        self._resource_lock_internal = None


class AzureVNet:

    def __init__(self, config, subscription, index):
        self._do_cleanup = False
        self._config = config
        self._subscription = subscription
        self._index = index
        self._name = "%s0su%ivn%i" % (
            self._config._base_name, self._subscription._index, self._index)
        self._resource_lock_internal = None

    @property
    def _resource_lock(self):
        if self._resource_lock_internal is None:
            self._resource_lock_internal = threading.Lock()
        return self._resource_lock_internal

    def _exists(self):
        try:
            result = self._subscription._sms.list_virtual_network_sites()
            if len(result):
                for virtual_network_site in result.virtual_network_sites:
                    if virtual_network_site.name == self._name:
                        return True
                return False
            else:
                return False    # no vnets
        except Exception as exc:
            log.error('error checking existence of vnet %s: %s',
                      self._name, exc)
            raise

    def _create(self):
        if not self._exists():
            try:
                # note that this is replacing the whole network config,
                # so would succeed even if vnet already existed
                path = "/%s/services/networking/media" % \
                       self._subscription._subscription_id
                xml = self._create_vnet_to_xml(
                    location=self._config._location, vnet_name=self._name)
                result = _rest_put(self._subscription, path, xml)
                log.debug('created vnet %s', self._name)
            except Exception as e:
                err = 'error in _create_virtual_network: %s' % e
                log.error(err)
                raise

    def _delete(self):
        if self._exists():
            # TODO dsteinkraus - to have full support for creating and
            # deleting a vnet while a subscription has other vnets, we
            # would need to download current config, remove or add the
            # vnet we want to change, and re-upload the config. Not sure
            # how useful this would be, since it's easy to create a new
            # subscription for a project and just use one vnet in that
            # subscription.
            return

    def _deco(self, str):
        return '{%s}%s' % (VNET_NS, str)

    def _create_vnet_to_xml(self, location, vnet_name):
        try:
            template = "<NetworkConfiguration xmlns:xsd=\"http://www.w3.org/" \
                       "2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/" \
                       "XMLSchema-instance\" xmlns=\"http://schemas." \
                       "microsoft.com/ServiceHosting/2011/07/" \
                       "NetworkConfiguration\">"
            template = template + """
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
            xmltree.register_namespace(
                '', 'http://www.w3.org/2001/XMLSchema-instance')
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

    def __getstate__(self):
        d = self.__dict__.copy()
        del d['_resource_lock_internal']
        return d

    def __setstate__(self, state):
        self.__dict__ = state
        self._resource_lock_internal = None


class AzureVM:

    def __init__(
            self,
            config,
            node_index,
            cloud_service=None,
            storage_account=None,
            subscription=None,
            flavor=None,
            image=None,
            node_name=None,
            host_name=None,
            image_userdata=None):
        self._do_cleanup = False
        self._config = config
        self._node_index = node_index
        self._cloud_service = cloud_service
        self._storage_account = storage_account
        self._subscription = subscription
        self._flavor = flavor
        self._image = image
        self._node_name = node_name
        self._host_name = host_name
        self._image_userdata = image_userdata

        # figure out what sub, cloud serv, stor acct to use if not specified
        if not self._cloud_service:
            parent = self._config._parent
            (i_subscription, i_cloud_service, i_vm_in_cs, i_storage_account,
             i_vm_in_sa) = self._config._vm_flat_to_resources(self._node_index)
            self._subscription = parent._subscriptions[i_subscription]
            self._cloud_service = \
                self._subscription._cloud_services[i_cloud_service]
            self._storage_account = \
                self._subscription._storage_accounts[i_storage_account]

        self._qualified_name = '{0}_vm{1:04d}'.format(
            self._config._base_name, self._node_index)
        self._public_ip_internal = None
        self._ssh_port = None
        self._os_virtual_hard_disk = None
        self._os_vhd_name = None
        self._created = False
        self._paused = False

    def _delete(self):
        try:
            if len(self._cloud_service._instances) == 1:
                # we are the last node, so delete deployment
                self._cloud_service._delete_deployment()
            else:
                result = self._cloud_service._subscription._sms.delete_role(
                    service_name=self._cloud_service._name,
                    deployment_name=self._cloud_service._name,
                    role_name=self._qualified_name)
                self._subscription._wait_result(result)
            self._storage_account._delete_vhd(self._os_vhd_name)
            with self._cloud_service._resource_lock:
                del(self._cloud_service._instances[self._qualified_name])
            # TODO - delete/reset our self?
        except Exception as e:
            log.error('error deleting vm %s: %s' % (self._qualified_name, e))
            raise

    def _start(self):
        try:
            self._create_network_config()

            (self._os_virtual_hard_disk, _) = \
                self._storage_account._create_vhd(self._node_name, self._image)
            virtual_network_name = \
                self._config._parent._subscriptions[0]._vnet._name

            sms = self._cloud_service._subscription._sms
            if self._cloud_service._instances:
                # add a node to existing deployement
                result = sms.add_role(
                    service_name=self._cloud_service._name,
                    deployment_name=self._cloud_service._name,
                    role_name=self._qualified_name,
                    system_config=self._system_config,
                    network_config=self._network_config,
                    os_virtual_hard_disk=self._os_virtual_hard_disk,
                    role_size=self._flavor,
                    role_type='PersistentVMRole')
                self._subscription._wait_result(result)
            else:
                # create the deployment and first node
                result = sms.create_virtual_machine_deployment(
                    service_name=self._cloud_service._name,
                    deployment_name=self._cloud_service._name,
                    deployment_slot='production',
                    label=self._node_name,
                    role_name=self._qualified_name,
                    system_config=self._system_config,
                    network_config=self._network_config,
                    os_virtual_hard_disk=self._os_virtual_hard_disk,
                    role_size=self._flavor,
                    role_type='PersistentVMRole',
                    virtual_network_name=virtual_network_name)
                self._subscription._wait_result(result)
        except Exception as e:
            if str(e) == 'Conflict (Conflict)':
                log.debug('virtual machine %s already exists.'
                          % self._qualified_name)
            else:
                log.error('error creating vm %s: %s'
                          % (self._qualified_name, e))
            raise
        self._created = True
        with self._cloud_service._resource_lock:
            self._cloud_service._instances[self._qualified_name] = self

        # need to find the disk name for the OS disk attached to this vm.
        # this involves redundant work that should be dealt with if it's
        # a problem.
        self._subscription._find_os_disks()

    def pause(self, instance_id, keep_provisioned=True):
        """shuts down the instance without destroying it.

        The AbstractCloudProvider class uses 'stop' to refer to destroying
        a VM, so use 'pause' to mean powering it down while leaving it
        allocated.

        :param str instance_id: instance identifier

        :return: None
        """
        try:
            node_info = self._instances.get(instance_id)
            if node_info is None:
                raise Exception(
                    "could not get state for instance %s" % instance_id)
            if node_info['PAUSED']:
                log.debug("node %s is already paused" % instance_id)
                return
            if node_info.get('FIRST'):
                # TODO - determine if any special logic needed for this
                # node
                pass
            node_info['PAUSED'] = True
            post_shutdown_action = 'Stopped' if keep_provisioned else \
                'StoppedDeallocated'
            result = self._sms[0].shutdown_role(
                service_name=self._cloud_service_name,
                deployment_name=self._deployment_name,
                role_name=instance_id,
                post_shutdown_action=post_shutdown_action)
            self._subscription._wait_result(result)
        except Exception as e:
            log.error("error pausing instance %s: %s" % (instance_id, e))
            raise
        log.debug('paused instance(instance_id=%s)' % instance_id)

    def restart(self, instance_id):
        """restarts a paused instance.

        :param str instance_id: instance identifier

        :return: None
        """
        try:
            node_info = self._instances.get(instance_id)
            if node_info is None:
                raise Exception(
                    "could not get state for instance %s" % instance_id)
            if not node_info['PAUSED']:
                log.debug(
                    'node %s is not paused, can\'t restart' % instance_id)
                return
            if node_info.get('FIRST'):
                # TODO - determine if any special logic needed for this
                # node
                pass
            node_info['PAUSED'] = False
            result = self._sms[0].start_role(
                service_name=self._cloud_service_name,
                deployment_name=self._deployment_name,
                role_name=instance_id)
            self._subscription._wait_result(result)
        except Exception as e:
            log.error('error restarting instance %s: %s' %
                      (instance_id, e))
            raise
        log.debug('restarted instance(instance_id=%s)' % instance_id)

    def _create_network_config(self):
        # Create linux configuration
        self._system_config = azure.servicemanagement.LinuxConfigurationSet(
            self._node_name,
            self._config._username,
            None,
            disable_ssh_password_authentication=True)
        ssh_config = azure.servicemanagement.SSH()
        ssh_config.public_keys = azure.servicemanagement.PublicKeys()
        authorized_keys_path = u'/home/%s/.ssh/authorized_keys' \
                               % self._config._username
        ssh_config.public_keys.public_keys.append(
            azure.servicemanagement.PublicKey(
                path=authorized_keys_path,
                fingerprint=self._subscription._fingerprint))
        self._system_config.ssh = ssh_config

        # Create network configuration
        self._network_config = azure.servicemanagement.ConfigurationSet()
        self._network_config.configuration_set_type = 'NetworkConfiguration'
        if self._config._use_public_ips:
            public_ip = azure.servicemanagement.PublicIP(
                u'pip-%s' % self._node_name)
            # allowed range is 4-30 mins
            public_ip.idle_timeout_in_minutes = 30
            public_ips = azure.servicemanagement.PublicIPs()
            public_ips.public_ips.append(public_ip)
            self._network_config.public_ips = public_ips
            self._ssh_port = SSH_PORT
        else:
            # create endpoints for ssh (22). Map to an offset + instance
            # index + port # for the public side
            self._ssh_port = PORT_MAP_OFFSET + self._node_index + SSH_PORT

        endpoints = azure.servicemanagement.ConfigurationSetInputEndpoints()
        endpoints.subnet_names = []
        endpoints.input_endpoints.append(
            azure.servicemanagement.ConfigurationSetInputEndpoint(
                name='TCP-%s' %
                self._ssh_port,
                protocol='TCP',
                port=self._ssh_port,
                local_port=SSH_PORT))
        self._network_config.input_endpoints = endpoints

    @property
    def _power_state(self):
        instances = self._cloud_service._deployment.role_instance_list
        for instance in instances:
            if instance.instance_name == self._qualified_name:
                # cache IP since it will be asked for soon
                if self._config._use_public_ips:
                    self._public_ip_internal = instance.public_ips[0].address
                else:
                    self._public_ip_internal = instance.instance_endpoints[
                        0].vip
                return instance.power_state
        raise Exception("could not get power_state for instance %s"
                        % self._qualified_name)

    @property
    def _public_ip(self):
        if not self._public_ip_internal:
            # not cached, so look it up
            instances = self._cloud_service._deployment.role_instance_list
            for instance in instances:
                if instance.instance_name == self._qualified_name:
                    if self._config._use_public_ips:
                        self._public_ip_internal = instance.public_ips[
                            0].address
                    else:
                        self._public_ip_internal = instance.instance_endpoints[
                            0].vip
                    return instance.power_state
            raise Exception("could not get public IP for instance %s"
                            % self._qualified_name)
        return self._public_ip_internal


class AzureCloudProvider(AbstractCloudProvider):

    """This implementation of
    :py:class:`elasticluster.providers.AbstractCloudProvider` uses the
    Azure Python interface connect to the Azure clouds and manage instances.

    An AzureCloudProvider owns a tree of Azure resources, rooted in one or
    more subscriptions and one or more storage accounts.
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
        # Paramiko debug level
        # logging.getLogger('paramiko').setLevel(logging.DEBUG)
        # logging.basicConfig(level=logging.DEBUG)

        # for winpdb debugging
        # import rpdb2
        # rpdb2.start_embedded_debugger('food')

        # Ansible debug level
        import ansible
        import ansible.utils
        ansible.utils.VERBOSITY = 2

        # this lock should never be held for long - only for changes to the
        # resource arrays this object owns, and queries about same.
        self._resource_lock_internal = None

        # resources
        self._subscriptions = []
        self._storage_accounts = []

        self._config = AzureGlobalConfig(
            self, subscription_id, certificate, storage_path)

    def start_instance(
            self,
            key_name,
            public_key_path,
            private_key_path,
            security_group,
            flavor,
            image,
            image_userdata,
            location=None,
            base_name=None,
            username=None,
            node_name=None,
            host_name=None,
            use_public_ips=None,
            wait_timeout=None,
            use_short_vm_names=None,
            n_cloud_services=None,
            n_storage_accounts=None,
            **kwargs):
        """Starts a new instance on the cloud using the given properties.
        Multiple instances might be started in different threads at the same
        time. The implementation should handle any problems regarding this
        itself.
        :return: str - instance id of the started instance
        """
        # locking is rudimentary at this point
        with self._resource_lock:
            # it'd be nice if elasticluster called something like
            # init_cluster() with all the args that will be the
            # same for every node created. But since it doesn't, handle that on
            # first start_instance call.
            if not self._config._setup_done:
                self._config.setup(
                    key_name,
                    public_key_path,
                    private_key_path,
                    security_group,
                    location,
                    base_name=base_name,
                    username=username,
                    use_public_ips=use_public_ips,
                    wait_timeout=wait_timeout,
                    use_short_vm_names=use_short_vm_names,
                    n_cloud_services=n_cloud_services,
                    n_storage_accounts=n_storage_accounts,
                    **kwargs)

            # absolute node index in cluster (0..n-1) determines what
            # subscription, cloud service, storage
            # account, etc. this VM will use. Cloud provider only tracks
            # how many instances have been created.
            index = self._n_instances
            if index == 0:
                self._create_global_reqs()

            vm = AzureVM(
                self._config,
                index,
                flavor=flavor,
                image=image,
                node_name=node_name,
                host_name=host_name,
                image_userdata=image_userdata)

            vm._start()
            log.debug('started instance %s' % vm._qualified_name)
            return vm._qualified_name

    def stop_instance(self, instance_id):
        """Stops the instance gracefully.

        :param str instance_id: instance identifier

        :return: None
        """
        with self._resource_lock:
            try:
                vm = self._qualified_name_to_vm(instance_id)
                if not vm:
                    err = "stop_instance: can't find instance %s" % instance_id
                    log.error(err)
                    raise Exception(err)
                vm._delete()
                # note: self._n_instances is a derived property, doesn't need
                # to be updated
                if self._n_instances == 0:
                    log.debug('last instance deleted, destroying '
                              'global resources')
                    self._delete_global_reqs()
            except Exception as exc:
                log.error('error stopping instance %s: %s' %
                          (instance_id, exc))
                raise
        log.debug('stopped instance %s' % instance_id)

    def get_ips(self, instance_id):
        """Retrieves the private and public ip addresses for a given instance.
        Note: Azure normally provides access to vms from a shared load
        balancer IP and
        mapping of ssh ports on the vms. So by default, the Azure provider
        returns strings
        of the form 'ip:port'. However, 'stock' elasticluster and ansible
        don't support this,
        so _use_public_ips uses Azure PublicIPs to expose each vm on the
        internet with its own IP
        and using the standard SSH port.

        :return: list (IPs)
        """
        ret = list()
        vm = self._qualified_name_to_vm(instance_id)
        if not vm:
            raise Exception("Can't find instance_id %s" % instance_id)
        if self._config._use_public_ips:
            ret.append(vm._public_ip)
        else:
            ret.append("%s:%s" % (vm._public_ip, vm._ssh_port))

        log.debug('get_ips (instance %s) returning %s' %
                  (instance_id, ', '.join(ret)))
        return ret

    def is_instance_running(self, instance_id):
        """Checks if the instance is up and running.

        :param str instance_id: instance identifier

        :return: bool - True if running, False otherwise
        """
        vm = self._qualified_name_to_vm(instance_id)
        if not vm:
            raise Exception("Can't find instance_id %s" % instance_id)
        return vm._power_state == 'Started'

    # ------------------ add-on methods ---------------------------------
    # (not part of the base class, but useful extensions)

    # -------------------- private members ------------------------------

    @property
    def _resource_lock(self):
        if self._resource_lock_internal is None:
            self._resource_lock_internal = threading.Lock()
        return self._resource_lock_internal

    @property
    def _n_instances(self):
        ret = 0
        for subscription in self._subscriptions:
            ret = ret + subscription._n_instances
        return ret

    def _qualified_name_to_vm(self, qualified_name):
        i_sub, i_cs, i_vm_in_cs, _, _ = \
            self._config._vm_name_to_resources(qualified_name)
        cs = self._subscriptions[i_sub]._cloud_services[i_cs]
        # TODO can't lock use be confined to its class?
        with cs._resource_lock:
            return cs._instances[qualified_name]

    def _create_global_reqs(self):
        try:
            for index in range(self._config._n_cloud_services):
                i_sub = floor_div(index, self._config._cs_per_sub)
                sub = self._subscriptions[i_sub]
                acs = AzureCloudService(self._config, sub, index)
                acs._create()
                acs._add_certificate()
                sub._cloud_services.append(acs)

            for index in range(self._config._n_storage_accounts):
                i_sub = floor_div(index, self._config._sa_per_sub)
                sub = self._subscriptions[i_sub]
                asa = AzureStorageAccount(self._config, sub, index)
                asa._create()
                sub._storage_accounts.append(asa)

            # one vnet should be enough for ~ 1000 vms. Tie it to
            # the first subscription.
            sub = self._subscriptions[0]
            sub._vnet = AzureVNet(self._config, sub, 0)
            sub._vnet._create()

        except Exception as e:
            log.error('_create_global_reqs error: %s' % e)
            raise

    # tear down non-node-specific resources. Current default is to delete
    # everything; this may change.
    #
    def _delete_global_reqs(self):
        try:
            for sub in self._subscriptions:
                for cs in sub._cloud_services:
                    if cs._instances:
                        err = "cloud service %s can't be destroyed, it " \
                              "still has %i vms." % \
                              (cs._name, len(cs._instances))
                        log.error(err)
                        raise Exception(err)
                    cs._delete()

                for sa in self._storage_accounts:
                    sa._delete()

            self._subscriptions[0]._vnet._delete()

        except Exception as e:
            log.error('_delete_global_reqs error: %s' % e)
            raise

    # methods to support pickling

    def __getstate__(self):
        d = self.__dict__.copy()
        del d['_resource_lock_internal']
        return d

    def __setstate__(self, state):
        self.__dict__ = state
        self._resource_lock_internal = None
