#!/usr/bin/env python
#
# Copyright 2015
#

# dsteinkraus - elasticluster 'azure' package conflicts with azure SDK. This fixes
# it by causing "import azure" to look for a system library module.
from __future__ import absolute_import

__author__ = 'Bob Davidson <bobd@microsoft.com>'


# System imports
import os
import threading
import base64
import subprocess
import time

# External imports
from azure import WindowsAzureError
from azure.servicemanagement import (ServiceManagementService, OSVirtualHardDisk, SSH, PublicKeys,
                                     PublicKey, LinuxConfigurationSet, ConfigurationSetInputEndpoints,
                                     ConfigurationSetInputEndpoint)

# Elasticluster imports
from elasticluster import log
from elasticluster.providers import AbstractCloudProvider
# TODO bad boy
from elasticluster.exceptions import *

class AzureCloudProvider(AbstractCloudProvider):
    """This implementation of
    :py:class:`elasticluster.providers.AbstractCloudProvider` uses the 
    Azure Python interface connect to the Azure clouds and manage instances.

    :param str subscription_id: subscription to connect with
    :param str user_key_private: access to secret key of the user account
    """

    __node_start_lock = threading.Lock()  # lock used for node startup

    # TODO get rid of this, elast/ansible have them
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
        raise WindowsAzureError('timed out')

    # TODO can't we do this more robustly than with string processing
    def _get_ssh_certificate_tokens(self, ssh_cert_path):
        """
        Returns the sha1 fingerprint and a base64-encoded PKCS12 version of the certificate.
        """
        # This returns a string such as SHA1 Fingerprint=88:60:0B:13:A9:14:47:DA:4E:19:10:7D:34:92:2B:DF:A1:7D:CA:FF

        rc, stdout, stderr = run_command(['openssl', 'x509', '-in', ssh_cert_path, '-fingerprint', '-noout'])
        if rc != 0:
            raise Exception("failed to generate the key fingerprint, error was: %s" % stderr)
        fingerprint = stdout.strip()[17:].replace(':', '')

        rc, stdout, stderr = run_command(['openssl', 'pkcs12', '-export', '-in', ssh_cert_path, '-nokeys', '-password', 'pass:'])
        if rc != 0:
            raise ConfigurationError(msg="failed to generate the pkcs12 signature from the certificate, error was: %s" % stderr)
        pkcs12_base64 = base64.b64encode(stdout.strip())

        return (fingerprint, pkcs12_base64)

    def _create_cloud_service(self):
        print 'creating cloud service...'
        try:
            result = self._sms.create_hosted_service(service_name=self._cloud_service_name, label=self._cloud_service_name, location=self._location)
            self._wait_result(result, self._wait_timeout)
        except WindowsAzureError as e:
            if str(e) == 'Conflict (Conflict)':
                print "cloud service already exists."
                return
            raise CloudProviderError(msg="error creating cloud service: %s" % e)
        print "cloud service created."

    def _create_storage_account(self):
        print "creating storage account..."
        try:
            result = self._sms.create_storage_account(
                service_name=self._storage_account,
                description='desc',
                label='storage account 97531',
                affinity_group=None,
                location='East US',
                account_type='Standard_LRS'
                )
            # this seems to be taking longer than the others...
            self._wait_result(result, self._wait_timeout * 100)
        except WindowsAzureError as e:
            raise CloudProviderError("error creating storage account: %s" % str(e))

    def _add_certificate(self):
        try:
            self._fingerprint, self._pkcs12_base64 = self._get_ssh_certificate_tokens(self._public_key_path)
            # Add certificate to cloud service
            result = self._sms.add_service_certificate(self._cloud_service_name, self._pkcs12_base64, 'pfx', '')
            self._wait_result(result, self._wait_timeout)
        except WindowsAzureError as e:
            raise CloudProviderError("error adding certificate: %s" % str(e))

    def _create_network_config(self):
        try:
            # Create linux configuration
            linux_config = LinuxConfigurationSet(self._hostname, self._username, None, disable_ssh_password_authentication=True)
            ssh_config = SSH()
            ssh_config.public_keys = PublicKeys()
            authorized_keys_path = u'/home/%s/.ssh/authorized_keys' % self._username
            ssh_config.public_keys.public_keys.append(PublicKey(path=authorized_keys_path, fingerprint=self._fingerprint))
            linux_config.ssh = ssh_config

            # Create network configuration
            network_config = ConfigurationSetInputEndpoints()
            network_config.configuration_set_type = 'NetworkConfiguration'
            network_config.subnet_names = []
            # create endpoints for ssh (22) and http. Only one vm, so we can use same port #s for public ports
            for port in (22, 80):
                network_config.input_endpoints.append(ConfigurationSetInputEndpoint(name='TCP-%s' % port,
                    protocol='TCP', port=port, local_port=port))
        except WindowsAzureError as e:
            raise CloudProviderError("error creating network configuration: %s" % str(e))

    def _ensure_state(self):
        try:
            self._sms = ServiceManagementService(self._subscription_id, self._certificate)
        except WindowsAzureError as e:
            print "bad thing happened: %s" % e
            self._sms = None
        try:
            self._create_cloud_service()
        except CloudProviderError as e:
            print "bad thing happened: %s" % e
            self._sms = None    #TODO just for now
        try:
            self._create_storage_account()
        except CloudProviderError as e:
            print "bad thing happened: %s" % e
            self._sms = None    #TODO just for now
        try:
            self._create_network_config()
        except CloudProviderError as e:
            print "bad thing happened: %s" % e
            self._sms = None    #TODO just for now

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
        self._wait_timeout = 600


    def start_instance(
            self,
            key_name,
            public_key_path,
            private_key_path,
            security_group,
            flavor,
            image_id,
            image_userdata,
            location,
            cloud_service_name,
            username=None,
            node_name=None,
            **kwargs):
        """Starts a new instance on the cloud using the given properties.
        Multiple instances might be started in different threads at the same
        time. The implementation should handle any problems regarding this
        itself.

        :param str key_name: name of the ssh key to connect
        :param str public_key_path: path to ssh public key
        :param str private_key_path: path to ssh private key
        :param str security_group: firewall rule definition to apply on the
                                   instance
        :param str flavor: machine type to use for the instance
        :param str image_name: image type (os) to use for the instance
        :param str image_userdata: command to execute after startup
        :param str username: username for the given ssh key, default None

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
        self._location = location
        self._storage_account = kwargs.get('storage_account')

        self._ensure_state()
        return self(node_name)

    def stop_instance(self, instance_id):
        """Stops the instance gracefully.

        :param str instance_id: instance identifier

        :return: None
        """
        #bd
        x = raw_input("azure.py: Entering stop_instance(instance_id=%s)" % instance_id)

    def get_ips(self, instance_id):
        """Retrieves the private and public ip addresses for a given instance.

        :return: list (IPs)
        """
        #bd
        x = raw_input("azure.py: Entering get_ips(instance_id=%s" % instance_id)

    def is_instance_running(self, instance_id):
        """Checks if the instance is up and running.

        :param str instance_id: instance identifier

        :return: bool - True if running, False otherwise
        """
        #bd
        x = raw_input("azure.py: Entering is_instance_running(instance_id=%s" % instance_id)
        return False
        

                       