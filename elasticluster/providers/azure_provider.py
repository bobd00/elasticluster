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

class AzureCloudProvider(AbstractCloudProvider):
    """This implementation of
    :py:class:`elasticluster.providers.AbstractCloudProvider` uses the 
    Azure Python interface connect to the Azure clouds and manage instances.

    :param str subscription_id: subscription to connect with
    :param str user_key_private: access to secret key of the user account
    """

    __node_start_lock = threading.Lock()  # lock used for node startup

    def wait_result(sms, req, timeout):
        if req is None:
            return  # sometimes this happens, seems to mean success
        giveup_time = time.time() + timeout
        while giveup_time > time.time():
            operation_result = sms.get_operation_status(req.request_id)
            if operation_result.status == "InProgress":
                time.sleep(10)
                continue
            if operation_result.status == "Succeeded":
                return
        raise WindowsAzureError('timed out')

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

    def start_instance(self, key_name, public_key_path, private_key_path,
                       security_group, flavor, image_id, image_userdata,
                       username=None, node_name=None, **kwargs):
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
        #bd
        x = raw_input("azure.py: Entering start_instance(key_name=%s node_name=%s)" % (key_name, node_name))
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
        

                       