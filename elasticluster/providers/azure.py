#
# Copyright (C) 2013 GC3, University of Zurich
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
__author__ = 'dsteinkraus'

# System imports
import os
import urllib
import threading

# External modules
# dsteinkraus TODO

# Elasticluster imports
from elasticluster import log
from elasticluster.providers import AbstractCloudProvider
from elasticluster.exceptions import VpcError, SecurityGroupError, \
    SubnetError, KeypairError, ImageError, InstanceError, ClusterError


class AzureCloudProvider(AbstractCloudProvider):
    """This implementation of
    :py:class:`elasticluster.providers.AbstractCloudProvider` uses the Azure
     REST API to connect to Azure clouds and manage instances.

    todo
    :param str ec2_url: url to connect to cloud web service
    :param str ec2_region: region identifier
    :param str ec2_access_key: access key of the user account
    :param str ec2_secret_key: secret key of the user account
    :param str storage_path: path to store temporary data
    :param bool request_floating_ip: Whether ip are assigned automatically
                                    `True` or floating ips have to be
                                    assigned manually `False`
    """
    __node_start_lock = threading.Lock()  # lock used for node startup

    #dsteinkraus TODO more args
    def __init__(self, auth_url, username, password, storage_path=None):
        pass

    def _connect(self):
        pass

    def start_instance(self, key_name, public_key_path, private_key_path,
                       security_group, flavor, image_id, image_userdata,
                       username=None, node_name=None, network_ids=None,
                       **kwargs):
        pass

    def stop_instance(self, instance_id):
        pass

    def get_ips(self, instance_id):
        pass

    def is_instance_running(self, instance_id):
        pass

    # dsteinkraus TODO - below this point not part of AbstractCloudProvider, delete if not wanted

    def _allocate_address(self, instance):
        pass

    def _load_instance(self, instance_id):
        pass

