OVERVIEW: 
In this branch (azure-experimental) is a working (though by no means finished) implementation of an 
elasticluster Azure cloud provider.

These elasticluster commands work (using the config file in this directory):

start azure-gridengine (see caveat below) - create the cluster.
ssh azure-gridengine - connect to the head node via ssh
stop azure-gridengine - destroy the VMs and associated resources
list
list-nodes azure-gridengine
list-templates azure-gridengine


Caveat: While the 'start' command successfully creates the VMs, the subsequent Ansible provisioning
step fails partway through.

These commands don't work:
setup (same Ansible caveat)

Not tested yet:
resize
sftp

Other files in this directory:
config - sample config file (1 head node, 6 compute nodes)
start.txt - output from the start command (with Ansible VERBOSITY = 9)
stop.txt - output from the stop command
ansible/runner/__init__.py
azure/servicemanagement/__init__.py
(these last 2 files were modified and are not part of the Git repo. Changes marked with # dsteinkraus
comments)

Note on ports:
Elasticluster is built on the assumption that every VM in a cluster is reachable by its own public 
IP address, on the standard ssh port (22). In Azure, unless Public IPs are used, the VMs are 
reachable on the internet using a common IP (that of the load balancer) and a different port number
for each VM. So, in this branch I've modified both elasticluster and Ansible to support explicit
port numbers in the usual form (1.1.1.1:1221).

In another branch, I'll explore using Public IPs to reach the Azure VMs, an option that will not
require these minor changes to elasticluster and Ansible.

TODO:
fix Ansible provisioning issues
support N of various resources (cloud service, storage account, etc.) instead of just 1
add support for auto-naming of resources
remove excessive use of instance variables
efficient locking (current locking has the effect of serializing VM creation)
when deleting VM, request deletion of OS image at the same time, instead of separate call
check for resources before creating
when deleting cluster, only destroy resources that we created
add support for virtual networks and public IPs
proper logging

