========================================================================
Testing gridengine + elasticluster + Azure
========================================================================

.. This file follows reStructuredText markup syntax; see
   http://docutils.sf.net/rst.html for more information


Dave Steinkraus / Trevor Eberl 5/18/2015

This document, and the Azure provider for elasticluster, are works in progress. Expect changes.

In this guide, we'll walk through all the steps to:

	- set up a Linux machine to run a test version of elasticluster that supports Microsoft Azure; 
	- start an Azure compute cluster and provision it to run gridengine; 
	- communicate with the cluster; and 
	- tear down the cluster.

1. Set up a client environment for running elasticluster. Most testing has been done on Ubuntu 14.04, so this is recommended. On a new machine, install prerequisites:

::

	sudo apt-get update
	sudo apt-get install git python-pip python-dev build-essential python-virtualenv \
		libssl-dev libffi-dev nodejs-legacy
	sudo apt-get install npm -y
	sudo apt-get install libxml2-dev libxslt1-dev
	sudo pip install virtualenvwrapper

2. Create and enter a virtual environment (this is strongly recommended, since you will be installing nonstandard forks of ansible and elasticluster):

::

	mkdir ~/.virtualenvs
	export WORKON_HOME=~/.virtualenvs
	source /usr/local/bin/virtualenvwrapper.sh
	mkvirtualenv elasticluster
	workon elasticluster
	cdvirtualenv

3. Install the specific Python packages for this test scenario into the virtualenv:

::

	pip install google-api-python-client

The Microsoft Azure SDK for Python will be automatically installed by the azure-elasticluster package. For more information see: https://github.com/Azure/azure-sdk-for-python/

These are the forked versions of elasticluster and Ansible that support Azure (for testing until those groups support it directly).
In spite of the different PyPI names here, the packages actually installed will be named ``ansible`` and ``elasticluster``, which is why using
a virtualenv is a good idea. The ``--pre`` flag is needed because these are both labeled as "dev" versions in PyPI.

::

	pip install --pre azure-ansible
	pip install --pre azure-elasticluster

4. Confirm elasticluster is ready to run:

::

	elasticluster --help

5. You'll need to have an Azure account and know its subscription ID. (see http://azure.microsoft.com/en-us/ to set up a 30-day trial account if necessary.) You'll also need to generate a management certificate (.cer) and upload it to Azure. If you haven't done this yet:

::

	mkdir ~/.ssh
	chmod 700 ~/.ssh

Here's one of those things that shouldn't matter, but it apparently does: you should run the following openssl commands from the ``~/.ssh`` directory. (Or maybe it's OK if you always use absolute paths instead of "~", but that's unconfirmed at this point.) If you don't do this, the resulting keys will not work - Azure will accept them, but Ansible won't, so your VMs will start and then fail to be provisioned.

::

	cd ~/.ssh

The next command will prompt for information. Set the company name as it will make finding the cert in azure portal easier. Everything else can be blank. 

::

	openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
	-keyout managementCert.pem -out managementCert.pem 

	openssl x509 -outform der -in managementCert.pem -out managementCert.cer

6. You'll need a keypair to access the virtual machines during provisioning, and later via ssh. For now [to be fixed soon], you should create a private key file that matches your management cert, like this:

::

	openssl rsa -in managementCert.pem -out managementCert.key

SSH is picky about ownership/permissions on key files. Make sure that yours look like this:

::

	$ ls -l ~/.ssh
	[...]
	-rw------- 1 dave dave  797 May  3 18:00 managementCert.cer

Use these commands if needed on the .pem, .cer, and .key files:

::

	# replace 'dave' with your username - you knew that
	sudo chown dave:dave ~/.ssh/managementCert.pem
	sudo chmod 600 ~/.ssh/managementCert.pem

7. Upload managementCert.cer to your Azure subscription via the web portal. (Scroll down to "settings" on the left-hand menu, then click "management certificates" at the top, and you'll find an "upload" button at the bottom.)



8. Edit the elasticluster config file. (The default is ``~/.elasticluster/config``. You can optionally specify a different file/path on the elasticluster command line.) You'll need to edit the items marked ``**** CHANGE ****``.

For the certificate, specify the .pem file created in step 5 (e.g. ``/home/dave/.ssh/managementCert.pem``).

For user_key_private, specify the .key file created in step 7 (e.g. ``/home/dave/.ssh/managementCert.key``). For user_key_public, specify the same .pem file you used for the certificate entry.

(Warning - do not use ``~`` (tilde) in the paths for these values - specify the whole path explicitly. This is another case where ``~`` will not be interpreted correctly.)

Set the basename to a meaningful string of between 3 and 15 characters, digits and lowercase letters only. All Azure resources created will include this string.


There are some other config settings available that are not needed for this example. Clusters with more than 10 or so compute nodes have not been tested yet.

9. Start the cluster (``-vvv`` will produce verbose diagnostic output - you can use zero to four v's):

::

	elasticluster -vvv start azure-gridengine

If all goes well, first you'll see global resources created and then the nodes being brought up. Then elasticluster will try to ssh to each node - this typically fails for awhile, as the nodes finish booting up, and then it succeeds. When all the nodes have been contacted, the Ansible provisioning step will start. This installs the normal gridengine setup that comes with elasticluster - nothing's been modified for Azure. Finally, elasticluster will print a "your cluster is ready!" message.

On occasion, something will go wrong during the Ansible provisioning phase, which follows the creation of the cluster itself (i.e. the virtual machines, storage accounts, cloud services, and virtual network). In these cases, at the end of the output there will usually be a "Your cluster is not ready!" message. If the last saved state of the cluster includes the correct addresses (ip:port) for the vms, there's no need to destroy and restart from scratch. Instead, you can re-run the Ansible phase with this command:

::

	elasticluster -vvv setup azure-gridengine

10. Contacting the cluster: this command should establish an interactive ssh connection with the head (frontend) node.

::

	elasticluster ssh azure-gridengine

11. Other supported elasticluster commands: ``list``, ``list-nodes``, and ``list-templates``.


12. Tearing down the cluster: this will permanently destroy all Azure resources, and stop Azure charges from accruing.

::

	elasticluster -vvv stop azure-gridengine

A final note on caching - elasticluster tries to preserve information about running clusters, so it frequently saves cluster state to disk. This is good, except when reality doesn't match the saved state. For example, a startup might have failed partway through, and you might have used the Azure management console to clean things up. To reset elasticluster's saved state, do something like this:

::

	rm ~/.elasticluster/storage/*gridengine*

