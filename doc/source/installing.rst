..
      Copyright 2011 OpenStack, LLC
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

Installing Keystone
===================

Installing from packages
~~~~~~~~~~~~~~~~~~~~~~~~

To install the latest version of Keystone from the Github repositories,
following the following instructions.

Debian/Ubuntu
#############

1. Add the Keystone PPA to your sources.lst::

   $> sudo add-apt-repository ppa:keystone-core/trunk
   $> sudo apt-get update

2. Install Keystone::

   $> sudo apt-get install keystone


RedHat/Fedora
#############

On some OSes, specifically Fedora 15, the current versions of
greenlet/eventlet segfault when running keystone. To fix this, install
the development versions of greenlet and eventlet::

    $ pip uninstall greenlet eventlet
    $ cd <appropriate working directory>
    $ hg clone https://bitbucket.org/ambroff/greenlet
    $ cd greenlet
    $ sudo python setup.py install

    $ cd <appropriate working directory>
    $ hg clone https://bitbucket.org/which_linden/eventlet
    $ cd greenlet
    $ sudo python setup.py install

Installing from source tarballs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To install the latest version of Keystone from the Launchpad Bazaar repositories,
following the following instructions.

#. Grab the source tarball from `Github <https://github.com/openstack/keystone>`_

#. Untar the source tarball::

   $> tar -xzf <FILE>

#. Install dependencies::

   $> sudo apt-get install -y git python-pip gcc python-lxml libxml2 python-greenlet-dbg python-dev libsqlite3-dev libldap2-dev libssl-dev libxml2-dev libxslt1-dev libsasl2-dev

#. Change into the package directory and build/install::

   $> cd keystone-<RELEASE>
   $> sudo python setup.py install

Installing from a Github Branch
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To install the latest version of Keystone from the Github repositories,
see the following instructions.

Debian/Ubuntu
#############

.. note::
   If you want to build the Keystone documentation locally, you will also want
   to install the python-sphinx package in the first step.

#. Install Git and build dependencies::

   $> sudo apt-get install git python-eventlet python-routes python-greenlet swift
   $> sudo apt-get install python-argparse python-sqlalchemy python-wsgiref python-pastedeploy

#. Branch Keystone's trunk branch:: (see http://wiki.openstack.org/GerritWorkflow to get the project initially setup)::

   $> git checkout master
   $> git pull origin master

#. Install Keystone::

   $> sudo python setup.py install

RedHat/Fedora
#############

.. todo:: Need some help on this one...

Mac OSX
#######

#. Install git - on your Mac this is most easily done by installing Xcode.

#. Branch Keystone's trunk branch:: (see http://wiki.openstack.org/GerritWorkflow to get the project initially setup)::

   $> git checkout master
   $> git pull origin master

#. Set up the virtual environment to get the additional dependencies

   $> python tools/install_venv.py

   If you don't want to use a virtual environment, install the dependencies
   directly using:

   $> sudo pip install -r tools/pip-requires

#. Activate the virtual environment

   $> source .keystone-venv/bin/activate

#. Install keystone:

   $> python setup.py develop

Configuring Keystone
~~~~~~~~~~~~~~~~~~~~

Once Keystone is installed, it needs to be configured, and then any services
that will be using Keystone need to be provided with service tokens. The
service tokens are used to allow those services to validate users against
Keystone's API interface.

.. toctree::
   :maxdepth: 1

   keystone.conf
   man/keystonemanage.rst

Once keystone is installed and running a number of elements need to be
configured to provide data to authenticate against.

Creating Tenants
################

* keystone-manage tenant add [tenant_name]

e.g.

    keystone-manage tenant add admin
    keystone-manage tenant add demo

Creating Users
##############

* keystone-manage user add [username] [password]

e.g.

    keystone-manage tenant add admin secrete
    keystone-manage tenant add demo johny5oh

Creating Roles
##############

* keystone-manage role add [username]
* keystone-manage role grant [role] [username] ([tenant])

e.g.

    keystone-manage role add Admin
    keystone-manage role add Member
    keystone-manage role add KeystoneAdmin
    keystone-manage role add KeystoneServiceAdmin

    keystone-manage role grant Admin admin admin
    keystone-manage role grant Member demo demo
    keystone-manage role grant Admin admin demo

    keystone-manage role grant Admin admin
    keystone-manage role grant KeystoneAdmin admin
    keystone-manage role grant KeystoneServiceAdmin admin

Creating Services
#################

Define the services that will be using Keystone for authentication

* keystone-manage service add [servicename] [type] [description]

e.g.

    keystone-manage service add nova compute "Nova Compute Service"
    keystone-manage service add glance image "Glance Image Service"
    keystone-manage service add keystone identity "Keystone Identity Service"

Creating Endpoints
##################


e.g.

    keystone-manage endpointTemplates add RegionOne nova http://%HOST_IP%:8774/v1.1/%tenant_id% http://%HOST_IP%:8774/v1.1/%tenant_id%  http://%HOST_IP%:8774/v1.1/%tenant_id% 1 1
    keystone-manage endpointTemplates add RegionOne glance http://%HOST_IP%:9292/v1.1/%tenant_id% http://%HOST_IP%:9292/v1.1/%tenant_id% http://%HOST_IP%:9292/v1.1/%tenant_id% 1 1
    keystone-manage endpointTemplates add RegionOne keystone http://%HOST_IP%:5000/v2.0 http://%HOST_IP%:35357/v2.0 http://%HOST_IP%:5000/v2.0 1 1
    keystone-manage endpointTemplates add RegionOne swift http://%HOST_IP%:8080/v1/AUTH_%tenant_id% http://%HOST_IP%:8080/ http://%HOST_IP%:8080/v1/AUTH_%tenant_id% 1 1



Defining an Administrative Service Token
########################################

This token is arbitrary text which needs to be identical between Keystone
and the services using Keystone to authenticate users, such as Nova, Swift,
Glance, and Dashboard.

* keystone-manage token add [token] [tenant] [user] [expire datetime]

e.g.
    keystone-manage token add 999888777666 admin admin 2015-02-05T00:00


Configuring Nova to use Keystone
################################

To configure Nova to use Keystone for authentication, the Nova API service
can be run against the api-paste file provided by Keystone. This is most
easily accomplished by setting the --api_paste_config flag in nova.conf to
point to examples/paste/nova-api-paste.ini from Keystone. This paste file
included references to the WSGI authentication middleware provided with the
keystone installation.

When configuring Nova, it is important to create a admin service token for
the service (from the Configuration step above) and include that as the key
'admin_token' in the nova-api-paste.ini. See the documented nova-api-paste.ini
file for references.

.. toctree::
   :maxdepth: 1

   nova-api-paste


Configuring Swift to use Keystone
#################################

Similar to Nova, swift can be configured to use Keystone for authentication
rather than it's built in 'tempauth'.

1. Add a service endpoint for Swift to Keystone

2. Configure the paste file for swift-proxy (/etc/swift/swift-proxy.conf)

3.  Reconfigure Swift's proxy server to use Keystone instead of TempAuth.
    Here's an example `/etc/swift/proxy-server.conf`:

        [DEFAULT]
        bind_port = 8888
        user = <user>

        [pipeline:main]
        pipeline = catch_errors cache keystone proxy-server

        [app:proxy-server]
        use = egg:swift#proxy
        account_autocreate = true

        [filter:keystone]
        use = egg:keystone#tokenauth
        auth_protocol = http
        auth_host = 127.0.0.1
        auth_port = 35357
        admin_token = 999888777666
        delay_auth_decision = 0
        service_protocol = http
        service_host = 127.0.0.1
        service_port = 8100
        service_pass = dTpw

        [filter:cache]
        use = egg:swift#memcache
        set log_name = cache

        [filter:catch_errors]
        use = egg:swift#catch_errors

4. Restart swift

5. Verify that keystone is providing authentication to Swift

Use `swift` to check everything works (note: you currently have to create a
container or upload something as your first action to have the account
created; there's a Swift bug to be fixed soon):

    $ swift -A http://127.0.0.1:5000/v1.0 -U joeuser -K secrete post container
    $ swift -A http://127.0.0.1:5000/v1.0 -U joeuser -K secrete stat -v
    StorageURL: http://127.0.0.1:8888/v1/AUTH_1234
    Auth Token: 74ce1b05-e839-43b7-bd76-85ef178726c3
    Account: AUTH_1234
    Containers: 1
    Objects: 0
    Bytes: 0
    Accept-Ranges: bytes
    X-Trans-Id: tx25c1a6969d8f4372b63912f411de3c3b

**Note: Keystone currently allows any valid token to do anything with any
account.**

