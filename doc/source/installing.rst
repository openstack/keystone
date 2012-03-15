..
      Copyright 2012 OpenStack, LLC
      Copyright 2012 Nebula, Inc
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

===================
Installing Keystone
===================

This document describes how to install Keystone in order to use it. If you are
intending to develop on or with Keystone, please read :doc:`developing` and
:doc:`setup`

Installing from Source
----------------------

The source install instructions specifically avoid using platform specific
packages, instead using the source for the code and the Python Package Index
(PyPi_).

.. _PyPi: http://pypi.python.org/pypi

Its expected that your system already has python_, pip_, and git_ available.

.. _python: http://www.python.org
.. _pip: http://www.pip-installer.org/en/latest/installing.html
.. _git: http://git-scm.com/

Clone the keystone repository::

    git clone http://github.com/openstack/keystone.git
    cd keystone

Install the dependencies to run keystone::

    sudo pip install -r tools/pip-requires

And at this point, you should have all the pieces you need to run keystone
installed on your system. The following commands should be available on the
commandline path:

* ``keystone`` the keystone client, used to configure keystone
* ``keystone-manage`` used to bootstrap keystone data
* ``keystone-all`` used to run the keystone services

You will find sample configuration files in ``etc/``

* keystone.conf
* logging.conf
* policy.json
* default_catalog.templates

From here, refer to :doc:`configuration` to choose which backend drivers to
enable and use. Once configured, you should be able to run keystone by issueing
the command::

    keystone-all

which (by default) will show logging on the console from which it was started.
Once started, you can initialize data in keystone for use with the rest of
openstack, as described in :doc:`configuringservices`.

An excellent reference implementation of setting up keystone is DEVSTACK_,
most commonly used for development and testing setup of not only Keystone,
but all of the core OpenStack projects.

.. _DEVSTACK: http://devstack.org/

The script with the latest examples of intializing data in Keystone is a
bash script called keystone_data.sh_

.. _keystone_data.sh: https://github.com/openstack-dev/devstack/blob/master/files/keystone_data.sh

Installing from packages: Ubuntu
--------------------------------

Ubuntu is providing packages for Keystone for Precise. To install keystone
on Ubuntu::

    sudo apt-get install keystone

In using Ubuntu's packages, the packages will set up a user account for
the Keystone service (`keystone`), and place default configurations in
``/etc/keystone``. The debian installer will also ask you about configuration
options for setting up and running Keystone. As of this writing, the defaults
for Keystone backends are all SQL based, stored locally in a sqlite.

Once installed, you still need to initialize data in Keystone, which you can
find described in :doc:`configuringservices`.

Installing from packages: Fedora
--------------------------------

Installing Keystone with Fedora 17 is documented at
http://fedoraproject.org/wiki/Getting_started_with_OpenStack_on_Fedora_17.

To install the packages::

    sudo yum install --enablerepo=updates-testing openstack-keystone

Once installed, you can configure keystone based on the instructions at:

http://fedoraproject.org/wiki/Getting_started_with_OpenStack_on_Fedora_17#Configuring_Keystone_for_authentication
