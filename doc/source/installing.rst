..
      Copyright 2012 OpenStack Foundation
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
:doc:`setup`.

Installing from Source
----------------------

The source install instructions specifically avoid using platform specific
packages, instead using the source for the code and the Python Package Index
(PyPi_).

.. _PyPi: http://pypi.python.org/pypi

It's expected that your system already has python_, pip_, and git_ available.

.. _python: http://www.python.org
.. _pip: http://www.pip-installer.org/en/latest/installing.html
.. _git: http://git-scm.com/

Clone the Keystone repository:

.. code-block:: bash

    $ git clone https://git.openstack.org/openstack/keystone.git
    $ cd keystone

Install the Keystone web service:

.. code-block:: bash

    $ python setup.py install

You should have all the pieces you need to run Keystone installed on your
system. The following commands should be available on the command-line path:

* ``keystone`` the Keystone client, used to interact with Keystone
* ``keystone-manage`` used to bootstrap Keystone data
* ``keystone-all`` used to run the Keystone services

You will find sample configuration files in ``etc/``:

* ``keystone.conf``
* ``keystone-paste.ini``
* ``logging.conf``
* ``policy.json``
* ``default_catalog.templates``

From here, refer to :doc:`configuration` to choose which backend drivers to
enable and use. Once configured, you should be able to run Keystone by issuing
the command:

.. code-block:: bash

    $ keystone-all

By default, this will show logging on the console from which it was started.
Once started, you can initialize data in Keystone for use with the rest of
OpenStack, as described in :doc:`configuringservices`.

An excellent reference implementation of setting up Keystone is DEVSTACK_,
most commonly used for development and testing setup of not only Keystone,
but all of the core OpenStack projects.

.. _DEVSTACK: http://docs.openstack.org/developer/devstack/

The script with the latest examples of initializing data in Keystone is a
bash script called `lib/keystone`_

.. _lib/keystone: https://git.openstack.org/cgit/openstack-dev/devstack/tree/lib/keystone

Installing from packages: Ubuntu
--------------------------------

Ubuntu is providing packages for Keystone for Precise. To install keystone
on Ubuntu:

.. code-block:: bash

    $ sudo apt-get install keystone

In using Ubuntu's packages, the packages will set up a user account for
the Keystone service (`keystone`), and place default configurations in
``/etc/keystone``. The Debian installer will also ask you about configuration
options for setting up and running Keystone. As of this writing, the defaults
for Keystone backends are all SQL based, stored locally in a SQLite.

Once installed, you still need to initialize data in Keystone, which you can
find described in :doc:`configuringservices`.

Installing from packages: Fedora
--------------------------------

To install Keystone on Fedora refer to the steps found in the `OpenStack
Install Guide`_.

To install the packages:

.. code-block:: bash

    $ sudo yum install openstack-keystone

Once installed, you still need to initialize data in Keystone, which you can
find described in :doc:`configuringservices`.

.. _`OpenStack Install Guide`: http://docs.openstack.org/juno/install-guide/install/yum/content/keystone-install.html
