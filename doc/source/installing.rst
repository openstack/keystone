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

