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

.. todo:: Need some help on this one...

Mac OSX
#######

.. todo:: No idea how to do install on Mac OSX. Somebody with a Mac should complete this section

Installing from source tarballs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To install the latest version of Keystone from the Launchpad Bazaar repositories,
following the following instructions.

1. Grab the source tarball from `Github <https://github.com/openstack/keystone>`_

2. Untar the source tarball::

   $> tar -xzf <FILE>

3. Change into the package directory and build/install::

   $> cd keystone-<RELEASE>
   $> sudo python setup.py install

Installing from a Github Branch
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To install the latest version of Keystone from the Github repositories,
see the following instructions.

Debian/Ubuntu
#############

1. Install Git and build dependencies::

   $> sudo apt-get install git python-eventlet python-routes python-greenlet swift
   $> sudo apt-get install python-argparse python-sqlalchemy python-wsgiref python-pastedeploy

.. note::

   If you want to build the Keystone documentation locally, you will also want
   to install the python-sphinx package

1. Branch Keystone's trunk branch:: (see http://wiki.openstack.org/GerritWorkflow to get the project initially setup)::
   
   $> git checkout master
   $> git pull origin master

1. Install Keystone::
   
   $> sudo python setup.py install

RedHat/Fedora
#############

.. todo:: Need some help on this one...

Mac OSX
#######

.. todo:: No idea how to do install on Mac OSX. Somebody with a Mac should complete this section
