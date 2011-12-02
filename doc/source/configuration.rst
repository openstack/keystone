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

====================
Configuring Keystone
====================

.. toctree::
   :maxdepth: 1

   keystone.conf
   man/keystone-manage

Once Keystone is installed, there are a number of configuration options
available and potentially some initial data to create and set up.

Sample data / Quick Setup
=========================

Default sampledata is provided for easy setup and testing in bin/sampeldata. To
set up the sample data run the following command while Keystone is running::

    $ ./bin/sampledata

The sample data created comes from the file :doc:`sourcecode/keystone.test.sampledata`


Keystone Configuration File
===========================

Most configuration is done via configuration files. The default files are
in ``/etc/keystone.conf``

When starting up a Keystone server, you can specify the configuration file to
use (see :doc:`controllingservers`).
If you do **not** specify a configuration file, keystone will look in the following
directories for a configuration file, in order:

* ``~/.keystone``
* ``~/``
* ``/etc/keystone``
* ``/etc``

The keystone configuration file should be named ``keystone.conf``.
If you installed keystone via your operating system's
package management system, it is likely that you will have sample
configuration files installed in ``/etc/keystone``.

In addition to this documentation page, you can check the
``etc/keystone.conf`` sample configuration
files distributed with keystone for example configuration files for each server
application with detailed comments on what each options does.

Sample Configuration Files
--------------------------

Keystone ships with sample configuration files in keystone/etc. These files are:

1. keystone.conf

    A standard configuration file for running keystone in stand-alone mode.
    It has a set of default extensions loaded to support administering Keystone
    over REST. It uses a local SQLite database.

2. memcache.conf

    A configuration that uses memcached for storing tokens (but still SQLite for all
    other entities). This requires memcached running.

3. ssl.conf

    A configuration that runs Keystone with SSL (so all URLs are accessed over HTTPS).

To run any of these configurations, use the `-c` option::

    ./keystone -c ../etc/ssl.conf



Usefule Links
-------------

For a sample configuration file with explanations of the settings, see :doc:`keystone.conf`

For configuring an LDAP backend, see http://mirantis.blogspot.com/2011/08/ldap-identity-store-for-openstack.html

For configuration settings of middleware components, see :doc:`middleware`