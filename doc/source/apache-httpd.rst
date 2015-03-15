
..
      Copyright 2011-2012 OpenStack Foundation
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

=========================
Running Keystone in HTTPD
=========================

.. WARNING::

    Running Keystone under HTTPD in the recommended (and tested) configuration
    does not support the use of ``Transfer-Encoding: chunked``. This is due to
    a limitation with the WSGI spec and the implementation used by
    ``mod_wsgi``. It is recommended that all clients assume Keystone will not
    support ``Transfer-Encoding: chunked``.


Firewall
--------

Add the following rule to IPTables in order to ensure the SSL traffic can pass
your firewall::

    -A INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT

it goes right before::

    -A INPUT -j REJECT --reject-with icmp-host-prohibited

Files
-----

Copy the file httpd/wsgi-keystone.conf to the appropriate location for your
Apache server, most likely::

    /etc/httpd/conf.d/wsgi-keystone.conf

Create the directory ``/var/www/cgi-bin/keystone/``. You can either hardlink or
softlink the files ``main`` and ``admin`` to the file ``keystone.py`` in this
directory. For a distribution appropriate place, it should probably be copied
to::

    /usr/share/openstack/keystone/httpd/keystone.py

Keystone's primary configuration file (``etc/keystone.conf``) and the
PasteDeploy configuration file (``etc/keystone-paste.ini``) must be readable to
HTTPD in one of the default locations described in :doc:`configuration`.

SELinux
-------

If you are running with SELinux enabled (and you should be) make sure that the
file has the appropriate SELinux context to access the linked file. If you
have the file in /var/www/cgi-bin,  you can do this by running:

.. code-block:: bash

    $ sudo restorecon /var/www/cgi-bin

Putting it somewhere else requires you set up your SELinux policy accordingly.

Keystone Configuration
----------------------

Make sure you use either the ``SQL`` or the ``memcached`` driver for
``tokens``, otherwise the tokens will not be shared between the processes of
the Apache HTTPD server.

For ``SQL,`` in ``/etc/keystone/keystone.conf`` make sure you have set::

    [token]
    driver = keystone.token.backends.sql.Token

For ``memcache,`` in ``/etc/keystone/keystone.conf`` make sure you have set::

    [token]
    driver = keystone.token.backends.memcache.Token

In both cases, all servers that are storing tokens need a shared backend. This
means either that both point to the same database server, or both point to a
common memcached instance.
