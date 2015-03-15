
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


Files
-----

Copy the file httpd/wsgi-keystone.conf to the appropriate location for your
Apache server, most likely::

    /etc/httpd/conf.d/wsgi-keystone.conf

Update this file to match your system configuration (for example, some
distributions put httpd logs in the ``apache2`` directory and some in the
``httpd`` directory; also, enable TLS).

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

Make sure that when using a token format that requires persistence, you use a
token persistence driver that can be shared between processes. The SQL and
memcached token persistence drivers provided with keystone can be shared
between processes.

.. WARNING::

    The KVS (``keystone.token.persistence.backends.kvs.Token``) token
    persistence driver cannot be shared between processes so must not be used
    when running keystone under HTTPD (the tokens will not be shared between
    the processes of the server and validation will fail).

For SQL, in ``/etc/keystone/keystone.conf`` set::

    [token]
    driver = keystone.token.persistence.backends.sql.Token

For memcached, in ``/etc/keystone/keystone.conf`` set::

    [token]
    driver = keystone.token.persistence.backends.memcache.Token

All servers that are storing tokens need a shared backend. This means that
either all servers use the same database server or use a common memcached pool.
