
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

mod_proxy_uwsgi
---------------

The recommended keystone deployment is to have a real web server such as Apache
HTTPD or nginx handle the HTTP connections and proxy requests to an independent
keystone server (or servers) running under a wsgi container such as uwsgi or
gunicorn. The typical deployment will have several applications proxied by the
web server (for example horizon on /dashboard and keystone on /identity,
/identity_admin, port :5000, and :35357). Proxying allows the applications to
be shut down and restarted independently, and a problem in one application
isn't going to affect the web server or other applications. The servers can
easily be run in their own virtualenvs.

The httpd/ directory contains sample files for configuring HTTPD to proxy
requests to keystone servers running under uwsgi.

Copy the `httpd/uwsgi-keystone.conf` sample configuration file to the
appropriate location for your Apache server, on Debian/Ubuntu systems it is::

    /etc/apache2/sites-available/uwsgi-keystone.conf

On Red Hat based systems it is::

    /etc/httpd/conf.d/uwsgi-keystone.conf

Update the file to match your system configuration. Enable TLS by supplying the
correct certificates.

Enable mod_proxy_uwsgi.

* On Ubuntu the required package is libapache2-mod-proxy-uwsgi; enable using
  ``sudo a2enmod proxy``, ``sudo a2enmod proxy_uwsgi``.
* On Fedora the required package is mod_proxy_uwsgi; enable by creating a file
  ``/etc/httpd/conf.modules.d/11-proxy_uwsgi.conf`` containing
  ``LoadModule proxy_uwsgi_module modules/mod_proxy_uwsgi.so``

Enable the site by creating a symlink from the file in ``sites-available`` to
``sites-enabled``, for example, on Debian/Ubuntu systems
(not required on Red Hat based systems)::

    ln -s /etc/apache2/sites-available/uwsgi-keystone.conf /etc/apache2/sites-enabled/

Start or restart HTTPD to pick up the new configuration.

Now configure and start the uwsgi services. Copy the
`httpd/keystone-uwsgi-admin.ini` and `httpd/keystone-uwsgi-public.ini` files to
`/etc/keystone`. Update the files to match your system configuration (for
example, you'll want to set the number of processes and threads for the public
and admin servers).

Start up the keystone servers using uwsgi::

    $ sudo pip install uwsgi
    $ uwsgi /etc/keystone/keystone-uwsgi-admin.ini
    $ uwsgi /etc/keystone/keystone-uwsgi-public.ini


mod_wsgi
--------

.. WARNING::

    Running Keystone under HTTPD in this configuration does not support the use
    of ``Transfer-Encoding: chunked``. This is due to a limitation with the
    WSGI spec and the implementation used by ``mod_wsgi``. It is recommended
    that all clients assume Keystone will not support
    ``Transfer-Encoding: chunked``.

Copy the ``httpd/wsgi-keystone.conf`` sample configuration file to the
appropriate location for your Apache server, on Debian/Ubuntu systems
it is::

    /etc/apache2/sites-available/wsgi-keystone.conf

On Red Hat based systems it is::

    /etc/httpd/conf.d/wsgi-keystone.conf

Update the file to match your system configuration. Note the following:

* Make sure the correct log directory is used. Some distributions put httpd
  server logs in the ``apache2`` directory and some in the ``httpd`` directory.
* Enable TLS by supplying the correct certificates.

Keystone's primary configuration file (``etc/keystone.conf``) and the
PasteDeploy configuration file (``etc/keystone-paste.ini``) must be readable to
HTTPD in one of the default locations described in :doc:`configuration`.

Configuration file location can be customized using the ``OS_KEYSTONE_CONFIG_DIR``
environment variable: if this is set, the ``keystone.conf`` file will be searched
inside this directory. Arbitrary configuration file locations can be specified
using ``OS_KEYSTONE_CONFIG_FILES`` variable as semicolon separated entries,
representing either configuration directory based relative paths or absolute
paths.

Enable the site by creating a symlink from the file in ``sites-available`` to
``sites-enabled``, for example, on Debian/Ubuntu systems
(not required on Red Hat based systems)::

  ln -s /etc/apache2/sites-available/wsgi-keystone.conf /etc/apache2/sites-enabled/

Restart Apache to have it start serving keystone.


Access Control
--------------

If you are running with Linux kernel security module enabled (for example
SELinux or AppArmor) make sure that the file has the appropriate context to
access the linked file.

Keystone Configuration
----------------------

Make sure that when using a token format that requires persistence, you use a
token persistence driver that can be shared between processes. The SQL and
memcached token persistence drivers provided with keystone can be shared
between processes.

.. WARNING::

    The KVS (``kvs``) token persistence driver cannot be shared between
    processes so must not be used when running keystone under HTTPD (the tokens
    will not be shared between the processes of the server and validation will
    fail).

For SQL, in ``/etc/keystone/keystone.conf`` set::

    [token]
    driver = sql

For memcached, in ``/etc/keystone/keystone.conf`` set::

    [token]
    driver = memcache

All servers that are storing tokens need a shared backend. This means that
either all servers use the same database server or use a common memcached pool.
