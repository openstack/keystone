..
      Copyright 2011-2012 OpenStack, LLC
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

============================
Controlling Keystone Servers
============================

This section describes the ways to start, stop, and reload the Keystone
services.

Keystone Services
-----------------

Keystone can serve a number of REST APIs and extensions on different TCP/IP
ports.

The Service API
~~~~~~~~~~~~~~~~

The core Keystone
API is primarily a read-only API (the only write operation being POST /tokens
which authenticates a client, and returns a generated token).
This API is sufficient to use OpenStack if all users, roles, endpoints already
exist. This is often the case if Keystone is using an enterprise backend
and the backend is managed through other entperrise tools and business
processes. This core API is called the Service API and can be started
separately from the more complete Admin API. By default, Keystone runs
this API on port 5000. This is not an IANA assigned port and should not
be relied upon (instead, use the Admin API on port 35357 to look for
this endpoint - more on this later)

The Service API is started using this command in the /bin directory::

    $ ./keystone-auth

The Admin API
~~~~~~~~~~~~~

Inn order for Keystone to be a fully functional service out of the box,
API extensions that provide full CRUD operations is included with Keystone.
This full set of API calls includes the OS-KSCATALOG, OS-KSADM, and OS-KSEC2
extensions. These extensions provide a full set of create, read, update, delete
(CRUD) operations that can be used to manage Keystone objects through REST
calls. By default Keystone runs this full REST API on TCP/IP port 35357
(assigned by IANA to Keystone).

The Admin API is started using this command in the /bin directory::

    $ ./keystone-admin


Both APIs can be loaded simultaneously (on different ports) using this command::

    $ ./keystone

Starting a server
-----------------

There are two ways to start a Keystone service (either the Service API server
or the Admin API server):

- Manually calling the server program
- Using the ``keystone-control`` server daemon wrapper program

We recommend using the second way in production and the first for development
and debugging.

Manually starting the server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The first is by directly calling the server program, passing in command-line
options and a single argument for a ``paste.deploy`` configuration file to
use when configuring the server application.

.. note::

  Keystone ships with an ``etc/`` directory that contains a sample ``paste.deploy``
  configuration files that you can copy to a standard configuration directory and
  adapt for your own uses.

If you do `not` specify a configuration file on the command line, Keystone will
do its best to locate a configuration file in one of the
following directories, stopping at the first config file it finds:

- ``$CWD``
- ``~/.keystone``
- ``~/``
- ``/etc/keystone``
- ``/etc``

The filename that is searched for is ``keystone.conf`` by default.

If no configuration file is found, you will see an error, like::

    $ keystone
    ERROR: Unable to locate any configuration file. Cannot load application keystone

Here is an example showing how you can manually start the ``keystone-auth`` server and ``keystone-registry`` in a shell::

    $ ./keystone -d
    keystone-legacy-auth: INFO     **************************************************
    keystone-legacy-auth: INFO     Configuration options gathered from config file:
    keystone-legacy-auth: INFO     /Users/ziadsawalha/Documents/Code/keystone/etc/keystone.conf
    keystone-legacy-auth: INFO     ================================================
    keystone-legacy-auth: INFO     admin_host           0.0.0.0
    keystone-legacy-auth: INFO     admin_port           35357
    keystone-legacy-auth: INFO     admin_ssl            False
    keystone-legacy-auth: INFO     backends             keystone.backends.sqlalchemy
    keystone-legacy-auth: INFO     ca_certs             /etc/keystone/ssl/certs/ca.pem
    keystone-legacy-auth: INFO     cert_required        True
    keystone-legacy-auth: INFO     certfile             /etc/keystone/ssl/certs/keystone.pem
    keystone-legacy-auth: INFO     debug                True
    keystone-legacy-auth: INFO     default_store        sqlite
    keystone-legacy-auth: INFO     extensions           osksadm,oskscatalog,hpidm
    keystone-legacy-auth: INFO     hash-password        True
    keystone-legacy-auth: INFO     keyfile              /etc/keystone/ssl/private/keystonekey.pem
    keystone-legacy-auth: INFO     keystone-admin-role  Admin
    keystone-legacy-auth: INFO     keystone-service-admin-role KeystoneServiceAdmin
    keystone-legacy-auth: INFO     log_dir              .
    keystone-legacy-auth: INFO     log_file             keystone.log
    keystone-legacy-auth: INFO     service-header-mappings {
    'nova' : 'X-Server-Management-Url',
    'swift' : 'X-Storage-Url',
    'cdn' : 'X-CDN-Management-Url'}
    keystone-legacy-auth: INFO     service_host         0.0.0.0
    keystone-legacy-auth: INFO     service_port         5000
    keystone-legacy-auth: INFO     service_ssl          False
    keystone-legacy-auth: INFO     verbose              False
    keystone-legacy-auth: INFO     **************************************************
    passlib.registry: INFO     registered crypt handler 'sha512_crypt': <class 'passlib.handlers.sha2_crypt.sha512_crypt'>
    Starting the RAX-KEY extension
    Starting the Legacy Authentication component
    admin       : INFO     **************************************************
    admin       : INFO     Configuration options gathered from config file:
    admin       : INFO     /Users/ziadsawalha/Documents/Code/keystone/etc/keystone.conf
    admin       : INFO     ================================================
    admin       : INFO     admin_host           0.0.0.0
    admin       : INFO     admin_port           35357
    admin       : INFO     admin_ssl            False
    admin       : INFO     backends             keystone.backends.sqlalchemy
    admin       : INFO     ca_certs             /etc/keystone/ssl/certs/ca.pem
    admin       : INFO     cert_required        True
    admin       : INFO     certfile             /etc/keystone/ssl/certs/keystone.pem
    admin       : INFO     debug                True
    admin       : INFO     default_store        sqlite
    admin       : INFO     extensions           osksadm,oskscatalog,hpidm
    admin       : INFO     hash-password        True
    admin       : INFO     keyfile              /etc/keystone/ssl/private/keystonekey.pem
    admin       : INFO     keystone-admin-role  Admin
    admin       : INFO     keystone-service-admin-role KeystoneServiceAdmin
    admin       : INFO     log_dir              .
    admin       : INFO     log_file             keystone.log
    admin       : INFO     service-header-mappings {
    'nova' : 'X-Server-Management-Url',
    'swift' : 'X-Storage-Url',
    'cdn' : 'X-CDN-Management-Url'}
    admin       : INFO     service_host         0.0.0.0
    admin       : INFO     service_port         5000
    admin       : INFO     service_ssl          False
    admin       : INFO     verbose              False
    admin       : INFO     **************************************************
    Using config file: /Users/ziadsawalha/Documents/Code/keystone/etc/keystone.conf
    Service API (ssl=False) listening on 0.0.0.0:5000
    Admin API (ssl=False) listening on 0.0.0.0:35357
    eventlet.wsgi.server: DEBUG    (77128) wsgi starting up on http://0.0.0.0:5000/
    eventlet.wsgi.server: DEBUG    (77128) wsgi starting up on http://0.0.0.0:35357/

    $ sudo keystone-registry keystone-registry.conf &
    jsuh@mc-ats1:~$ 2011-04-13 14:51:16     INFO [sqlalchemy.engine.base.Engine.0x...feac] PRAGMA table_info("images")
    2011-04-13 14:51:16     INFO [sqlalchemy.engine.base.Engine.0x...feac] ()
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Col ('cid', 'name', 'type', 'notnull', 'dflt_value', 'pk')
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (0, u'created_at', u'DATETIME', 1, None, 0)
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (1, u'updated_at', u'DATETIME', 0, None, 0)
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (2, u'deleted_at', u'DATETIME', 0, None, 0)
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (3, u'deleted', u'BOOLEAN', 1, None, 0)
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (4, u'id', u'INTEGER', 1, None, 1)
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (5, u'name', u'VARCHAR(255)', 0, None, 0)
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (6, u'disk_format', u'VARCHAR(20)', 0, None, 0)
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (7, u'container_format', u'VARCHAR(20)', 0, None, 0)
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (8, u'size', u'INTEGER', 0, None, 0)
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (9, u'status', u'VARCHAR(30)', 1, None, 0)
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (10, u'is_public', u'BOOLEAN', 1, None, 0)
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (11, u'location', u'TEXT', 0, None, 0)
    2011-04-13 14:51:16     INFO [sqlalchemy.engine.base.Engine.0x...feac] PRAGMA table_info("image_properties")
    2011-04-13 14:51:16     INFO [sqlalchemy.engine.base.Engine.0x...feac] ()
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Col ('cid', 'name', 'type', 'notnull', 'dflt_value', 'pk')
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (0, u'created_at', u'DATETIME', 1, None, 0)
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (1, u'updated_at', u'DATETIME', 0, None, 0)
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (2, u'deleted_at', u'DATETIME', 0, None, 0)
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (3, u'deleted', u'BOOLEAN', 1, None, 0)
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (4, u'id', u'INTEGER', 1, None, 1)
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (5, u'image_id', u'INTEGER', 1, None, 0)
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (6, u'key', u'VARCHAR(255)', 1, None, 0)
    2011-04-13 14:51:16    DEBUG [sqlalchemy.engine.base.Engine.0x...feac] Row (7, u'value', u'TEXT', 0, None, 0)

    $ ps aux | grep keystone
    myuser    77148   0.0  0.0  2434892    472 s012  U+   11:50AM   0:00.01 grep keystone
    myuser    77128   0.0  0.6  2459356  25360 s011  S+   11:48AM   0:00.82 python ./keystone -d

Simply supply the configuration file as the first argument
and then any common options
you want to use (``-d`` was used above to show some of the debugging
output that the server shows when starting up. Call the server program
with ``--help`` to see all available options you can specify on the
command line.)

Using ``--trace-calls`` is useful for showing a trace of calls (errors in red)
for debugging.

For more information on configuring the server via the ``paste.deploy``
configuration files, see the section entitled
:doc:`Configuring Keystone <configuration>`

Note that the server `daemonizes` itself by using the standard
shell backgrounding indicator, ``&``, in the previous example. For most use cases, we recommend
using the ``keystone-control`` server daemon wrapper for daemonizing. See below
for more details on daemonization with ``keystone-control``.

Using ``keystone-control`` to start the server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The second way to start up a Keystone server is to use the ``keystone-control``
program. ``keystone-control`` is a wrapper script that allows the user to
start, stop, restart, and reload the other Keystone server programs in
a fashion that is more conducive to automation and scripting.

Servers started via the ``keystone-control`` program are always `daemonized`,
meaning that the server program process runs in the background.

To start a Keystone server with ``keystone-control``, simply call
``keystone-control`` with a server and the word "start", followed by
any command-line options you wish to provide. Start the server with ``keystone-control``
in the following way::

    $ sudo keystone-control <SERVER> start [CONFPATH]

.. note::

    You must use the ``sudo`` program to run ``keystone-control`` currently, as the
    pid files for the server programs are written to /var/run/keystone/

Start the ``keystone-admin`` server using ``keystone-control``::

    $ sudo keystone-control admin start
    Starting keystone-admin with /etc/keystone.conf

The same ``paste.deploy`` configuration files are used by ``keystone-control``
to start the Keystone server programs, and you can specify (as the example above
shows) a configuration file when starting the server.

Stopping a server
-----------------

If you started a Keystone server manually and did not use the ``&`` backgrounding
function, simply send a terminate signal to the server process by typing
``Ctrl-C``

If you started the Keystone server using ``keystone-control``, you can
use the ``keystone-control`` program to stop it::

    $ sudo keystone-control <SERVER> stop

For example::

    $ sudo keystone-control auth stop
    Stopping keystone-auth  pid: 77401  signal: 15

Restarting a server
-------------------

Restart the Keystone server using ``keystone-control``::

    $ sudo keystone-control admin restart /etc/keystone.conf
    Stopping keystone-admin  pid: 77401  signal: 15
    Starting keystone-admin with /etc/keystone.conf
