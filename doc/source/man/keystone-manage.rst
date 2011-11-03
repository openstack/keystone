===============
keystone-manage
===============

---------------------------
Keystone Management Utility
---------------------------

:Author: keystone@lists.launchpad.net
:Date:   2010-11-16
:Copyright: OpenStack LLC
:Version: 0.1.2
:Manual section: 1
:Manual group: cloud computing

SYNOPSIS
========

  keystone-manage [options]

DESCRIPTION
===========

keystone-manage is the command line tool that interacts with the keystone
service to configure Keystone

USAGE
=====

    ``keystone-manage [options] type action [additional args]``

user
^^^^

* **user add** [username] [password]

  adds a user to Keystone's data store

* **user list**

  lists all users

* **user disable** [username]

  disables the user *username*

tenant
^^^^^^

* **tenant add** [tenant_name]

  adds a tenant to Keystone's data store

* **tenant list**

  lists all users

* **tenant disable** [tenant_name]

role
^^^^

Roles are used to associated users to tenants. Two roles are defined related
to the Keystone service in it's configuration file :doc:`../keystone.conf`

* **role add** [role_name]

  adds a role

* **role list** ([tenant_name])

  lists all roles, or all roles for tenant, if tenant_name is provided

* **role grant** [role_name] [username] ([tenant])

  grants a role to a specific user. Granted globally if tenant_name is not
  provided or granted for a specific tenant if tenant_name is provided.

service
^^^^^^^

* **service add** [name] [type] [description]

  adds a service

* **service list**

  lists all services with id, name, and type

endpointTemplate
^^^^^^^^^^^^^^^^

* **endpointTemplate add** [region] [service] [public_url] [admin_url] [internal_url] [enabled] [is_global]

  Add a service endpoint for keystone.

  example::

      keystone-manage endpointTemplates add RegionOne \
                      keystone \
                      http://keystone_host:5000/v2.0 \
                      http://keystone_host:35357/v2.0 \
                      http://keystone_host:5000/v2.0 \
                      1 1


* **endpointTemplate list** ([tenant_name])

  lists endpoint templates with service, region, and public_url. Restricted to
tenant endpoints if tenant_name is provided.

token
^^^^^

* **token add** [token] [username] [tenant] [expiration]

  adds a token for a given user and tenant with an expiration

* **token list**

  lists all tokens

* **token delete** [token]

  deletes the identified token

endpoint
^^^^^^^^

* **endpoint add** [tenant_name] [endpoint_template]

  adds a tenant-specific endpoint

credentials
^^^^^^^^^^^

* **credentials add** [username] [type] [key] [password] ([tenant_name])

OPTIONS
=======

   --version                     show program's version number and exit
   -h, --help                    show this help message and exit
   -v, --verbose                 Print more verbose output
   -d, --debug                   Print debugging output to console
   -c PATH, --config-file=PATH   Path to the config file to use. When not
                                 specified (the default), we generally look at
                                 the first argument specified to be a config
                                 file, and if that is also missing, we search
                                 standard directories for a config file.
   -p BIND_PORT, --port=BIND_PORT, --bind-port=BIND_PORT
                                 specifies port to listen on (default is 5000)
   --host=BIND_HOST, --bind-host=BIND_HOST
                                 specifies host address to listen on (default
                                 is all or 0.0.0.0)
   -t, --trace-calls             Turns on call tracing for troubleshooting
   -a PORT, --admin-port=PORT    Specifies port for Admin API to listen on
                                 (default is 35357)

Logging Options:
================

The following configuration options are specific to logging
functionality for this program.

   --log-config=PATH             If this option is specified, the logging
                                 configuration file specified is used and
                                 overrides any other logging options specified.
                                 Please see the Python logging module
                                 documentation for details on logging
                                 configuration files.
   --log-date-format=FORMAT      Format string for %(asctime)s in log records.
                                 Default: %Y-%m-%d %H:%M:%S
   --log-file=PATH               (Optional) Name of log file to output to. If
                                 not set, logging will go to stdout.
   --log-dir=LOG_DIR             (Optional) The directory to keep log files in
                                 (will be prepended to --logfile)

FILES
=====

None

SEE ALSO
========

* `Keystone <http://github.com/openstack/keystone>`__

SOURCE
======

* Keystone is sourced in GitHub `Keystone <http://github.com/openstack/keystone>`__
* Keystone bugs are managed at Launchpad `Launchpad Keystone <https://bugs.launchpad.net/keystone>`__
