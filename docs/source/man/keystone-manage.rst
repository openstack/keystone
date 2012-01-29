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
service to initialize and update data within Keystone. Keystone *must* be 
opertional for the keystone-manage commands to function correctly.

USAGE
=====

    ``keystone-manage [options] type action [additional args]``


General keystone-manage options:
--------------------------------

* ``--id-only`` : causes ``keystone-manage`` to return only the UUID result
from the API call.
* ``--endpoint`` : allows you to specify the keystone endpoint to communicate with. The default endpoint is http://localhost:35357/v2.0'
* ``--auth-token`` : provides the authorization token

``keystone-manage`` is set up to expect commands in the general form of ``keystone-manage`` ``command`` ``subcommand``, with keyword arguments to provide additional information to the command. For example, the command
``tenant`` has the subcommand ``create``, which takes the required keyword ``tenant_name``::

	keystone-manage tenant create tenant_name=example_tenant

Invoking keystone-manage by itself will give you some usage information.

Available keystone-manage commands:
  db_sync: Sync the database.
      ec2: no docs
     role: Role CRUD functions.
  service: Service CRUD functions.
   tenant: Tenant CRUD functions.
    token: Token CRUD functions.
     user: User CRUD functions.

Tenants
-------

Tenants are the high level grouping within Keystone that represent groups of
users. A tenant is the grouping that owns virtual machines within Nova, or
containers within Swift. A tenant can have zero or more users, Users can be assocaited with more than one tenant, and each tenant - user pairing can have a role associated with it.

* tenant create

	keyword arguments
    * tenant_name
	* id (optional)

example::
	keystone-manage --id-only tenant create tenant_name=admin

creates a tenant named "admin".

* tenant delete

	keyword arguments
	* tenant_id
	
example::
	keystone-manage tenant delete tenant_id=f2b7b39c860840dfa47d9ee4adffa0b3

* tenant update

	keyword arguments
	* description
	* name
	* tenant_id

example::
	keystone-manage tenant update \
	tenant_id=f2b7b39c860840dfa47d9ee4adffa0b3 \
	description="those other guys" \
	name=tog

Users
-----

* user create

	keyword arguments
	* name
	* password
	* email
	
example::
	keystone-manage user --ks-id-only create \
	name=admin \
	password=secrete \
	email=admin@example.com
	
* user delete

	keyword arguments

* user list

	keyword arguments

* user update_email

	keyword arguments

* user update_enabled

	keyword arguments

* user update_password
 
	keyword arguments

* user update_tenant

	keyword arguments

Roles
-----

* role create

	keyword arguments
	* name

exmaple::
	keystone-manage role --ks-id-only create name=Admin
	
* role add_user_to_tenant

	keyword arguments
	* role_id
	* user_id
	* tenant_id

example::

	keystone-manage role add_user_to_tenant \
	role_id=19d1d3344873464d819c45f521ff9890 \
	user_id=08741d8ed88242ca88d1f61484a0fe3b \
	tenant_id=20601a7f1d94447daa4dff438cb1c209
	
* role remove_user_from_tenant

* role get_user_role_refs

Services
--------

* service create

	keyword arguments
	* name
	* service_type
	* description

example::
	keystone-manage service create \
    name=nova \
    service_type=compute \
    description="Nova Compute Service"


OPTIONS
=======

Options:
  -h, --help            show this help message and exit
  --config-file=PATH    Path to a config file to use. Multiple config files
                        can be specified, with values in later files taking
                        precedence. The default files used are: []
  -d, --debug           Print debugging output
  --nodebug             Print debugging output
  -v, --verbose         Print more verbose output
  --noverbose           Print more verbose output
  --log-config=PATH     If this option is specified, the logging configuration
                        file specified is used and overrides any other logging
                        options specified. Please see the Python logging
                        module documentation for details on logging
                        configuration files.
  --log-format=FORMAT   A logging.Formatter log message format string which
                        may use any of the available logging.LogRecord
                        attributes. Default: none
  --log-date-format=DATE_FORMAT
                        Format string for %(asctime)s in log records. Default:
                        none
  --log-file=PATH       (Optional) Name of log file to output to. If not set,
                        logging will go to stdout.
  --log-dir=LOG_DIR     (Optional) The directory to keep log files in (will be
                        prepended to --logfile)
  --syslog-log-facility=SYSLOG_LOG_FACILITY
                        (Optional) The syslog facility to use when logging to
                        syslog (defaults to LOG_USER)
  --use-syslog          Use syslog for logging.
  --nouse-syslog        Use syslog for logging.
  --endpoint=ENDPOINT   
  --auth-token=AUTH_TOKEN
                        authorization token
  --id-only             
  --noid-only           
  
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
