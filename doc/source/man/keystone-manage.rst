===============
keystone-manage
===============

---------------------------
Keystone Management Utility
---------------------------

:Author: openstack@lists.launchpad.net
:Date:   2010-11-16
:Copyright: OpenStack LLC
:Version: 2012.1
:Manual section: 1
:Manual group: cloud computing

SYNOPSIS
========

  keystone-manage [options]

DESCRIPTION
===========

keystone-manage is the command line tool that interacts with the keystone
service to initialize and update data within Keystone.  Generally,
keystone-manage is only used for operations that can not be accomplished
with through the keystone REST api, such data import/export and schema
migrations.


USAGE
=====

    ``keystone-manage [options] action [additional args]``


General keystone-manage options:
--------------------------------

* ``--help`` : display verbose help output.

Invoking keystone-manage by itself will give you some usage information.

Available commands:

* ``db_sync``: Sync the database.
* ``export_legacy_catalog``: Export the service catalog from a legacy database.
* ``import_legacy``: Import a legacy database.
* ``import_nova_auth``: Import a dump of nova auth data into keystone.
* ``pki_setup``: Initialize the certificates used to sign tokens.
* ``ssl_setup``: Generate certificates for SSL.
* ``token_flush``: Purge expired tokens.


OPTIONS
=======

  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --pydev-debug-port PYDEV_DEBUG_PORT
  --verbose, -v         Print more verbose output (set logging level to INFO
                        instead of default WARNING level).
  --noverbose           The inverse of --verbose
  --config-dir DIR      Path to a config directory to pull *.conf files from.
                        This file set is sorted, so as to provide a
                        predictable parse order if individual options are
                        over-ridden. The set is parsed after the file(s), if
                        any, specified via --config-file, hence over-ridden
                        options in the directory take precedence.
  --log-config PATH     If this option is specified, the logging configuration
                        file specified is used and overrides any other logging
                        options specified. Please see the Python logging
                        module documentation for details on logging
                        configuration files.
  --log-date-format DATE_FORMAT
                        Format string for %(asctime)s in log records.
  --use-syslog          Use syslog for logging.
  --nouse-syslog        The inverse of --use-syslog
  --log-dir LOG_DIR     The directory in which to store log files. (will be
                        prepended to --log-file)
  --syslog-log-facility SYSLOG_LOG_FACILITY
                        syslog facility to receive log lines.
  --standard-threads
  --nostandard-threads  The inverse of --standard-threads
  --config-file PATH    Path to a config file to use. Multiple config files
                        can be specified, with values in later files taking
                        precedence. The default files used are:
                        ['/etc/keystone/keystone.conf']
  --pydev-debug-host PYDEV_DEBUG_HOST
  --debug, -d           Print debugging output (set logging level to DEBUG
                        instead of default WARNING level).
  --nodebug             The inverse of --debug
  --log-format FORMAT   A logging.Formatter log message format string which
                        may use any of the available logging.LogRecord
                        attributes.
  --log-file PATH       Name of log file to output. If not set, logging will
                        go to stdout.

FILES
=====

None

SEE ALSO
========

* `Keystone <http://github.com/openstack/keystone>`__

SOURCE
======

* Keystone is sourced in GitHub `Keystone <http://github.com/openstack/keystone>`__
* Keystone bugs are managed at Launchpad `Keystone <https://bugs.launchpad.net/keystone>`__
