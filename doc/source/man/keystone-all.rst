============
keystone-all
============

------------------------
Keystone Startup Command
------------------------

:Author: openstack@lists.openstack.org
:Date:   2013-10-17
:Copyright: OpenStack Foundation
:Version: 2013.2
:Manual section: 1
:Manual group: cloud computing

SYNOPSIS
========

::

  keystone-all [-h] [--config-dir DIR] [--config-file PATH] [--debug]
                    [--log-config PATH] [--log-date-format DATE_FORMAT]
                    [--log-dir LOG_DIR] [--log-file PATH]
                    [--log-format FORMAT] [--nodebug] [--nostandard-threads]
                    [--nouse-syslog] [--noverbose]
                    [--pydev-debug-host PYDEV_DEBUG_HOST]
                    [--pydev-debug-port PYDEV_DEBUG_PORT] [--standard-threads]
                    [--syslog-log-facility SYSLOG_LOG_FACILITY] [--use-syslog]
                    [--verbose] [--version]

DESCRIPTION
===========

keystone-all starts both the service and administrative APIs in a single
process to provide catalog, authorization, and authentication services for
OpenStack.

OPTIONS
=======

  -h, --help            show this help message and exit
  --config-dir DIR      Path to a config directory to pull \*.conf files from.
                        This file set is sorted, so as to provide a
                        predictable parse order if individual options are
                        over-ridden. The set is parsed after the file(s)
                        specified via previous --config-file, arguments hence
                        over-ridden options in the directory take precedence.
  --config-file PATH    Path to a config file to use. Multiple config files
                        can be specified, with values in later files taking
                        precedence. The default files used are: None
  --debug, -d           Print debugging output (set logging level to DEBUG
                        instead of default WARNING level).
  --log-config PATH     If this option is specified, the logging configuration
                        file specified is used and overrides any other logging
                        options specified. Please see the Python logging
                        module documentation for details on logging
                        configuration files.
  --log-date-format DATE_FORMAT
                        Format string for %(asctime)s in log records. Default:
                        None
  --log-dir LOG_DIR, --logdir LOG_DIR
                        (Optional) The base directory used for relative
                        --log-file paths
  --log-file PATH, --logfile PATH
                        (Optional) Name of log file to output to. If no
                        default is set, logging will go to stdout.
  --log-format FORMAT   DEPRECATED. A logging.Formatter log message format
                        string which may use any of the available
                        logging.LogRecord attributes. This option is
                        deprecated. Please use logging_context_format_string
                        and logging_default_format_string instead.
  --nodebug             The inverse of --debug
  --nostandard-threads  The inverse of --standard-threads
  --nouse-syslog        The inverse of --use-syslog
  --noverbose           The inverse of --verbose
  --pydev-debug-host PYDEV_DEBUG_HOST
                        Host to connect to for remote debugger.
  --pydev-debug-port PYDEV_DEBUG_PORT
                        Port to connect to for remote debugger.
  --standard-threads    Do not monkey-patch threading system modules.
  --syslog-log-facility SYSLOG_LOG_FACILITY
                        syslog facility to receive log lines
  --use-syslog          Use syslog for logging.
  --verbose, -v         Print more verbose output (set logging level to INFO
                        instead of default WARNING level).
  --version             show program's version number and exit

FILES
=====

None

SEE ALSO
========

* `Keystone <http://github.com/openstack/keystone>`__

SOURCE
======

* Keystone source is managed in GitHub `Keystone <http://github.com/openstack/keystone>`__
* Keystone bugs are managed at Launchpad `Keystone <https://bugs.launchpad.net/keystone>`__
