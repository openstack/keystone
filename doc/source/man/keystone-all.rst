============
keystone-all
============

------------------------
Keystone Startup Command
------------------------

:Author: openstack@lists.launchpad.net
:Date:   2010-11-16
:Copyright: OpenStack LLC
:Version: 2012.1
:Manual section: 1
:Manual group: cloud computing

SYNOPSIS
========

  keystone-all [options]

DESCRIPTION
===========

keystone-all starts both the service and administrative APIs in a single
process to provide catalog, authorization, and authentication services for
OpenStack.

OPTIONS
=======

  -h, --help            show this help message and exit
  --config-file=PATH    Path to a config file to use. Multiple config files
                        can be specified, with values in later files taking
                        precedence. The default files used are:
                        ['/etc/keystone/keystone.conf']
  --config-dir=DIR      Path to a config directory to pull *.conf files from.
                        This file set is sorted, so as to provide a
                        predictable parse order if individual options are
                        over-ridden. The set is parsed after the file(s), if
                        any, specified via --config-file, hence over-ridden
                        options in the directory take precedence.
  -d, --debug           Print debugging output
  --nodebug             The inverse of --debug
  -v, --verbose         Print more verbose output
  --noverbose           The inverse of --verbose
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
  --nouse-syslog        The inverse of --use-syslog

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
