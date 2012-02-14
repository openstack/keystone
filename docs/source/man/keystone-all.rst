========
keystone
========

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

  keystone-all [options]

DESCRIPTION
===========

keystone-all starts both the service and administrative APIs in a single
process to provide catalog, authorization, and authentication services for
OpenStack.

USAGE
=====

    ``keystone-all [options]``

Common Options:
^^^^^^^^^^^^^^^
   -h, --help            show this help message and exit

The following configuration options are common to all keystone
programs.::

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

FILES
=====

None

SEE ALSO
========

* `Keystone <http://github.com/openstack/keystone>`__

SOURCE
======

* Keystone source is managed in GitHub `Keystone <http://github.com/openstack/keystone>`__
* Keystone bugs are managed at Launchpad `Launchpad Keystone <https://bugs.launchpad.net/keystone>`__
