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

keystone-manage is a utility for managing and configuring a Keystone installation.
One important use of keystone-manage is to setup the database. To do this run::

    keystone-manage db_sync

OPTIONS
=======

  **General options**

  **-v, --verbose**
        Print more verbose output

  **--sql_connection=CONN_STRING**
        A proper SQLAlchemy connection string as described
        `here <http://www.sqlalchemy.org/docs/05/reference/sqlalchemy/connections.html?highlight=engine#sqlalchemy.create_engine>`_

FILES
=====

None

SEE ALSO
========

* `Keystone <http://github.com/rackspace/keystone>`__

BUGS
====

* Keystone is sourced in GitHub so you can view current bugs at `Keystone <http://github.com/rackspace/keystone>`__
